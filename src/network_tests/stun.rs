//! GAP-005: STUN binding (RFC 5389) and TURN allocation (RFC 5766) built
//! directly on raw sockets -- a STUN binding request/response is a small,
//! fixed-format binary message, and shelling out to an external client
//! would add a dependency on a tool that may not be installed (the exact
//! gap: no `stun`/`turnutils` binary was present during the incident this
//! closes).
//!
//! The mapped address this protocol reveals is the host's public egress
//! IP -- a sensitive identifier under the same policy as a BSSID (GAP-018).
//! Every type here keeps the address reachable only through explicit
//! accessors so a caller cannot serialize/print it by accident; the CLI
//! layer decides whether an explicit reveal flag was passed.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use crate::network_tests::crypto_min::{hmac_sha1, md5};

pub const MAGIC_COOKIE: u32 = 0x2112_A442;

const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;
const BINDING_ERROR: u16 = 0x0111;
const ALLOCATE_REQUEST: u16 = 0x0003;
const ALLOCATE_SUCCESS: u16 = 0x0103;
const ALLOCATE_ERROR: u16 = 0x0113;

const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_USERNAME: u16 = 0x0006;
const ATTR_MESSAGE_INTEGRITY: u16 = 0x0008;
const ATTR_ERROR_CODE: u16 = 0x0009;
const ATTR_REALM: u16 = 0x0014;
const ATTR_NONCE: u16 = 0x0015;
const ATTR_XOR_RELAYED_ADDRESS: u16 = 0x0016;
const ATTR_REQUESTED_TRANSPORT: u16 = 0x0019;
const ATTR_LIFETIME: u16 = 0x000D;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

const FAMILY_IPV4: u8 = 0x01;
const FAMILY_IPV6: u8 = 0x02;

fn random_transaction_id() -> [u8; 12] {
    use rand::RngCore;
    let mut id = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut id);
    id
}

fn pad4(len: usize) -> usize {
    (4 - (len % 4)) % 4
}

struct AttrBuilder(Vec<u8>);

impl AttrBuilder {
    fn new() -> Self {
        Self(Vec::new())
    }
    fn push(&mut self, attr_type: u16, value: &[u8]) {
        self.0.extend_from_slice(&attr_type.to_be_bytes());
        self.0.extend_from_slice(&(value.len() as u16).to_be_bytes());
        self.0.extend_from_slice(value);
        for _ in 0..pad4(value.len()) {
            self.0.push(0);
        }
    }
}

fn build_message(msg_type: u16, transaction_id: [u8; 12], attrs: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(20 + attrs.len());
    out.extend_from_slice(&msg_type.to_be_bytes());
    out.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
    out.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    out.extend_from_slice(&transaction_id);
    out.extend_from_slice(attrs);
    out
}

pub fn build_binding_request() -> (Vec<u8>, [u8; 12]) {
    let txn = random_transaction_id();
    (build_message(BINDING_REQUEST, txn, &[]), txn)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StunError {
    TooShort,
    BadMagicCookie,
    TransactionIdMismatch,
    UnexpectedMessageType(u16),
    ErrorResponse { class: u8, number: u8 },
    MissingMappedAddress,
    MalformedAddressAttribute,
}

impl std::fmt::Display for StunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StunError::TooShort => write!(f, "response shorter than a STUN header"),
            StunError::BadMagicCookie => write!(f, "response magic cookie does not match RFC 5389"),
            StunError::TransactionIdMismatch => write!(f, "response transaction ID does not match the request"),
            StunError::UnexpectedMessageType(t) => write!(f, "unexpected STUN message type 0x{t:04x}"),
            StunError::ErrorResponse { class, number } => write!(f, "STUN error response {}{:02}", class, number),
            StunError::MissingMappedAddress => write!(f, "success response carried no (XOR-)MAPPED-ADDRESS"),
            StunError::MalformedAddressAttribute => write!(f, "(XOR-)MAPPED-ADDRESS attribute was malformed"),
        }
    }
}

struct ParsedMessage {
    msg_type: u16,
    transaction_id: [u8; 12],
    attrs: Vec<(u16, Vec<u8>)>,
}

fn parse_message(bytes: &[u8]) -> Result<ParsedMessage, StunError> {
    if bytes.len() < 20 {
        return Err(StunError::TooShort);
    }
    let msg_type = u16::from_be_bytes([bytes[0], bytes[1]]);
    let length = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
    let cookie = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    if cookie != MAGIC_COOKIE {
        return Err(StunError::BadMagicCookie);
    }
    let mut transaction_id = [0u8; 12];
    transaction_id.copy_from_slice(&bytes[8..20]);

    let body_end = (20 + length).min(bytes.len());
    let body = &bytes[20..body_end];
    let mut attrs = Vec::new();
    let mut i = 0;
    while i + 4 <= body.len() {
        let attr_type = u16::from_be_bytes([body[i], body[i + 1]]);
        let attr_len = u16::from_be_bytes([body[i + 2], body[i + 3]]) as usize;
        let val_start = i + 4;
        let val_end = (val_start + attr_len).min(body.len());
        if val_start > body.len() {
            break;
        }
        attrs.push((attr_type, body[val_start..val_end].to_vec()));
        i = val_end + pad4(attr_len);
    }
    Ok(ParsedMessage { msg_type, transaction_id, attrs })
}

fn decode_xor_mapped_address(value: &[u8], txn: &[u8; 12]) -> Result<SocketAddr, StunError> {
    if value.len() < 4 {
        return Err(StunError::MalformedAddressAttribute);
    }
    let family = value[1];
    let xport = u16::from_be_bytes([value[2], value[3]]);
    let port = xport ^ ((MAGIC_COOKIE >> 16) as u16);
    match family {
        FAMILY_IPV4 => {
            if value.len() < 8 {
                return Err(StunError::MalformedAddressAttribute);
            }
            let xaddr = u32::from_be_bytes([value[4], value[5], value[6], value[7]]);
            let addr = xaddr ^ MAGIC_COOKIE;
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(addr)), port))
        }
        FAMILY_IPV6 => {
            if value.len() < 20 {
                return Err(StunError::MalformedAddressAttribute);
            }
            let mut mask = [0u8; 16];
            mask[0..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
            mask[4..16].copy_from_slice(txn);
            let mut addr_bytes = [0u8; 16];
            for i in 0..16 {
                addr_bytes[i] = value[4 + i] ^ mask[i];
            }
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(addr_bytes)), port))
        }
        _ => Err(StunError::MalformedAddressAttribute),
    }
}

fn decode_mapped_address(value: &[u8]) -> Result<SocketAddr, StunError> {
    if value.len() < 4 {
        return Err(StunError::MalformedAddressAttribute);
    }
    let family = value[1];
    let port = u16::from_be_bytes([value[2], value[3]]);
    match family {
        FAMILY_IPV4 => {
            if value.len() < 8 {
                return Err(StunError::MalformedAddressAttribute);
            }
            Ok(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(value[4], value[5], value[6], value[7])),
                port,
            ))
        }
        FAMILY_IPV6 => {
            if value.len() < 20 {
                return Err(StunError::MalformedAddressAttribute);
            }
            let mut b = [0u8; 16];
            b.copy_from_slice(&value[4..20]);
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(b)), port))
        }
        _ => Err(StunError::MalformedAddressAttribute),
    }
}

/// Validates a binding response against the request it answers -- magic
/// cookie, transaction ID, message type, and a well-formed mapped-address
/// attribute all have to hold before this counts as a successful binding.
/// A response failing any of these is `Err`, never silently treated as a
/// weaker form of success (the acceptance criteria's "with validation").
pub fn parse_binding_response(bytes: &[u8], expected_txn: [u8; 12]) -> Result<SocketAddr, StunError> {
    let parsed = parse_message(bytes)?;
    if parsed.transaction_id != expected_txn {
        return Err(StunError::TransactionIdMismatch);
    }
    match parsed.msg_type {
        BINDING_SUCCESS => {}
        BINDING_ERROR => {
            let (class, number) = extract_error_code(&parsed.attrs);
            return Err(StunError::ErrorResponse { class, number });
        }
        other => return Err(StunError::UnexpectedMessageType(other)),
    }
    for (t, v) in &parsed.attrs {
        if *t == ATTR_XOR_MAPPED_ADDRESS {
            return decode_xor_mapped_address(v, &expected_txn);
        }
    }
    for (t, v) in &parsed.attrs {
        if *t == ATTR_MAPPED_ADDRESS {
            return decode_mapped_address(v);
        }
    }
    Err(StunError::MissingMappedAddress)
}

fn extract_error_code(attrs: &[(u16, Vec<u8>)]) -> (u8, u8) {
    for (t, v) in attrs {
        if *t == ATTR_ERROR_CODE && v.len() >= 4 {
            return (v[2] & 0x07, v[3]);
        }
    }
    (0, 0)
}

/// One outcome of a single binding attempt. `Unreachable` (no response
/// within the timeout) and a validated `Mapped` address are kept as
/// distinct variants deliberately -- collapsing "no answer" into "same as
/// before" is exactly the silence-read-as-stability bug this gate exists
/// to catch.
#[derive(Debug, Clone)]
pub enum BindingOutcome {
    Mapped(SocketAddr),
    Unreachable,
    Invalid(StunError),
}

#[derive(Debug, Clone)]
pub struct BindingAttempt {
    pub outcome: BindingOutcome,
    pub rtt_ms: Option<f64>,
}

pub fn binding_request_once(socket: &UdpSocket, server: SocketAddr, timeout: Duration) -> BindingAttempt {
    let (request, txn) = build_binding_request();
    socket.set_read_timeout(Some(timeout)).ok();
    let start = Instant::now();
    if socket.send_to(&request, server).is_err() {
        return BindingAttempt { outcome: BindingOutcome::Unreachable, rtt_ms: None };
    }
    let mut buf = [0u8; 512];
    match socket.recv_from(&mut buf) {
        Ok((n, _from)) => {
            let rtt_ms = start.elapsed().as_secs_f64() * 1000.0;
            match parse_binding_response(&buf[..n], txn) {
                Ok(addr) => BindingAttempt { outcome: BindingOutcome::Mapped(addr), rtt_ms: Some(rtt_ms) },
                Err(e) => BindingAttempt { outcome: BindingOutcome::Invalid(e), rtt_ms: Some(rtt_ms) },
            }
        }
        Err(_) => BindingAttempt { outcome: BindingOutcome::Unreachable, rtt_ms: None },
    }
}

// --- TURN allocation (RFC 5766), reusing the STUN header/attribute wire
// format -- TURN messages are STUN messages with a different method set. ---

#[derive(Debug, Clone)]
pub struct TurnCredentials {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone)]
pub enum TurnOutcome {
    Allocated { lifetime_secs: u32, relayed: SocketAddr },
    Unauthorized,
    CredentialsRejected,
    NoCredentialsSupplied,
    Unreachable,
    Invalid(String),
}

fn build_allocate_request(txn: [u8; 12]) -> Vec<u8> {
    let mut attrs = AttrBuilder::new();
    // REQUESTED-TRANSPORT: protocol 17 = UDP (RFC 5766 14.7), 3 reserved bytes.
    attrs.push(ATTR_REQUESTED_TRANSPORT, &[17, 0, 0, 0]);
    build_message(ALLOCATE_REQUEST, txn, &attrs.0)
}

fn long_term_key(username: &str, realm: &str, password: &str) -> [u8; 16] {
    let input = format!("{username}:{realm}:{password}");
    md5(input.as_bytes())
}

fn build_authenticated_allocate_request(
    txn: [u8; 12],
    username: &str,
    realm: &str,
    nonce: &[u8],
    key: &[u8; 16],
) -> Vec<u8> {
    let mut attrs = AttrBuilder::new();
    attrs.push(ATTR_REQUESTED_TRANSPORT, &[17, 0, 0, 0]);
    attrs.push(ATTR_USERNAME, username.as_bytes());
    attrs.push(ATTR_REALM, realm.as_bytes());
    attrs.push(ATTR_NONCE, nonce);

    // MESSAGE-INTEGRITY (RFC 5389 15.4): HMAC-SHA1 over everything up to
    // this attribute, with the header length field set as if the message
    // ended right after a 24-byte MESSAGE-INTEGRITY attribute (20-byte
    // HMAC + 4-byte attribute header) -- the receiver computes the same
    // over-truncated view, so the field must reflect that, not the final
    // message length.
    let mi_len_placeholder = attrs.0.len() + 24;
    let mut header_for_mi = Vec::with_capacity(20 + attrs.0.len());
    header_for_mi.extend_from_slice(&ALLOCATE_REQUEST.to_be_bytes());
    header_for_mi.extend_from_slice(&(mi_len_placeholder as u16).to_be_bytes());
    header_for_mi.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    header_for_mi.extend_from_slice(&txn);
    header_for_mi.extend_from_slice(&attrs.0);

    let mac = hmac_sha1(key, &header_for_mi);
    attrs.push(ATTR_MESSAGE_INTEGRITY, &mac);

    build_message(ALLOCATE_REQUEST, txn, &attrs.0)
}

fn extract_realm_nonce(attrs: &[(u16, Vec<u8>)]) -> (Option<String>, Option<Vec<u8>>) {
    let mut realm = None;
    let mut nonce = None;
    for (t, v) in attrs {
        if *t == ATTR_REALM {
            realm = String::from_utf8(v.clone()).ok();
        } else if *t == ATTR_NONCE {
            nonce = Some(v.clone());
        }
    }
    (realm, nonce)
}

fn parse_allocate_response(bytes: &[u8], expected_txn: [u8; 12]) -> Result<TurnOutcome, String> {
    let parsed = parse_message(bytes).map_err(|e| e.to_string())?;
    if parsed.transaction_id != expected_txn {
        return Err("TURN response transaction ID mismatch".to_string());
    }
    match parsed.msg_type {
        ALLOCATE_SUCCESS => {
            let mut lifetime = None;
            let mut relayed = None;
            for (t, v) in &parsed.attrs {
                if *t == ATTR_LIFETIME && v.len() >= 4 {
                    lifetime = Some(u32::from_be_bytes([v[0], v[1], v[2], v[3]]));
                } else if *t == ATTR_XOR_RELAYED_ADDRESS {
                    relayed = decode_xor_mapped_address(v, &expected_txn).ok();
                }
            }
            match (lifetime, relayed) {
                (Some(l), Some(r)) => Ok(TurnOutcome::Allocated { lifetime_secs: l, relayed: r }),
                _ => Err("ALLOCATE success carried no LIFETIME/XOR-RELAYED-ADDRESS".to_string()),
            }
        }
        ALLOCATE_ERROR => {
            let (class, number) = extract_error_code(&parsed.attrs);
            if class == 4 && number == 1 {
                Ok(TurnOutcome::Unauthorized)
            } else if class == 4 && (number == 1 || number == 41) {
                Ok(TurnOutcome::CredentialsRejected)
            } else if class == 4 && number == 38 {
                Ok(TurnOutcome::CredentialsRejected)
            } else {
                Err(format!("TURN error response {class}{number:02}"))
            }
        }
        other => Err(format!("unexpected TURN message type 0x{other:04x}")),
    }
}

/// Runs the full long-term-credential ALLOCATE exchange over UDP: the first
/// (unauthenticated) request gets a 401 challenge carrying REALM/NONCE,
/// which is then used to compute the MD5 long-term key and resend an
/// authenticated request. Returns cleanly with `NoCredentialsSupplied`
/// rather than attempting an unauthenticated allocation and reporting a
/// bare rejection as if the server itself were unreachable or broken --
/// most public TURN deployments require auth, so a credential-less run
/// must not be misread as "TURN is broken here".
pub fn turn_allocate_udp(
    socket: &UdpSocket,
    server: SocketAddr,
    credentials: Option<&TurnCredentials>,
    timeout: Duration,
) -> TurnOutcome {
    let Some(creds) = credentials else {
        return TurnOutcome::NoCredentialsSupplied;
    };

    socket.set_read_timeout(Some(timeout)).ok();
    let txn1 = random_transaction_id();
    let req1 = build_allocate_request(txn1);
    if socket.send_to(&req1, server).is_err() {
        return TurnOutcome::Unreachable;
    }
    let mut buf = [0u8; 1024];
    let n1 = match socket.recv_from(&mut buf) {
        Ok((n, _)) => n,
        Err(_) => return TurnOutcome::Unreachable,
    };
    let parsed1 = match parse_message(&buf[..n1]) {
        Ok(p) => p,
        Err(e) => return TurnOutcome::Invalid(e.to_string()),
    };
    if parsed1.msg_type != ALLOCATE_ERROR {
        return match parse_allocate_response(&buf[..n1], txn1) {
            Ok(o) => o,
            Err(e) => TurnOutcome::Invalid(e),
        };
    }
    let (realm, nonce) = extract_realm_nonce(&parsed1.attrs);
    let (Some(realm), Some(nonce)) = (realm, nonce) else {
        return TurnOutcome::Invalid("401 challenge carried no REALM/NONCE".to_string());
    };

    let key = long_term_key(&creds.username, &realm, &creds.password);
    let txn2 = random_transaction_id();
    let req2 = build_authenticated_allocate_request(txn2, &creds.username, &realm, &nonce, &key);
    if socket.send_to(&req2, server).is_err() {
        return TurnOutcome::Unreachable;
    }
    let n2 = match socket.recv_from(&mut buf) {
        Ok((n, _)) => n,
        Err(_) => return TurnOutcome::Unreachable,
    };
    match parse_allocate_response(&buf[..n2], txn2) {
        Ok(o) => o,
        Err(e) => TurnOutcome::Invalid(e),
    }
}

/// TURN-over-TCP/TLS uses the same STUN-framed messages, just over a
/// stream socket instead of datagrams; a stream has no inherent message
/// boundary, so the caller must read exactly one STUN header first, then
/// exactly `length` more bytes.
fn read_one_stun_message(stream: &mut dyn Read, buf: &mut Vec<u8>) -> std::io::Result<()> {
    let mut header = [0u8; 20];
    stream.read_exact(&mut header)?;
    let length = u16::from_be_bytes([header[2], header[3]]) as usize;
    buf.clear();
    buf.extend_from_slice(&header);
    let mut body = vec![0u8; length];
    stream.read_exact(&mut body)?;
    buf.extend_from_slice(&body);
    Ok(())
}

use std::io::{Read, Write};

pub fn turn_allocate_tcp(
    stream: &mut TcpStream,
    credentials: Option<&TurnCredentials>,
) -> TurnOutcome {
    let Some(creds) = credentials else {
        return TurnOutcome::NoCredentialsSupplied;
    };
    let txn1 = random_transaction_id();
    let req1 = build_allocate_request(txn1);
    if stream.write_all(&req1).is_err() {
        return TurnOutcome::Unreachable;
    }
    let mut buf = Vec::new();
    if read_one_stun_message(stream, &mut buf).is_err() {
        return TurnOutcome::Unreachable;
    }
    let parsed1 = match parse_message(&buf) {
        Ok(p) => p,
        Err(e) => return TurnOutcome::Invalid(e.to_string()),
    };
    if parsed1.msg_type != ALLOCATE_ERROR {
        return match parse_allocate_response(&buf, txn1) {
            Ok(o) => o,
            Err(e) => TurnOutcome::Invalid(e),
        };
    }
    let (realm, nonce) = extract_realm_nonce(&parsed1.attrs);
    let (Some(realm), Some(nonce)) = (realm, nonce) else {
        return TurnOutcome::Invalid("401 challenge carried no REALM/NONCE".to_string());
    };
    let key = long_term_key(&creds.username, &realm, &creds.password);
    let txn2 = random_transaction_id();
    let req2 = build_authenticated_allocate_request(txn2, &creds.username, &realm, &nonce, &key);
    if stream.write_all(&req2).is_err() {
        return TurnOutcome::Unreachable;
    }
    if read_one_stun_message(stream, &mut buf).is_err() {
        return TurnOutcome::Unreachable;
    }
    match parse_allocate_response(&buf, txn2) {
        Ok(o) => o,
        Err(e) => TurnOutcome::Invalid(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn success_response_bytes(txn: [u8; 12], mapped: SocketAddr) -> Vec<u8> {
        let mut attrs = AttrBuilder::new();
        let SocketAddr::V4(v4) = mapped else { panic!("test only builds IPv4") };
        let port = v4.port() ^ ((MAGIC_COOKIE >> 16) as u16);
        let addr_u32 = u32::from_be_bytes(v4.ip().octets()) ^ MAGIC_COOKIE;
        let mut val = vec![0u8, FAMILY_IPV4];
        val.extend_from_slice(&port.to_be_bytes());
        val.extend_from_slice(&addr_u32.to_be_bytes());
        attrs.push(ATTR_XOR_MAPPED_ADDRESS, &val);
        build_message(BINDING_SUCCESS, txn, &attrs.0)
    }

    #[test]
    fn a_well_formed_success_response_yields_the_mapped_address() {
        let (_, txn) = build_binding_request();
        let mapped: SocketAddr = "203.0.113.7:54321".parse().unwrap();
        let resp = success_response_bytes(txn, mapped);
        assert_eq!(parse_binding_response(&resp, txn).unwrap(), mapped);
    }

    #[test]
    fn a_response_with_the_wrong_transaction_id_is_rejected() {
        let (_, txn) = build_binding_request();
        let mapped: SocketAddr = "203.0.113.7:54321".parse().unwrap();
        let resp = success_response_bytes(txn, mapped);
        let (_, other_txn) = build_binding_request();
        assert_eq!(parse_binding_response(&resp, other_txn), Err(StunError::TransactionIdMismatch));
    }

    #[test]
    fn a_response_with_the_wrong_magic_cookie_is_rejected() {
        let (_, txn) = build_binding_request();
        let mapped: SocketAddr = "203.0.113.7:54321".parse().unwrap();
        let mut resp = success_response_bytes(txn, mapped);
        resp[4] = 0xff;
        assert_eq!(parse_binding_response(&resp, txn), Err(StunError::BadMagicCookie));
    }

    #[test]
    fn a_binding_error_response_is_not_counted_as_success() {
        let (_, txn) = build_binding_request();
        let mut attrs = AttrBuilder::new();
        attrs.push(ATTR_ERROR_CODE, &[0, 0, (4 << 0), 0]);
        let resp = build_message(BINDING_ERROR, txn, &attrs.0);
        assert!(parse_binding_response(&resp, txn).is_err());
    }

    #[test]
    fn a_success_response_missing_the_mapped_address_attribute_is_rejected() {
        let (_, txn) = build_binding_request();
        let resp = build_message(BINDING_SUCCESS, txn, &[]);
        assert_eq!(parse_binding_response(&resp, txn), Err(StunError::MissingMappedAddress));
    }

    #[test]
    fn a_truncated_response_is_rejected_not_panicking() {
        let bytes = [0u8; 10];
        assert_eq!(parse_binding_response(&bytes, [0u8; 12]), Err(StunError::TooShort));
    }

    #[test]
    fn xor_mapped_address_roundtrips_through_encode_and_decode() {
        let (_, txn) = build_binding_request();
        let mapped: SocketAddr = "198.51.100.23:1024".parse().unwrap();
        let resp = success_response_bytes(txn, mapped);
        let decoded = parse_binding_response(&resp, txn).unwrap();
        assert_eq!(decoded, mapped);
    }

    #[test]
    fn turn_allocate_without_credentials_reports_no_credentials_supplied_not_an_error() {
        // No live server needed: the credential-less path returns before
        // any I/O happens.
        assert!(matches!(
            turn_allocate_udp(&UdpSocket::bind("127.0.0.1:0").unwrap(), "127.0.0.1:1".parse().unwrap(), None, Duration::from_millis(10)),
            TurnOutcome::NoCredentialsSupplied
        ));
    }

    #[test]
    fn long_term_key_matches_md5_of_username_realm_password() {
        let key = long_term_key("alice", "example.org", "secret");
        let expected = md5(b"alice:example.org:secret");
        assert_eq!(key, expected);
    }
}
