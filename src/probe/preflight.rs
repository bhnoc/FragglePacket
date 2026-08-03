//! GAP-025: protocol capability preflight.
//!
//! The field bug this closes: an endpoint that never offers HTTP/3 looks
//! identical, from a single failed handshake, to a network that blocks QUIC.
//! `speed.cloudflare.com` and `www.apple.com` failed h3 in the same session
//! where cloudflare.com, google.com, and Apple's network-quality endpoint
//! succeeded on the same Wi-Fi. This module separates "this endpoint doesn't
//! support the protocol" from "something in the path is filtering it", and
//! refuses to call the latter from a single host.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::quic::SkipServerVerification;

/// A protocol under test. Kept small on purpose; GAP-025's acceptance
/// criteria only requires h1/h2/h3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol {
    Http1,
    Http2,
    Http3,
}

impl Protocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            Protocol::Http1 => "http/1.1",
            Protocol::Http2 => "h2",
            Protocol::Http3 => "h3",
        }
    }

    fn alpn_token(&self) -> &'static str {
        match self {
            Protocol::Http1 => "http/1.1",
            Protocol::Http2 => "h2",
            Protocol::Http3 => "h3",
        }
    }
}

/// Built-in endpoints the field notes confirmed support HTTP/3 as of the
/// 2026-08-02 investigation: Cloudflare's main site, Google, and Apple's
/// dedicated network-quality endpoint (`mensura.cdn-apple.com`).
/// `speed.cloudflare.com` and `www.apple.com` are deliberately NOT in this
/// list: the whole point of GAP-025 is that they are not reliably
/// h3-capable, so hardcoding them here would recreate the bug this feature
/// exists to prevent. Callers can extend/override via `--endpoint`.
pub fn default_h3_endpoints() -> Vec<String> {
    vec![
        "cloudflare.com".to_string(),
        "google.com".to_string(),
        "mensura.cdn-apple.com".to_string(),
    ]
}

/// Per-endpoint, per-protocol verdict. These states must not be collapsed
/// into each other -- that collapse is exactly the false-diagnosis bug.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EndpointVerdict {
    /// Endpoint doesn't advertise or offer the protocol. Network is exonerated.
    Unsupported,
    /// Reached the peer; peer refused/failed the handshake (TLS alert, QUIC
    /// CONNECTION_CLOSE, version negotiation failure). Distinct from silence.
    HandshakeRejected,
    /// No response at all. Ambiguous on its own.
    Timeout,
    /// Evidence pointing at the network rather than the endpoint.
    Filtered,
    /// Handshake completed with the expected protocol.
    Ok,
}

impl EndpointVerdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            EndpointVerdict::Unsupported => "unsupported",
            EndpointVerdict::HandshakeRejected => "handshake-rejected",
            EndpointVerdict::Timeout => "timeout",
            EndpointVerdict::Filtered => "filtered",
            EndpointVerdict::Ok => "ok",
        }
    }
}

/// Whether an endpoint advertises h3 support (Alt-Svc). Kept as three states
/// on purpose: an undetermined probe (couldn't complete a lower-protocol
/// handshake or parse a response) must never collapse into `NotAdvertised`,
/// or a probe failure silently becomes "confirmed unsupported" -- the same
/// unknown-becoming-a-value trap that runs through this whole gap list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Advertisement {
    /// Alt-Svc header (or fallback probe) confirmed an h3 advertisement.
    Advertised,
    /// A valid lower-protocol response was parsed and it carried no h3
    /// Alt-Svc advertisement. This is a confirmed negative.
    NotAdvertised,
    /// Could not complete a lower-protocol handshake or parse a response at
    /// all, so advertisement status is simply unknown.
    Undetermined,
}

impl Advertisement {
    pub fn as_str(&self) -> &'static str {
        match self {
            Advertisement::Advertised => "advertised",
            Advertisement::NotAdvertised => "not-advertised",
            Advertisement::Undetermined => "undetermined",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointResult {
    pub host: String,
    pub resolved_ip: Option<String>,
    pub protocol: String,
    /// `None` when advertisement isn't a meaningful concept for this
    /// protocol (h1/h2 have no advertisement mechanism); `Some(_)` for h3.
    pub advertised: Option<Advertisement>,
    pub negotiated_alpn: Option<String>,
    pub verdict: EndpointVerdict,
    pub detail: String,
    pub elapsed_ms: u64,
}

/// Network-level verdict for one protocol, drawn across all tested endpoints.
/// Never produced from a single host: `NetworkVerdict::Filtered` requires
/// at least two independently known-capable endpoints failing consistently
/// while a control protocol to the same endpoints succeeds.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkVerdict {
    /// Every known-capable endpoint negotiated the protocol.
    Usable,
    /// Multiple independently known-capable endpoints failed consistently
    /// (handshake-rejected/timeout/filtered) while a control protocol to
    /// the same endpoints succeeded.
    Filtered {
        corroborating_endpoints: Vec<String>,
    },
    /// Not enough evidence to call it either way; says what's missing.
    Inconclusive { reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolReport {
    pub protocol: String,
    pub endpoints: Vec<EndpointResult>,
    pub network_verdict: NetworkVerdict,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreflightReport {
    pub protocols: Vec<ProtocolReport>,
}

/// Minimum number of independently-known-capable endpoints that must fail
/// consistently before we will even consider a `Filtered` network verdict.
/// One host is never enough -- that is the exact bug GAP-025 exists to fix.
const MIN_CORROBORATING_ENDPOINTS: usize = 2;

/// Resolve `host` to a concrete IP, honoring an optional forced override
/// (GAP-012/GAP-017 need pinned-IP comparisons).
pub fn resolve_for_preflight(host: &str, forced_ip: Option<IpAddr>) -> Option<IpAddr> {
    if let Some(ip) = forced_ip {
        return Some(ip);
    }
    super::resolve::resolve_hostname(host).ok()
}

/// Fetch response headers over HTTP/1.1 to read `Alt-Svc`, which is how
/// HTTP/3 support is advertised.
///
/// Deliberately pins ALPN to `http/1.1` only (not `["h2", "http/1.1"]`).
/// Requesting h2 and then writing a plaintext HTTP/1.1 request onto whatever
/// the peer picks was the root cause of a real bug here: Cloudflare and
/// Google both select h2 when offered, the plaintext request is garbage on
/// an h2 binary stream, the read returns framing bytes with no `Alt-Svc`
/// line, and the probe silently reported "not advertised" for two endpoints
/// that plainly do advertise h3. Pinning to `http/1.1` costs nothing here --
/// we only need the headers, not real h2 performance -- and guarantees the
/// response we parse is the protocol we sent.
///
/// Returns `Err` (-> `Advertisement::Undetermined`) if we couldn't complete
/// the handshake, get a response, or find a recognizable status line --
/// never silently turning "couldn't tell" into "confirmed absent".
fn fetch_alt_svc(
    host: &str,
    ip: IpAddr,
    port: u16,
    timeout: Duration,
) -> Result<Option<String>, String> {
    let addr = SocketAddr::new(ip, port);
    let mut stream =
        TcpStream::connect_timeout(&addr, timeout).map_err(|e| format!("tcp connect: {}", e))?;
    stream.set_read_timeout(Some(timeout)).ok();
    stream.set_write_timeout(Some(timeout)).ok();

    let mut config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    let server_name: rustls::pki_types::ServerName<'static> = host
        .to_string()
        .try_into()
        .map_err(|e| format!("invalid server name: {:?}", e))?;
    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name)
        .map_err(|e| format!("tls client config: {}", e))?;
    let mut tls = rustls::Stream::new(&mut conn, &mut stream);

    let request = format!(
        "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: fraggle-packet-preflight/0.1\r\nConnection: close\r\n\r\n",
        host
    );
    tls.write_all(request.as_bytes())
        .map_err(|e| format!("write: {}", e))?;

    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match tls.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() > 64 * 1024 {
                    break;
                }
                // We only need headers; stop once we've seen the blank line.
                if let Some(pos) = find_header_end(&buf) {
                    buf.truncate(pos);
                    break;
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                break
            }
            Err(e) => return Err(format!("read: {}", e)),
        }
    }

    if !looks_like_http_response(&buf) {
        return Err(format!(
            "response did not parse as HTTP/1.1 ({} bytes read)",
            buf.len()
        ));
    }

    let headers = String::from_utf8_lossy(&buf).to_lowercase();
    for line in headers.lines() {
        if line.starts_with("alt-svc:") {
            return Ok(Some(line["alt-svc:".len()..].trim().to_string()));
        }
    }
    Ok(None)
}

/// Sanity check that what we read is a real HTTP/1.1 response and not
/// binary framing from a protocol we didn't ask for -- the exact failure
/// mode that made the old h2-then-plaintext probe silently useless.
fn looks_like_http_response(buf: &[u8]) -> bool {
    if buf.is_empty() {
        return false;
    }
    let head = String::from_utf8_lossy(&buf[..buf.len().min(16)]);
    head.starts_with("HTTP/1.")
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

/// Does an Alt-Svc header value advertise h3?
fn alt_svc_advertises_h3(value: &str) -> bool {
    value.contains("h3=") || value.contains("h3-")
}

/// Real handshake for HTTP/1.1 or HTTP/2 via TLS+ALPN. Reports the ALPN the
/// peer actually selected, not the one we asked for.
fn negotiate_tls_alpn(
    host: &str,
    ip: IpAddr,
    port: u16,
    wanted: &str,
    timeout: Duration,
) -> (EndpointVerdict, Option<String>, String) {
    let addr = SocketAddr::new(ip, port);
    let start = Instant::now();
    let stream = match TcpStream::connect_timeout(&addr, timeout) {
        Ok(s) => s,
        Err(e) => {
            let detail = e.to_string();
            let verdict = if e.kind() == std::io::ErrorKind::TimedOut {
                EndpointVerdict::Timeout
            } else {
                EndpointVerdict::HandshakeRejected
            };
            return (verdict, None, format!("tcp connect failed: {}", detail));
        }
    };
    stream.set_read_timeout(Some(timeout)).ok();
    stream.set_write_timeout(Some(timeout)).ok();

    let connector = match native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .request_alpns(&[wanted, "http/1.1"])
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return (
                EndpointVerdict::HandshakeRejected,
                None,
                format!("tls connector build: {}", e),
            )
        }
    };

    match connector.connect(host, stream) {
        Ok(tls) => {
            let negotiated = tls
                .negotiated_alpn()
                .ok()
                .flatten()
                .map(|b| String::from_utf8_lossy(&b).to_string());
            let elapsed = start.elapsed();
            if negotiated.as_deref() == Some(wanted) {
                (
                    EndpointVerdict::Ok,
                    negotiated,
                    format!("negotiated in {:?}", elapsed),
                )
            } else {
                // Peer completed a handshake but picked something else
                // (or didn't return ALPN at all) -- treat as unsupported
                // for the requested protocol, not a network problem.
                (
                    EndpointVerdict::Unsupported,
                    negotiated.clone(),
                    format!(
                        "handshake ok but negotiated {:?} instead of {}",
                        negotiated, wanted
                    ),
                )
            }
        }
        Err(e) => {
            let msg = e.to_string();
            let lower = msg.to_lowercase();
            let verdict = if lower.contains("timed out") || lower.contains("timeout") {
                EndpointVerdict::Timeout
            } else {
                EndpointVerdict::HandshakeRejected
            };
            (verdict, None, format!("tls handshake failed: {}", msg))
        }
    }
}

/// Real QUIC handshake attempt, reporting the ALPN quinn/rustls actually
/// negotiated (not just "connected").
async fn negotiate_h3_async(
    host: String,
    ip: IpAddr,
    port: u16,
    timeout: Duration,
) -> (EndpointVerdict, Option<String>, String) {
    use quinn::{ClientConfig, Endpoint, TransportConfig};

    let crypto = match rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth()
    {
        cfg => {
            let mut cfg = cfg;
            cfg.alpn_protocols = vec![b"h3".to_vec()];
            cfg
        }
    };

    let quic_crypto = match quinn::crypto::rustls::QuicClientConfig::try_from(crypto) {
        Ok(c) => c,
        Err(e) => {
            return (
                EndpointVerdict::HandshakeRejected,
                None,
                format!("quic tls config: {}", e),
            )
        }
    };

    let mut transport = TransportConfig::default();
    let idle = match Duration::from_millis(timeout.as_millis() as u64).try_into() {
        Ok(v) => v,
        Err(_) => {
            return (
                EndpointVerdict::HandshakeRejected,
                None,
                "invalid idle timeout".to_string(),
            )
        }
    };
    transport.max_idle_timeout(Some(idle));

    let mut client_config = ClientConfig::new(Arc::new(quic_crypto));
    client_config.transport_config(Arc::new(transport));

    let bind_addr = if ip.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let mut endpoint = match Endpoint::client(bind_addr.parse().unwrap()) {
        Ok(e) => e,
        Err(e) => {
            return (
                EndpointVerdict::HandshakeRejected,
                None,
                format!("endpoint bind: {}", e),
            )
        }
    };
    endpoint.set_default_client_config(client_config);

    let addr = SocketAddr::new(ip, port);
    let start = Instant::now();

    let connecting = match endpoint.connect(addr, &host) {
        Ok(c) => c,
        Err(e) => {
            return (
                EndpointVerdict::HandshakeRejected,
                None,
                format!("connect setup: {}", e),
            )
        }
    };

    match tokio::time::timeout(timeout, connecting).await {
        Ok(Ok(conn)) => {
            let alpn = conn
                .handshake_data()
                .and_then(|d| d.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
                .and_then(|d| d.protocol)
                .map(|p| String::from_utf8_lossy(&p).to_string());
            let elapsed = start.elapsed();
            conn.close(0u32.into(), b"preflight complete");
            endpoint.wait_idle().await;
            if alpn.as_deref() == Some("h3") {
                (
                    EndpointVerdict::Ok,
                    alpn,
                    format!("negotiated in {:?}", elapsed),
                )
            } else {
                (
                    EndpointVerdict::Unsupported,
                    alpn.clone(),
                    format!("quic connected but negotiated {:?} instead of h3", alpn),
                )
            }
        }
        Ok(Err(e)) => {
            let msg = e.to_string();
            let lower = msg.to_lowercase();
            let verdict = if lower.contains("timed out") || lower.contains("timeout") {
                EndpointVerdict::Timeout
            } else if lower.contains("version mismatch")
                || lower.contains("aborted by peer")
                || lower.contains("closed by peer")
                || lower.contains("reset by peer")
            {
                EndpointVerdict::HandshakeRejected
            } else {
                EndpointVerdict::HandshakeRejected
            };
            (verdict, None, format!("quic handshake failed: {}", msg))
        }
        Err(_) => (
            EndpointVerdict::Timeout,
            None,
            format!("quic handshake exceeded {:?}", timeout),
        ),
    }
}

fn negotiate_h3(
    host: &str,
    ip: IpAddr,
    port: u16,
    timeout: Duration,
) -> (EndpointVerdict, Option<String>, String) {
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            return (
                EndpointVerdict::HandshakeRejected,
                None,
                format!("runtime build: {}", e),
            )
        }
    };
    rt.block_on(negotiate_h3_async(host.to_string(), ip, port, timeout))
}

/// Curl-based Alt-Svc probe kept as a fallback for environments where the
/// direct TLS path above can't reach a peer (matches the existing
/// `check_quic_support` heuristic used elsewhere in this codebase).
///
/// Returns `Err` (undetermined) when curl itself fails to run or produces
/// nothing usable -- never collapsed into "no header found".
pub fn curl_alt_svc(host: &str, timeout_secs: u64) -> Result<Option<String>, String> {
    let output = Command::new("curl")
        .args([
            "-s",
            "-I",
            "--http1.1",
            "--max-time",
            &timeout_secs.to_string(),
            &format!("https://{}", host),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .map_err(|e| format!("curl spawn failed: {}", e))?;

    if !output.status.success() {
        return Err(format!("curl exited with {}", output.status));
    }

    let headers = String::from_utf8_lossy(&output.stdout);
    if !headers.to_lowercase().starts_with("http/1.") {
        return Err("curl output did not parse as an HTTP/1.1 response".to_string());
    }

    Ok(headers
        .lines()
        .find(|l| l.to_lowercase().starts_with("alt-svc:"))
        .map(|l| l["alt-svc:".len()..].trim().to_string()))
}

/// Run the full preflight for one (protocol, host) pair.
pub fn preflight_one(
    host: &str,
    forced_ip: Option<IpAddr>,
    protocol: Protocol,
    port: u16,
    timeout: Duration,
) -> EndpointResult {
    let start = Instant::now();
    let ip = match resolve_for_preflight(host, forced_ip) {
        Some(ip) => ip,
        None => {
            return EndpointResult {
                host: host.to_string(),
                resolved_ip: None,
                protocol: protocol.as_str().to_string(),
                advertised: None,
                negotiated_alpn: None,
                verdict: EndpointVerdict::Timeout,
                detail: "DNS resolution failed".to_string(),
                elapsed_ms: start.elapsed().as_millis() as u64,
            };
        }
    };

    match protocol {
        Protocol::Http1 | Protocol::Http2 => {
            let (verdict, alpn, detail) =
                negotiate_tls_alpn(host, ip, port, protocol.alpn_token(), timeout);
            EndpointResult {
                host: host.to_string(),
                resolved_ip: Some(ip.to_string()),
                protocol: protocol.as_str().to_string(),
                advertised: None,
                negotiated_alpn: alpn,
                verdict,
                detail,
                elapsed_ms: start.elapsed().as_millis() as u64,
            }
        }
        Protocol::Http3 => {
            // Step 1: advertised capability, obtained over a working lower
            // protocol (falls back to curl if the direct TLS path fails to
            // even parse a response, e.g. no h1 stack reachable at all).
            // A transport/parse failure on BOTH probes stays Undetermined --
            // it must never be reported the same as a confirmed absence.
            let advertised = match fetch_alt_svc(host, ip, port, timeout) {
                Ok(Some(alt_svc)) if alt_svc_advertises_h3(&alt_svc) => Advertisement::Advertised,
                Ok(_) => Advertisement::NotAdvertised,
                Err(direct_err) => match curl_alt_svc(host, timeout.as_secs().max(1)) {
                    Ok(Some(alt_svc)) if alt_svc_advertises_h3(&alt_svc) => {
                        Advertisement::Advertised
                    }
                    Ok(_) => Advertisement::NotAdvertised,
                    Err(_) => {
                        return EndpointResult {
                            host: host.to_string(),
                            resolved_ip: Some(ip.to_string()),
                            protocol: protocol.as_str().to_string(),
                            advertised: Some(Advertisement::Undetermined),
                            negotiated_alpn: None,
                            verdict: EndpointVerdict::Timeout,
                            detail: format!(
                                "could not determine Alt-Svc advertisement: {}",
                                direct_err
                            ),
                            elapsed_ms: start.elapsed().as_millis() as u64,
                        };
                    }
                },
            };

            // Step 2: negotiated capability -- a real QUIC handshake.
            let (verdict, alpn, mut detail) = negotiate_h3(host, ip, port, timeout);

            let final_verdict = match (advertised, verdict) {
                // Endpoint never claimed h3: it's unsupported regardless of
                // how the handshake attempt failed. This is the core
                // false-diagnosis fix -- do not let a failed/timed-out
                // handshake against a non-advertising host read as network
                // interference.
                (Advertisement::NotAdvertised, v) if v != EndpointVerdict::Ok => {
                    detail = format!("{} (confirmed no Alt-Svc h3 advertisement)", detail);
                    EndpointVerdict::Unsupported
                }
                (_, v) => v,
            };

            EndpointResult {
                host: host.to_string(),
                resolved_ip: Some(ip.to_string()),
                protocol: protocol.as_str().to_string(),
                advertised: Some(advertised),
                negotiated_alpn: alpn,
                verdict: final_verdict,
                detail,
                elapsed_ms: start.elapsed().as_millis() as u64,
            }
        }
    }
}

/// Derive the network-level verdict for one protocol from its per-endpoint
/// results plus optional control-protocol results against the SAME
/// endpoints. This is the corroboration gate: never infer blocking from one
/// host.
///
/// `control_ok_hosts` should list hosts where a control protocol (e.g.
/// HTTP/2, when testing HTTP/3) succeeded, proving those hosts are reachable
/// at all on this network.
pub fn network_verdict(results: &[EndpointResult], control_ok_hosts: &[String]) -> NetworkVerdict {
    let known_capable_failures: Vec<&EndpointResult> = results
        .iter()
        .filter(|r| {
            matches!(
                r.verdict,
                EndpointVerdict::HandshakeRejected
                    | EndpointVerdict::Timeout
                    | EndpointVerdict::Filtered
            )
        })
        .collect();

    let ok_count = results
        .iter()
        .filter(|r| r.verdict == EndpointVerdict::Ok)
        .count();
    let unsupported_count = results
        .iter()
        .filter(|r| r.verdict == EndpointVerdict::Unsupported)
        .count();

    if results.is_empty() {
        return NetworkVerdict::Inconclusive {
            reason: "no endpoints tested".to_string(),
        };
    }

    if ok_count == results.len() {
        return NetworkVerdict::Usable;
    }

    if ok_count > 0 && known_capable_failures.is_empty() {
        // Some endpoints are unsupported, the rest succeeded: protocol is
        // usable on this network, capability is just endpoint-specific.
        return NetworkVerdict::Usable;
    }

    // Only endpoints that failed AND had a working control protocol count
    // as corroborating evidence of network interference. A failure against
    // a host we never proved reachable at all is not evidence of anything.
    let corroborating: Vec<String> = known_capable_failures
        .iter()
        .filter(|r| control_ok_hosts.contains(&r.host))
        .map(|r| r.host.clone())
        .collect();

    if corroborating.len() >= MIN_CORROBORATING_ENDPOINTS {
        return NetworkVerdict::Filtered {
            corroborating_endpoints: corroborating,
        };
    }

    if unsupported_count == results.len() {
        return NetworkVerdict::Inconclusive {
            reason: "every tested endpoint is unsupported for this protocol; add known-capable endpoints".to_string(),
        };
    }

    NetworkVerdict::Inconclusive {
        reason: format!(
            "only {} of {} required known-capable-endpoint failures corroborated (need {}); add more known-capable endpoints or confirm control-protocol reachability",
            corroborating.len(),
            MIN_CORROBORATING_ENDPOINTS,
            MIN_CORROBORATING_ENDPOINTS
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result(host: &str, verdict: EndpointVerdict) -> EndpointResult {
        EndpointResult {
            host: host.to_string(),
            resolved_ip: Some("203.0.113.1".to_string()),
            protocol: "h3".to_string(),
            advertised: Some(Advertisement::Advertised),
            negotiated_alpn: None,
            verdict,
            detail: String::new(),
            elapsed_ms: 1,
        }
    }

    #[test]
    fn single_failure_never_infers_blocking() {
        // The exact regression this gate exists for: one known-capable
        // endpoint failing must never become a Filtered network verdict.
        let results = vec![result("cloudflare.com", EndpointVerdict::Timeout)];
        let controls = vec!["cloudflare.com".to_string()];
        match network_verdict(&results, &controls) {
            NetworkVerdict::Filtered { .. } => panic!("one host must never produce Filtered"),
            _ => {}
        }
    }

    #[test]
    fn unsupported_single_host_is_not_filtered() {
        let results = vec![result("speed.cloudflare.com", EndpointVerdict::Unsupported)];
        let controls = vec!["speed.cloudflare.com".to_string()];
        let v = network_verdict(&results, &controls);
        assert!(matches!(v, NetworkVerdict::Inconclusive { .. }));
    }

    #[test]
    fn two_corroborating_failures_with_control_yields_filtered() {
        let results = vec![
            result("cloudflare.com", EndpointVerdict::Timeout),
            result("google.com", EndpointVerdict::HandshakeRejected),
            result("mensura.cdn-apple.com", EndpointVerdict::Ok),
        ];
        let controls = vec![
            "cloudflare.com".to_string(),
            "google.com".to_string(),
            "mensura.cdn-apple.com".to_string(),
        ];
        match network_verdict(&results, &controls) {
            NetworkVerdict::Filtered {
                corroborating_endpoints,
            } => {
                assert_eq!(corroborating_endpoints.len(), 2);
            }
            other => panic!("expected Filtered, got {:?}", other),
        }
    }

    #[test]
    fn failures_without_control_reachability_stay_inconclusive() {
        // Two endpoints failed h3, but we never proved they're even
        // reachable on this network (no control-protocol success), so it
        // must not corroborate blocking.
        let results = vec![
            result("cloudflare.com", EndpointVerdict::Timeout),
            result("google.com", EndpointVerdict::Timeout),
        ];
        let controls: Vec<String> = vec![];
        let v = network_verdict(&results, &controls);
        assert!(matches!(v, NetworkVerdict::Inconclusive { .. }));
    }

    #[test]
    fn all_ok_is_usable() {
        let results = vec![
            result("cloudflare.com", EndpointVerdict::Ok),
            result("google.com", EndpointVerdict::Ok),
        ];
        let v = network_verdict(&results, &[]);
        assert!(matches!(v, NetworkVerdict::Usable));
    }

    #[test]
    fn alt_svc_h3_detection() {
        assert!(alt_svc_advertises_h3(r#"h3=":443"; ma=86400"#));
        assert!(alt_svc_advertises_h3(r#"h3-29=":443""#));
        assert!(!alt_svc_advertises_h3(r#"clear"#));
        assert!(!alt_svc_advertises_h3(""));
    }
}
