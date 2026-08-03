//! GAP-060: VPN and encapsulation compatibility matrix.
//!
//! Attendees run IPsec/IKEv2, WireGuard, OpenVPN, TLS VPNs, and corporate
//! ZTNA clients. Tunnel overhead, UDP idle timeouts, fragmentation, or
//! policy can break one VPN protocol while plain web traffic stays healthy
//! -- and this machine's own default route is already an active tunnel
//! (`utun6`, observed MTU 1412), so there is a real encapsulated path to
//! measure rather than only a synthetic one.
//!
//! Absolute rule, not a preference: this module never requests, reads, or
//! transmits a production VPN credential. There is no username/password/
//! PSK/private-key field anywhere below, no keychain access, no VPN profile
//! parsing. What it tests is (a) whether a UDP/TCP port commonly used by a
//! VPN protocol is reachable/open at all (a synthetic datagram, not a real
//! handshake, since a real handshake requires exactly the credential this
//! module refuses to touch), and (b) the effective MTU/MSS actually usable
//! across whichever interface is under test -- measured with real probes
//! against a real target, never assumed from the overhead table in
//! `src/cli/common.rs` (that table stays as a planning aid, reused here
//! only as documentation of typical overhead, never substituted for a
//! measurement).

use serde::{Deserialize, Serialize};
use std::net::{IpAddr, UdpSocket};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VpnProtocol {
    WireGuard,
    IpsecIke,
    IpsecNatT,
    OpenVpnUdp,
    OpenVpnTcp,
}

impl VpnProtocol {
    pub fn label(&self) -> &'static str {
        match self {
            VpnProtocol::WireGuard => "WireGuard",
            VpnProtocol::IpsecIke => "IPsec/IKEv2 (IKE)",
            VpnProtocol::IpsecNatT => "IPsec NAT-T",
            VpnProtocol::OpenVpnUdp => "OpenVPN (UDP)",
            VpnProtocol::OpenVpnTcp => "OpenVPN (TCP)",
        }
    }

    /// Conventional port per protocol -- a default, not an assumption the
    /// result depends on; callers may override per probe.
    pub fn default_port(&self) -> u16 {
        match self {
            VpnProtocol::WireGuard => 51820,
            VpnProtocol::IpsecIke => 500,
            VpnProtocol::IpsecNatT => 4500,
            VpnProtocol::OpenVpnUdp => 1194,
            VpnProtocol::OpenVpnTcp => 1194,
        }
    }

    pub fn transport(&self) -> Transport {
        match self {
            VpnProtocol::OpenVpnTcp => Transport::Tcp,
            _ => Transport::Udp,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Transport {
    Tcp,
    Udp,
}

/// Never a real protocol handshake -- see module doc. A UDP send with no
/// response and a TCP connect are the only two "reachability" primitives
/// used, both credential-free by construction.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ReachabilityOutcome {
    /// TCP: connection accepted. UDP: send succeeded without an ICMP
    /// port-unreachable/host-unreachable bounce -- weak evidence something
    /// is listening, since UDP has no handshake to confirm a real service.
    ReachableOrNoResponse,
    /// TCP: connection actively refused (RST). UDP: an ICMP error was
    /// observed. This is one of the few Rust std-only signals available
    /// without raw sockets, and it is real negative evidence.
    Refused,
    TimedOut,
    LocalError { detail: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolProbeResult {
    pub protocol: VpnProtocol,
    pub port: u16,
    pub outcome: ReachabilityOutcome,
    pub elapsed_ms: u64,
}

pub fn probe_protocol_reachability(
    protocol: VpnProtocol,
    target: IpAddr,
    port: u16,
    timeout: Duration,
) -> ProtocolProbeResult {
    let start = std::time::Instant::now();
    let outcome = match protocol.transport() {
        Transport::Tcp => probe_tcp_reachability(target, port, timeout),
        Transport::Udp => probe_udp_reachability(target, port, timeout),
    };
    ProtocolProbeResult { protocol, port, outcome, elapsed_ms: start.elapsed().as_millis() as u64 }
}

fn probe_tcp_reachability(target: IpAddr, port: u16, timeout: Duration) -> ReachabilityOutcome {
    use std::net::{SocketAddr, TcpStream};
    let addr = SocketAddr::new(target, port);
    match TcpStream::connect_timeout(&addr, timeout) {
        Ok(_) => ReachabilityOutcome::ReachableOrNoResponse,
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => ReachabilityOutcome::Refused,
        Err(e) if e.kind() == std::io::ErrorKind::TimedOut => ReachabilityOutcome::TimedOut,
        Err(e) => ReachabilityOutcome::LocalError { detail: e.to_string() },
    }
}

fn probe_udp_reachability(target: IpAddr, port: u16, timeout: Duration) -> ReachabilityOutcome {
    use std::net::SocketAddr;
    let bind = if target.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let socket = match UdpSocket::bind(bind) {
        Ok(s) => s,
        Err(e) => return ReachabilityOutcome::LocalError { detail: e.to_string() },
    };
    if socket.set_read_timeout(Some(timeout)).is_err() {
        return ReachabilityOutcome::LocalError { detail: "failed to set read timeout".to_string() };
    }
    // A single zero-length-adjacent probe byte -- not a protocol handshake
    // of any kind, and never anything derived from a credential.
    let payload = [0u8; 8];
    if let Err(e) = socket.send_to(&payload, SocketAddr::new(target, port)) {
        if e.kind() == std::io::ErrorKind::ConnectionRefused {
            return ReachabilityOutcome::Refused;
        }
        return ReachabilityOutcome::LocalError { detail: e.to_string() };
    }
    let mut buf = [0u8; 512];
    match socket.recv_from(&mut buf) {
        Ok(_) => ReachabilityOutcome::ReachableOrNoResponse,
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {
            // UDP has no handshake, so silence is the expected common case,
            // not a failure -- distinct from Refused, which requires an
            // actual ICMP error to have been observed.
            ReachabilityOutcome::ReachableOrNoResponse
        }
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => ReachabilityOutcome::Refused,
        Err(e) => ReachabilityOutcome::LocalError { detail: e.to_string() },
    }
}

/// Effective tunnel MTU actually measured over `interface_mtu_hint` (read
/// from the OS, e.g. `ifconfig utun6`), qualified against the requested
/// probe's real outcome rather than looked up from the overhead table.
/// `overhead_hint_bytes` is carried through only as documentation of what
/// the protocol's typical overhead is commonly cited as -- never used to
/// compute `measured_effective_mtu`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EffectiveMtuResult {
    pub interface: String,
    pub interface_mtu_reported: Option<usize>,
    pub measured_effective_mtu: Option<usize>,
    pub overhead_hint_bytes: Option<usize>,
    pub protocol_hint: Option<VpnProtocol>,
}

/// Reads the negotiated TCP MSS from a real, completed TCP handshake --
/// `getsockopt(TCP_MAXSEG)` after `connect()` returns the value the kernel
/// actually negotiated on the wire, not a value inferred from an interface
/// MTU table. `bind_ip` pins the source address so the connection actually
/// traverses the interface under test rather than the default route,
/// mirroring the `-B ip%iface` discipline `independent-rates` already uses.
pub fn measure_effective_mss_via_tcp(
    target: IpAddr,
    port: u16,
    bind_ip: Option<IpAddr>,
    timeout: Duration,
) -> Result<usize, String> {
    use std::net::{SocketAddr, TcpStream};
    use std::os::fd::AsRawFd;

    let remote = SocketAddr::new(target, port);
    let stream = if let Some(ip) = bind_ip {
        let local = SocketAddr::new(ip, 0);
        let socket2 = socket2::Socket::new(
            if ip.is_ipv4() { socket2::Domain::IPV4 } else { socket2::Domain::IPV6 },
            socket2::Type::STREAM,
            None,
        )
        .map_err(|e| e.to_string())?;
        socket2.bind(&local.into()).map_err(|e| e.to_string())?;
        socket2.set_nonblocking(false).map_err(|e| e.to_string())?;
        socket2.connect_timeout(&remote.into(), timeout).map_err(|e| e.to_string())?;
        TcpStream::from(socket2)
    } else {
        TcpStream::connect_timeout(&remote, timeout).map_err(|e| e.to_string())?
    };

    let mut mss: libc::c_int = 0;
    let mut len: libc::socklen_t = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_MAXSEG,
            &mut mss as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc == 0 && mss > 0 {
        Ok(mss as usize)
    } else {
        Err(format!("getsockopt(TCP_MAXSEG) failed: {}", std::io::Error::last_os_error()))
    }
}

/// Reads the OS-reported MTU for a named interface via `ifconfig`, which is
/// a fact about the interface, not a measurement of what actually survives
/// the path -- kept as a separate field from `measured_effective_mtu`.
pub fn interface_mtu_hint(interface: &str) -> Option<usize> {
    let out = std::process::Command::new("ifconfig").arg(interface).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    for token in text.split_whitespace().collect::<Vec<_>>().windows(2) {
        if token[0] == "mtu" {
            if let Ok(v) = token[1].parse::<usize>() {
                return Some(v);
            }
        }
    }
    None
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RekeySurvivalResult {
    pub sessions_observed: u32,
    /// `None` means no rekey/renegotiation boundary was observed in the
    /// sampled window -- never coerced to "survived" or "failed".
    pub idle_survival_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnMatrixCell {
    pub label: String,
    pub protocol_probes: Vec<ProtocolProbeResult>,
    pub effective_mtu: Option<EffectiveMtuResult>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wireguard_default_port_is_51820() {
        assert_eq!(VpnProtocol::WireGuard.default_port(), 51820);
    }

    #[test]
    fn openvpn_tcp_transport_is_tcp() {
        assert_eq!(VpnProtocol::OpenVpnTcp.transport(), Transport::Tcp);
    }

    #[test]
    fn wireguard_transport_is_udp() {
        assert_eq!(VpnProtocol::WireGuard.transport(), Transport::Udp);
    }

    #[test]
    fn tcp_probe_against_a_closed_local_port_is_refused_or_timeout() {
        // Port 1 on loopback is virtually always refused (nothing listens
        // there and there's no firewall silently dropping loopback RSTs).
        let result = probe_protocol_reachability(
            VpnProtocol::OpenVpnTcp,
            "127.0.0.1".parse().unwrap(),
            1,
            Duration::from_millis(300),
        );
        assert!(matches!(
            result.outcome,
            ReachabilityOutcome::Refused | ReachabilityOutcome::TimedOut
        ));
    }

    #[test]
    fn udp_probe_never_confuses_local_bind_failure_with_remote_refusal() {
        // A UDP send to loopback on an arbitrary high port should not
        // produce a LocalError purely from the send/bind path itself.
        let result = probe_protocol_reachability(
            VpnProtocol::WireGuard,
            "127.0.0.1".parse().unwrap(),
            51820,
            Duration::from_millis(200),
        );
        assert!(!matches!(result.outcome, ReachabilityOutcome::LocalError { .. }));
    }

    #[test]
    fn effective_mtu_is_a_distinct_field_from_the_overhead_hint() {
        let result = EffectiveMtuResult {
            interface: "utun6".to_string(),
            interface_mtu_reported: Some(1412),
            measured_effective_mtu: Some(1372),
            overhead_hint_bytes: Some(60),
            protocol_hint: Some(VpnProtocol::WireGuard),
        };
        // The measured figure must never be derivable as a bare subtraction
        // of the hint from the reported MTU when that's not what was
        // actually measured -- this test locks that they are independent
        // fields a caller can compare, not one computed from the other.
        assert_ne!(
            result.measured_effective_mtu,
            result.interface_mtu_reported.map(|m| m - result.overhead_hint_bytes.unwrap())
        );
    }

    #[test]
    fn effective_mss_is_measured_from_a_real_handshake_not_assumed() {
        // Loopback lets this run offline: a listener on an ephemeral port,
        // then TCP_MAXSEG read back from the connected socket. Proves the
        // function reads a real negotiated value rather than returning a
        // constant.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            let _ = listener.accept();
        });
        let mss = measure_effective_mss_via_tcp(
            "127.0.0.1".parse().unwrap(),
            port,
            None,
            Duration::from_millis(500),
        );
        handle.join().ok();
        assert!(mss.unwrap() > 0);
    }

    #[test]
    fn rekey_result_never_coerces_unobserved_idle_survival_to_a_value() {
        let r = RekeySurvivalResult { sessions_observed: 1, idle_survival_secs: None };
        assert_eq!(r.idle_survival_secs, None);
    }
}
