//! GAP-022: first-hop isolation must not depend solely on ICMP echo.
//!
//! Field evidence: a conference WLAN passed Internet ICMP with zero loss but
//! suppressed every echo request to its own default gateway. Read naively,
//! that is "100% packet loss to the gateway" -- which looks like a
//! catastrophic local fault when it's simply a policy choice (many APs/edge
//! routers block echo to their own management IP while still forwarding
//! transit ICMP). Treating suppression as loss sends someone hunting for a
//! broken first hop that isn't broken.
//!
//! This module keeps ICMP-suppression and packet-loss as distinct, separately
//! reported states, and falls back to a non-ICMP timing method (TCP SYN
//! timing against a gateway port) when ICMP is suppressed, so a
//! gateway-latency comparison is still possible.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::probe::probe_icmp;
use crate::load_guard::route::{detect_live as detect_default_route, is_tunnel_interface};

/// The state of first-hop ICMP reachability. Suppression and loss are kept
/// as distinct variants on purpose -- see module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IcmpState {
    /// Echo replies came back for at least some probes.
    Responding,
    /// Every probe went unanswered AND a non-ICMP method (TCP SYN/ACK, ARP)
    /// proved the host is actually up. This is policy, not a fault.
    Suppressed,
    /// Every probe went unanswered and no corroborating non-ICMP evidence of
    /// liveness exists either. This is genuine packet loss / unreachability,
    /// not policy.
    Lost,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IcmpProbeResult {
    pub sent: usize,
    pub received: usize,
    pub state: IcmpState,
}

impl IcmpProbeResult {
    pub fn loss_percent(&self) -> f64 {
        if self.sent == 0 {
            return 0.0;
        }
        ((self.sent - self.received) as f64 / self.sent as f64) * 100.0
    }
}

pub fn probe_icmp_n(target: IpAddr, count: usize, timeout_ms: u64) -> (usize, usize) {
    let mut received = 0;
    for _ in 0..count {
        if probe_icmp(target, 32, timeout_ms, 0) {
            received += 1;
        }
    }
    (count, received)
}

/// A non-ICMP fallback method for first-hop timing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FallbackMethod {
    TcpSyn,
    Arp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FallbackResult {
    pub method: FallbackMethod,
    pub attempted: bool,
    pub succeeded: bool,
    pub rtt_ms: Option<f64>,
    /// Set when the method could not even be attempted, e.g. missing
    /// privilege -- degrade gracefully and say what's missing rather than
    /// failing opaquely.
    pub unavailable_reason: Option<String>,
}

/// TCP SYN timing against a gateway port. Works unprivileged: a plain
/// `connect()` performs the SYN/SYN-ACK/ACK handshake and we just time it.
/// A `ConnectionRefused` still proves the host answered (RST is a reply),
/// so it counts as a successful liveness/timing measurement; only a timeout
/// or unreachable-host error means the gateway didn't respond at all.
pub fn tcp_syn_timing(gateway: IpAddr, port: u16, timeout_ms: u64) -> FallbackResult {
    let addr = SocketAddr::new(gateway, port);
    let timeout = Duration::from_millis(timeout_ms);
    let start = Instant::now();
    match std::net::TcpStream::connect_timeout(&addr, timeout) {
        Ok(_) => FallbackResult {
            method: FallbackMethod::TcpSyn,
            attempted: true,
            succeeded: true,
            rtt_ms: Some(start.elapsed().as_secs_f64() * 1000.0),
            unavailable_reason: None,
        },
        Err(e) => {
            // A RST (connection refused) still means the gateway answered
            // the SYN -- that's a valid timing sample, distinct from "no
            // response at all" (timeout).
            let refused = e.kind() == std::io::ErrorKind::ConnectionRefused;
            FallbackResult {
                method: FallbackMethod::TcpSyn,
                attempted: true,
                succeeded: refused,
                rtt_ms: if refused { Some(start.elapsed().as_secs_f64() * 1000.0) } else { None },
                unavailable_reason: None,
            }
        }
    }
}

/// ARP timing against a gateway on the local segment. Requires either a raw
/// socket (root on most platforms) or shelling out to a system ARP tool that
/// itself needs elevation to actively probe (vs. reading the cache). We do
/// not attempt a raw-socket ARP implementation here; instead we degrade
/// gracefully: report that ARP fallback needs elevated privilege rather than
/// failing opaquely or silently skipping it.
pub fn arp_timing_unprivileged_probe(_gateway: IpAddr) -> FallbackResult {
    let is_root = unsafe { libc::geteuid() } == 0;
    if !is_root {
        return FallbackResult {
            method: FallbackMethod::Arp,
            attempted: false,
            succeeded: false,
            rtt_ms: None,
            unavailable_reason: Some(
                "ARP active probing requires a raw socket, which needs root/CAP_NET_RAW; \
                 re-run elevated to enable this fallback, or rely on TCP SYN timing"
                    .to_string(),
            ),
        };
    }
    // Root is available in principle, but we don't ship a raw-socket ARP
    // sender: rather than claim a measurement we don't produce, report
    // explicitly that this path isn't implemented yet.
    FallbackResult {
        method: FallbackMethod::Arp,
        attempted: false,
        succeeded: false,
        rtt_ms: None,
        unavailable_reason: Some(
            "running as root but ARP active-probe sender is not implemented; use TCP SYN timing".to_string(),
        ),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirstHopReport {
    pub interface: Option<String>,
    pub interface_is_tunnel: bool,
    pub gateway: String,
    pub icmp: IcmpProbeResult,
    pub fallback: Option<FallbackResult>,
}

/// Determines interface/gateway to probe. If the caller specified an
/// interface explicitly, that's trusted as-is (report which interface was
/// actually probed, per the tunnel-default-route caveat). Otherwise falls
/// back to `route -n get default`, warning if that resolves to a tunnel.
pub fn resolve_probe_interface(explicit: Option<&str>) -> (Option<String>, bool) {
    if let Some(iface) = explicit {
        return (Some(iface.to_string()), is_tunnel_interface(iface));
    }
    match detect_default_route() {
        Ok(info) => (Some(info.interface.clone()), info.is_tunnel),
        Err(_) => (None, false),
    }
}

/// Classifies ICMP outcome into Responding/Suppressed/Lost using a
/// corroborating fallback result, and builds the final report. `fallback` is
/// `None` when ICMP already succeeded and no fallback was needed.
pub fn classify(icmp: (usize, usize), fallback: Option<FallbackResult>) -> (IcmpProbeResult, Option<FallbackResult>) {
    let (sent, received) = icmp;
    let state = if received > 0 {
        IcmpState::Responding
    } else if fallback.as_ref().map(|f| f.succeeded).unwrap_or(false) {
        IcmpState::Suppressed
    } else {
        IcmpState::Lost
    };
    (IcmpProbeResult { sent, received, state }, fallback)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn total_icmp_loss_with_successful_fallback_is_suppression_not_loss() {
        let fallback = FallbackResult {
            method: FallbackMethod::TcpSyn,
            attempted: true,
            succeeded: true,
            rtt_ms: Some(3.2),
            unavailable_reason: None,
        };
        let (icmp, fb) = classify((10, 0), Some(fallback));
        assert_eq!(icmp.state, IcmpState::Suppressed);
        assert_eq!(icmp.loss_percent(), 100.0);
        assert!(fb.unwrap().succeeded);
    }

    #[test]
    fn total_icmp_loss_with_failed_fallback_is_real_loss() {
        let fallback = FallbackResult {
            method: FallbackMethod::TcpSyn,
            attempted: true,
            succeeded: false,
            rtt_ms: None,
            unavailable_reason: None,
        };
        let (icmp, _) = classify((10, 0), Some(fallback));
        assert_eq!(icmp.state, IcmpState::Lost);
    }

    #[test]
    fn responding_icmp_never_needs_fallback_classification() {
        let (icmp, fb) = classify((10, 9), None);
        assert_eq!(icmp.state, IcmpState::Responding);
        assert!(fb.is_none());
    }

    #[test]
    fn arp_fallback_without_root_reports_missing_privilege_not_opaque_failure() {
        // Test harness is not expected to run as root.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let result = arp_timing_unprivileged_probe("192.0.2.1".parse().unwrap());
        assert!(!result.attempted);
        assert!(result.unavailable_reason.is_some());
        assert!(result.unavailable_reason.unwrap().contains("root"));
    }
}
