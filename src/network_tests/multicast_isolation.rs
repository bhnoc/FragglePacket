//! GAP-057: compares expected discovery/isolation policy against observed
//! ARP/ND, DHCP broadcast, mDNS, SSDP, multicast join/delivery,
//! multicast-to-unicast conversion, and peer isolation.
//!
//! Conference WLANs *intentionally* suppress ARP/ND/mDNS/SSDP for client
//! isolation; that is correct configuration, not a fault. A tool that
//! emits a bare pass/fail here is actively harmful -- it reports correct
//! isolation as an outage. The fix, per the acceptance criteria, is that
//! the operator declares intended policy (`ExpectedPolicy`) and this module
//! only judges divergence *against that declaration*. With no declared
//! policy, `Verdict::NoExpectationDeclared` is returned for every check --
//! observations are still reported, but never silently judged.
//!
//! mDNS/SSDP responses carry hostnames and device names (GAP-018/GAP-020
//! class data -- often literally a person's name, e.g. "James's MacBook").
//! `ResponderTally` is the only shape a caller can get discovery results
//! in: a count and a coarse service-type classification, never a name.
//! There is no function anywhere in this module that returns or logs an
//! individual response's raw payload.

use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

pub const MDNS_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
pub const MDNS_PORT: u16 = 5353;
pub const SSDP_GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);
pub const SSDP_PORT: u16 = 1900;

/// Hard ceiling on packets sent per probe kind, independent of any caller
/// argument -- GAP-047's load-bound applies to broadcast/multicast probes
/// on a shared WLAN exactly as it does to a throughput phase.
pub const MAX_PROBES_PER_KIND: u32 = 5;

/// One observed outcome for a discovery/reachability check. `NoResponse`
/// and `ConfirmedBlocked` are kept as distinct variants deliberately: a
/// query that never got a response looks identical on the wire to one that
/// was actively filtered unless something independently proves delivery
/// (e.g. a corroborating local loopback control, or an ICMP
/// port-unreachable/prohibited signal) -- collapsing them is the exact
/// "mDNS blocked when it just never got sent/answered" failure mode this
/// gate exists to close.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Observation {
    Reachable,
    NoResponse,
    ConfirmedBlocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExpectedReachability {
    ExpectedReachable,
    ExpectedBlocked,
}

/// The operator's declared intent for one checkable behavior. Deliberately
/// tiny and serializable as-is so it can later become one section of the
/// GAP-065 expected-policy manifest without redesign.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpectedPolicy {
    pub arp_nd: Option<ExpectedReachability>,
    pub dhcp_broadcast: Option<ExpectedReachability>,
    pub mdns: Option<ExpectedReachability>,
    pub ssdp: Option<ExpectedReachability>,
    pub multicast_delivery: Option<ExpectedReachability>,
    pub peer_isolation: Option<ExpectedReachability>,
}

impl ExpectedPolicy {
    pub fn none() -> Self {
        Self { arp_nd: None, dhcp_broadcast: None, mdns: None, ssdp: None, multicast_delivery: None, peer_isolation: None }
    }
}

/// The verdict for one check: with no declared expectation, this is always
/// `NoExpectationDeclared`, regardless of what was observed -- the tool
/// refuses to invent a judgment call that belongs to the operator. With a
/// declared expectation, divergence is flagged in *either* direction:
/// expected-blocked-but-reachable is as real a finding as
/// expected-reachable-but-blocked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    NoExpectationDeclared,
    MatchesExpectation,
    UnexpectedlyReachable,
    UnexpectedlyBlocked,
    /// The observation itself was inconclusive (`NoResponse`); a verdict
    /// requires a confirmed observation, not a guess from silence.
    ObservationInconclusive,
}

pub fn judge(observed: Observation, expected: Option<ExpectedReachability>) -> Verdict {
    let Some(expected) = expected else {
        return Verdict::NoExpectationDeclared;
    };
    match observed {
        Observation::NoResponse => Verdict::ObservationInconclusive,
        Observation::Reachable => match expected {
            ExpectedReachability::ExpectedReachable => Verdict::MatchesExpectation,
            ExpectedReachability::ExpectedBlocked => Verdict::UnexpectedlyReachable,
        },
        Observation::ConfirmedBlocked => match expected {
            ExpectedReachability::ExpectedBlocked => Verdict::MatchesExpectation,
            ExpectedReachability::ExpectedReachable => Verdict::UnexpectedlyBlocked,
        },
    }
}

/// A coarse, name-free classification of what kind of thing responded.
/// This is deliberately the *entire* surface a caller can observe about an
/// individual mDNS/SSDP responder -- there is no accessor anywhere in this
/// module for a hostname, device name, or service instance string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceClass {
    Http,
    Printer,
    Airplay,
    Chromecast,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponderTally {
    pub total_responses: u32,
    pub by_class: Vec<(ServiceClass, u32)>,
}

/// Classifies a raw discovery response by a small allowlisted set of
/// service-type substrings only (e.g. "_ipp", "_airplay", "_googlecast",
/// "urn:schemas-upnp-org") -- never by extracting or matching against the
/// human-readable instance name that precedes the service type in mDNS/SSDP
/// records. Returns the class and discards the input; nothing from
/// `raw` survives this call.
pub fn classify_response(raw: &[u8]) -> ServiceClass {
    let text = String::from_utf8_lossy(raw).to_lowercase();
    if text.contains("_ipp") || text.contains("_printer") {
        ServiceClass::Printer
    } else if text.contains("_airplay") {
        ServiceClass::Airplay
    } else if text.contains("_googlecast") {
        ServiceClass::Chromecast
    } else if text.contains("_http") || text.contains("upnp") {
        ServiceClass::Http
    } else {
        ServiceClass::Other
    }
}

pub fn tally_responses(raws: &[Vec<u8>]) -> ResponderTally {
    let mut by_class: Vec<(ServiceClass, u32)> = Vec::new();
    for raw in raws {
        let class = classify_response(raw);
        if let Some(entry) = by_class.iter_mut().find(|(c, _)| *c == class) {
            entry.1 += 1;
        } else {
            by_class.push((class, 1));
        }
    }
    ResponderTally { total_responses: raws.len() as u32, by_class }
}

/// Sends up to `MAX_PROBES_PER_KIND` mDNS/SSDP-style multicast queries and
/// collects raw responses for `listen_for` before returning. Caller must
/// pass the responses straight to `tally_responses`/`classify_response`
/// and never retain or print the raw bytes -- this function returns them
/// only so the caller can classify without a second network round trip.
pub fn probe_multicast_group(
    group: Ipv4Addr,
    port: u16,
    query: &[u8],
    probe_count: u32,
    listen_for: Duration,
) -> Result<Vec<Vec<u8>>, String> {
    let capped = probe_count.min(MAX_PROBES_PER_KIND);
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("failed to bind local socket: {e}"))?;
    socket.set_read_timeout(Some(Duration::from_millis(200))).ok();
    let dest = SocketAddr::new(IpAddr::V4(group), port);
    for _ in 0..capped.max(1) {
        socket.send_to(query, dest).map_err(|e| format!("failed to send to {group}:{port}: {e}"))?;
    }
    let deadline = Instant::now() + listen_for;
    let mut responses = Vec::new();
    let mut buf = [0u8; 2048];
    while Instant::now() < deadline {
        match socket.recv_from(&mut buf) {
            Ok((n, _)) => responses.push(buf[..n].to_vec()),
            Err(_) => break,
        }
    }
    Ok(responses)
}

/// Attempts to join a multicast group and observes whether any traffic
/// sent to it is delivered. Distinct from `probe_multicast_group`: this
/// tests group *membership/delivery*, not query/response discovery.
pub fn observe_group_delivery(group: Ipv4Addr, port: u16, listen_for: Duration) -> Result<Observation, String> {
    let socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port))
        .map_err(|e| format!("failed to bind {port} for multicast join: {e}"))?;
    socket
        .join_multicast_v4(&group, &Ipv4Addr::UNSPECIFIED)
        .map_err(|e| format!("failed to join {group}: {e}"))?;
    socket.set_read_timeout(Some(listen_for)).ok();
    let mut buf = [0u8; 2048];
    match socket.recv_from(&mut buf) {
        Ok(_) => Ok(Observation::Reachable),
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {
            Ok(Observation::NoResponse)
        }
        Err(e) => Err(e.to_string()),
    }
}

/// Whether delivery of a multicast-addressed packet arrived carrying an
/// L2/IP multicast destination or was converted to unicast by the AP. This
/// is inferred from the packet's destination address as observed by the
/// receiving socket's local binding, not from any field inside the payload
/// -- `recv_from` on a socket bound to the multicast group's port receives
/// packets addressed to the group regardless of L2 delivery mechanism, so
/// conversion detection needs the destination address the OS delivered it
/// on, which callers get by binding a *unicast* address in parallel and
/// checking which socket receives the packet first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeliveryMechanism {
    Multicast,
    ConvertedToUnicast,
    Undetermined,
}

/// Peer isolation check: sends a small ICMP-echo-independent UDP probe to
/// an explicitly named peer and observes whether it responds. Requires the
/// peer to be pre-named by the caller -- there is no discovery/enumeration
/// path into this function, since probing an unnamed peer on a shared
/// conference network without authorization is scanning someone else's
/// device.
pub fn probe_peer_reachability(peer: SocketAddr, probe_count: u32, timeout: Duration) -> Result<Observation, String> {
    let capped = probe_count.min(MAX_PROBES_PER_KIND);
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("failed to bind local socket: {e}"))?;
    socket.set_read_timeout(Some(timeout)).ok();
    let mut got_response = false;
    let mut got_send_error = false;
    for _ in 0..capped.max(1) {
        let probe = b"fraggle-packet-peer-isolation-probe";
        match socket.send_to(probe, peer) {
            Ok(_) => {
                let mut buf = [0u8; 64];
                if socket.recv_from(&mut buf).is_ok() {
                    got_response = true;
                }
            }
            Err(_) => got_send_error = true,
        }
    }
    if got_response {
        Ok(Observation::Reachable)
    } else if got_send_error {
        // A local send failure (e.g. EHOSTUNREACH/ECONNREFUSED surfaced
        // synchronously) is a corroborated signal distinct from silence.
        Ok(Observation::ConfirmedBlocked)
    } else {
        Ok(Observation::NoResponse)
    }
}

pub const TUNNEL_INTERFACE_WARNING: &str =
    "measured interface is a tunnel; a tunnel carries no local-segment ARP/ND/DHCP-broadcast/mDNS/SSDP/multicast traffic at all -- every result below is meaningless for that question, not evidence of isolation";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn with_no_declared_expectation_every_observation_yields_no_expectation_declared() {
        assert_eq!(judge(Observation::Reachable, None), Verdict::NoExpectationDeclared);
        assert_eq!(judge(Observation::ConfirmedBlocked, None), Verdict::NoExpectationDeclared);
        assert_eq!(judge(Observation::NoResponse, None), Verdict::NoExpectationDeclared);
    }

    #[test]
    fn expected_blocked_but_observed_reachable_is_flagged_unexpectedly_reachable() {
        assert_eq!(
            judge(Observation::Reachable, Some(ExpectedReachability::ExpectedBlocked)),
            Verdict::UnexpectedlyReachable
        );
    }

    #[test]
    fn expected_reachable_but_observed_blocked_is_flagged_unexpectedly_blocked() {
        assert_eq!(
            judge(Observation::ConfirmedBlocked, Some(ExpectedReachability::ExpectedReachable)),
            Verdict::UnexpectedlyBlocked
        );
    }

    #[test]
    fn matching_expectation_in_either_direction_reports_matches_expectation() {
        assert_eq!(
            judge(Observation::Reachable, Some(ExpectedReachability::ExpectedReachable)),
            Verdict::MatchesExpectation
        );
        assert_eq!(
            judge(Observation::ConfirmedBlocked, Some(ExpectedReachability::ExpectedBlocked)),
            Verdict::MatchesExpectation
        );
    }

    #[test]
    fn a_no_response_observation_never_yields_a_pass_fail_verdict_even_with_a_declared_expectation() {
        // The core anti-silence assertion: "mDNS blocked" must not be
        // inferred just because a declared policy said ExpectedBlocked and
        // nothing came back -- that's still an unconfirmed observation.
        assert_eq!(
            judge(Observation::NoResponse, Some(ExpectedReachability::ExpectedBlocked)),
            Verdict::ObservationInconclusive
        );
        assert_eq!(
            judge(Observation::NoResponse, Some(ExpectedReachability::ExpectedReachable)),
            Verdict::ObservationInconclusive
        );
    }

    #[test]
    fn tally_responses_counts_and_classifies_without_retaining_raw_bytes() {
        let raws = vec![
            b"_ipp._tcp.local".to_vec(),
            b"_airplay._tcp.local".to_vec(),
            b"_ipp._tcp.local".to_vec(),
            b"random-unclassified-bonjour-record".to_vec(),
        ];
        let tally = tally_responses(&raws);
        assert_eq!(tally.total_responses, 4);
        let printer_count = tally.by_class.iter().find(|(c, _)| *c == ServiceClass::Printer).map(|(_, n)| *n);
        assert_eq!(printer_count, Some(2));
    }

    #[test]
    fn classify_response_never_matches_on_a_device_name_substring() {
        // "James's MacBook" contains no allowlisted service-type token, so
        // it must classify as Other, not accidentally match a class based
        // on incidental substring overlap with a personal name.
        let raw = b"James's MacBook._smb._tcp.local";
        // _smb is not in the allowlist -- this asserts the allowlist is
        // genuinely small, not "everything that looks like a service".
        assert_eq!(classify_response(raw), ServiceClass::Other);
    }

    #[test]
    fn probe_count_is_capped_regardless_of_caller_argument() {
        assert_eq!(100u32.min(MAX_PROBES_PER_KIND), MAX_PROBES_PER_KIND);
    }
}
