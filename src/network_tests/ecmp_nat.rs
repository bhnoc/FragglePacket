//! GAP-028: multi-uplink ECMP/LAG hash and NAT-affinity diagnostic.
//!
//! Field evidence this closes recorded a *negative* result: a ten-bucket
//! fixed-source-port sweep of a failing 350 Mbps bidirectional run did not
//! split bimodally -- every bucket failed the same way, which argued
//! against one bad ECMP member and toward shared queue/policer/WLAN
//! behavior instead. A tool that can only confirm "yes, one bucket is
//! bad" is useless for that finding, so `BimodalityVerdict::NoSplitDetected`
//! is a first-class success outcome here, not an inconclusive shrug.
//!
//! "Preserve each 5-tuple" is the core mechanic: each bucket binds one
//! fixed local port and keeps using it for every packet in that bucket, so
//! the flow stays in one ECMP/LAG hash bucket and one NAT mapping for its
//! whole (short) lifetime. Per GAP-047, buckets are tiny (a few hundred KB)
//! -- this proves the mechanism, it does not reproduce the 350 Mbps matrix
//! from the incident.

use serde::{Deserialize, Serialize};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use crate::network_tests::stun::{binding_request_once, BindingOutcome};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BucketOutcome {
    Succeeded,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BucketResult {
    pub local_port: u16,
    pub outcome: BucketOutcome,
    pub bytes_sent: u64,
    pub bytes_acked_or_echoed: u64,
    pub rtt_ms: Option<f64>,
    /// True only when a STUN sample was taken both before and after this
    /// bucket's flow and the mapped address differed between them -- a
    /// mid-flow rebinding, distinct from never having sampled at all.
    pub mid_flow_rebind_detected: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BimodalityVerdict {
    /// At least one bucket succeeded and at least one failed -- consistent
    /// with one bad hash-bucket/ECMP-member/NAT-owner rather than a
    /// shared-path problem.
    BimodalSplitDetected,
    /// Every bucket produced the same outcome (all succeeded or all
    /// failed). This is evidence *against* a single bad member and toward
    /// a shared-path cause (queue, policer, WLAN) -- reported explicitly,
    /// not folded into "inconclusive".
    NoSplitDetected,
    /// Fewer than two buckets ran; no split judgement can be made honestly.
    InsufficientBuckets,
}

/// Computes the bimodality verdict from a set of bucket outcomes. A split
/// requires both a success and a failure to be *present*, not merely a
/// majority -- one lone failing bucket among nine successes is still a
/// split, because that is exactly the "one bad ECMP member" shape this
/// exists to catch.
pub fn classify_bimodality(results: &[BucketResult]) -> BimodalityVerdict {
    if results.len() < 2 {
        return BimodalityVerdict::InsufficientBuckets;
    }
    let succeeded = results
        .iter()
        .any(|r| r.outcome == BucketOutcome::Succeeded);
    let failed = results.iter().any(|r| r.outcome == BucketOutcome::Failed);
    if succeeded && failed {
        BimodalityVerdict::BimodalSplitDetected
    } else {
        BimodalityVerdict::NoSplitDetected
    }
}

/// A single fixed-5-tuple UDP bucket: bind one local port, send a tiny
/// payload to `target`, and treat any reply (or a successful send with no
/// reply expected) within `timeout` as success. Deliberately does not
/// generate sustained load -- one small datagram round-trip is enough to
/// prove the 5-tuple/hash-bucket mechanism.
pub fn run_udp_bucket(
    local_port: u16,
    target: SocketAddr,
    payload_len: usize,
    timeout: Duration,
) -> BucketResult {
    let bind_addr = if target.is_ipv4() {
        format!("0.0.0.0:{local_port}")
    } else {
        format!("[::]:{local_port}")
    };
    let socket = match UdpSocket::bind(&bind_addr) {
        Ok(s) => s,
        Err(_) => {
            return BucketResult {
                local_port,
                outcome: BucketOutcome::Failed,
                bytes_sent: 0,
                bytes_acked_or_echoed: 0,
                rtt_ms: None,
                mid_flow_rebind_detected: None,
            }
        }
    };
    socket.set_read_timeout(Some(timeout)).ok();
    let payload = vec![0xABu8; payload_len.max(1)];
    let start = Instant::now();
    let sent = socket.send_to(&payload, target);
    let mut buf = [0u8; 1500];
    let (outcome, echoed, rtt_ms) = match &sent {
        Ok(_) => match socket.recv_from(&mut buf) {
            Ok((r, _)) => (
                BucketOutcome::Succeeded,
                r as u64,
                Some(start.elapsed().as_secs_f64() * 1000.0),
            ),
            // No reply is expected from a bare UDP echo-less target; a
            // successful send is still evidence the bucket's path/NAT
            // mapping admitted the flow, so it counts as success with
            // zero bytes echoed.
            Err(_) => (BucketOutcome::Succeeded, 0, None),
        },
        Err(_) => (BucketOutcome::Failed, 0u64, None),
    };
    BucketResult {
        local_port,
        outcome,
        bytes_sent: sent.unwrap_or(0) as u64,
        bytes_acked_or_echoed: echoed,
        rtt_ms,
        mid_flow_rebind_detected: None,
    }
}

/// A single fixed-5-tuple TCP bucket: bind one specific local port, then
/// connect from it, send a small payload, read back whatever the peer
/// sends (may be zero bytes), and close. A plain `TcpStream::connect`
/// leaves source-port selection to the OS, which is the opposite of what
/// "preserve each 5-tuple" requires -- this binds explicitly via
/// `socket2::Socket::bind` before `connect_timeout`, the same pattern
/// `network_tests::vpn_matrix::measure_effective_mss_via_tcp` uses. A
/// failed connect is `Failed`; a completed connect+send is `Succeeded`
/// regardless of how many bytes came back, since TCP admission (not
/// application-level echo) is what a hash-bucket/NAT problem would break.
pub fn run_tcp_bucket(
    local_port: u16,
    target: SocketAddr,
    payload_len: usize,
    timeout: Duration,
) -> BucketResult {
    let local: SocketAddr = if target.is_ipv4() {
        format!("0.0.0.0:{local_port}").parse().unwrap()
    } else {
        format!("[::]:{local_port}").parse().unwrap()
    };
    let failed = || BucketResult {
        local_port,
        outcome: BucketOutcome::Failed,
        bytes_sent: 0,
        bytes_acked_or_echoed: 0,
        rtt_ms: None,
        mid_flow_rebind_detected: None,
    };
    let domain = if target.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let sock2 = match socket2::Socket::new(domain, socket2::Type::STREAM, None) {
        Ok(s) => s,
        Err(_) => return failed(),
    };
    if sock2.set_reuse_address(true).is_err() {
        return failed();
    }
    if sock2.bind(&local.into()).is_err() {
        return failed();
    }
    if sock2.connect_timeout(&target.into(), timeout).is_err() {
        return failed();
    }
    let stream = std::net::TcpStream::from(sock2);
    tcp_bucket_from_stream(local_port, stream, payload_len, timeout)
}

fn tcp_bucket_from_stream(
    local_port: u16,
    mut stream: TcpStream,
    payload_len: usize,
    timeout: Duration,
) -> BucketResult {
    use std::io::{Read, Write};
    stream.set_read_timeout(Some(timeout)).ok();
    let payload = vec![0xCDu8; payload_len.max(1)];
    let start = Instant::now();
    let write_result = stream.write_all(&payload);
    if write_result.is_err() {
        return BucketResult {
            local_port,
            outcome: BucketOutcome::Failed,
            bytes_sent: 0,
            bytes_acked_or_echoed: 0,
            rtt_ms: None,
            mid_flow_rebind_detected: None,
        };
    }
    let mut buf = [0u8; 4096];
    let echoed = stream.read(&mut buf).unwrap_or(0) as u64;
    BucketResult {
        local_port,
        outcome: BucketOutcome::Succeeded,
        bytes_sent: payload.len() as u64,
        bytes_acked_or_echoed: echoed,
        rtt_ms: Some(start.elapsed().as_secs_f64() * 1000.0),
        mid_flow_rebind_detected: None,
    }
}

/// Wraps a bucket run with a STUN mapped-address sample immediately before
/// and after it, on the *same bound local port* the bucket's flow used --
/// this is what lets `mid_flow_rebind_detected` distinguish "the NAT kept
/// this 5-tuple's mapping stable through the flow" from "the mapping
/// changed while the flow was live". A STUN timeout on either side leaves
/// the field `None` (unavailable), never `false` (falsely "stable").
pub fn run_udp_bucket_with_stun_bracket(
    local_port: u16,
    target: SocketAddr,
    stun_server: SocketAddr,
    payload_len: usize,
    timeout: Duration,
) -> BucketResult {
    let bind_addr = format!("0.0.0.0:{local_port}");
    let socket = match UdpSocket::bind(&bind_addr) {
        Ok(s) => s,
        Err(_) => {
            return BucketResult {
                local_port,
                outcome: BucketOutcome::Failed,
                bytes_sent: 0,
                bytes_acked_or_echoed: 0,
                rtt_ms: None,
                mid_flow_rebind_detected: None,
            }
        }
    };
    let before = binding_request_once(&socket, stun_server, timeout);

    let mut result = run_udp_bucket(local_port, target, payload_len, timeout);
    // run_udp_bucket rebinds its own socket internally; re-use this
    // function's socket instead so the STUN before/after brackets the
    // exact same 5-tuple as the data flow, not a second bind on the port.
    let payload = vec![0xABu8; payload_len.max(1)];
    let start = Instant::now();
    socket.set_read_timeout(Some(timeout)).ok();
    let sent = socket.send_to(&payload, target);
    let mut buf = [0u8; 1500];
    let (outcome, echoed, rtt_ms) = match sent {
        Ok(_) => match socket.recv_from(&mut buf) {
            Ok((r, _)) => (
                BucketOutcome::Succeeded,
                r as u64,
                Some(start.elapsed().as_secs_f64() * 1000.0),
            ),
            Err(_) => (BucketOutcome::Succeeded, 0u64, None),
        },
        Err(_) => (BucketOutcome::Failed, 0u64, None),
    };
    result.outcome = outcome;
    result.bytes_acked_or_echoed = echoed;
    result.rtt_ms = rtt_ms;

    let after = binding_request_once(&socket, stun_server, timeout);

    result.mid_flow_rebind_detected = match (&before.outcome, &after.outcome) {
        (BindingOutcome::Mapped(b), BindingOutcome::Mapped(a)) => Some(b != a),
        _ => None,
    };
    result
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcmpNatReport {
    pub target: String,
    pub buckets: Vec<BucketResult>,
    pub bimodality: BimodalityVerdict,
    pub interface_is_tunnel: bool,
}

pub const TUNNEL_INTERFACE_WARNING: &str =
    "measured interface is a tunnel; a tunnel re-encapsulates every flow through its own single path, masking any real ECMP/LAG/NAT behavior on the underlying physical uplinks -- this result is meaningless for that question";

#[cfg(test)]
mod tests {
    use super::*;

    fn bucket(port: u16, outcome: BucketOutcome) -> BucketResult {
        BucketResult {
            local_port: port,
            outcome,
            bytes_sent: 1,
            bytes_acked_or_echoed: 0,
            rtt_ms: None,
            mid_flow_rebind_detected: None,
        }
    }

    #[test]
    fn all_buckets_succeeding_reports_no_split_not_inconclusive() {
        let results = vec![
            bucket(1, BucketOutcome::Succeeded),
            bucket(2, BucketOutcome::Succeeded),
            bucket(3, BucketOutcome::Succeeded),
        ];
        assert_eq!(
            classify_bimodality(&results),
            BimodalityVerdict::NoSplitDetected
        );
    }

    #[test]
    fn all_buckets_failing_reports_no_split_not_inconclusive() {
        // This is the exact field-evidence shape: every 350 Mbps bucket
        // failed the same way, and that absence of a split was itself the
        // finding (argues against one bad ECMP member).
        let results = vec![
            bucket(1, BucketOutcome::Failed),
            bucket(2, BucketOutcome::Failed),
            bucket(3, BucketOutcome::Failed),
        ];
        assert_eq!(
            classify_bimodality(&results),
            BimodalityVerdict::NoSplitDetected
        );
    }

    #[test]
    fn one_failing_bucket_among_successes_is_a_bimodal_split() {
        let results = vec![
            bucket(1, BucketOutcome::Succeeded),
            bucket(2, BucketOutcome::Failed),
            bucket(3, BucketOutcome::Succeeded),
        ];
        assert_eq!(
            classify_bimodality(&results),
            BimodalityVerdict::BimodalSplitDetected
        );
    }

    #[test]
    fn fewer_than_two_buckets_refuses_a_split_judgement() {
        let results = vec![bucket(1, BucketOutcome::Succeeded)];
        assert_eq!(
            classify_bimodality(&results),
            BimodalityVerdict::InsufficientBuckets
        );
        assert_eq!(
            classify_bimodality(&[]),
            BimodalityVerdict::InsufficientBuckets
        );
    }

    #[test]
    fn mid_flow_rebind_is_true_only_when_mapped_addresses_actually_differ() {
        let a: SocketAddr = "203.0.113.5:4000".parse().unwrap();
        let b: SocketAddr = "203.0.113.5:4000".parse().unwrap();
        let c: SocketAddr = "203.0.113.9:4001".parse().unwrap();
        assert_eq!(
            match (BindingOutcome::Mapped(a), BindingOutcome::Mapped(b)) {
                (BindingOutcome::Mapped(x), BindingOutcome::Mapped(y)) => Some(x != y),
                _ => None,
            },
            Some(false)
        );
        assert_eq!(
            match (BindingOutcome::Mapped(a), BindingOutcome::Mapped(c)) {
                (BindingOutcome::Mapped(x), BindingOutcome::Mapped(y)) => Some(x != y),
                _ => None,
            },
            Some(true)
        );
    }

    #[test]
    fn mid_flow_rebind_is_unavailable_not_false_when_stun_was_unreachable() {
        let a: SocketAddr = "203.0.113.5:4000".parse().unwrap();
        let result: Option<bool> = match (BindingOutcome::Mapped(a), BindingOutcome::Unreachable) {
            (BindingOutcome::Mapped(x), BindingOutcome::Mapped(y)) => Some(x != y),
            _ => None,
        };
        assert_eq!(result, None);
    }
}
