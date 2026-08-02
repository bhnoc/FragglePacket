//! GAP-006: controlled TCP-versus-UDP throughput/loss comparison against a
//! user-supplied endpoint.
//!
//! No hardcoded default server per the acceptance criteria -- the endpoint
//! is always caller-supplied. Parsing reuses `network_tests::iperf`
//! (GAP-039); this module holds only the comparison/verdict logic on top of
//! its `IperfResult`/`RateEvidence`.

use crate::network_tests::iperf::{IperfParseError, IperfResult};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolResult {
    pub protocol: Protocol,
    pub port: u16,
    pub target_mbps: f64,
    /// `false` when the run itself failed to parse/produce a result (error
    /// present, missing fields) -- every field below is then `None`, not a
    /// best-effort guess from a partially-populated result.
    pub usable: bool,
    pub achieved_mbps: Option<f64>,
    pub loss_percent: Option<f64>,
    /// UDP: packets observed out of order relative to sequence, if the
    /// summary carried that data. TCP has no analogous field here --
    /// retransmission is a different phenomenon and is not reused as a
    /// stand-in for reordering.
    pub reordered_packets: Option<u64>,
    pub unusable_reason: Option<String>,
}

fn unusable(protocol: Protocol, port: u16, target_mbps: f64, reason: String) -> ProtocolResult {
    ProtocolResult {
        protocol,
        port,
        target_mbps,
        usable: false,
        achieved_mbps: None,
        loss_percent: None,
        reordered_packets: None,
        unusable_reason: Some(reason),
    }
}

/// Builds a TCP result from a parsed `IperfResult`. Prefers the receiver
/// side's `received` sample (GAP-039: only the receiver saw what actually
/// arrived), falling back to `sent` only if `received` is absent/hollow.
pub fn tcp_result(port: u16, target_mbps: f64, parsed: &Result<IperfResult, IperfParseError>) -> ProtocolResult {
    let result = match parsed {
        Err(e) => return unusable(Protocol::Tcp, port, target_mbps, e.to_string()),
        Ok(r) => r,
    };
    let sample = result.forward.received.or(result.forward.sent);
    let Some(sample) = sample else {
        return unusable(Protocol::Tcp, port, target_mbps, "no usable rate sample (sum_sent/sum_received missing or hollow)".to_string());
    };
    ProtocolResult {
        protocol: Protocol::Tcp,
        port,
        target_mbps,
        usable: true,
        achieved_mbps: Some(sample.bits_per_second / 1e6),
        // TCP has no native loss-percent field the way UDP does (loss shows
        // up as retransmissions on a different scale); not fabricated here.
        loss_percent: None,
        reordered_packets: None,
        unusable_reason: None,
    }
}

pub fn udp_result(port: u16, target_mbps: f64, parsed: &Result<IperfResult, IperfParseError>) -> ProtocolResult {
    let result = match parsed {
        Err(e) => return unusable(Protocol::Udp, port, target_mbps, e.to_string()),
        Ok(r) => r,
    };
    let sample = result.forward.received.or(result.forward.estimated_received);
    let Some(sample) = sample else {
        return unusable(Protocol::Udp, port, target_mbps, "no usable rate sample (sum_received/sum missing or hollow)".to_string());
    };
    ProtocolResult {
        protocol: Protocol::Udp,
        port,
        target_mbps,
        usable: true,
        achieved_mbps: Some(sample.bits_per_second / 1e6),
        loss_percent: sample.lost_percent,
        reordered_packets: None,
        unusable_reason: None,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpVsUdpComparison {
    pub endpoint: String,
    pub tcp: ProtocolResult,
    pub udp: ProtocolResult,
}

impl TcpVsUdpComparison {
    /// `None` when either side is unusable -- a comparison needs both
    /// figures to mean anything; reporting a one-sided "delta" against a
    /// missing measurement would be another instance of the recurring
    /// number-with-no-referent failure.
    pub fn achieved_mbps_delta(&self) -> Option<f64> {
        match (self.tcp.achieved_mbps, self.udp.achieved_mbps) {
            (Some(t), Some(u)) => Some(t - u),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network_tests::iperf::parse_iperf_json;

    fn load_fixture(name: &str) -> String {
        let path = format!("{}/harness/fixtures/iperf/{}", env!("CARGO_MANIFEST_DIR"), name);
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {}", path, e))
    }

    #[test]
    fn tcp_forward_fixture_yields_usable_result_with_achieved_rate() {
        let parsed = parse_iperf_json(&load_fixture("tcp-forward-3.21.json"));
        let r = tcp_result(5201, 100.0, &parsed);
        assert!(r.usable);
        assert!(r.achieved_mbps.unwrap() > 0.0);
        assert!(r.unusable_reason.is_none());
    }

    #[test]
    fn udp_reverse_fixture_reads_loss_from_a_non_hollow_sample() {
        let parsed = parse_iperf_json(&load_fixture("udp-reverse-3.21.json"));
        let r = udp_result(5202, 5.0, &parsed);
        assert!(r.usable);
        // sum_sent is hollow in this fixture; the iperf module already
        // filters it out, and this layer must not reach around that by
        // reading a different, unfiltered field.
        assert_eq!(r.loss_percent, Some(0.0));
    }

    #[test]
    fn refused_connection_is_unusable_with_stated_reason_no_fabricated_rate() {
        let parsed = parse_iperf_json(&load_fixture("error-refused.json"));
        let r = tcp_result(5201, 100.0, &parsed);
        assert!(!r.usable);
        assert!(r.achieved_mbps.is_none());
        assert!(r.unusable_reason.is_some());
    }

    #[test]
    fn comparison_delta_is_none_when_either_side_unusable() {
        let refused = parse_iperf_json(&load_fixture("error-refused.json"));
        let tcp_forward = parse_iperf_json(&load_fixture("tcp-forward-3.21.json"));

        let comparison = TcpVsUdpComparison {
            endpoint: "example.test".to_string(),
            tcp: tcp_result(5201, 100.0, &tcp_forward),
            udp: udp_result(5202, 100.0, &refused),
        };
        assert!(comparison.achieved_mbps_delta().is_none());
    }
}
