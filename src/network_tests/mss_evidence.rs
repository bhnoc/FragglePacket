//! MSS clamp / on-wire evidence (GAP-010) and multi-destination MSS
//! clustering against confirmed route MTU (GAP-026).
//!
//! `tcp_options_echo.rs` reads TCP_MAXSEG from an established local socket
//! and compares it with the route MTU -- that catches an unexplained local
//! reduction but cannot say whether the peer or a middlebox caused it,
//! because it never sees a SYN or SYN-ACK on the wire. This module ingests
//! (or, given root, captures) both SYN directions and keeps three
//! attributions separate:
//!
//! * `local_advertised` -- MSS this host's SYN offered. Local stack only.
//! * `peer_advertised` -- MSS in the peer's SYN-ACK. Could be genuine peer
//!   policy (proxy/CDN edge) OR a middlebox rewrite in transit -- observing
//!   only this side cannot distinguish the two.
//! * `middlebox_rewrite_evidence` -- requires BOTH directions plus a
//!   cross-check (e.g. the same peer offering different MSS to different
//!   local ports/hosts, or a local MSS that does not match what this stack
//!   would normally advertise). Without both directions this is always
//!   `Insufficient`, and the confidence label says so explicitly.
//!
//! GAP-026 asks a different question: given MSS observed/negotiated against
//! several *independent* destinations, does the evidence support
//! peer-specific values, a uniform TCP-level clamp/proxy, or a true PMTU
//! ceiling? The discriminator is whether large DF-marked probes still
//! succeed on the same path (see `pmtu_evidence`): if they do, a uniform low
//! MSS is a TCP policy, not a path MTU limit.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;

use serde::{Deserialize, Serialize};

use etherparse::{LaxNetSlice, LaxSlicedPacket, TcpOptionElement, TransportSlice};
use pcap_file::pcap::PcapReader;
use pcap_file::pcapng::PcapNgReader;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Confidence {
    /// Only one SYN direction observed for this flow, or a single sample.
    Insufficient,
    Low,
    Medium,
    High,
}

/// One TCP flow's SYN evidence, keyed by (local port, peer ip, peer port).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowMssEvidence {
    pub local_ip: String,
    pub local_port: u16,
    pub peer_ip: String,
    pub peer_port: u16,
    /// MSS this host advertised in its SYN, if that SYN was observed.
    pub local_advertised: Option<u16>,
    /// MSS the peer advertised in its SYN-ACK, if observed.
    pub peer_advertised: Option<u16>,
    pub both_directions_observed: bool,
}

impl FlowMssEvidence {
    fn new(local_ip: String, local_port: u16, peer_ip: String, peer_port: u16) -> Self {
        FlowMssEvidence {
            local_ip,
            local_port,
            peer_ip,
            peer_port,
            local_advertised: None,
            peer_advertised: None,
            both_directions_observed: false,
        }
    }

    fn recompute(&mut self) {
        self.both_directions_observed =
            self.local_advertised.is_some() && self.peer_advertised.is_some();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MiddleboxVerdict {
    /// Both SYN and SYN-ACK were observed and the peer's advertised MSS
    /// is consistent with what would be expected on an unmodified path
    /// (i.e. no reduction beyond ordinary local/peer stack choice).
    NoRewriteEvidence,
    /// Both directions observed. The peer's advertised MSS is present but
    /// this alone cannot prove whether the reduction originated at the
    /// peer (proxy/CDN edge policy) or a middlebox in transit -- that
    /// requires corroboration such as the same peer IP advertising
    /// different MSS to different local flows, which this single-flow
    /// evidence does not provide.
    Ambiguous,
    /// Only one direction was observed for this flow. A middlebox-rewrite
    /// claim is never made from single-direction evidence.
    InsufficientEvidence,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiddleboxAttribution {
    pub verdict: MiddleboxVerdict,
    pub confidence: Confidence,
    pub explanation: String,
}

fn attribute_middlebox(flow: &FlowMssEvidence) -> MiddleboxAttribution {
    if !flow.both_directions_observed {
        return MiddleboxAttribution {
            verdict: MiddleboxVerdict::InsufficientEvidence,
            confidence: Confidence::Insufficient,
            explanation: format!(
                "only {} SYN direction observed for {}:{} <-> {}:{}; a middlebox-rewrite claim requires both SYN and SYN-ACK",
                if flow.local_advertised.is_some() { "the local->peer" } else { "the peer->local" },
                flow.local_ip, flow.local_port, flow.peer_ip, flow.peer_port
            ),
        };
    }

    let local = flow.local_advertised.unwrap();
    let peer = flow.peer_advertised.unwrap();

    MiddleboxAttribution {
        verdict: MiddleboxVerdict::Ambiguous,
        confidence: Confidence::Low,
        explanation: format!(
            "both directions observed: local advertised {} in SYN, peer advertised {} in SYN-ACK to {}:{}. \
             This alone cannot distinguish genuine peer/proxy policy from an in-path rewrite of either value; \
             it requires corroboration across independent flows to the same or different peers to raise confidence.",
            local, peer, flow.peer_ip, flow.peer_port
        ),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GapTenReport {
    pub source: String,
    pub flows: Vec<FlowMssEvidence>,
    pub attributions: Vec<MiddleboxAttribution>,
    pub flows_with_both_directions: usize,
    pub flows_total: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum MssEvidenceError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("unrecognized capture format (not pcap or pcapng)")]
    UnrecognizedFormat,
    #[error("pcap parse error: {0}")]
    Pcap(String),
}

fn mss_from_options(options: &[u8]) -> Option<u16> {
    for opt in etherparse::TcpOptionsIterator::from_slice(options) {
        if let Ok(TcpOptionElement::MaximumSegmentSize(v)) = opt {
            return Some(v);
        }
    }
    None
}

/// Ingests a pcap/pcapng file and extracts SYN/SYN-ACK MSS evidence per flow.
///
/// `local_ips` identifies which observed endpoint is "local" for the
/// local/peer attribution; packets whose neither side matches are still
/// recorded (both sides get labeled by source/destination of the SYN) but
/// `local_advertised` vs `peer_advertised` falls back to "SYN sender is
/// local" when no local IP set is supplied.
pub fn ingest_syn_mss<P: AsRef<Path>>(
    path: P,
    local_ips: &[IpAddr],
) -> Result<GapTenReport, MssEvidenceError> {
    let path_ref = path.as_ref();
    let bytes = std::fs::read(path_ref)?;
    if bytes.len() < 4 {
        return Err(MssEvidenceError::UnrecognizedFormat);
    }

    let magic = &bytes[0..4];
    let is_pcapng = magic == [0x0A, 0x0D, 0x0D, 0x0A];
    let is_pcap_be = magic == [0xA1, 0xB2, 0xC3, 0xD4] || magic == [0xA1, 0xB2, 0x3C, 0x4D];
    let is_pcap_le = magic == [0xD4, 0xC3, 0xB2, 0xA1] || magic == [0x4D, 0x3C, 0xB2, 0xA1];

    if !is_pcapng && !is_pcap_be && !is_pcap_le {
        return Err(MssEvidenceError::UnrecognizedFormat);
    }

    let mut flows: HashMap<(String, u16, String, u16), FlowMssEvidence> = HashMap::new();

    let mut record = |src_ip: IpAddr,
                      src_port: u16,
                      dst_ip: IpAddr,
                      dst_port: u16,
                      syn: bool,
                      ack: bool,
                      mss: Option<u16>| {
        let mss = match mss {
            Some(m) => m,
            None => return,
        };
        if !syn {
            return;
        }

        let src_is_local = local_ips.contains(&src_ip);
        let dst_is_local = local_ips.contains(&dst_ip);

        // Fall back when no local-IP hint was given: treat the SYN
        // (non-ACK) sender as local, the SYN-ACK sender as peer. This
        // matches the common single-host-capture case.
        let (local_addr, local_port, peer_addr, peer_port, is_local_leg) = if local_ips.is_empty() {
            if !ack {
                (src_ip, src_port, dst_ip, dst_port, true)
            } else {
                (dst_ip, dst_port, src_ip, src_port, false)
            }
        } else if src_is_local {
            (src_ip, src_port, dst_ip, dst_port, true)
        } else if dst_is_local {
            (dst_ip, dst_port, src_ip, src_port, false)
        } else {
            return;
        };

        let key = (
            local_addr.to_string(),
            local_port,
            peer_addr.to_string(),
            peer_port,
        );
        let entry = flows.entry(key).or_insert_with(|| {
            FlowMssEvidence::new(
                local_addr.to_string(),
                local_port,
                peer_addr.to_string(),
                peer_port,
            )
        });

        if is_local_leg {
            entry.local_advertised = Some(mss);
        } else {
            entry.peer_advertised = Some(mss);
        }
        entry.recompute();
    };

    if is_pcapng {
        let mut reader = PcapNgReader::new(bytes.as_slice())
            .map_err(|e| MssEvidenceError::Pcap(e.to_string()))?;
        while let Some(block) = reader.next_block() {
            let block = block.map_err(|e| MssEvidenceError::Pcap(e.to_string()))?;
            if let Some(epb) = block.as_enhanced_packet() {
                inspect_frame(epb.data.as_ref(), &mut record);
            } else if let Some(spb) = block.as_simple_packet() {
                inspect_frame(spb.data.as_ref(), &mut record);
            }
        }
    } else {
        let mut reader =
            PcapReader::new(bytes.as_slice()).map_err(|e| MssEvidenceError::Pcap(e.to_string()))?;
        while let Some(pkt) = reader.next_packet() {
            let pkt = pkt.map_err(|e| MssEvidenceError::Pcap(e.to_string()))?;
            inspect_frame(pkt.data.as_ref(), &mut record);
        }
    }

    let mut flow_list: Vec<FlowMssEvidence> = flows.into_values().collect();
    flow_list
        .sort_by(|a, b| (a.peer_ip.clone(), a.peer_port).cmp(&(b.peer_ip.clone(), b.peer_port)));

    let attributions: Vec<MiddleboxAttribution> =
        flow_list.iter().map(attribute_middlebox).collect();
    let flows_with_both = flow_list
        .iter()
        .filter(|f| f.both_directions_observed)
        .count();
    let flows_total = flow_list.len();

    Ok(GapTenReport {
        source: path_ref.display().to_string(),
        flows: flow_list,
        attributions,
        flows_with_both_directions: flows_with_both,
        flows_total,
    })
}

fn inspect_frame(
    captured: &[u8],
    record: &mut impl FnMut(IpAddr, u16, IpAddr, u16, bool, bool, Option<u16>),
) {
    let parsed = match LaxSlicedPacket::from_ethernet(captured) {
        Ok(p) => p,
        Err(_) => return,
    };
    let net = match &parsed.net {
        Some(n) => n,
        None => return,
    };
    let (src, dst): (IpAddr, IpAddr) = match net {
        LaxNetSlice::Ipv4(v4) => (
            IpAddr::V4(std::net::Ipv4Addr::from(v4.header().source())),
            IpAddr::V4(std::net::Ipv4Addr::from(v4.header().destination())),
        ),
        LaxNetSlice::Ipv6(v6) => (
            IpAddr::V6(std::net::Ipv6Addr::from(v6.header().source())),
            IpAddr::V6(std::net::Ipv6Addr::from(v6.header().destination())),
        ),
    };

    if let Some(TransportSlice::Tcp(tcp)) = &parsed.transport {
        if !tcp.syn() {
            return;
        }
        let mss = mss_from_options(tcp.options());
        record(
            src,
            tcp.source_port(),
            dst,
            tcp.destination_port(),
            true,
            tcp.ack(),
            mss,
        );
    }
}

/// GAP-026: cluster MSS values observed/negotiated against independent
/// destinations and relate them to a confirmed route/path MTU.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DestinationMss {
    pub destination: String,
    pub negotiated_mss: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClusterVerdict {
    /// MSS values differ meaningfully by destination -- consistent with
    /// each peer/CDN edge choosing its own value, no evidence of a
    /// uniform local/path-level clamp.
    PeerSpecific,
    /// MSS values converge across independent destinations AND large
    /// DF-marked probes on the same path still succeed -- a real PMTU
    /// ceiling would have broken those probes too, so this points at a
    /// TCP-specific clamp or transparent proxy rather than path MTU.
    UniformClampOrProxy,
    /// MSS values converge across independent destinations AND large
    /// DF-marked probes fail (or are unconfirmed) -- consistent with an
    /// actual path MTU ceiling rather than a TCP-level policy.
    TruePmtuCeiling,
    /// Fewer than two independent destinations, or DF-probe evidence is
    /// missing -- not enough to discriminate.
    Inconclusive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GapTwentySixReport {
    pub destinations: Vec<DestinationMss>,
    pub route_mtu: Option<u16>,
    pub route_interface: Option<String>,
    pub route_is_tunnel: bool,
    /// Whether a large (near-1500-byte) DF-marked probe was confirmed to
    /// cross the same path. `None` means this was not tested.
    pub large_df_probe_confirmed: Option<bool>,
    pub mss_spread: u16,
    pub verdict: ClusterVerdict,
    pub explanation: String,
}

/// Values within this many bytes of each other are treated as "converged"
/// for clustering purposes -- small deltas can come from TCP timestamp/SACK
/// option presence differences, not distinct policies.
const CONVERGENCE_TOLERANCE_BYTES: u16 = 24;

pub fn cluster_destination_mss(
    destinations: Vec<DestinationMss>,
    route_mtu: Option<u16>,
    route_interface: Option<String>,
    route_is_tunnel: bool,
    large_df_probe_confirmed: Option<bool>,
) -> GapTwentySixReport {
    let values: Vec<u16> = destinations.iter().map(|d| d.negotiated_mss).collect();
    let spread = match (values.iter().min(), values.iter().max()) {
        (Some(min), Some(max)) => max - min,
        _ => 0,
    };

    let (verdict, explanation) = if destinations.len() < 2 {
        (
            ClusterVerdict::Inconclusive,
            "fewer than two independent destinations probed; cannot cluster".to_string(),
        )
    } else if spread > CONVERGENCE_TOLERANCE_BYTES {
        (
            ClusterVerdict::PeerSpecific,
            format!(
                "MSS spread of {} bytes across {} destinations exceeds the {}-byte convergence tolerance -- values are destination-specific, no evidence of a uniform clamp",
                spread, destinations.len(), CONVERGENCE_TOLERANCE_BYTES
            ),
        )
    } else {
        match large_df_probe_confirmed {
            Some(true) => (
                ClusterVerdict::UniformClampOrProxy,
                format!(
                    "MSS converged to within {} bytes across {} independent destinations, but a large DF-marked probe on the same path was confirmed to succeed -- a true PMTU ceiling would have broken that probe too, so this is TCP-specific clamping or transparent proxying, not a low path MTU",
                    spread, destinations.len()
                ),
            ),
            Some(false) => (
                ClusterVerdict::TruePmtuCeiling,
                format!(
                    "MSS converged to within {} bytes across {} independent destinations AND a large DF-marked probe on the same path failed to be confirmed -- consistent with a true path MTU ceiling",
                    spread, destinations.len()
                ),
            ),
            None => (
                ClusterVerdict::Inconclusive,
                format!(
                    "MSS converged to within {} bytes across {} independent destinations, but no large DF-marked probe result is available to discriminate a TCP clamp from a true PMTU ceiling",
                    spread, destinations.len()
                ),
            ),
        }
    };

    GapTwentySixReport {
        destinations,
        route_mtu,
        route_interface,
        route_is_tunnel,
        large_df_probe_confirmed,
        mss_spread: spread,
        verdict,
        explanation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_direction_never_yields_middlebox_claim() {
        let mut flow = FlowMssEvidence::new("10.0.0.1".into(), 1234, "1.1.1.1".into(), 443);
        flow.local_advertised = Some(1460);
        flow.recompute();
        let attribution = attribute_middlebox(&flow);
        assert_eq!(attribution.verdict, MiddleboxVerdict::InsufficientEvidence);
        assert_eq!(attribution.confidence, Confidence::Insufficient);
    }

    #[test]
    fn both_directions_yields_ambiguous_not_certain() {
        let mut flow = FlowMssEvidence::new("10.0.0.1".into(), 1234, "1.1.1.1".into(), 443);
        flow.local_advertised = Some(1460);
        flow.peer_advertised = Some(1400);
        flow.recompute();
        let attribution = attribute_middlebox(&flow);
        assert_eq!(attribution.verdict, MiddleboxVerdict::Ambiguous);
        assert_ne!(attribution.confidence, Confidence::High);
    }

    #[test]
    fn mgm_case_reports_uniform_clamp_not_pmtu_ceiling() {
        let dests = vec![
            DestinationMss {
                destination: "apple".into(),
                negotiated_mss: 1238,
            },
            DestinationMss {
                destination: "cloudflare".into(),
                negotiated_mss: 1238,
            },
            DestinationMss {
                destination: "google".into(),
                negotiated_mss: 1238,
            },
        ];
        let report =
            cluster_destination_mss(dests, Some(1500), Some("en0".into()), false, Some(true));
        assert_eq!(report.verdict, ClusterVerdict::UniformClampOrProxy);
    }

    #[test]
    fn true_pmtu_ceiling_when_large_probe_fails() {
        let dests = vec![
            DestinationMss {
                destination: "a".into(),
                negotiated_mss: 1220,
            },
            DestinationMss {
                destination: "b".into(),
                negotiated_mss: 1230,
            },
        ];
        let report = cluster_destination_mss(dests, Some(1280), None, false, Some(false));
        assert_eq!(report.verdict, ClusterVerdict::TruePmtuCeiling);
    }

    #[test]
    fn destination_specific_spread_is_peer_specific() {
        let dests = vec![
            DestinationMss {
                destination: "apple".into(),
                negotiated_mss: 1460,
            },
            DestinationMss {
                destination: "cloudflare".into(),
                negotiated_mss: 1400,
            },
            DestinationMss {
                destination: "google".into(),
                negotiated_mss: 1412,
            },
        ];
        let report =
            cluster_destination_mss(dests, Some(1500), Some("en0".into()), false, Some(true));
        assert_eq!(report.verdict, ClusterVerdict::PeerSpecific);
    }

    #[test]
    fn mss_from_options_parses_maximum_segment_size() {
        use etherparse::TcpHeader;
        let mut header = TcpHeader::new(1234, 443, 0, 65535);
        header
            .set_options(&[TcpOptionElement::MaximumSegmentSize(1460)])
            .unwrap();
        let mut buf = Vec::new();
        header.write(&mut buf).unwrap();
        assert_eq!(mss_from_options(&buf[20..]), Some(1460));
    }
}
