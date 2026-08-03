//! PCAP capture analysis (GAP-019 / GAP-008).
//!
//! Reads a pcap or pcapng file end-to-end, streaming packet-by-packet so a
//! 2+ GB capture never lands fully in memory, and produces a report that is
//! explicit about what the file can and cannot prove:
//!
//! * Capture health (snaplen, link type, packet/byte counts, drop counts)
//!   is reported before anything else, and an unknown drop count (classic
//!   pcap has no such field) is reported as unknown, never coerced to zero.
//! * Vantage point (host-side/offload-subject vs on-wire mirror/tap) is
//!   classified from evidence found in the file, with a confidence level
//!   and the evidence listed, never asserted as certain.
//! * Frame-size verdicts compare captured length against link MTU plus the
//!   L2 (Ethernet) header, not a bare 1500-byte constant. A 1,510-byte
//!   Ethernet frame carrying a 1,496-byte IP payload is legal at MTU 1500.
//! * TCP retransmission/out-of-order/dup-ACK counts are always produced,
//!   but on a host-side capture they are qualified as "not usable as
//!   on-wire evidence" rather than reported as network faults, because
//!   TSO/GSO/GRO reconstruct host segments that were never on the wire.

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use std::time::Duration as StdDuration;

use pcap_file::pcap::PcapReader;
use pcap_file::pcapng::PcapNgReader;
use pcap_file::DataLink;
use serde::{Deserialize, Serialize};

const ETHERNET_HEADER_LEN: usize = 14;
const DEFAULT_LINK_MTU: usize = 1500;
/// L2 encapsulation ceiling we compare captured frame length against:
/// link MTU + Ethernet header. This is the fix for the GAP-019 measurement
/// error, which compared frame length against a bare 1500.
fn oversize_threshold(link_mtu: usize) -> usize {
    link_mtu + ETHERNET_HEADER_LEN
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Vantage {
    HostOffloadSuspect,
    OnWireMirrorOrTap,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VantageClassification {
    pub vantage: Vantage,
    pub confidence: Confidence,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureHealth {
    pub file_format: String,
    pub link_type: String,
    pub interface_name: Option<String>,
    pub snaplen: u32,
    /// True when at least one packet's captured length is less than the
    /// interface/file snaplen would allow for its original length, i.e.
    /// payload bytes beyond snaplen were discarded by the capture tool.
    pub truncated: bool,
    pub packet_count: u64,
    pub byte_count: u64,
    pub duration_secs: Option<f64>,
    /// None means "the file format/blocks present cannot report this",
    /// which must never be displayed or treated as zero.
    pub drops_known: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FrameSizeAnalysis {
    pub link_mtu_assumed: usize,
    pub oversize_threshold: usize,
    pub observed_over_threshold: u64,
    pub max_observed_frame_len: u64,
    /// Frames over threshold are pre-segmentation host segments, not
    /// evidence of an on-wire oversize frame, when vantage is host-side.
    pub oversize_is_host_segment_artifact: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChecksumOffloadSignal {
    pub tcp_checksum_zero_or_invalid: u64,
    pub tcp_checksum_checked: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TcpAnomalyCounts {
    pub sampled_packets: u64,
    pub retransmissions: u64,
    pub out_of_order: u64,
    pub duplicate_acks: u64,
    /// Always true today: this counter set is derived from single-vantage
    /// packet reconstruction and cannot itself prove capture location.
    pub qualification_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcapReport {
    pub path: String,
    pub health: CaptureHealth,
    pub vantage: VantageClassification,
    pub frame_size: FrameSizeAnalysis,
    pub checksum_offload: ChecksumOffloadSignal,
    pub tcp_anomalies: TcpAnomalyCounts,
    pub directions_seen: DirectionsSeen,
    pub protocol_breakdown: ProtocolBreakdown,
    pub payload_analysis_suppressed: bool,
    pub notes: Vec<String>,
}

/// Per-protocol packet/byte counts for the GAP-008 comparison report. QUIC
/// has no IANA-assigned transport number of its own (it rides on UDP), so
/// `quic_candidate_*` is a heuristic (UDP/443 or a long-header-shaped first
/// payload byte), never a certain classification.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProtocolBreakdown {
    pub tcp_packets: u64,
    pub tcp_bytes: u64,
    pub udp_packets: u64,
    pub udp_bytes: u64,
    pub udp_flows: u64,
    pub quic_candidate_packets: u64,
    pub quic_candidate_bytes: u64,
    pub icmp_packets: u64,
    pub other_packets: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DirectionsSeen {
    pub src_ips_seen: u64,
    pub dst_ips_seen: u64,
    pub bidirectional_tcp_flows: u64,
    pub total_tcp_flows: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum PcapReportError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("unrecognized capture format (not pcap or pcapng)")]
    UnrecognizedFormat,
    #[error("pcap parse error: {0}")]
    Pcap(String),
}

struct FlowKey {
    a_ip: [u8; 16],
    a_port: u16,
    b_ip: [u8; 16],
    b_port: u16,
}

impl FlowKey {
    fn normalized(src_ip: [u8; 16], src_port: u16, dst_ip: [u8; 16], dst_port: u16) -> Self {
        if (src_ip, src_port) <= (dst_ip, dst_port) {
            FlowKey {
                a_ip: src_ip,
                a_port: src_port,
                b_ip: dst_ip,
                b_port: dst_port,
            }
        } else {
            FlowKey {
                a_ip: dst_ip,
                a_port: dst_port,
                b_ip: src_ip,
                b_port: src_port,
            }
        }
    }

    fn id(&self) -> (u128, u16, u128, u16) {
        (
            u128::from_be_bytes(self.a_ip),
            self.a_port,
            u128::from_be_bytes(self.b_ip),
            self.b_port,
        )
    }
}

#[derive(Default)]
struct FlowState {
    seen_from_a: bool,
    seen_from_b: bool,
    /// Highest (seq, len) observed per direction, used to spot repeats
    /// (retransmissions) and gaps/out-of-order arrivals in the sample.
    a_max_seq_end: Option<u64>,
    b_max_seq_end: Option<u64>,
    a_last_ack: Option<u32>,
    b_last_ack: Option<u32>,
    a_dup_ack_run: u32,
    b_dup_ack_run: u32,
}

/// Cap on how many distinct flows we track state for. Bounds memory on a
/// capture with millions of flows; beyond this, additional flows are still
/// counted toward frame/health stats but not toward anomaly detection.
const MAX_TRACKED_FLOWS: usize = 200_000;
/// Cap on how many packets the TCP anomaly pass inspects in detail. This
/// mirrors the "sample" framing used in the GAP-019 write-up: with a
/// 1.5M-packet file the point is qualification, not an exhaustive replay.
const MAX_TCP_SAMPLE_PACKETS: u64 = 2_000_000;

pub fn analyze_pcap<P: AsRef<Path>>(path: P) -> Result<PcapReport, PcapReportError> {
    let path_ref = path.as_ref();
    let file = File::open(path_ref)?;
    let mut reader = BufReader::with_capacity(1 << 20, file);

    let mut magic = [0u8; 4];
    reader.read_exact(&mut magic)?;
    let reader = std::io::Read::chain(std::io::Cursor::new(magic), reader);

    let is_pcapng = magic == [0x0A, 0x0D, 0x0D, 0x0A];
    let is_pcap_be = magic == [0xA1, 0xB2, 0xC3, 0xD4] || magic == [0xA1, 0xB2, 0x3C, 0x4D];
    let is_pcap_le = magic == [0xD4, 0xC3, 0xB2, 0xA1] || magic == [0x4D, 0x3C, 0xB2, 0xA1];

    if is_pcapng {
        analyze_pcapng(path_ref, reader)
    } else if is_pcap_be || is_pcap_le {
        analyze_pcap_classic(path_ref, reader)
    } else {
        Err(PcapReportError::UnrecognizedFormat)
    }
}

fn analyze_pcap_classic<R: Read>(path: &Path, reader: R) -> Result<PcapReport, PcapReportError> {
    let mut pcap_reader =
        PcapReader::new(reader).map_err(|e| PcapReportError::Pcap(e.to_string()))?;
    let header = pcap_reader.header();

    let mut acc = Accumulator::new(header.snaplen, datalink_name(header.datalink));

    while let Some(pkt) = pcap_reader.next_packet() {
        let pkt = pkt.map_err(|e| PcapReportError::Pcap(e.to_string()))?;
        acc.observe(pkt.orig_len as u64, pkt.data.as_ref(), Some(pkt.timestamp));
    }

    // Classic pcap carries no per-interface drop-count block: it is
    // structurally unknowable from this file format, not zero.
    Ok(acc.finish(path, "pcap", None, None))
}

fn analyze_pcapng<R: Read>(path: &Path, reader: R) -> Result<PcapReport, PcapReportError> {
    let mut pcapng_reader =
        PcapNgReader::new(reader).map_err(|e| PcapReportError::Pcap(e.to_string()))?;

    let mut acc: Option<Accumulator> = None;
    let mut isb_drop: Option<u64> = None;
    let mut saw_isb = false;
    let mut if_name: Option<String> = None;

    while let Some(block) = pcapng_reader.next_block() {
        let block = block.map_err(|e| PcapReportError::Pcap(e.to_string()))?;

        if let Some(idb) = block.as_interface_description() {
            if acc.is_none() {
                let snaplen = if idb.snaplen == 0 {
                    u32::MAX
                } else {
                    idb.snaplen
                };
                acc = Some(Accumulator::new(snaplen, datalink_name(idb.linktype)));
            }
            for opt in &idb.options {
                if let pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionOption::IfName(name) = opt {
                    if_name = Some(name.to_string());
                }
            }
            continue;
        }

        if let Some(isb) = block.as_interface_statistics() {
            saw_isb = true;
            for opt in &isb.options {
                if let pcap_file::pcapng::blocks::interface_statistics::InterfaceStatisticsOption::IsbIfDrop(n) = opt {
                    isb_drop = Some(isb_drop.unwrap_or(0) + n);
                }
            }
            continue;
        }

        if let Some(epb) = block.as_enhanced_packet() {
            let acc = acc.get_or_insert_with(|| Accumulator::new(u32::MAX, "Unknown".to_string()));
            acc.observe(
                epb.original_len as u64,
                epb.data.as_ref(),
                Some(epb.timestamp),
            );
            continue;
        }

        if let Some(spb) = block.as_simple_packet() {
            let acc = acc.get_or_insert_with(|| Accumulator::new(u32::MAX, "Unknown".to_string()));
            let len = spb.original_len as u64;
            acc.observe(len, spb.data.as_ref(), None);
            continue;
        }
    }

    let acc = acc.unwrap_or_else(|| Accumulator::new(u32::MAX, "Unknown".to_string()));
    // A pcapng file *can* carry isb_ifdrop; if we never saw an ISB block at
    // all, treat drops as unknown rather than assuming zero loss.
    let drops = if saw_isb {
        Some(isb_drop.unwrap_or(0))
    } else {
        None
    };
    Ok(acc.finish(path, "pcapng", if_name, drops))
}

fn datalink_name(dl: DataLink) -> String {
    format!("{:?}", dl)
}

struct Accumulator {
    snaplen: u32,
    link_type: String,
    packet_count: u64,
    byte_count: u64,
    truncated: bool,
    max_frame_len: u64,
    oversize_count: u64,
    first_ts_seen: bool,
    tcp_checksum_zero: u64,
    tcp_checksum_checked: u64,
    src_ips: std::collections::HashSet<[u8; 16]>,
    dst_ips: std::collections::HashSet<[u8; 16]>,
    flows: std::collections::HashMap<(u128, u16, u128, u16), FlowState>,
    retransmissions: u64,
    out_of_order: u64,
    duplicate_acks: u64,
    tcp_sampled: u64,
    tcp_packets: u64,
    tcp_bytes: u64,
    udp_packets: u64,
    udp_bytes: u64,
    quic_candidate_packets: u64,
    quic_candidate_bytes: u64,
    icmp_packets: u64,
    other_packets: u64,
    udp_flows: std::collections::HashSet<(u128, u16, u128, u16)>,
    min_ts: Option<StdDuration>,
    max_ts: Option<StdDuration>,
}

impl Accumulator {
    fn new(snaplen: u32, link_type: String) -> Self {
        Accumulator {
            snaplen,
            link_type,
            packet_count: 0,
            byte_count: 0,
            truncated: false,
            max_frame_len: 0,
            oversize_count: 0,
            first_ts_seen: false,
            tcp_checksum_zero: 0,
            tcp_checksum_checked: 0,
            src_ips: std::collections::HashSet::new(),
            dst_ips: std::collections::HashSet::new(),
            flows: std::collections::HashMap::new(),
            retransmissions: 0,
            out_of_order: 0,
            duplicate_acks: 0,
            tcp_sampled: 0,
            tcp_packets: 0,
            tcp_bytes: 0,
            udp_packets: 0,
            udp_bytes: 0,
            quic_candidate_packets: 0,
            quic_candidate_bytes: 0,
            icmp_packets: 0,
            other_packets: 0,
            udp_flows: std::collections::HashSet::new(),
            min_ts: None,
            max_ts: None,
        }
    }

    fn observe(&mut self, orig_len: u64, captured: &[u8], ts: Option<StdDuration>) {
        self.packet_count += 1;
        self.byte_count += orig_len;
        self.first_ts_seen = true;

        if let Some(t) = ts {
            self.min_ts = Some(self.min_ts.map_or(t, |m| m.min(t)));
            self.max_ts = Some(self.max_ts.map_or(t, |m| m.max(t)));
        }

        if (captured.len() as u64) < orig_len {
            self.truncated = true;
        }

        if captured.len() as u64 > self.max_frame_len {
            self.max_frame_len = captured.len() as u64;
        }
        if orig_len > self.max_frame_len {
            self.max_frame_len = orig_len;
        }

        let threshold = oversize_threshold(DEFAULT_LINK_MTU) as u64;
        if orig_len > threshold {
            self.oversize_count += 1;
        }

        self.classify_protocol(captured, orig_len);

        if self.tcp_sampled >= MAX_TCP_SAMPLE_PACKETS {
            return;
        }

        let frame_complete = captured.len() as u64 == orig_len;
        self.inspect_packet(captured, frame_complete);
    }

    /// Lightweight per-packet protocol tally for the GAP-008 comparison
    /// report. Separate from `inspect_packet`'s deeper TCP flow-state work
    /// so a UDP/QUIC-heavy capture pays only for what it needs.
    fn classify_protocol(&mut self, captured: &[u8], orig_len: u64) {
        use etherparse::{LaxNetSlice, LaxSlicedPacket, TransportSlice};

        let parsed = match LaxSlicedPacket::from_ethernet(captured) {
            Ok(p) => p,
            Err(_) => {
                self.other_packets += 1;
                return;
            }
        };

        let net = match &parsed.net {
            Some(n) => n,
            None => {
                self.other_packets += 1;
                return;
            }
        };

        let (src16, dst16): ([u8; 16], [u8; 16]) = match net {
            LaxNetSlice::Ipv4(v4) => {
                let mut s = [0u8; 16];
                let mut d = [0u8; 16];
                s[..4].copy_from_slice(&v4.header().source());
                d[..4].copy_from_slice(&v4.header().destination());
                (s, d)
            }
            LaxNetSlice::Ipv6(v6) => {
                let mut s = [0u8; 16];
                let mut d = [0u8; 16];
                s.copy_from_slice(&v6.header().source());
                d.copy_from_slice(&v6.header().destination());
                (s, d)
            }
        };

        match &parsed.transport {
            Some(TransportSlice::Tcp(tcp)) => {
                self.tcp_packets += 1;
                self.tcp_bytes += orig_len;
                let _ = (tcp.source_port(), tcp.destination_port());
            }
            Some(TransportSlice::Udp(udp)) => {
                self.udp_packets += 1;
                self.udp_bytes += orig_len;
                let sp = udp.source_port();
                let dp = udp.destination_port();
                self.udp_flows
                    .insert(FlowKey::normalized(src16, sp, dst16, dp).id());
                // QUIC has no fixed port, but the near-universal convention
                // is UDP/443; a long-header Initial packet's first byte also
                // has its top bit set (0x80) with version bits following.
                // This is a heuristic label, not a certain classification.
                let payload = udp.payload();
                let looks_like_quic_first_byte =
                    payload.first().map(|b| b & 0x80 != 0).unwrap_or(false);
                if sp == 443 || dp == 443 || looks_like_quic_first_byte {
                    self.quic_candidate_packets += 1;
                    self.quic_candidate_bytes += orig_len;
                }
            }
            Some(TransportSlice::Icmpv4(_)) | Some(TransportSlice::Icmpv6(_)) => {
                self.icmp_packets += 1;
            }
            None => {
                self.other_packets += 1;
            }
        }
    }

    fn inspect_packet(&mut self, captured: &[u8], frame_complete: bool) {
        use etherparse::{LaxSlicedPacket, LinkSlice, TransportSlice};

        let parsed = match LaxSlicedPacket::from_ethernet(captured) {
            Ok(p) => p,
            Err(_) => return,
        };

        if let Some(LinkSlice::Ethernet2(_)) = &parsed.link {
            // link parsed fine
        }

        let net = match &parsed.net {
            Some(n) => n,
            None => return,
        };

        let (src16, dst16, v4_addrs): ([u8; 16], [u8; 16], Option<([u8; 4], [u8; 4])>) = match net {
            etherparse::LaxNetSlice::Ipv4(v4) => {
                let mut s = [0u8; 16];
                let mut d = [0u8; 16];
                let src4 = v4.header().source();
                let dst4 = v4.header().destination();
                s[..4].copy_from_slice(&src4);
                d[..4].copy_from_slice(&dst4);
                (s, d, Some((src4, dst4)))
            }
            etherparse::LaxNetSlice::Ipv6(v6) => {
                let mut s = [0u8; 16];
                let mut d = [0u8; 16];
                s.copy_from_slice(&v6.header().source());
                d.copy_from_slice(&v6.header().destination());
                (s, d, None)
            }
        };
        self.src_ips.insert(src16);
        self.dst_ips.insert(dst16);

        let transport = match &parsed.transport {
            Some(t) => t,
            None => return,
        };

        if let TransportSlice::Tcp(tcp) = transport {
            self.tcp_sampled += 1;
            self.tcp_checksum_checked += 1;
            // A zero checksum, or a checksum that fails to verify against
            // the actual segment, both indicate the NIC/driver never wrote
            // (or wrote before recompute) a real on-wire checksum — the
            // classic checksum-offload signature on a host-side capture.
            // Checksum verification requires the full segment; on a
            // snaplen-truncated frame a mismatch would just reflect the
            // missing bytes, not an offload artifact, so skip it there.
            let checksum_bad = tcp.checksum() == 0
                || (frame_complete
                    && v4_addrs
                        .map(|(s, d)| {
                            tcp.calc_checksum_ipv4(s, d)
                                .map(|c| c != tcp.checksum())
                                .unwrap_or(false)
                        })
                        .unwrap_or(false));
            if checksum_bad {
                self.tcp_checksum_zero += 1;
            }

            let seq = tcp.sequence_number() as u64;
            let ack = tcp.acknowledgment_number();
            let payload_len = tcp.payload().len() as u64;
            let seq_end = seq + payload_len.max(1);

            let src_port = tcp.source_port();
            let dst_port = tcp.destination_port();
            let key = FlowKey::normalized(src16, src_port, dst16, dst_port);
            let a_side = (src16, src_port) <= (dst16, dst_port);

            if self.flows.len() < MAX_TRACKED_FLOWS || self.flows.contains_key(&key.id()) {
                let state = self.flows.entry(key.id()).or_default();

                if a_side {
                    state.seen_from_a = true;
                } else {
                    state.seen_from_b = true;
                }

                let (max_seq_end, last_ack, dup_run) = if a_side {
                    (
                        &mut state.a_max_seq_end,
                        &mut state.a_last_ack,
                        &mut state.a_dup_ack_run,
                    )
                } else {
                    (
                        &mut state.b_max_seq_end,
                        &mut state.b_last_ack,
                        &mut state.b_dup_ack_run,
                    )
                };

                if payload_len > 0 {
                    match *max_seq_end {
                        Some(prev_max) if seq_end <= prev_max => {
                            self.retransmissions += 1;
                        }
                        Some(prev_max) if seq < prev_max.saturating_sub(payload_len) => {
                            self.out_of_order += 1;
                        }
                        _ => {}
                    }
                    *max_seq_end = Some((*max_seq_end).unwrap_or(0).max(seq_end));
                }

                if tcp.ack() && payload_len == 0 {
                    if *last_ack == Some(ack) {
                        *dup_run += 1;
                        if *dup_run >= 2 {
                            self.duplicate_acks += 1;
                        }
                    } else {
                        *dup_run = 0;
                    }
                    *last_ack = Some(ack);
                }
            }
        }
    }

    fn finish(
        self,
        path: &Path,
        format: &str,
        if_name: Option<String>,
        drops_known: Option<u64>,
    ) -> PcapReport {
        let threshold = oversize_threshold(DEFAULT_LINK_MTU);
        let effective_snaplen = self.snaplen;

        let mut total_flows: u64 = 0;
        let mut bidir_flows: u64 = 0;
        for state in self.flows.values() {
            total_flows += 1;
            if state.seen_from_a && state.seen_from_b {
                bidir_flows += 1;
            }
        }

        let mut evidence = Vec::new();
        let mut score_host = 0i32;
        let mut score_wire = 0i32;

        if self.oversize_count > 0 {
            evidence.push(format!(
                "{} frames exceed link MTU+L2 ({} bytes) — strong TSO/GSO/GRO signal",
                self.oversize_count, threshold
            ));
            score_host += 3;
        } else {
            evidence.push(format!(
                "no frames exceed link MTU+L2 ({} bytes)",
                threshold
            ));
        }

        if self.tcp_checksum_checked > 0 {
            let zero_frac = self.tcp_checksum_zero as f64 / self.tcp_checksum_checked as f64;
            if zero_frac > 0.05 {
                evidence.push(format!(
                    "{}/{} sampled TCP segments carry zero/placeholder checksums — checksum-offload artifact typical of host-side capture of transmitted packets",
                    self.tcp_checksum_zero, self.tcp_checksum_checked
                ));
                score_host += 2;
            } else {
                evidence.push(format!(
                    "{}/{} sampled TCP segments show non-zero checksums",
                    self.tcp_checksum_zero, self.tcp_checksum_checked
                ));
            }
        }

        if total_flows > 0 {
            let bidir_frac = bidir_flows as f64 / total_flows as f64;
            if bidir_frac > 0.4 {
                evidence.push(format!(
                    "{}/{} TCP flows show both directions in the file — consistent with a host endpoint's own send+receive path",
                    bidir_flows, total_flows
                ));
                score_host += 1;
            } else {
                evidence.push(format!(
                    "{}/{} TCP flows show only one direction — consistent with an on-path mirror/tap seeing partial traffic",
                    bidir_flows, total_flows
                ));
                score_wire += 1;
            }
        }

        if let Some(name) = &if_name {
            let lname = name.to_lowercase();
            if lname.starts_with("en")
                || lname.starts_with("eth")
                || lname.contains("wl")
                || lname.starts_with("utun")
            {
                evidence.push(format!(
                    "interface name '{}' matches a host NIC naming convention",
                    name
                ));
                score_host += 1;
            }
        } else {
            evidence.push("interface name not recorded in file".to_string());
        }

        let (vantage, confidence) = if score_host >= 3 {
            (
                Vantage::HostOffloadSuspect,
                if score_host >= 5 {
                    Confidence::High
                } else {
                    Confidence::Medium
                },
            )
        } else if score_wire > score_host {
            (Vantage::OnWireMirrorOrTap, Confidence::Low)
        } else if score_host > 0 {
            (Vantage::HostOffloadSuspect, Confidence::Low)
        } else {
            (Vantage::Unknown, Confidence::Low)
        };

        let host_side = matches!(vantage, Vantage::HostOffloadSuspect);

        let mut notes = Vec::new();
        if self.truncated {
            notes.push(format!(
                "snaplen truncation detected: at least one packet's captured length is shorter than its original length (file/interface snaplen {}). Payload-dependent verdicts are suppressed.",
                effective_snaplen
            ));
        }
        if drops_known.is_none() {
            notes.push("capture drop count is unknown: this file format/section carries no drop-count record (classic pcap never does; this pcapng section had no Interface Statistics Block). This is reported as unknown, not zero.".to_string());
        } else if let Some(d) = drops_known {
            if d > 0 {
                notes.push(format!("capture reports {} interface drops (isb_ifdrop) — captured packets may undercount what actually arrived.", d));
            }
        }
        if host_side {
            notes.push("vantage classified as host-side/offload-suspect: retransmission/out-of-order/duplicate-ACK counts below are NOT usable as on-wire network-fault evidence. TSO/GSO/GRO on a host capture reconstruct segments that were never sent/received as observed; capture drops can also manufacture phantom retransmissions.".to_string());
        }
        if self.oversize_count > 0 && host_side {
            notes.push(format!(
                "{} frames over link MTU+L2 are pre-segmentation host segments (TSO/GRO), not on-wire oversize frames — no MTU conclusion can be drawn from them.",
                self.oversize_count
            ));
        }

        let duration_secs = match (self.min_ts, self.max_ts) {
            (Some(min), Some(max)) if max >= min => Some((max - min).as_secs_f64()),
            _ => None,
        };

        PcapReport {
            path: path.display().to_string(),
            health: CaptureHealth {
                file_format: format.to_string(),
                link_type: self.link_type,
                interface_name: if_name,
                snaplen: effective_snaplen,
                truncated: self.truncated,
                packet_count: self.packet_count,
                byte_count: self.byte_count,
                duration_secs,
                drops_known,
            },
            vantage: VantageClassification {
                vantage,
                confidence,
                evidence,
            },
            frame_size: FrameSizeAnalysis {
                link_mtu_assumed: DEFAULT_LINK_MTU,
                oversize_threshold: threshold,
                observed_over_threshold: self.oversize_count,
                max_observed_frame_len: self.max_frame_len,
                oversize_is_host_segment_artifact: self.oversize_count > 0 && host_side,
            },
            checksum_offload: ChecksumOffloadSignal {
                tcp_checksum_zero_or_invalid: self.tcp_checksum_zero,
                tcp_checksum_checked: self.tcp_checksum_checked,
            },
            tcp_anomalies: TcpAnomalyCounts {
                sampled_packets: self.tcp_sampled,
                retransmissions: self.retransmissions,
                out_of_order: self.out_of_order,
                duplicate_acks: self.duplicate_acks,
                qualification_required: host_side,
            },
            directions_seen: DirectionsSeen {
                src_ips_seen: self.src_ips.len() as u64,
                dst_ips_seen: self.dst_ips.len() as u64,
                bidirectional_tcp_flows: bidir_flows,
                total_tcp_flows: total_flows,
            },
            protocol_breakdown: ProtocolBreakdown {
                tcp_packets: self.tcp_packets,
                tcp_bytes: self.tcp_bytes,
                udp_packets: self.udp_packets,
                udp_bytes: self.udp_bytes,
                udp_flows: self.udp_flows.len() as u64,
                quic_candidate_packets: self.quic_candidate_packets,
                quic_candidate_bytes: self.quic_candidate_bytes,
                icmp_packets: self.icmp_packets,
                other_packets: self.other_packets,
            },
            payload_analysis_suppressed: self.truncated,
            notes,
        }
    }
}

/// GAP-008: a side-by-side comparison across two or more already-analyzed
/// captures. Built from `PcapReport`s that were produced by streaming
/// analysis, so comparing captures never requires holding more than one
/// report's summary in memory at a time -- the source files themselves are
/// never re-read or loaded whole.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcapComparison {
    pub reports: Vec<PcapReport>,
    /// True if any compared report is host-side/offload-suspect. A
    /// comparison inherits every input capture's limitations, so this must
    /// be checked before any cross-capture claim is treated as network
    /// evidence.
    pub any_offload_suspect: bool,
    pub notes: Vec<String>,
}

pub fn compare_reports(reports: Vec<PcapReport>) -> PcapComparison {
    let any_offload_suspect = reports
        .iter()
        .any(|r| matches!(r.vantage.vantage, Vantage::HostOffloadSuspect));

    let mut notes = Vec::new();
    if any_offload_suspect {
        notes.push(
            "at least one compared capture is classified host-side/offload-suspect: \
             retransmission/out-of-order/duplicate-ACK counts and TCP byte totals for that \
             capture are NOT usable as on-wire network-fault evidence, and any comparison \
             built from them inherits that limitation"
                .to_string(),
        );
    }
    if reports.iter().any(|r| r.health.truncated) {
        notes.push(
            "at least one compared capture is snaplen-truncated: payload-dependent \
             comparisons for that capture are suppressed"
                .to_string(),
        );
    }
    if reports.iter().any(|r| r.health.drops_known.is_none()) {
        notes.push(
            "at least one compared capture has an unknown drop count: apparent differences \
             in packet/flow counts between captures may reflect capture loss, not real \
             traffic differences"
                .to_string(),
        );
    }

    PcapComparison {
        reports,
        any_offload_suspect,
        notes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversize_threshold_accounts_for_l2_header() {
        assert_eq!(oversize_threshold(1500), 1514);
        // a 1,510-byte frame (IP total_len 1,496) must be below threshold
        assert!(1510 <= oversize_threshold(1500));
    }

    #[test]
    fn unrecognized_format_errors_cleanly() {
        let dir = std::env::temp_dir();
        let path = dir.join("fp_pcap_report_test_not_a_pcap.bin");
        std::fs::write(&path, b"not a pcap file at all").unwrap();
        let res = analyze_pcap(&path);
        assert!(res.is_err());
        let _ = std::fs::remove_file(&path);
    }
}
