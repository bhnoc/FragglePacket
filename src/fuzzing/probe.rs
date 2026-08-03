//! Active Probe Engine
//!
//! Pairs a crafted packet send (via `replay`) with a passive capture (via
//! `capture`) so we can do scapy `sr1()`-style probes and measure real RTTs.
//!
//! Today this exposes two helpers:
//!   * `send_and_wait` sends one packet, waits up to `timeout`, and returns
//!     the first matching frame plus its RTT.
//!   * `active_pmtu_probe` binary-searches path MTU using DF IPv4 pings,
//!     watching for ICMP fragmentation-needed on the capture side.
//!
//! The engine uses our Rust DSL for crafting and our native replay/capture
//! for sending. No external ping/hping3/nping binaries required.

use crate::fuzzing::capture::{start_capture, CaptureError, FilterFn};
use crate::fuzzing::dsl::{Ether, Icmp, Ip, Packet, Raw};
use crate::fuzzing::replay::{replay_pcap, ReplayError, ReplayOptions};
use std::net::Ipv4Addr;
use std::path::Path;
use std::time::{Duration, Instant};
use std::fs::File;
use pcap_file::pcap::{PcapHeader, PcapPacket, PcapWriter};
use pcap_file::DataLink;

#[derive(Debug, Clone)]
pub struct ProbeResponse {
    pub bytes: Vec<u8>,
    pub rtt_ms: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum ProbeError {
    #[error("Capture error: {0}")]
    Capture(#[from] CaptureError),
    #[error("Replay error: {0}")]
    Replay(#[from] ReplayError),
    #[error("DSL build error: {0}")]
    Dsl(#[from] crate::fuzzing::dsl::DslError),
    #[error("IO: {0}")]
    Io(#[from] std::io::Error),
    #[error("PCAP: {0}")]
    Pcap(String),
}

/// Send one DSL packet and wait for the first matching reply.
pub fn send_and_wait(
    iface: &str,
    pkt: &Packet,
    filter: FilterFn,
    timeout: Duration,
) -> Result<Option<ProbeResponse>, ProbeError> {
    let bytes = pkt.build()?;
    let tmp = write_tmp_pcap(&[bytes])?;
    let capture = start_capture(iface, filter)?;
    let opts = ReplayOptions::new().iface(iface);
    let start = Instant::now();
    let _ = replay_pcap(&tmp, &opts)?;
    let reply = capture.recv_timeout(timeout);
    let _ = std::fs::remove_file(&tmp);
    Ok(reply.map(|f| ProbeResponse {
        bytes: f.data,
        rtt_ms: start.elapsed().as_millis() as u64,
    }))
}

#[derive(Debug, Clone)]
pub struct PmtuProbeResult {
    pub estimated_mtu: Option<u16>,
    pub frag_needed_reported: bool,
    pub samples_tried: Vec<u16>,
}

/// Binary-search the path MTU via DF echo-requests at the DSL level. Any
/// ICMP "fragmentation needed" (type 3, code 4) observed on the capture side
/// is recorded and used to narrow the search.
pub fn active_pmtu_probe(
    iface: &str,
    target: Ipv4Addr,
    min_mtu: u16,
    max_mtu: u16,
    per_probe_timeout: Duration,
) -> Result<PmtuProbeResult, ProbeError> {
    let mut result = PmtuProbeResult {
        estimated_mtu: None,
        frag_needed_reported: false,
        samples_tried: Vec::new(),
    };
    let mut lo = min_mtu;
    let mut hi = max_mtu;
    while lo <= hi {
        let mid = lo + (hi - lo) / 2;
        result.samples_tried.push(mid);
        let payload_size = (mid as usize).saturating_sub(28);
        let pkt = Ether::new()
            / Ip::new().dst_addr(target).df()
            / Icmp::echo_request()
            / Raw::of_size(payload_size, b'Q');
        let target_ip = target;
        let filter: FilterFn = Box::new(move |buf| {
            if buf.len() < 14 + 20 + 8 {
                return false;
            }
            if u16::from_be_bytes([buf[12], buf[13]]) != 0x0800 {
                return false;
            }
            let ip = &buf[14..];
            let proto = ip[9];
            if proto != 1 {
                return false;
            }
            let ihl = (ip[0] & 0x0F) as usize * 4;
            if ip.len() < ihl + 8 {
                return false;
            }
            let icmp = &ip[ihl..];
            let t = icmp[0];
            let c = icmp[1];
            if t == 0 {
                let src = Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]);
                return src == target_ip;
            }
            t == 3 && c == 4
        });
        let reply = send_and_wait(iface, &pkt, filter, per_probe_timeout)?;
        match reply {
            Some(frame) => {
                let ip = &frame.bytes[14..];
                let ihl = (ip[0] & 0x0F) as usize * 4;
                let icmp = &ip[ihl..];
                let t = icmp[0];
                if t == 0 {
                    result.estimated_mtu = Some(mid);
                    lo = mid + 1;
                } else {
                    result.frag_needed_reported = true;
                    hi = mid - 1;
                }
            }
            None => {
                hi = mid - 1;
            }
        }
    }
    Ok(result)
}

fn write_tmp_pcap(frames: &[Vec<u8>]) -> Result<std::path::PathBuf, ProbeError> {
    let path = std::env::temp_dir().join(format!(
        "fraggle_probe_{}.pcap",
        std::process::id()
    ));
    let file = File::create(&path)?;
    let header = PcapHeader {
        datalink: DataLink::ETHERNET,
        snaplen: 65535,
        ..Default::default()
    };
    let mut writer =
        PcapWriter::with_header(file, header).map_err(|e| ProbeError::Pcap(e.to_string()))?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    for f in frames {
        let pkt = PcapPacket::new(now, f.len() as u32, f);
        writer
            .write_packet(&pkt)
            .map_err(|e| ProbeError::Pcap(e.to_string()))?;
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pmtu_result_struct_default() {
        let r = PmtuProbeResult {
            estimated_mtu: None,
            frag_needed_reported: false,
            samples_tried: vec![1500, 1200],
        };
        assert_eq!(r.samples_tried.len(), 2);
    }

    #[test]
    #[ignore]
    fn write_tmp_roundtrip() {
        let p = write_tmp_pcap(&[vec![0u8; 64]]).unwrap();
        assert!(p.exists());
        std::fs::remove_file(p).ok();
    }

    fn _path_constructible(_p: &Path) {}
}
