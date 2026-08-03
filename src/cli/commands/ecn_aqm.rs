//! GAP-023: ECN/AQM protocol A/B control (`ecn-aqm`).
//!
//! `--pcap-in` counts ECT(0)/ECT(1)/CE from a capture's own bytes -- a
//! standalone Ethernet/IPv4 parser owned by this file, not
//! `network_tests::pcap_report` (another agent's, off limits). This
//! command only reads the IP header's low two TOS bits; it does not reuse
//! or duplicate that module's vantage/offload classification, which is a
//! different concern entirely.

use colored::*;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::path::Path;

use fraggle_packet::load_guard::route::is_tunnel_interface;
use fraggle_packet::network_tests::ecn_aqm::{
    evaluate_capability_without_marking, tunnel_warning, EcnCodepoint, EcnCounts,
};

#[derive(clap::Args, Debug)]
pub struct EcnAqmArgs {
    /// PCAP/pcapng file to count ECN codepoints from.
    #[arg(long)]
    pub pcap_in: Option<String>,

    /// Interface this measurement is bound to, purely for the tunnel
    /// warning -- ECN bits are commonly stripped/rewritten by tunnels.
    #[arg(long)]
    pub interface: Option<String>,

    /// Attempt to set an ECN codepoint (ect0/ect1) on an outgoing UDP
    /// socket and report whether the platform permitted it.
    #[arg(long)]
    pub set_ecn: Option<String>,

    #[arg(long)]
    pub target: Option<IpAddr>,

    #[arg(long, default_value_t = 9)]
    pub port: u16,

    #[arg(long)]
    pub json: bool,
}

fn parse_pcapng_ecn(bytes: &[u8]) -> Result<EcnCounts, String> {
    use pcap_file::pcapng::PcapNgReader;
    let mut reader = PcapNgReader::new(bytes).map_err(|e| e.to_string())?;
    let mut counts = EcnCounts::default();
    while let Some(block) = reader.next_block() {
        let block = block.map_err(|e| e.to_string())?;
        if let Some(pkt) = block.as_enhanced_packet() {
            if let Some(cp) = ecn_from_ethernet_frame(&pkt.data) {
                counts.record(cp);
            }
        }
    }
    Ok(counts)
}

fn parse_pcap_classic_ecn(bytes: &[u8]) -> Result<EcnCounts, String> {
    use pcap_file::pcap::PcapReader;
    let mut reader = PcapReader::new(bytes).map_err(|e| e.to_string())?;
    let mut counts = EcnCounts::default();
    while let Some(pkt) = reader.next_packet() {
        let pkt = pkt.map_err(|e| e.to_string())?;
        if let Some(cp) = ecn_from_ethernet_frame(&pkt.data) {
            counts.record(cp);
        }
    }
    Ok(counts)
}

/// Reads the IP TOS/traffic-class byte's ECN bits from a raw Ethernet
/// frame. Returns `None` for anything that isn't an IPv4 (0x0800) or IPv6
/// (0x86DD) frame long enough to contain the byte -- never a fabricated
/// NotEct for a frame this parser couldn't actually classify.
fn ecn_from_ethernet_frame(frame: &[u8]) -> Option<EcnCodepoint> {
    const ETH_HEADER_LEN: usize = 14;
    if frame.len() < ETH_HEADER_LEN + 2 {
        return None;
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    match ethertype {
        0x0800 => {
            // IPv4: TOS is byte 1 of the IP header.
            let ip_start = ETH_HEADER_LEN;
            if frame.len() < ip_start + 2 {
                return None;
            }
            Some(EcnCodepoint::from_tos_byte(frame[ip_start + 1]))
        }
        0x86DD => {
            // IPv6: traffic class spans the low nibble of byte 0 and high
            // nibble of byte 1 of the fixed header.
            let ip_start = ETH_HEADER_LEN;
            if frame.len() < ip_start + 2 {
                return None;
            }
            let tc = ((frame[ip_start] & 0x0F) << 4) | (frame[ip_start + 1] >> 4);
            Some(EcnCodepoint::from_tos_byte(tc))
        }
        _ => None,
    }
}

fn attempt_set_ecn(codepoint: &str, target: IpAddr, port: u16) -> Result<(), String> {
    let cp: u8 = match codepoint {
        "ect0" => libc::IPTOS_ECN_ECT0,
        "ect1" => libc::IPTOS_ECN_ECT1,
        other => {
            return Err(format!(
                "unknown codepoint '{}' (expected ect0 or ect1)",
                other
            ))
        }
    };
    let socket = UdpSocket::bind(if target.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .map_err(|e| e.to_string())?;
    use std::os::fd::AsRawFd;
    let fd = socket.as_raw_fd();
    let tos: libc::c_int = cp as i32;
    let (level, name) = if target.is_ipv4() {
        (libc::IPPROTO_IP, libc::IP_TOS)
    } else {
        (libc::IPPROTO_IPV6, libc::IPV6_TCLASS)
    };
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            &tos as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(format!(
            "setsockopt failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    // Confirm the platform actually applied it, not just accepted the call.
    let mut got: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let rc2 = unsafe {
        libc::getsockopt(
            fd,
            level,
            name,
            &mut got as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc2 != 0 {
        return Err(format!(
            "getsockopt (confirmation) failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    if (got as u8 & 0x03) != cp {
        return Err(format!(
            "platform accepted setsockopt but readback shows codepoint {} (requested {})",
            got & 0x03,
            cp
        ));
    }
    let dest = SocketAddr::new(target, port);
    socket
        .send_to(b"ecn-probe", dest)
        .map_err(|e| e.to_string())?;
    Ok(())
}

pub fn run(args: &EcnAqmArgs) {
    let mut out = serde_json::Map::new();

    if let Some(iface) = &args.interface {
        if let Some(w) = tunnel_warning(is_tunnel_interface(iface), iface) {
            if !args.json {
                println!("{} {}", "⚠".yellow(), w);
            }
            out.insert("tunnel_warning".to_string(), serde_json::Value::String(w));
        }
    }

    if let Some(path) = &args.pcap_in {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("{} failed to read {}: {}", "✗".red(), path, e);
                std::process::exit(1);
            }
        };
        let is_pcapng = bytes.len() >= 4 && bytes[0..4] == [0x0a, 0x0d, 0x0d, 0x0a];
        let counts = if is_pcapng {
            parse_pcapng_ecn(&bytes)
        } else {
            parse_pcap_classic_ecn(&bytes)
        };
        match counts {
            Ok(counts) => {
                let finding = evaluate_capability_without_marking(&counts);
                if args.json {
                    out.insert("counts".to_string(), serde_json::to_value(&counts).unwrap());
                    out.insert(
                        "scheme".to_string(),
                        serde_json::to_value(counts.scheme()).unwrap(),
                    );
                    out.insert(
                        "finding".to_string(),
                        serde_json::to_value(&finding).unwrap(),
                    );
                } else {
                    println!(
                        "{}",
                        format!("== ECN counts: {} ==", Path::new(path).display())
                            .cyan()
                            .bold()
                    );
                    println!(
                        "  not_ect={} ect0={} ect1={} ce={} total={}",
                        counts.not_ect,
                        counts.ect0,
                        counts.ect1,
                        counts.ce,
                        counts.total()
                    );
                    println!("  scheme: {:?}", counts.scheme());
                    println!("  finding: {}", finding.statement);
                }
            }
            Err(e) => {
                eprintln!("{} failed to parse {}: {}", "✗".red(), path, e);
                std::process::exit(1);
            }
        }
    }

    if let (Some(cp), Some(target)) = (&args.set_ecn, args.target) {
        match attempt_set_ecn(cp, target, args.port) {
            Ok(()) => {
                if args.json {
                    out.insert("ecn_set_attempt".to_string(), serde_json::json!({"requested": cp, "applied": true, "detail": "setsockopt applied and confirmed via getsockopt"}));
                } else {
                    println!(
                        "{} ECN codepoint '{}' applied and confirmed",
                        "✓".green(),
                        cp
                    );
                }
            }
            Err(e) => {
                if args.json {
                    out.insert(
                        "ecn_set_attempt".to_string(),
                        serde_json::json!({"requested": cp, "applied": false, "detail": e}),
                    );
                } else {
                    println!("{} ECN codepoint '{}' NOT applied: {}", "✗".red(), cp, e);
                }
            }
        }
    }

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::Value::Object(out)).unwrap()
        );
    }
}
