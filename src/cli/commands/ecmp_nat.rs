//! GAP-028: multi-uplink ECMP/LAG hash and NAT-affinity diagnostic (`ecmp-nat`).

use colored::*;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::Duration;

use fraggle_packet::load_guard::route::is_tunnel_interface;
use fraggle_packet::network_tests::ecmp_nat::{
    classify_bimodality, run_tcp_bucket, run_udp_bucket, run_udp_bucket_with_stun_bracket, BimodalityVerdict,
    BucketOutcome, BucketResult, TUNNEL_INTERFACE_WARNING,
};

#[derive(clap::Args, Debug)]
pub struct EcmpNatArgs {
    /// Interface under test, only used for the tunnel-interface warning
    /// (this command binds by local port, not by interface, since a
    /// fixed-5-tuple sweep needs port control more than interface binding).
    #[arg(long)]
    pub interface: Option<String>,

    #[arg(long)]
    pub target: Option<String>,

    #[arg(long, value_enum, default_value = "udp")]
    pub transport: Transport,

    /// Fixed local source ports to sweep, one bucket per port. Each bucket
    /// keeps this port for its entire (short) flow -- this is the "preserve
    /// each 5-tuple" mechanic.
    #[arg(long, value_delimiter = ',', default_values_t = vec![40001u16, 40002, 40003, 40004, 40005])]
    pub ports: Vec<u16>,

    /// Bytes sent per bucket. Kept tiny per GAP-047 -- this proves the
    /// mechanism, never the field incident's 350 Mbps matrix.
    #[arg(long, default_value_t = 512)]
    pub payload_bytes: usize,

    #[arg(long, default_value_t = 1500)]
    pub timeout_ms: u64,

    /// STUN server used to bracket each bucket's mapping before/after, to
    /// detect mid-flow rebinding. Omit to skip the STUN bracket (UDP only).
    #[arg(long)]
    pub stun_server: Option<String>,

    #[arg(long)]
    pub inject_fixture: Option<String>,

    #[arg(long)]
    pub json: bool,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    Udp,
    Tcp,
}

fn resolve(host_port: &str) -> Result<SocketAddr, String> {
    host_port
        .to_socket_addrs()
        .map_err(|e| format!("failed to resolve {host_port}: {e}"))?
        .next()
        .ok_or_else(|| format!("{host_port} resolved to no addresses"))
}

fn synthetic_buckets(seed: &str, ports: &[u16]) -> Vec<BucketResult> {
    let all_ok = |ports: &[u16]| {
        ports
            .iter()
            .map(|p| BucketResult {
                local_port: *p,
                outcome: BucketOutcome::Succeeded,
                bytes_sent: 512,
                bytes_acked_or_echoed: 0,
                rtt_ms: Some(8.0),
                mid_flow_rebind_detected: Some(false),
            })
            .collect::<Vec<_>>()
    };
    match seed {
        "all-fail" => ports
            .iter()
            .map(|p| BucketResult {
                local_port: *p,
                outcome: BucketOutcome::Failed,
                bytes_sent: 0,
                bytes_acked_or_echoed: 0,
                rtt_ms: None,
                mid_flow_rebind_detected: None,
            })
            .collect(),
        "one-bad-bucket" => {
            let mut buckets = all_ok(ports);
            if let Some(mid) = buckets.get_mut(ports.len() / 2) {
                mid.outcome = BucketOutcome::Failed;
                mid.bytes_acked_or_echoed = 0;
                mid.rtt_ms = None;
                mid.mid_flow_rebind_detected = None;
            }
            buckets
        }
        "mid-flow-rebind" => {
            let mut buckets = all_ok(ports);
            if let Some(first) = buckets.first_mut() {
                first.mid_flow_rebind_detected = Some(true);
            }
            buckets
        }
        _ => all_ok(ports),
    }
}

pub fn run(args: &EcmpNatArgs) {
    let interface_is_tunnel = args.interface.as_deref().map(is_tunnel_interface).unwrap_or(false);
    if interface_is_tunnel {
        eprintln!("{} {}", "⚠".yellow().bold(), TUNNEL_INTERFACE_WARNING);
    }

    let buckets: Vec<BucketResult> = if let Some(seed) = &args.inject_fixture {
        synthetic_buckets(seed, &args.ports)
    } else {
        let target_str = match &args.target {
            Some(t) => t.clone(),
            None => {
                eprintln!("{} --target is required; there is no hardcoded default endpoint.", "✗".red());
                std::process::exit(1);
            }
        };
        let target = match resolve(&target_str) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("{} {}", "✗".red(), e);
                std::process::exit(1);
            }
        };
        let timeout = Duration::from_millis(args.timeout_ms);
        let stun_server = args.stun_server.as_ref().and_then(|s| resolve(s).ok());

        args.ports
            .iter()
            .map(|&port| match args.transport {
                Transport::Tcp => run_tcp_bucket(port, target, args.payload_bytes, timeout),
                Transport::Udp => match stun_server {
                    Some(stun) => run_udp_bucket_with_stun_bracket(port, target, stun, args.payload_bytes, timeout),
                    None => run_udp_bucket(port, target, args.payload_bytes, timeout),
                },
            })
            .collect()
    };

    let bimodality = classify_bimodality(&buckets);

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "interface": args.interface,
                "interface_is_tunnel": interface_is_tunnel,
                "buckets": buckets,
                "bimodality": bimodality,
            }))
            .unwrap()
        );
        return;
    }

    println!();
    println!("{}", "== ECMP/LAG Hash and NAT-Affinity Sweep ==".cyan().bold());
    if interface_is_tunnel {
        println!("  {} {}", "⚠".yellow(), TUNNEL_INTERFACE_WARNING);
    }
    for b in &buckets {
        let status = match b.outcome {
            BucketOutcome::Succeeded => "OK".green().to_string(),
            BucketOutcome::Failed => "FAILED".red().to_string(),
        };
        let rebind = match b.mid_flow_rebind_detected {
            Some(true) => " mid_flow_rebind=YES".red().to_string(),
            Some(false) => " mid_flow_rebind=no".to_string(),
            None => " mid_flow_rebind=unavailable".dimmed().to_string(),
        };
        println!("  port={:<6} {}{}", b.local_port, status, rebind);
    }
    println!();
    match bimodality {
        BimodalityVerdict::BimodalSplitDetected => println!(
            "  {} at least one bucket failed while others succeeded -- consistent with one bad hash bucket/ECMP member/NAT owner",
            "BIMODAL SPLIT DETECTED".red().bold()
        ),
        BimodalityVerdict::NoSplitDetected => println!(
            "  {} every bucket produced the same outcome -- this argues AGAINST one bad ECMP member and toward a shared-path cause (queue, policer, WLAN)",
            "NO SPLIT DETECTED".green().bold()
        ),
        BimodalityVerdict::InsufficientBuckets => println!(
            "  {} fewer than two buckets ran; no split judgement can be made",
            "INSUFFICIENT BUCKETS".yellow().bold()
        ),
    }
    println!();
}
