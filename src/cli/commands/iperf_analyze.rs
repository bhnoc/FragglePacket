//! GAP-039 (version/direction-aware iperf3 JSON parsing) and GAP-036
//! (explicit-allowlist endpoint capability discovery).

use colored::*;
use std::fs;

use fraggle_packet::network_tests::iperf::{
    detect_local_version, discover_listeners, parse_iperf_json, run_iperf_client, select_independent_listener,
    EndpointAllowlist, IperfParseError, TestDirection,
};

#[derive(clap::Args, Debug)]
pub struct IperfAnalyzeArgs {
    /// Parse a previously captured iperf3 -J JSON file instead of running a
    /// live test.
    #[arg(long)]
    pub parse_file: Option<String>,

    /// Run a live bounded iperf3 client test against this host (GAP-039).
    #[arg(long)]
    pub target: Option<String>,

    /// Port for --target. Ignored unless --target is set.
    #[arg(long, default_value_t = 5201)]
    pub port: u16,

    /// Duration cap in seconds. Kept small: this tool must not generate
    /// heavy load against shared infrastructure.
    #[arg(long, default_value_t = 1)]
    pub duration_secs: u32,

    #[arg(long)]
    pub reverse: bool,

    #[arg(long)]
    pub bidir: bool,

    #[arg(long)]
    pub udp: bool,

    /// Target bitrate for -b, e.g. "2M". Strongly recommended for UDP to
    /// avoid an unbounded send rate.
    #[arg(long)]
    pub bitrate: Option<String>,

    /// Bind the client to this interface (iperf3 --bind-dev), so the test
    /// measures the named interface rather than the default route, which
    /// on this class of machine is frequently a VPN tunnel.
    #[arg(long)]
    pub bind_interface: Option<String>,

    /// GAP-036: discover capability on an explicit, operator-named
    /// allowlist of ports against --target. Never sweeps a range; every
    /// port probed must be named here.
    #[arg(long = "allow-port")]
    pub allow_ports: Vec<u16>,

    #[arg(long)]
    pub json: bool,
}

pub fn run(args: &IperfAnalyzeArgs) {
    if !args.allow_ports.is_empty() {
        run_discovery(args);
        return;
    }

    let result = if let Some(path) = &args.parse_file {
        match fs::read_to_string(path) {
            Ok(text) => parse_iperf_json(&text),
            Err(e) => {
                eprintln!("{} could not read {}: {}", "✗".red(), path, e);
                std::process::exit(1);
            }
        }
    } else if let Some(target) = &args.target {
        run_iperf_client(
            target,
            args.port,
            args.duration_secs,
            args.reverse,
            args.bidir,
            args.udp,
            args.bitrate.as_deref(),
            args.bind_interface.as_deref(),
        )
    } else {
        eprintln!(
            "{} nothing to do: pass --parse-file <json>, --target <host> (GAP-039), or --allow-port (GAP-036)",
            "✗".red()
        );
        std::process::exit(2);
    };

    match result {
        Ok(r) => {
            if args.json {
                println!("{}", serde_json::to_string_pretty(&r).unwrap());
            } else {
                print_result(&r);
            }
        }
        Err(IperfParseError::ServerError(detail)) => {
            eprintln!("{} iperf3 reported an error before any measurement: {}", "✗".red().bold(), detail);
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("{} iperf parse error: {}", "✗".red(), e);
            std::process::exit(1);
        }
    }
}

fn run_discovery(args: &IperfAnalyzeArgs) {
    let target = match &args.target {
        Some(t) => t,
        None => {
            eprintln!("{} --allow-port requires --target", "✗".red());
            std::process::exit(2);
        }
    };

    let allowlist = EndpointAllowlist::new(target.clone(), args.allow_ports.clone());
    let local_version = detect_local_version();
    let capabilities = discover_listeners(&allowlist, 2000);
    let selected = select_independent_listener(&capabilities).map(|c| c.port);

    if args.json {
        let payload = serde_json::json!({
            "target": target,
            "allowlisted_ports": allowlist.ports,
            "local_version": local_version,
            "capabilities": capabilities,
            "selected_port": selected,
        });
        println!("{}", serde_json::to_string_pretty(&payload).unwrap());
        return;
    }

    println!("{}", format!("== Endpoint capability discovery: {} ==", target).cyan().bold());
    println!(
        "  local iperf3 version: {}",
        local_version.map(|v| format!("{}.{}", v.major, v.minor)).unwrap_or_else(|| "unknown".to_string())
    );
    println!("  allowlisted ports (probed, and only these): {:?}", allowlist.ports);
    for cap in &capabilities {
        let status = if cap.reachable { "reachable".green() } else { "unreachable".red() };
        println!(
            "  port {}: {} version={} bidir_reliable={:?} -- {}",
            cap.port,
            status,
            cap.version.map(|v| format!("{}.{}", v.major, v.minor)).unwrap_or_else(|| "unknown".to_string()),
            cap.supports_bidir,
            cap.detail.dimmed()
        );
    }
    match selected {
        Some(p) => println!("  selected independent listener: port {}", p),
        None => println!("  {}", "no allowlisted listener answered".yellow()),
    }
}

fn print_result(r: &fraggle_packet::network_tests::iperf::IperfResult) {
    println!("{}", "== iperf3 result ==".cyan().bold());
    println!(
        "  version: {}",
        r.version.map(|v| format!("{}.{}", v.major, v.minor)).unwrap_or_else(|| "unknown".to_string())
    );
    println!("  protocol: {}  direction: {:?}", r.protocol, r.direction);
    print_rate_evidence("forward", &r.forward);
    if let Some(rev) = &r.bidir_reverse {
        print_rate_evidence("bidir-reverse", rev);
    }
    if !r.required_fields_missing.is_empty() {
        println!(
            "  {}",
            format!("missing fields (reported unavailable, not zero): {}", r.required_fields_missing.join(", "))
                .yellow()
        );
    }
    if matches!(r.direction, TestDirection::Bidirectional) && r.bidir_reverse.is_none() {
        println!(
            "  {}",
            "WARNING: bidir requested but no bidir-reverse evidence present -- version may not support --bidir reliably"
                .yellow()
        );
    }
}

fn print_rate_evidence(label: &str, e: &fraggle_packet::network_tests::iperf::RateEvidence) {
    println!("  [{}]", label);
    println!("    offered:  {}", e.offered_bps.map(|b| format!("{:.1} bps", b)).unwrap_or_else(|| "unavailable".to_string()));
    println!("    sent:     {}", fmt_sample(e.sent.as_ref()));
    println!("    received: {}", fmt_sample(e.received.as_ref()));
    if let Some(est) = &e.estimated_received {
        println!("    estimated_received (legacy sum): {}", fmt_sample(Some(est)));
    }
}

fn fmt_sample(s: Option<&fraggle_packet::network_tests::iperf::RateSample>) -> String {
    match s {
        None => "unavailable".to_string(),
        Some(s) => match s.packets {
            Some(p) => format!(
                "{:.1} bps, {} bytes, {} packets, loss={}",
                s.bits_per_second,
                s.bytes,
                p,
                s.lost_percent.map(|l| format!("{:.2}%", l)).unwrap_or_else(|| "unavailable".to_string())
            ),
            None => format!("{:.1} bps, {} bytes", s.bits_per_second, s.bytes),
        },
    }
}
