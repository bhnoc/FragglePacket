use colored::*;
use fraggle_packet::probe::{
    binary_search_mtu_icmp, probe_icmp, resolve_hostname, ICMP_HEADER_SIZE, IP_HEADER_SIZE,
};
use std::io::Write;

use crate::cli::GlobalArgs;

#[derive(clap::Args, Debug)]
pub struct QuickArgs {
    /// Target IP address
    pub target: String,

    /// Emit the result as JSON
    #[arg(long)]
    pub json: bool,
}

pub fn run(args: &QuickArgs, global: &GlobalArgs) {
    run_quick_icmp(&args.target, global.timeout_ms, global.min, global.max, global.retries, args.json);
}

fn run_quick_icmp(target: &str, timeout_ms: u64, min_mtu: usize, max_mtu: usize, retries: usize, json: bool) {
    let ip = match resolve_hostname(target) {
        Ok(ip) => ip,
        Err(e) => {
            eprintln!("{}: {}", "DNS resolution failed".red(), e);
        std::process::exit(1);
    }
    };

    if !json {
        println!("Target: {} ({})", target, ip);
        println!();
        print!("Connectivity check... ");
        std::io::stdout().flush().ok();
    }
    if !probe_icmp(ip, 64, timeout_ms, 1) {
        if json {
            // Unreachable is reported, not silently exited: a consumer must be
            // able to tell "no answer" from "never asked".
            let doc = serde_json::json!({
                "target": target,
                "resolved_ip": ip.to_string(),
                "path_mtu": serde_json::Value::Null,
                "reason": "target did not respond to ICMP",
            });
            println!("{}", serde_json::to_string_pretty(&doc).unwrap_or_default());
            std::process::exit(1);
        }
        println!("{}", "FAILED".red());
        eprintln!("Target is not responding to ICMP. Check if ICMP is allowed.");
        std::process::exit(1);
    }
    if !json {
        println!("{}", "OK".green());
        print!("Finding path MTU... ");
        std::io::stdout().flush().ok();
    }
    let mtu = binary_search_mtu_icmp(ip, min_mtu, max_mtu, timeout_ms, retries);
    if !json {
        println!("{} bytes", mtu.to_string().green().bold());
        print!("Stability check (10 packets at {} bytes)... ", mtu);
        std::io::stdout().flush().ok();
    }
    let payload = mtu.saturating_sub(IP_HEADER_SIZE + ICMP_HEADER_SIZE);
    let mut drops = 0;
    for _ in 0..10 {
        if !probe_icmp(ip, payload, timeout_ms, 0) {
            drops += 1;
        }
    }
    if json {
        let doc = serde_json::json!({
            "target": target,
            "resolved_ip": ip.to_string(),
            "path_mtu": mtu,
            "tcp_mss": mtu.saturating_sub(40),
            "stability_probes": 10,
            "stability_drops": drops,
            "stable": drops == 0,
        });
        match serde_json::to_string_pretty(&doc) {
            Ok(s) => println!("{s}"),
            Err(e) => eprintln!("failed to serialize result: {e}"),
        }
        return;
    }

    if drops == 0 {
        println!("{}", "STABLE".green());
    } else {
        println!("{} ({}/10 lost)", "UNSTABLE".yellow(), drops);
    }

    println!();
    println!("{}", "RESULTS:".cyan().bold());
    println!("  Path MTU:  {} bytes", mtu);
    println!("  TCP MSS:   {} bytes", mtu - 40);
}
