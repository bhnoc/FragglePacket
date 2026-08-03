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
}

pub fn run(args: &QuickArgs, global: &GlobalArgs) {
    run_quick_icmp(
        &args.target,
        global.timeout_ms,
        global.min,
        global.max,
        global.retries,
    );
}

fn run_quick_icmp(target: &str, timeout_ms: u64, min_mtu: usize, max_mtu: usize, retries: usize) {
    let ip = match resolve_hostname(target) {
        Ok(ip) => ip,
        Err(e) => {
            eprintln!("{}: {}", "DNS resolution failed".red(), e);
            std::process::exit(1);
        }
    };

    println!("Target: {} ({})", target, ip);
    println!();

    // Sanity check
    print!("Connectivity check... ");
    std::io::stdout().flush().ok();
    if !probe_icmp(ip, 64, timeout_ms, 1) {
        println!("{}", "FAILED".red());
        eprintln!("Target is not responding to ICMP. Check if ICMP is allowed.");
        std::process::exit(1);
    }
    println!("{}", "OK".green());

    // Binary search
    print!("Finding path MTU... ");
    std::io::stdout().flush().ok();
    let mtu = binary_search_mtu_icmp(ip, min_mtu, max_mtu, timeout_ms, retries);
    println!("{} bytes", mtu.to_string().green().bold());

    // Stability test
    print!("Stability check (10 packets at {} bytes)... ", mtu);
    std::io::stdout().flush().ok();
    let payload = mtu.saturating_sub(IP_HEADER_SIZE + ICMP_HEADER_SIZE);
    let mut drops = 0;
    for _ in 0..10 {
        if !probe_icmp(ip, payload, timeout_ms, 0) {
            drops += 1;
        }
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
