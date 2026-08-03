use colored::*;
use fraggle_packet::probe::{binary_search_mtu_icmp, probe_icmp, resolve_hostname};
use std::io::Write;

use crate::cli::GlobalArgs;

#[derive(clap::Args, Debug)]
pub struct MultiArgs {
    /// Comma-separated list of targets
    pub targets: String,
}

pub fn run(args: &MultiArgs, global: &GlobalArgs) {
    run_multi_target(
        &args.targets,
        global.timeout_ms,
        global.min,
        global.max,
        global.retries,
    );
}

fn run_multi_target(
    targets: &str,
    timeout_ms: u64,
    min_mtu: usize,
    max_mtu: usize,
    retries: usize,
) {
    let target_list: Vec<&str> = targets.split(',').map(|s| s.trim()).collect();

    println!(
        "{}",
        format!("Comparing MTU across {} targets", target_list.len())
            .cyan()
            .bold()
    );
    println!();

    let mut results: Vec<(String, Option<usize>)> = Vec::new();

    for target in &target_list {
        print!("Testing {}... ", target);
        std::io::stdout().flush().ok();

        let ip = match resolve_hostname(target) {
            Ok(ip) => ip,
            Err(_) => {
                println!("{}", "DNS failed".red());
                results.push((target.to_string(), None));
                continue;
            }
        };

        if !probe_icmp(ip, 64, timeout_ms, 1) {
            println!("{}", "ICMP blocked".yellow());
            results.push((target.to_string(), None));
            continue;
        }

        let mtu = binary_search_mtu_icmp(ip, min_mtu, max_mtu, timeout_ms, retries);
        println!("{} bytes", mtu.to_string().green());
        results.push((target.to_string(), Some(mtu)));
    }

    println!();
    println!("{}", "=".repeat(50).blue());
    println!("{}", " COMPARISON RESULTS ".white().on_blue().bold());
    println!("{}", "=".repeat(50).blue());

    let mut min_observed = usize::MAX;
    for (target, mtu) in &results {
        match mtu {
            Some(m) => {
                println!("  {:30} {} bytes", target, m.to_string().green());
                if *m < min_observed {
                    min_observed = *m;
                }
            }
            None => {
                println!("  {:30} {}", target, "N/A".yellow());
            }
        }
    }

    if min_observed < usize::MAX {
        println!();
        println!(
            "{}: {} bytes",
            "Lowest common MTU".cyan().bold(),
            min_observed
        );
        println!("{}: {} bytes", "Safe TCP MSS".cyan(), min_observed - 40);
    }
}
