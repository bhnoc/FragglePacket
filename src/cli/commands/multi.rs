use colored::*;
use fraggle_packet::probe::{binary_search_mtu_icmp, probe_icmp, resolve_hostname};
use std::io::Write;

use crate::cli::GlobalArgs;

#[derive(clap::Args, Debug)]
pub struct MultiArgs {
    /// Comma-separated list of targets
    pub targets: String,

    /// Emit the comparison as JSON
    #[arg(long)]
    pub json: bool,
}

pub fn run(args: &MultiArgs, global: &GlobalArgs) {
    run_multi_target(&args.targets, global.timeout_ms, global.min, global.max, global.retries, args.json);
}

fn run_multi_target(targets: &str, timeout_ms: u64, min_mtu: usize, max_mtu: usize, retries: usize, json: bool) {
    let target_list: Vec<&str> = targets.split(',').map(|s| s.trim()).collect();

    if !json {
        println!("{}", format!("Comparing MTU across {} targets", target_list.len()).cyan().bold());
        println!();
    }

    let mut results: Vec<(String, Option<usize>)> = Vec::new();
    // GAP-073's rule applied here: a target that produced no MTU is recorded with
    // WHY, so it stays in the denominator instead of vanishing from the summary.
    let mut reasons: Vec<(String, &'static str)> = Vec::new();

    for target in &target_list {
        if !json {
            print!("Testing {}... ", target);
            std::io::stdout().flush().ok();
        }

        let ip = match resolve_hostname(target) {
            Ok(ip) => ip,
            Err(_) => {
                if !json { println!("{}", "DNS failed".red()); }
                results.push((target.to_string(), None));
                reasons.push((target.to_string(), "dns resolution failed"));
                continue;
            }
        };

        if !probe_icmp(ip, 64, timeout_ms, 1) {
            if !json { println!("{}", "ICMP blocked".yellow()); }
            results.push((target.to_string(), None));
            reasons.push((target.to_string(), "no ICMP response"));
            continue;
        }

        let mtu = binary_search_mtu_icmp(ip, min_mtu, max_mtu, timeout_ms, retries);
        if !json { println!("{} bytes", mtu.to_string().green()); }
        results.push((target.to_string(), Some(mtu)));
    }

    if json {
        let measured = results.iter().filter(|(_, m)| m.is_some()).count();
        let lowest = results.iter().filter_map(|(_, m)| *m).min();
        let doc = serde_json::json!({
            "targets_attempted": results.len(),
            "targets_measured": measured,
            "per_target": results.iter().map(|(t, m)| serde_json::json!({
                "target": t,
                "path_mtu": m,
                "reason": reasons.iter().find(|(rt, _)| rt == t).map(|(_, r)| *r),
            })).collect::<Vec<_>>(),
            "lowest_common_mtu": lowest,
            "safe_tcp_mss": lowest.map(|m| m.saturating_sub(40)),
        });
        match serde_json::to_string_pretty(&doc) {
            Ok(s) => println!("{s}"),
            Err(e) => eprintln!("failed to serialize comparison: {e}"),
        }
        return;
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
        println!("{}: {} bytes", "Lowest common MTU".cyan().bold(), min_observed);
        println!("{}: {} bytes", "Safe TCP MSS".cyan(), min_observed - 40);
    }
}
