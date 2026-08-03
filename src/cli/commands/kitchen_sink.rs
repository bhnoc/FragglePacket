use chrono::{DateTime, Utc};
use colored::*;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::Path;

use fraggle_packet::probe::{
    binary_search_mtu_icmp, binary_search_mtu_tcp, binary_search_mtu_udp,
    check_tracepath_available, probe_icmp, probe_quic_mtu, probe_tcp_mss, resolve_hostname,
    run_tracepath,
};

use crate::cli::common::{
    VPN_OVERHEAD_GLOBAL_PROTECT, VPN_OVERHEAD_OPENVPN_UDP, VPN_OVERHEAD_WIREGUARD,
    VPN_OVERHEAD_ZSCALER,
};
use crate::cli::GlobalArgs;

#[derive(clap::Args, Debug)]
pub struct KitchenSinkArgs {
    /// Max MTU to test (default 1500, use 9000 for jumbo)
    #[arg(long, default_value_t = 1500)]
    pub max: usize,

    /// Output results as JSON
    #[arg(long)]
    pub json: bool,

    /// Save JSON report to file
    #[arg(long)]
    pub output: Option<String>,
}

pub fn run(args: &KitchenSinkArgs, global: &GlobalArgs) {
    run_kitchen_sink(
        global.timeout_ms,
        global.min,
        args.max,
        global.retries,
        args.json,
        args.output.clone(),
    );
}

#[derive(Debug, Serialize, Deserialize)]
struct MtuReport {
    timestamp: DateTime<Utc>,
    hostname: String,
    version: String,
    summary: ReportSummary,
    targets: Vec<TargetResult>,
    hops: Vec<HopResult>,
    verdict: Verdict,
}

#[derive(Debug, Serialize, Deserialize)]
struct ReportSummary {
    total_targets: usize,
    successful_tests: usize,
    median_mtu: usize,
    min_mtu: usize,
    max_mtu: usize,
    percent_at_1500: f64,
}

#[derive(Debug, Serialize, Deserialize)]
struct TargetResult {
    target: String,
    description: String,
    icmp_mtu: Option<usize>,
    tcp_mtu: Option<usize>,
    udp_mtu: Option<usize>,
    quic_mtu: Option<usize>,
    tcp_mss: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
struct HopResult {
    hop: u8,
    address: String,
    mtu: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Verdict {
    status: String, // PASS, REVIEW, ACTION_NEEDED
    recommended_mtu: Option<usize>,
    recommended_mss: Option<usize>,
    reasons: Vec<String>,
}

#[derive(Clone)]
struct MtuTestResult {
    target: String,
    desc: String,
    icmp_mtu: Option<usize>,
    tcp_mtu: Option<usize>,
    udp_mtu: Option<usize>,
    tcp_mss: Option<usize>,
    quic_mtu: Option<usize>,
}

fn load_targets() -> Vec<(String, String, u16)> {
    let default_targets = vec![
        ("8.8.8.8", "Google DNS", 0),
        ("1.1.1.1", "Cloudflare DNS", 0),
        ("9.9.9.9", "Quad9 DNS", 0),
        ("github.com", "GitHub", 443),
        ("outlook.office365.com", "M365 Outlook", 443),
        ("teams.microsoft.com", "MS Teams", 443),
        ("login.microsoftonline.com", "M365 Auth", 443),
        ("aws.amazon.com", "AWS", 443),
        ("azure.microsoft.com", "Azure", 443),
        ("mail.google.com", "Gmail", 443),
        ("zoom.us", "Zoom", 443),
        ("slack.com", "Slack", 443),
    ];

    // Try to load from file
    let targets_file = Path::new("targets.txt");
    if targets_file.exists() {
        if let Ok(content) = fs::read_to_string(targets_file) {
            let mut targets = Vec::new();
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let parts: Vec<&str> = line.split(',').collect();
                if parts.len() >= 2 {
                    let target = parts[0].trim().to_string();
                    let desc = parts[1].trim().to_string();
                    let port: u16 = parts
                        .get(2)
                        .and_then(|p| p.trim().parse().ok())
                        .unwrap_or(443);
                    targets.push((target, desc, port));
                }
            }
            if !targets.is_empty() {
                return targets;
            }
        }
    }

    default_targets
        .iter()
        .map(|(t, d, p)| (t.to_string(), d.to_string(), *p))
        .collect()
}

fn run_kitchen_sink(
    timeout_ms: u64,
    min_mtu: usize,
    max_mtu: usize,
    retries: usize,
    json_output: bool,
    output_file: Option<String>,
) {
    if !json_output {
        println!("{}", "=".repeat(70).blue());
        println!(
            "{}",
            " FragglePacket - COMPREHENSIVE TEST "
                .white()
                .on_blue()
                .bold()
        );
        println!("{}", "=".repeat(70).blue());
        println!();
    }

    let targets = load_targets();

    if !json_output {
        println!(
            "Testing {} targets in parallel...",
            targets.len().to_string().cyan()
        );
        println!();
    }

    // Phase 1: Parallel ICMP + TCP testing
    println!(
        "{}",
        "PHASE 1: Path MTU Discovery (ICMP + TCP)".cyan().bold()
    );
    println!("{}", "-".repeat(60));

    let results: Vec<MtuTestResult> = targets
        .par_iter()
        .map(|(target, desc, port)| {
            let mut result = MtuTestResult {
                target: target.clone(),
                desc: desc.clone(),
                icmp_mtu: None,
                tcp_mtu: None,
                udp_mtu: None,
                tcp_mss: None,
                quic_mtu: None,
            };

            // Resolve hostname once
            let ip = resolve_hostname(target).ok();

            // ICMP test
            if let Some(ip) = ip {
                if probe_icmp(ip, 64, timeout_ms, 1) {
                    result.icmp_mtu = Some(binary_search_mtu_icmp(
                        ip, min_mtu, max_mtu, timeout_ms, retries,
                    ));
                }

                // UDP test (for DNS servers - port 0 means DNS)
                if *port == 0 {
                    result.udp_mtu =
                        binary_search_mtu_udp(ip, min_mtu, max_mtu, timeout_ms, retries);
                }
            }

            // TCP test (if port specified)
            if *port > 0 {
                let tcp_target = format!("{}:{}", target, port);
                result.tcp_mtu = binary_search_mtu_tcp(&tcp_target, min_mtu, max_mtu, timeout_ms);

                // Also get TCP MSS
                if let Some(mss_info) = probe_tcp_mss(&tcp_target, timeout_ms) {
                    result.tcp_mss = Some(mss_info.mss);
                }

                // QUIC test (port 443 only, and only if target likely supports it)
                if *port == 443 {
                    result.quic_mtu = probe_quic_mtu(target, 443, timeout_ms);
                }
            }

            result
        })
        .collect();

    // Display results
    println!(
        "  {:20} {:>6} {:>6} {:>6} {:>6} {:>6}",
        "Target".dimmed(),
        "ICMP".dimmed(),
        "TCP".dimmed(),
        "UDP".dimmed(),
        "QUIC".dimmed(),
        "MSS".dimmed()
    );
    println!("  {}", "-".repeat(62));

    for r in &results {
        let fmt_mtu = |m: Option<usize>| -> String {
            match m {
                Some(v) if v >= 1500 => v.to_string().green().to_string(),
                Some(v) if v >= 1400 => v.to_string().yellow().to_string(),
                Some(v) => v.to_string().red().to_string(),
                None => "---".dimmed().to_string(),
            }
        };

        let mss_str = match r.tcp_mss {
            Some(m) if m >= 1460 => m.to_string().green().to_string(),
            Some(m) if m >= 1360 => m.to_string().yellow().to_string(),
            Some(m) => m.to_string().red().to_string(),
            None => "---".dimmed().to_string(),
        };

        println!(
            "  {:20} {:>6} {:>6} {:>6} {:>6} {:>6}",
            r.desc,
            fmt_mtu(r.icmp_mtu),
            fmt_mtu(r.tcp_mtu),
            fmt_mtu(r.udp_mtu),
            fmt_mtu(r.quic_mtu),
            mss_str
        );
    }
    println!();

    // Collect all successful MTU measurements
    let mut all_mtus: Vec<(String, String, usize)> = Vec::new();
    let mut all_mss: Vec<(String, usize)> = Vec::new();

    for r in &results {
        if let Some(m) = r.icmp_mtu {
            all_mtus.push((r.desc.clone(), "ICMP".into(), m));
        }
        if let Some(m) = r.tcp_mtu {
            all_mtus.push((r.desc.clone(), "TCP".into(), m));
        }
        if let Some(m) = r.udp_mtu {
            all_mtus.push((r.desc.clone(), "UDP".into(), m));
        }
        if let Some(m) = r.quic_mtu {
            all_mtus.push((r.desc.clone(), "QUIC".into(), m));
        }
        if let Some(m) = r.tcp_mss {
            all_mss.push((r.desc.clone(), m));
        }
    }

    if all_mtus.is_empty() {
        println!(
            "{}",
            "ERROR: No successful MTU tests. Check network connectivity.".red()
        );
        return;
    }

    // Show MSS summary if we got any
    if !all_mss.is_empty() {
        let avg_mss: usize = all_mss.iter().map(|(_, m)| m).sum::<usize>() / all_mss.len();
        let min_mss = all_mss.iter().map(|(_, m)| *m).min().unwrap_or(0);
        println!();
        println!(
            "  TCP MSS observed: avg {} / min {} ({} connections)",
            avg_mss,
            min_mss,
            all_mss.len()
        );
    }

    // Phase 2: Per-Hop MTU Analysis (if tracepath available)
    let mut hop_mtu_drop: Option<(String, usize, usize)> = None;

    if check_tracepath_available() {
        println!(
            "{}",
            "PHASE 2: Per-Hop MTU Analysis (tracepath)".cyan().bold()
        );
        println!("{}", "-".repeat(60));

        // Run tracepath on a few key targets to find where MTU drops
        let tracepath_targets = vec!["8.8.8.8", "1.1.1.1"];

        for target in tracepath_targets {
            print!("  Tracing {}... ", target);
            std::io::stdout().flush().ok();

            let hops = run_tracepath(target);

            if hops.is_empty() {
                println!("{}", "no data".dimmed());
                continue;
            }

            // Find where MTU drops
            let mut prev_mtu: Option<usize> = None;
            let mut drop_found = false;

            for hop in &hops {
                if let Some(mtu) = hop.mtu {
                    if let Some(prev) = prev_mtu {
                        if mtu < prev {
                            println!(
                                "MTU drops {} -> {} at hop {} ({})",
                                prev, mtu, hop.hop, hop.addr
                            );
                            drop_found = true;
                            if hop_mtu_drop.is_none() {
                                hop_mtu_drop = Some((hop.addr.clone(), prev, mtu));
                            }
                        }
                    }
                    prev_mtu = Some(mtu);
                }
            }

            if !drop_found {
                if let Some(last_mtu) = hops.iter().filter_map(|h| h.mtu).last() {
                    println!("{} bytes (consistent)", last_mtu.to_string().green());
                } else {
                    println!("{}", "no MTU data".dimmed());
                }
            }
        }
        println!();
    }

    // Phase 3: Statistical analysis
    println!("{}", "PHASE 3: Statistical Analysis".cyan().bold());
    println!("{}", "-".repeat(60));

    let mut mtu_values: Vec<usize> = all_mtus.iter().map(|(_, _, m)| *m).collect();
    mtu_values.sort();

    let total_tests = mtu_values.len();
    let min_mtu_found = *mtu_values.first().unwrap();
    let max_mtu_found = *mtu_values.last().unwrap();
    let median_mtu = mtu_values[total_tests / 2];

    // Count how many are at 1500
    let at_1500 = mtu_values.iter().filter(|&&m| m >= 1500).count();
    let below_1500 = total_tests - at_1500;
    let pct_ok = (at_1500 as f64 / total_tests as f64) * 100.0;

    println!("  Total tests:    {}", total_tests);
    println!("  At 1500:        {} ({:.0}%)", at_1500, pct_ok);
    println!("  Below 1500:     {}", below_1500);
    println!("  Median MTU:     {}", median_mtu);
    println!("  Range:          {} - {}", min_mtu_found, max_mtu_found);
    println!();

    // Find anomalies (significantly lower than median)
    let anomaly_threshold = if median_mtu >= 1400 {
        1350
    } else {
        median_mtu - 100
    };
    let anomalies: Vec<_> = all_mtus
        .iter()
        .filter(|(_, _, m)| *m < anomaly_threshold)
        .collect();

    // Phase 3: Re-test anomalies
    if !anomalies.is_empty() && median_mtu >= 1400 {
        println!("{}", "PHASE 4: Re-testing Anomalies".cyan().bold());
        println!("{}", "-".repeat(60));
        println!(
            "  {} results below {} - verifying...",
            anomalies.len(),
            anomaly_threshold
        );
        println!();

        let mut confirmed_low: Vec<(String, String, usize)> = Vec::new();

        for (desc, proto, mtu) in &anomalies {
            print!("  {:25} {} @ {} -> ", desc, proto, mtu);
            std::io::stdout().flush().ok();

            // Find original target
            let target_info = targets.iter().find(|(_, d, _)| d == desc);
            if let Some((target, _, port)) = target_info {
                let retest_mtu = if proto == "ICMP" {
                    if let Ok(ip) = resolve_hostname(target) {
                        // More retries for confirmation
                        Some(binary_search_mtu_icmp(ip, min_mtu, max_mtu, timeout_ms, 5))
                    } else {
                        None
                    }
                } else {
                    let tcp_target = format!("{}:{}", target, port);
                    binary_search_mtu_tcp(&tcp_target, min_mtu, max_mtu, timeout_ms * 2)
                };

                match retest_mtu {
                    Some(new_mtu) if new_mtu < 1400 => {
                        println!("{} (confirmed)", new_mtu.to_string().red());
                        confirmed_low.push((desc.clone(), proto.clone(), new_mtu));
                    }
                    Some(new_mtu) => {
                        println!("{} (was flaky)", new_mtu.to_string().green());
                    }
                    None => {
                        println!("{}", "failed".yellow());
                    }
                }
            }
        }
        println!();

        // Update anomalies with confirmed ones
        if confirmed_low.is_empty() && !anomalies.is_empty() {
            println!("  {} All anomalies were transient/flaky", "OK".green());
            println!();
        }
    }

    // Phase 4: VPN Overhead check
    println!("{}", "PHASE 5: VPN/SASE Compatibility".cyan().bold());
    println!("{}", "-".repeat(60));

    let consensus_mtu = if pct_ok >= 90.0 { 1500 } else { median_mtu };
    println!(
        "  Using consensus MTU: {} bytes",
        consensus_mtu.to_string().white().bold()
    );
    println!();

    let vpn_overheads = vec![
        ("WireGuard", VPN_OVERHEAD_WIREGUARD),
        ("OpenVPN-UDP", VPN_OVERHEAD_OPENVPN_UDP),
        ("Zscaler/ZPA", VPN_OVERHEAD_ZSCALER),
        ("GlobalProtect", VPN_OVERHEAD_GLOBAL_PROTECT),
    ];

    for (vpn_name, overhead) in &vpn_overheads {
        let inner = consensus_mtu.saturating_sub(*overhead);
        let status = if inner >= 1280 {
            "OK".green()
        } else {
            "LOW".red()
        };
        println!(
            "  {:20} -{:3}b = {:4} inner [{}]",
            vpn_name, overhead, inner, status
        );
    }
    println!();

    // Final Verdict
    println!("{}", "=".repeat(70).blue());
    println!("{}", " VERDICT ".white().on_blue().bold());
    println!("{}", "=".repeat(70).blue());
    println!();

    if pct_ok >= 95.0 && min_mtu_found >= 1400 {
        // Nearly everything at 1500, no significant issues
        println!("  {} No MTU changes needed", "PASS".green().bold());
        println!();
        println!("  {}% of tests at 1500 MTU", pct_ok as usize);
        println!("  Interface MTU: 1500 (keep current)");
        println!("  TCP MSS Clamp: 1460 (optional)");
    } else if pct_ok >= 80.0 && median_mtu >= 1400 {
        // Most OK, some outliers
        println!("  {} Mostly OK with some outliers", "PASS".green().bold());
        println!();
        println!("  {}% of tests at 1500 MTU", pct_ok as usize);
        println!("  Outliers are likely endpoint-specific (not your network)");
        println!("  Interface MTU: 1500 (keep current)");
        println!("  TCP MSS Clamp: 1460 (optional)");
    } else if median_mtu >= 1400 {
        // Median OK but significant issues
        println!(
            "  {} Some paths have MTU restrictions",
            "REVIEW".yellow().bold()
        );
        println!();
        println!("  Median: {} | Lowest: {}", median_mtu, min_mtu_found);
        println!(
            "  Consider: Interface MTU {} if seeing connection issues",
            median_mtu
        );
        println!("  TCP MSS Clamp: {}", median_mtu - 40);
    } else {
        // Real problem
        println!("  {} Path MTU is restricted", "ACTION NEEDED".red().bold());
        println!();
        println!("  Median MTU: {} bytes", median_mtu);
        println!(
            "  SET INTERFACE MTU: {}",
            median_mtu.to_string().yellow().bold()
        );
        println!(
            "  SET TCP MSS CLAMP: {}",
            (median_mtu - 40).to_string().yellow()
        );
        println!();

        // Show what's limiting
        let limiters: Vec<_> = all_mtus.iter().filter(|(_, _, m)| *m < 1400).collect();
        if !limiters.is_empty() {
            println!("  Limiting factors:");
            for (desc, proto, mtu) in limiters.iter().take(5) {
                println!("    {} {} = {}", desc, proto, mtu);
            }
        }

        // Show where MTU drops if tracepath found it
        if let Some((addr, from, to)) = &hop_mtu_drop {
            println!();
            println!(
                "  {} MTU drops from {} to {} at {}",
                "WHERE:".cyan(),
                from,
                to,
                addr.yellow()
            );
        }
    }
    println!();

    // Generate JSON report if requested
    if json_output || output_file.is_some() {
        let hostname = std::env::var("HOSTNAME")
            .or_else(|_| std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()))
            .unwrap_or_else(|_| "unknown".to_string());

        let (status, rec_mtu, rec_mss) =
            if pct_ok >= 95.0 && mtu_values.first().copied().unwrap_or(0) >= 1400 {
                ("PASS".to_string(), None, None)
            } else if pct_ok >= 80.0 && median_mtu >= 1400 {
                ("PASS".to_string(), None, None)
            } else if median_mtu >= 1400 {
                (
                    "REVIEW".to_string(),
                    Some(median_mtu),
                    Some(median_mtu - 40),
                )
            } else {
                (
                    "ACTION_NEEDED".to_string(),
                    Some(median_mtu),
                    Some(median_mtu - 40),
                )
            };

        let target_results: Vec<TargetResult> = results
            .iter()
            .map(|r| TargetResult {
                target: r.target.clone(),
                description: r.desc.clone(),
                icmp_mtu: r.icmp_mtu,
                tcp_mtu: r.tcp_mtu,
                udp_mtu: r.udp_mtu,
                quic_mtu: r.quic_mtu,
                tcp_mss: r.tcp_mss,
            })
            .collect();

        let report = MtuReport {
            timestamp: Utc::now(),
            hostname,
            version: env!("CARGO_PKG_VERSION").to_string(),
            summary: ReportSummary {
                total_targets: results.len(),
                successful_tests: all_mtus.len(),
                median_mtu,
                min_mtu: *mtu_values.first().unwrap_or(&0),
                max_mtu: *mtu_values.last().unwrap_or(&0),
                percent_at_1500: pct_ok,
            },
            targets: target_results,
            hops: Vec::new(), // TODO: populate from tracepath
            verdict: Verdict {
                status,
                recommended_mtu: rec_mtu,
                recommended_mss: rec_mss,
                reasons: Vec::new(), // TODO: populate reasons
            },
        };

        let json = serde_json::to_string_pretty(&report).unwrap();

        if let Some(path) = output_file {
            // Ensure parent directory exists
            if let Some(parent) = std::path::Path::new(&path).parent() {
                std::fs::create_dir_all(parent).ok();
            }
            if let Err(e) = std::fs::write(&path, &json) {
                eprintln!("Failed to write report to {}: {}", path, e);
            } else {
                println!("Report saved to: {}", path);
            }
        }

        if json_output {
            println!("{}", json);
        }
    }
}
