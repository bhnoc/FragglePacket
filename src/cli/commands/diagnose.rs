use colored::*;
use fraggle_packet::probe::{
    binary_search_mtu_icmp, binary_search_mtu_tcp, probe_icmp, resolve_hostname,
    test_https_fetch, test_tcp_connect,
};

use crate::cli::GlobalArgs;

#[derive(clap::Args, Debug)]
pub struct DiagnoseArgs {
    /// Target hostname or IP (e.g., github.com, 8.8.8.8)
    pub target: String,
    /// Port to test TCP on
    #[arg(short, long, default_value_t = 443)]
    pub port: u16,

    /// Emit every stage result plus recommendations as JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
struct TestResult {
    protocol: String,
    target: String,
    mtu: Option<usize>,
    success: bool,
    message: String,
    latency_ms: Option<u64>,
}

pub fn run(args: &DiagnoseArgs, global: &GlobalArgs) {
    run_full_diagnostic(&args.target, args.port, global.timeout_ms, global.min, global.max, global.retries, args.json);
}

fn run_full_diagnostic(target: &str, port: u16, timeout_ms: u64, min_mtu: usize, max_mtu: usize, retries: usize, json: bool) {
    if !json {
        println!("{}", format!("Running full diagnostic against: {}", target).cyan().bold());
        println!();
    }

    let mut results: Vec<TestResult> = Vec::new();
    let mut recommendations: Vec<String> = Vec::new();

    // Step 1: DNS Resolution
    println!("{}", "[1/6] DNS Resolution".yellow().bold());
    let ip = match resolve_hostname(target) {
        Ok(ip) => {
            println!("  {} Resolved {} -> {}", "OK".green(), target, ip);
            results.push(TestResult {
                protocol: "DNS".into(),
                target: target.into(),
                mtu: None,
                success: true,
                message: format!("Resolved to {}", ip),
                latency_ms: None,
            });
            ip
        }
        Err(e) => {
            println!("  {} DNS resolution failed: {}", "FAIL".red(), e);
            results.push(TestResult {
                protocol: "DNS".into(),
                target: target.into(),
                mtu: None,
                success: false,
                message: e.clone(),
                latency_ms: None,
            });
            recommendations.push("FIX: DNS resolution failed".into());
            print_summary(&results, &recommendations);
            return;
        }
    };
    println!();

    // Step 2: Basic connectivity (small ICMP)
    println!("{}", "[2/6] Basic ICMP Connectivity".yellow().bold());
    let icmp_ok = probe_icmp(ip, 64, timeout_ms, 1);
    if icmp_ok {
        println!("  {} Target responds to ICMP ping", "OK".green());
        results.push(TestResult {
            protocol: "ICMP".into(),
            target: ip.to_string(),
            mtu: None,
            success: true,
            message: "Basic ping works".into(),
            latency_ms: None,
        });
    } else {
        println!("  {} Target does not respond to ICMP (may be filtered)", "WARN".yellow());
        results.push(TestResult {
            protocol: "ICMP".into(),
            target: ip.to_string(),
            mtu: None,
            success: false,
            message: "ICMP blocked or filtered".into(),
            latency_ms: None,
        });
        recommendations.push("NOTE: ICMP blocked, using TCP only".into());
    }
    println!();

    // Step 3: TCP Connectivity
    println!("{}", format!("[3/6] TCP Connection (port {})", port).yellow().bold());
    let tcp_result = test_tcp_connect(&format!("{}:{}", ip, port), timeout_ms);
    match &tcp_result {
        Ok(latency) => {
            println!("  {} TCP connection established ({}ms)", "OK".green(), latency);
            results.push(TestResult {
                protocol: "TCP".into(),
                target: format!("{}:{}", ip, port),
                mtu: None,
                success: true,
                message: "Connection established".into(),
                latency_ms: Some(*latency),
            });
        }
        Err(e) => {
            println!("  {} TCP connection failed: {}", "FAIL".red(), e);
            results.push(TestResult {
                protocol: "TCP".into(),
                target: format!("{}:{}", ip, port),
                mtu: None,
                success: false,
                message: e.clone(),
                latency_ms: None,
            });
            recommendations.push(format!("FIX: TCP port {} blocked", port));
        }
    }
    println!();

    // Step 4: ICMP Path MTU Discovery
    println!("{}", "[4/6] ICMP Path MTU Discovery".yellow().bold());
    let icmp_mtu = if icmp_ok {
        let mtu = binary_search_mtu_icmp(ip, min_mtu, max_mtu, timeout_ms, retries);
        println!("  {} ICMP Path MTU: {} bytes", "OK".green(), mtu);
        results.push(TestResult {
            protocol: "ICMP-MTU".into(),
            target: ip.to_string(),
            mtu: Some(mtu),
            success: true,
            message: format!("{} bytes", mtu),
            latency_ms: None,
        });
        Some(mtu)
    } else {
        println!("  {} Skipped (ICMP unavailable)", "SKIP".yellow());
        None
    };
    println!();

    // Step 5: TCP-based MTU probing
    println!("{}", "[5/6] TCP Path MTU Discovery".yellow().bold());
    let tcp_mtu = if tcp_result.is_ok() {
        match binary_search_mtu_tcp(&format!("{}:{}", ip, port), min_mtu, max_mtu, timeout_ms) {
            Some(mtu) => {
                println!("  {} TCP Path MTU: {} bytes", "OK".green(), mtu);
                results.push(TestResult {
                    protocol: "TCP-MTU".into(),
                    target: format!("{}:{}", ip, port),
                    mtu: Some(mtu),
                    success: true,
                    message: format!("{} bytes", mtu),
                    latency_ms: None,
                });
                Some(mtu)
            }
            None => {
                println!("  {} Could not determine TCP MTU", "WARN".yellow());
                None
            }
        }
    } else {
        println!("  {} Skipped (TCP unavailable)", "SKIP".yellow());
        None
    };
    println!();

    // Step 6: HTTPS fetch test
    println!("{}", "[6/6] HTTPS Data Transfer Test".yellow().bold());
    if port == 443 {
        match test_https_fetch(target, timeout_ms) {
            Ok((size, latency)) => {
                println!("  {} HTTPS fetch successful ({} bytes, {}ms)", "OK".green(), size, latency);
                results.push(TestResult {
                    protocol: "HTTPS".into(),
                    target: target.into(),
                    mtu: None,
                    success: true,
                    message: format!("Fetched {} bytes", size),
                    latency_ms: Some(latency),
                });
            }
            Err(e) => {
                println!("  {} HTTPS fetch failed: {}", "FAIL".red(), e);
                results.push(TestResult {
                    protocol: "HTTPS".into(),
                    target: target.into(),
                    mtu: None,
                    success: false,
                    message: e.clone(),
                    latency_ms: None,
                });

                // This is the PMTUD black hole signature!
                if icmp_ok && tcp_result.is_ok() {
                    recommendations.push("PMTUD BLACK HOLE: Set interface MTU to 1400".into());
                }
            }
        }
    } else {
        println!("  {} Skipped (non-HTTPS port)", "SKIP".yellow());
    }
    println!();

    // Analysis: Compare ICMP vs TCP MTU
    if let (Some(icmp), Some(tcp)) = (icmp_mtu, tcp_mtu) {
        if icmp > tcp + 100 {
            recommendations.push(format!(
                "MTU MISMATCH: ICMP={} TCP={} - set interface to lower value",
                icmp, tcp
            ));
        }
    }

    // Generate safe MTU recommendation
    let safe_mtu = match (icmp_mtu, tcp_mtu) {
        (Some(i), Some(t)) => Some(std::cmp::min(i, t)),
        (Some(m), None) | (None, Some(m)) => Some(m),
        (None, None) => None,
    };

    if let Some(mtu) = safe_mtu {
        if mtu >= 1500 {
            recommendations.push("NO CHANGE NEEDED: Path supports standard 1500 MTU".into());
        } else {
            recommendations.push(format!("SET INTERFACE MTU: {}", mtu));
        }
        recommendations.push(format!("TCP MSS CLAMP: {}", mtu - 40));
    }

    if json {
        let doc = serde_json::json!({
            "target": target,
            "port": port,
            "stages": results,
            "safe_mtu": safe_mtu,
            "recommendations": recommendations,
        });
        match serde_json::to_string_pretty(&doc) {
            Ok(s) => println!("{s}"),
            Err(e) => eprintln!("failed to serialize diagnostic: {e}"),
        }
        return;
    }

    print_summary(&results, &recommendations);
}

fn print_summary(results: &[TestResult], recommendations: &[String]) {
    println!();
    println!("{}", "=".repeat(60).blue());
    println!("{}", " SUMMARY ".white().on_blue().bold());
    println!("{}", "=".repeat(60).blue());

    // Show MTU results
    for r in results {
        if let Some(mtu) = r.mtu {
            println!("  {:12} MTU: {} bytes", r.protocol, mtu.to_string().green().bold());
        }
    }

    if !recommendations.is_empty() {
        println!();
        println!("{}", "ACTION:".cyan().bold());
        for rec in recommendations {
            if rec.starts_with("SET ") || rec.starts_with("FIX:") || rec.contains("BLACK HOLE") || rec.contains("MISMATCH") {
                println!("  {} {}", ">".yellow().bold(), rec.yellow().bold());
            } else if rec.starts_with("NO CHANGE") {
                println!("  {} {}", ">".green().bold(), rec.green());
            } else if rec.starts_with("TCP MSS") {
                println!("  {}", rec.dimmed());
            } else if !rec.starts_with("NOTE:") {
                println!("  {}", rec);
            }
        }
    }
    println!();
}
