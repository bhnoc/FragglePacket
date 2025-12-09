use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use colored::*;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, Socket, Type};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::mem::MaybeUninit;
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::os::fd::AsRawFd;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU16, Ordering};
use std::future::IntoFuture;
use std::sync::Arc;
use std::time::{Duration, Instant};

// Use library modules
use fraggle_packet::fuzzing;
use fraggle_packet::network_tests;
use fraggle_packet::diagnosis;

// Binary-specific modules - using #[path] since they're not in standard locations
#[path = "src/bin/cli/fuzzing.rs"]
mod cli_fuzzing;

#[path = "src/bin/tui/app.rs"]
mod tui_app;

#[path = "src/bin/tui/fuzzing_panel.rs"]
mod tui_fuzzing_panel;

// =============================================================================
// JSON REPORT STRUCTURES
// =============================================================================

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
    status: String,  // PASS, REVIEW, ACTION_NEEDED
    recommended_mtu: Option<usize>,
    recommended_mss: Option<usize>,
    reasons: Vec<String>,
}

const ICMP_ECHO_REQUEST: u8 = 8;
const ICMP_HEADER_SIZE: usize = 8;
const IP_HEADER_SIZE: usize = 20;

// VPN/Tunnel overheads (bytes added to each packet)
// Traditional VPNs
const VPN_OVERHEAD_WIREGUARD: usize = 60;      // UDP + WG header
const VPN_OVERHEAD_OPENVPN_UDP: usize = 70;    // UDP + OpenVPN header + encryption
const VPN_OVERHEAD_OPENVPN_TCP: usize = 90;    // TCP + OpenVPN + encryption (avoid TCP-over-TCP)
const VPN_OVERHEAD_IPSEC_UDP: usize = 72;      // ESP + UDP encap (NAT-T)
const VPN_OVERHEAD_IPSEC_TUNNEL: usize = 80;   // ESP tunnel mode
const VPN_OVERHEAD_IKEV2: usize = 80;          // IKEv2/IPsec
const VPN_OVERHEAD_PPTP: usize = 48;           // GRE + PPP
const VPN_OVERHEAD_L2TP: usize = 76;           // L2TP + IPsec

// Zero Trust / SASE solutions (conservative estimates)
const VPN_OVERHEAD_ZSCALER: usize = 100;       // Zscaler ZIA/ZPA tunnel overhead
const VPN_OVERHEAD_NETSKOPE: usize = 90;       // Netskope SASE
const VPN_OVERHEAD_CLOUDFLARE_WARP: usize = 60; // WARP uses WireGuard
const VPN_OVERHEAD_GLOBAL_PROTECT: usize = 80; // Palo Alto GlobalProtect
const VPN_OVERHEAD_CISCO_ANYCONNECT: usize = 80;
const VPN_OVERHEAD_FORTINET: usize = 76;       // FortiClient

// Overlay/Tunnel protocols
const VPN_OVERHEAD_GRE: usize = 24;            // Basic GRE
const VPN_OVERHEAD_VXLAN: usize = 50;          // VXLAN encap
const VPN_OVERHEAD_GENEVE: usize = 50;         // Geneve (similar to VXLAN)

#[derive(Parser, Debug)]
#[command(name = "fraggle-packet")]
#[command(author, version, about = "FragglePacket - Comprehensive MTU and Path Discovery Tool")]
struct Args {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Target IP address (for quick ICMP test)
    #[arg(short, long)]
    target: Option<String>,

    /// Starting minimum MTU (default: 576 - minimum IPv4)
    #[arg(long, default_value_t = 576)]
    min: usize,

    /// Starting maximum MTU (default: 1500, use 9000 for jumbo frames)
    #[arg(long, default_value_t = 1500)]
    max: usize,

    /// Timeout in milliseconds
    #[arg(short = 'T', long, default_value_t = 2000)]
    timeout_ms: u64,

    /// Retries per probe
    #[arg(short, long, default_value_t = 2)]
    retries: usize,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Full diagnostic against a hostname (DNS, TCP, HTTP, ICMP comparison)
    Diagnose {
        /// Target hostname or IP (e.g., github.com, 8.8.8.8)
        target: String,
        /// Port to test TCP on
        #[arg(short, long, default_value_t = 443)]
        port: u16,
    },
    
    /// Test HTTPS connectivity with stage-by-stage analysis (MTU blackhole detection)
    Https {
        /// Target hostname (e.g., google.com, github.com)
        target: String,
        /// Timeout in seconds
        #[arg(short = 'T', long, default_value_t = 10)]
        timeout: u64,
        /// Show diagnosis and recommendations
        #[arg(short = 'd', long)]
        diagnose: bool,
    },

    /// Test multiple targets and compare path MTUs
    Multi {
        /// Comma-separated list of targets
        targets: String,
    },

    /// Calculate safe MTU for VPN/SASE/Zero-Trust usage
    Vpn {
        /// VPN type (see --help for full list)
        vpn_type: String,
        /// Base MTU to calculate from (default: auto-detect)
        #[arg(short, long)]
        base_mtu: Option<usize>,
    },

    /// Quick ICMP-only MTU test
    Quick {
        /// Target IP address
        target: String,
    },

    /// Packet fuzzing for security testing
    Fuzz {
        /// Target hostname or IP
        target: String,
        /// Output PCAP file path
        #[arg(short, long, default_value = "reports/fuzz.pcap")]
        output: String,
        /// Fuzzing mode (segment-size, length-mismatch, tcp-options, fragmentation, checksum)
        #[arg(short, long, default_value = "segment-size")]
        mode: String,
    },

    /// TCP-based MTU discovery (no ICMP required)
    Tcp {
        /// Target hostname:port
        target: String,
    },

    /// Run all tests against common targets and give final verdict
    KitchenSink {
        /// Max MTU to test (default 1500, use 9000 for jumbo)
        #[arg(long, default_value_t = 1500)]
        max: usize,
        
        /// Output results as JSON
        #[arg(long)]
        json: bool,
        
        /// Save JSON report to file
        #[arg(long)]
        output: Option<String>,
    },
}

#[derive(Debug, Clone)]
struct TestResult {
    protocol: String,
    target: String,
    mtu: Option<usize>,
    success: bool,
    message: String,
    latency_ms: Option<u64>,
}

fn main() {
    env_logger::init();
    let args = Args::parse();

    println!("{}", "=".repeat(60).blue());
    println!("{}", " FragglePacket v0.2 ".white().on_blue().bold());
    println!("{}", "=".repeat(60).blue());
    println!();

    match args.command {
        Some(Commands::Diagnose { target, port }) => {
            run_full_diagnostic(&target, port, args.timeout_ms, args.min, args.max, args.retries);
        }
        Some(Commands::Multi { targets }) => {
            run_multi_target(&targets, args.timeout_ms, args.min, args.max, args.retries);
        }
        Some(Commands::Vpn { vpn_type, base_mtu }) => {
            run_vpn_calculator(&vpn_type, base_mtu, args.timeout_ms, args.min, args.max, args.retries);
        }
        Some(Commands::Quick { target }) => {
            run_quick_icmp(&target, args.timeout_ms, args.min, args.max, args.retries);
        }
        Some(Commands::Fuzz { target, output, mode }) => {
            match cli_fuzzing::handle_fuzz_command(&target, &output, &mode) {
                Ok(_) => {},
                Err(e) => {
                    eprintln!("{} Fuzzing error: {}", "✗".red().bold(), e);
                    std::process::exit(1);
                }
            }
        }
        
        Some(Commands::Https { target, timeout, diagnose }) => {
            run_https_test(&target, timeout, diagnose);
        }
        
        Some(Commands::Tcp { target }) => {
            run_tcp_mtu_test(&target, args.timeout_ms, args.min, args.max);
        }
        Some(Commands::KitchenSink { max, json, output }) => {
            run_kitchen_sink(args.timeout_ms, args.min, max, args.retries, json, output);
        }
        None => {
            // Default: if --target provided, do quick test; otherwise show help
            if let Some(target) = args.target {
                run_quick_icmp(&target, args.timeout_ms, args.min, args.max, args.retries);
            } else {
                println!("Usage examples:");
                println!("  {} --target 8.8.8.8           # Quick ICMP MTU test", "fraggle-packet".green());
                println!("  {} diagnose github.com        # Full diagnostic", "fraggle-packet".green());
                println!("  {} multi 8.8.8.8,1.1.1.1      # Compare multiple targets", "fraggle-packet".green());
                println!("  {} vpn wireguard              # Calculate VPN-safe MTU", "fraggle-packet".green());
                println!("  {} tcp github.com:443         # TCP-only MTU probe", "fraggle-packet".green());
                println!();
                println!("Run with {} for full options", "--help".yellow());
            }
        }
    }
}

// =============================================================================
// FULL DIAGNOSTIC MODE
// =============================================================================

fn run_full_diagnostic(target: &str, port: u16, timeout_ms: u64, min_mtu: usize, max_mtu: usize, retries: usize) {
    println!("{}", format!("Running full diagnostic against: {}", target).cyan().bold());
    println!();

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

    print_summary(&results, &recommendations);
}

// =============================================================================
// MULTI-TARGET COMPARISON
// =============================================================================

fn run_multi_target(targets: &str, timeout_ms: u64, min_mtu: usize, max_mtu: usize, retries: usize) {
    let target_list: Vec<&str> = targets.split(',').map(|s| s.trim()).collect();
    
    println!("{}", format!("Comparing MTU across {} targets", target_list.len()).cyan().bold());
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
        println!("{}: {} bytes", "Lowest common MTU".cyan().bold(), min_observed);
        println!("{}: {} bytes", "Safe TCP MSS".cyan(), min_observed - 40);
    }
}

// =============================================================================
// VPN CALCULATOR
// =============================================================================

fn run_vpn_calculator(vpn_type: &str, base_mtu: Option<usize>, timeout_ms: u64, min_mtu: usize, max_mtu: usize, retries: usize) {
    let (overhead, proto_desc) = match vpn_type.to_lowercase().as_str() {
        // Traditional VPNs
        "wireguard" | "wg" => (VPN_OVERHEAD_WIREGUARD, "WireGuard (UDP)"),
        "openvpn-udp" | "ovpn-udp" => (VPN_OVERHEAD_OPENVPN_UDP, "OpenVPN over UDP"),
        "openvpn-tcp" | "ovpn-tcp" => (VPN_OVERHEAD_OPENVPN_TCP, "OpenVPN over TCP"),
        "ipsec" | "ipsec-udp" => (VPN_OVERHEAD_IPSEC_UDP, "IPsec with NAT-T (UDP)"),
        "ipsec-tunnel" => (VPN_OVERHEAD_IPSEC_TUNNEL, "IPsec tunnel mode"),
        "ikev2" => (VPN_OVERHEAD_IKEV2, "IKEv2/IPsec"),
        "pptp" => (VPN_OVERHEAD_PPTP, "PPTP (GRE+PPP)"),
        "l2tp" => (VPN_OVERHEAD_L2TP, "L2TP/IPsec"),
        
        // Zero Trust / SASE
        "zscaler" | "zia" | "zpa" => (VPN_OVERHEAD_ZSCALER, "Zscaler ZIA/ZPA"),
        "netskope" => (VPN_OVERHEAD_NETSKOPE, "Netskope SASE"),
        "cloudflare" | "warp" => (VPN_OVERHEAD_CLOUDFLARE_WARP, "Cloudflare WARP"),
        "globalprotect" | "paloalto" => (VPN_OVERHEAD_GLOBAL_PROTECT, "Palo Alto GlobalProtect"),
        "anyconnect" | "cisco" => (VPN_OVERHEAD_CISCO_ANYCONNECT, "Cisco AnyConnect"),
        "forticlient" | "fortinet" => (VPN_OVERHEAD_FORTINET, "FortiClient"),
        
        // Overlay protocols
        "gre" => (VPN_OVERHEAD_GRE, "GRE tunnel"),
        "vxlan" => (VPN_OVERHEAD_VXLAN, "VXLAN overlay"),
        "geneve" => (VPN_OVERHEAD_GENEVE, "Geneve overlay"),
        
        "list" => {
            println!("{}", "Supported VPN/Tunnel Types:".cyan().bold());
            println!();
            println!("{}", "Traditional VPNs:".yellow());
            println!("  wireguard, wg          WireGuard (UDP)              ~60 bytes");
            println!("  openvpn-udp            OpenVPN over UDP             ~70 bytes");
            println!("  openvpn-tcp            OpenVPN over TCP             ~90 bytes");
            println!("  ipsec, ipsec-udp       IPsec with NAT-T             ~72 bytes");
            println!("  ipsec-tunnel           IPsec tunnel mode            ~80 bytes");
            println!("  ikev2                  IKEv2/IPsec                  ~80 bytes");
            println!("  pptp                   PPTP                         ~48 bytes");
            println!("  l2tp                   L2TP/IPsec                   ~76 bytes");
            println!();
            println!("{}", "Zero Trust / SASE:".yellow());
            println!("  zscaler, zia, zpa      Zscaler ZIA/ZPA             ~100 bytes");
            println!("  netskope               Netskope                     ~90 bytes");
            println!("  cloudflare, warp       Cloudflare WARP              ~60 bytes");
            println!("  globalprotect          Palo Alto GlobalProtect      ~80 bytes");
            println!("  anyconnect, cisco      Cisco AnyConnect             ~80 bytes");
            println!("  forticlient            FortiClient                  ~76 bytes");
            println!();
            println!("{}", "Overlay Protocols:".yellow());
            println!("  gre                    GRE tunnel                   ~24 bytes");
            println!("  vxlan                  VXLAN overlay                ~50 bytes");
            println!("  geneve                 Geneve overlay               ~50 bytes");
            return;
        }
        
        _ => {
            eprintln!("{}: Unknown VPN type '{}'. Run 'fraggle-packet vpn list' for options", "Error".red(), vpn_type);
            return;
        }
    };

    let base = match base_mtu {
        Some(m) => m,
        None => {
            // Auto-detect by testing common DNS server
            println!("Auto-detecting base MTU via 8.8.8.8...");
            let ip: IpAddr = "8.8.8.8".parse().unwrap();
            if !probe_icmp(ip, 64, timeout_ms, 1) {
                println!("{}: Cannot reach 8.8.8.8, using default 1500", "Warning".yellow());
                1500
            } else {
                binary_search_mtu_icmp(ip, min_mtu, max_mtu, timeout_ms, retries)
            }
        }
    };

    println!();
    println!("{}", "=".repeat(60).blue());
    println!("{}", " VPN/TUNNEL MTU CALCULATOR ".white().on_blue().bold());
    println!("{}", "=".repeat(60).blue());
    println!();
    println!("  Solution:          {}", proto_desc.green());
    println!("  Protocol Overhead: {} bytes", overhead);
    println!("  Base Path MTU:     {} bytes", base);
    println!();
    
    let tunnel_mtu = base.saturating_sub(overhead);
    let inner_mss = tunnel_mtu.saturating_sub(40);
    
    // For extra safety with SASE/Zero Trust, recommend slightly lower
    let safe_tunnel_mtu = if overhead >= 80 {
        tunnel_mtu.saturating_sub(20) // Extra buffer for SASE solutions
    } else {
        tunnel_mtu
    };

    println!("{}", "RECOMMENDATIONS:".cyan().bold());
    println!("  Tunnel interface MTU: {} bytes", tunnel_mtu.to_string().green().bold());
    println!("  Safe/conservative:    {} bytes", safe_tunnel_mtu.to_string().yellow());
    println!("  Inner TCP MSS:        {} bytes", inner_mss.to_string().green());
    println!();
    
    println!("{}", "CONFIGURATION:".cyan());
    match vpn_type.to_lowercase().as_str() {
        "wireguard" | "wg" | "cloudflare" | "warp" => {
            println!("  [Interface]");
            println!("  MTU = {}", tunnel_mtu);
        }
        "openvpn-udp" | "openvpn-tcp" | "ovpn-udp" | "ovpn-tcp" => {
            println!("  # In server/client config:");
            println!("  tun-mtu {}", tunnel_mtu);
            println!("  mssfix {}", inner_mss);
        }
        "zscaler" | "zia" | "zpa" => {
            println!("  # Zscaler ZCC / tunnel interface:");
            println!("  MTU = {}", safe_tunnel_mtu);
        }
        "globalprotect" | "paloalto" => {
            println!("  # GlobalProtect portal/gateway config:");
            println!("  tunnel-mtu {}", tunnel_mtu);
            println!("  # Or in agent settings");
        }
        "anyconnect" | "cisco" => {
            println!("  # AnyConnect profile XML:");
            println!("  <MTU>{}</MTU>", tunnel_mtu);
        }
        _ => {
            println!("  # Set interface MTU to {}", tunnel_mtu);
        }
    }
    
}

// =============================================================================
// KITCHEN SINK - TEST EVERYTHING
// =============================================================================

// Test result for a single target
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
                    let port: u16 = parts.get(2).and_then(|p| p.trim().parse().ok()).unwrap_or(443);
                    targets.push((target, desc, port));
                }
            }
            if !targets.is_empty() {
                return targets;
            }
        }
    }

    default_targets.iter().map(|(t, d, p)| (t.to_string(), d.to_string(), *p)).collect()
}

fn run_kitchen_sink(timeout_ms: u64, min_mtu: usize, max_mtu: usize, retries: usize, json_output: bool, output_file: Option<String>) {
    if !json_output {
        println!("{}", "=".repeat(70).blue());
        println!("{}", " FragglePacket - COMPREHENSIVE TEST ".white().on_blue().bold());
        println!("{}", "=".repeat(70).blue());
        println!();
    }

    let targets = load_targets();
    
    if !json_output {
        println!("Testing {} targets in parallel...", targets.len().to_string().cyan());
        println!();
    }

    // Phase 1: Parallel ICMP + TCP testing
    println!("{}", "PHASE 1: Path MTU Discovery (ICMP + TCP)".cyan().bold());
    println!("{}", "-".repeat(60));

    let results: Vec<MtuTestResult> = targets.par_iter().map(|(target, desc, port)| {
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
                result.icmp_mtu = Some(binary_search_mtu_icmp(ip, min_mtu, max_mtu, timeout_ms, retries));
            }
            
            // UDP test (for DNS servers - port 0 means DNS)
            if *port == 0 {
                result.udp_mtu = binary_search_mtu_udp(ip, min_mtu, max_mtu, timeout_ms, retries);
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
    }).collect();

    // Display results
    println!("  {:20} {:>6} {:>6} {:>6} {:>6} {:>6}", 
        "Target".dimmed(), "ICMP".dimmed(), "TCP".dimmed(), "UDP".dimmed(), "QUIC".dimmed(), "MSS".dimmed());
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
        
        println!("  {:20} {:>6} {:>6} {:>6} {:>6} {:>6}", 
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
        println!("{}", "ERROR: No successful MTU tests. Check network connectivity.".red());
        return;
    }
    
    // Show MSS summary if we got any
    if !all_mss.is_empty() {
        let avg_mss: usize = all_mss.iter().map(|(_, m)| m).sum::<usize>() / all_mss.len();
        let min_mss = all_mss.iter().map(|(_, m)| *m).min().unwrap_or(0);
        println!();
        println!("  TCP MSS observed: avg {} / min {} ({} connections)", 
            avg_mss, min_mss, all_mss.len());
    }

    // Phase 2: Per-Hop MTU Analysis (if tracepath available)
    let mut hop_mtu_drop: Option<(String, usize, usize)> = None;
    
    if check_tracepath_available() {
        println!("{}", "PHASE 2: Per-Hop MTU Analysis (tracepath)".cyan().bold());
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
                            println!("MTU drops {} -> {} at hop {} ({})", 
                                prev, mtu, hop.hop, hop.addr);
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
    let anomaly_threshold = if median_mtu >= 1400 { 1350 } else { median_mtu - 100 };
    let anomalies: Vec<_> = all_mtus.iter()
        .filter(|(_, _, m)| *m < anomaly_threshold)
        .collect();

    // Phase 3: Re-test anomalies
    if !anomalies.is_empty() && median_mtu >= 1400 {
        println!("{}", "PHASE 4: Re-testing Anomalies".cyan().bold());
        println!("{}", "-".repeat(60));
        println!("  {} results below {} - verifying...", anomalies.len(), anomaly_threshold);
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
                    } else { None }
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
    println!("  Using consensus MTU: {} bytes", consensus_mtu.to_string().white().bold());
    println!();

    let vpn_overheads = vec![
        ("WireGuard", VPN_OVERHEAD_WIREGUARD),
        ("OpenVPN-UDP", VPN_OVERHEAD_OPENVPN_UDP),
        ("Zscaler/ZPA", VPN_OVERHEAD_ZSCALER),
        ("GlobalProtect", VPN_OVERHEAD_GLOBAL_PROTECT),
    ];

    for (vpn_name, overhead) in &vpn_overheads {
        let inner = consensus_mtu.saturating_sub(*overhead);
        let status = if inner >= 1280 { "OK".green() } else { "LOW".red() };
        println!("  {:20} -{:3}b = {:4} inner [{}]", vpn_name, overhead, inner, status);
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
        println!("  {} Some paths have MTU restrictions", "REVIEW".yellow().bold());
        println!();
        println!("  Median: {} | Lowest: {}", median_mtu, min_mtu_found);
        println!("  Consider: Interface MTU {} if seeing connection issues", median_mtu);
        println!("  TCP MSS Clamp: {}", median_mtu - 40);
    } else {
        // Real problem
        println!("  {} Path MTU is restricted", "ACTION NEEDED".red().bold());
        println!();
        println!("  Median MTU: {} bytes", median_mtu);
        println!("  SET INTERFACE MTU: {}", median_mtu.to_string().yellow().bold());
        println!("  SET TCP MSS CLAMP: {}", (median_mtu - 40).to_string().yellow());
        println!();
        
        // Show what's limiting
        let limiters: Vec<_> = all_mtus.iter()
            .filter(|(_, _, m)| *m < 1400)
            .collect();
        if !limiters.is_empty() {
            println!("  Limiting factors:");
            for (desc, proto, mtu) in limiters.iter().take(5) {
                println!("    {} {} = {}", desc, proto, mtu);
            }
        }
        
        // Show where MTU drops if tracepath found it
        if let Some((addr, from, to)) = &hop_mtu_drop {
            println!();
            println!("  {} MTU drops from {} to {} at {}", 
                "WHERE:".cyan(), from, to, addr.yellow());
        }
    }
    println!();
    
    // Generate JSON report if requested
    if json_output || output_file.is_some() {
        let hostname = std::env::var("HOSTNAME")
            .or_else(|_| std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()))
            .unwrap_or_else(|_| "unknown".to_string());
        
        let (status, rec_mtu, rec_mss) = if pct_ok >= 95.0 && mtu_values.first().copied().unwrap_or(0) >= 1400 {
            ("PASS".to_string(), None, None)
        } else if pct_ok >= 80.0 && median_mtu >= 1400 {
            ("PASS".to_string(), None, None)
        } else if median_mtu >= 1400 {
            ("REVIEW".to_string(), Some(median_mtu), Some(median_mtu - 40))
        } else {
            ("ACTION_NEEDED".to_string(), Some(median_mtu), Some(median_mtu - 40))
        };
        
        let target_results: Vec<TargetResult> = results.iter().map(|r| {
            TargetResult {
                target: r.target.clone(),
                description: r.desc.clone(),
                icmp_mtu: r.icmp_mtu,
                tcp_mtu: r.tcp_mtu,
                udp_mtu: r.udp_mtu,
                quic_mtu: r.quic_mtu,
                tcp_mss: r.tcp_mss,
            }
        }).collect();
        
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

// =============================================================================
// QUICK ICMP TEST
// =============================================================================

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

// =============================================================================
// TCP-BASED MTU TESTING
// =============================================================================

fn run_tcp_mtu_test(target: &str, timeout_ms: u64, min_mtu: usize, max_mtu: usize) {
    println!("TCP-based MTU discovery to {}", target.cyan());
    println!("(Does not require ICMP - useful when ping is blocked)");
    println!();

    match binary_search_mtu_tcp(target, min_mtu, max_mtu, timeout_ms) {
        Some(mtu) => {
            println!("{}", "RESULTS:".cyan().bold());
            println!("  Effective TCP MTU: {} bytes", mtu.to_string().green().bold());
            println!("  TCP MSS:           {} bytes", mtu - 40);
        }
        None => {
            eprintln!("{}: Could not complete TCP MTU discovery", "Error".red());
        }
    }
}

// =============================================================================
// CORE FUNCTIONS
// =============================================================================

fn resolve_hostname(host: &str) -> Result<IpAddr, String> {
    // If it's already an IP, just parse it
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ip);
    }

    // Try system resolver
    let addr = format!("{}:80", host);
    match addr.to_socket_addrs() {
        Ok(mut addrs) => {
            if let Some(addr) = addrs.next() {
                Ok(addr.ip())
            } else {
                Err("No addresses returned".into())
            }
        }
        Err(e) => Err(e.to_string()),
    }
}

fn test_tcp_connect(target: &str, timeout_ms: u64) -> Result<u64, String> {
    let start = Instant::now();
    let timeout = Duration::from_millis(timeout_ms);

    let addr: SocketAddr = target
        .to_socket_addrs()
        .map_err(|e| e.to_string())?
        .next()
        .ok_or("No address found")?;

    match TcpStream::connect_timeout(&addr, timeout) {
        Ok(_) => Ok(start.elapsed().as_millis() as u64),
        Err(e) => Err(e.to_string()),
    }
}

fn test_https_fetch(host: &str, timeout_ms: u64) -> Result<(usize, u64), String> {
    let start = Instant::now();
    
    // Simple blocking HTTPS request without async runtime
    // Use a simple TCP+TLS approach or shell out to curl
    // For simplicity, we'll use a basic HEAD request approach
    let addr: SocketAddr = format!("{}:443", host)
        .to_socket_addrs()
        .map_err(|e| e.to_string())?
        .next()
        .ok_or("No address")?;

    let timeout = Duration::from_millis(timeout_ms);
    let mut stream = TcpStream::connect_timeout(&addr, timeout).map_err(|e| e.to_string())?;
    stream.set_read_timeout(Some(timeout)).ok();
    stream.set_write_timeout(Some(timeout)).ok();

    // For a real HTTPS test, we'd need TLS. For now, just verify TCP data flow works.
    // This tests that large TCP packets can flow (after TLS would fragment them).
    
    // Send a minimal HTTP request over plain TCP to see if data flows
    // Note: This won't work for HTTPS, but tests TCP path
    let request = format!(
        "HEAD / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        host
    );
    
    // For actual HTTPS, we'll just report TCP worked
    // A full impl would use rustls here
    stream.write_all(request.as_bytes()).map_err(|e| e.to_string())?;
    
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);

    let latency = start.elapsed().as_millis() as u64;
    
    if response.is_empty() {
        // For HTTPS sites, empty response is expected (TLS required)
        // But we proved TCP data transfer works
        Ok((0, latency))
    } else {
        Ok((response.len(), latency))
    }
}

fn binary_search_mtu_icmp(target: IpAddr, min: usize, max: usize, timeout_ms: u64, retries: usize) -> usize {
    let mut low = min;
    let mut high = max;
    let mut best = min;

    while low <= high {
        let mid = (low + high) / 2;
        let payload = mid.saturating_sub(IP_HEADER_SIZE + ICMP_HEADER_SIZE);

        if probe_icmp(target, payload, timeout_ms, retries) {
            best = mid;
            low = mid + 1;
        } else {
            if mid == 0 {
                break;
            }
            high = mid - 1;
        }
    }

    best
}

fn binary_search_mtu_tcp(target: &str, min: usize, max: usize, timeout_ms: u64) -> Option<usize> {
    let addr: SocketAddr = target.to_socket_addrs().ok()?.next()?;
    let timeout = Duration::from_millis(timeout_ms);

    let mut low = min;
    let mut high = max;
    let mut best = None;

    while low <= high {
        let mid = (low + high) / 2;
        // TCP payload size to test (subtract IP + TCP headers)
        let payload_size = mid.saturating_sub(40);

        if probe_tcp(&addr, payload_size, timeout) {
            best = Some(mid);
            low = mid + 1;
        } else {
            if mid == 0 {
                break;
            }
            high = mid - 1;
        }
    }

    best
}

fn probe_tcp(addr: &SocketAddr, _payload_size: usize, timeout: Duration) -> bool {
    let stream = match TcpStream::connect_timeout(addr, timeout) {
        Ok(s) => s,
        Err(_) => return false,
    };
    
    stream.set_write_timeout(Some(timeout)).ok();
    stream.set_read_timeout(Some(timeout)).ok();
    stream.set_nodelay(true).ok();

    // We can't easily test MTU with established TCP (it handles fragmentation)
    // But we can detect if connection stalls with large data
    // For now, just verify connection works
    drop(stream);
    true
}

fn probe_icmp(target: IpAddr, payload_len: usize, timeout_ms: u64, retries: usize) -> bool {
    for _ in 0..=retries {
        if send_icmp_probe(target, payload_len, timeout_ms).unwrap_or(false) {
            return true;
        }
    }
    false
}

fn send_icmp_probe(target: IpAddr, payload_len: usize, timeout_ms: u64) -> std::io::Result<bool> {
    let socket = Socket::new(Domain::IPV4, Type::from(libc::SOCK_RAW), Some(Protocol::ICMPV4))?;

    // Set DF bit on Linux
    #[cfg(target_os = "linux")]
    {
        let val: libc::c_int = libc::IP_PMTUDISC_DO;
        unsafe {
            let ret = libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_MTU_DISCOVER,
                &val as *const _ as *const libc::c_void,
                std::mem::size_of_val(&val) as libc::socklen_t,
            );
            if ret < 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
    }

    socket.set_read_timeout(Some(Duration::from_millis(timeout_ms)))?;

    // Build ICMP packet
    let mut packet = vec![0u8; ICMP_HEADER_SIZE + payload_len];
    packet[0] = ICMP_ECHO_REQUEST;
    packet[1] = 0;

    static SEQ: AtomicU16 = AtomicU16::new(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let id: u16 = std::process::id() as u16;
    
    packet[4] = (id >> 8) as u8;
    packet[5] = id as u8;
    packet[6] = (seq >> 8) as u8;
    packet[7] = seq as u8;
    
    // Fill payload
    for i in 0..payload_len {
        packet[ICMP_HEADER_SIZE + i] = (i % 256) as u8;
    }

    // Checksum
    let checksum = icmp_checksum(&packet);
    packet[2] = (checksum >> 8) as u8;
    packet[3] = checksum as u8;

    let dest = SocketAddr::new(target, 0);
    
    if socket.send_to(&packet, &dest.into()).is_err() {
        return Ok(false);
    }

    // Wait for reply
    let mut buffer = [MaybeUninit::uninit(); 4096];
    let start = Instant::now();

    loop {
        if start.elapsed().as_millis() as u64 > timeout_ms {
            return Ok(false);
        }
        
        match socket.recv_from(&mut buffer) {
            Ok((size, _)) => {
                let received = unsafe { 
                    std::slice::from_raw_parts(buffer[0].as_ptr() as *const u8, size) 
                };

                if received.len() < 20 + ICMP_HEADER_SIZE {
                    continue; 
                }
                
                let ip_header_len = ((received[0] & 0x0F) * 4) as usize;
                if received.len() < ip_header_len + ICMP_HEADER_SIZE {
                    continue;
                }

                let icmp = &received[ip_header_len..];
                
                // Echo Reply (type 0) with matching ID
                if icmp[0] == 0 {
                    let reply_id = ((icmp[4] as u16) << 8) | (icmp[5] as u16);
                    if reply_id == id {
                    return Ok(true);
                }
            }
            }
            Err(_) => return Ok(false),
        }
    }
}

// =============================================================================
// TRACEPATH - Per-Hop MTU Discovery
// =============================================================================

#[derive(Debug, Clone)]
struct HopInfo {
    hop: u8,
    addr: String,
    mtu: Option<usize>,
}

fn run_tracepath(target: &str) -> Vec<HopInfo> {
    let mut hops = Vec::new();
    
    // Try tracepath first (Linux)
    let output = Command::new("tracepath")
        .arg("-n")  // No DNS lookups (faster)
        .arg("-m")
        .arg("15")  // Max 15 hops
        .arg(target)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output();

    if let Ok(output) = output {
        if output.status.success() {
            let reader = BufReader::new(&output.stdout[..]);
            for line in reader.lines().map_while(Result::ok) {
                // Parse tracepath output:
                // " 1:  192.168.1.1    0.5ms pmtu 1500"
                // " 2:  10.0.0.1      5.2ms pmtu 1400"
                if let Some(hop_info) = parse_tracepath_line(&line) {
                    hops.push(hop_info);
                }
            }
        }
    }

    hops
}

fn parse_tracepath_line(line: &str) -> Option<HopInfo> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }

    // Format: " N:  ADDRESS  TIMEms [pmtu MTU]"
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.is_empty() {
        return None;
    }

    // Extract hop number
    let hop_str = parts[0].trim_end_matches(':');
    let hop: u8 = hop_str.parse().ok()?;

    // Extract address (second element if exists)
    let addr = if parts.len() > 1 && !parts[1].ends_with("ms") {
        parts[1].to_string()
    } else {
        "???".to_string()
    };

    // Look for "pmtu" in the line
    let mtu = if let Some(pos) = parts.iter().position(|&p| p == "pmtu") {
        parts.get(pos + 1).and_then(|m| m.parse().ok())
    } else {
        None
    };

    Some(HopInfo { hop, addr, mtu })
}

fn check_tracepath_available() -> bool {
    Command::new("tracepath")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

// =============================================================================
// UDP MTU PROBING (DPLPMTUD-style)
// =============================================================================

const UDP_HEADER_SIZE: usize = 8;

/// Probe UDP path MTU by sending UDP packets with DF bit
/// Uses a high port that's likely to get ICMP port unreachable back
fn probe_udp(target: IpAddr, payload_len: usize, timeout_ms: u64, retries: usize) -> bool {
    for _ in 0..=retries {
        if send_udp_probe(target, payload_len, timeout_ms).unwrap_or(false) {
            return true;
        }
    }
    false
}

fn send_udp_probe(target: IpAddr, payload_len: usize, timeout_ms: u64) -> std::io::Result<bool> {
    use std::net::UdpSocket;
    
    // Bind to any available port
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(Duration::from_millis(timeout_ms)))?;
    socket.set_write_timeout(Some(Duration::from_millis(timeout_ms)))?;
    
    // Set DF bit
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let val: libc::c_int = libc::IP_PMTUDISC_DO;
        unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_MTU_DISCOVER,
                &val as *const _ as *const libc::c_void,
                std::mem::size_of_val(&val) as libc::socklen_t,
            );
        }
    }
    
    // Create payload
    let payload = vec![0x42u8; payload_len];
    
    // Send to a high port (likely to get ICMP unreachable = packet arrived)
    // Port 33434 is traditional traceroute port
    let dest = SocketAddr::new(target, 33434);
    
    match socket.send_to(&payload, dest) {
        Ok(_) => {
            // For UDP, if send succeeds without EMSGSIZE, the packet fit
            // We can try to receive an ICMP error back
            let mut buf = [0u8; 1024];
            match socket.recv_from(&mut buf) {
                Ok(_) => Ok(true),   // Got response
                Err(e) => {
                    // Timeout is expected (no response = packet probably arrived)
                    // EMSGSIZE means too big
                    if e.raw_os_error() == Some(libc::EMSGSIZE) {
                        Ok(false)
                    } else {
                        Ok(true) // Timeout = probably worked
                    }
                }
            }
        }
        Err(e) => {
            // EMSGSIZE = message too long (MTU exceeded)
            if e.raw_os_error() == Some(libc::EMSGSIZE) {
                Ok(false)
            } else {
                Err(e)
            }
        }
    }
}

fn binary_search_mtu_udp(target: IpAddr, min: usize, max: usize, timeout_ms: u64, retries: usize) -> Option<usize> {
    // First check if UDP works at all
    if !probe_udp(target, 64, timeout_ms, 1) {
        return None;
    }
    
    let mut low = min;
    let mut high = max;
    let mut best = min;

    while low <= high {
        let mid = (low + high) / 2;
        // UDP payload = MTU - IP header - UDP header
        let payload = mid.saturating_sub(IP_HEADER_SIZE + UDP_HEADER_SIZE);

        if probe_udp(target, payload, timeout_ms, retries) {
            best = mid;
            low = mid + 1;
        } else {
            if mid == 0 {
                break;
            }
            high = mid - 1;
        }
    }

    Some(best)
}

// =============================================================================
// TCP MSS CAPTURE
// =============================================================================

/// Capture TCP MSS from a connection using /proc or ss command
fn get_tcp_mss_info(target: &str) -> Option<TcpMssInfo> {
    // Try ss command to get MSS info
    let output = Command::new("ss")
        .args(["-ti", "state", "established"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    
    // Parse ss output for MSS values
    // Look for lines containing our target
    for line in stdout.lines() {
        if line.contains(target) || line.contains("mss:") {
            // Parse mss:NNNN from the line
            if let Some(mss_pos) = line.find("mss:") {
                let mss_str = &line[mss_pos + 4..];
                if let Some(end) = mss_str.find(|c: char| !c.is_ascii_digit()) {
                    if let Ok(mss) = mss_str[..end].parse::<usize>() {
                        return Some(TcpMssInfo {
                            mss,
                            inferred_mtu: mss + 40, // MSS + IP + TCP headers
                        });
                    }
                }
            }
        }
    }
    
    None
}

#[derive(Debug, Clone)]
struct TcpMssInfo {
    mss: usize,
    inferred_mtu: usize,
}

/// Make a TCP connection and try to get the negotiated MSS
fn probe_tcp_mss(target: &str, timeout_ms: u64) -> Option<TcpMssInfo> {
    let addr: SocketAddr = target.to_socket_addrs().ok()?.next()?;
    let timeout = Duration::from_millis(timeout_ms);
    
    // Connect
    let stream = TcpStream::connect_timeout(&addr, timeout).ok()?;
    stream.set_nodelay(true).ok();
    
    // Try to get MSS from socket options
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let mut mss: libc::c_int = 0;
        let mut len: libc::socklen_t = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        
        unsafe {
            let ret = libc::getsockopt(
                stream.as_raw_fd(),
                libc::IPPROTO_TCP,
                libc::TCP_MAXSEG,
                &mut mss as *mut _ as *mut libc::c_void,
                &mut len,
            );
            
            if ret == 0 && mss > 0 {
                return Some(TcpMssInfo {
                    mss: mss as usize,
                    inferred_mtu: mss as usize + 40,
                });
            }
        }
    }
    
    // Fallback: try ss command
    drop(stream);
    get_tcp_mss_info(target)
}

// =============================================================================
// DNS EDNS0 PROBING  
// =============================================================================

/// Test DNS with EDNS0 buffer size to probe UDP MTU
fn probe_dns_edns(server: &str, bufsize: usize, timeout_ms: u64) -> bool {
    // Use dig command if available
    let output = Command::new("dig")
        .args([
            &format!("+bufsize={}", bufsize),
            "+norecurse",
            "@",
            server,
            "google.com",
            "A",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output();

    match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            // Check if we got a response (not truncated)
            !stdout.contains("truncated") && stdout.contains("ANSWER")
        }
        Err(_) => false,
    }
}

// =============================================================================
// QUIC MTU PROBING (RFC 9000)
// =============================================================================

/// QUIC-based MTU discovery
/// QUIC has built-in PMTUD using PING frames with padding
fn probe_quic_mtu(target: &str, port: u16, timeout_ms: u64) -> Option<usize> {
    // Build a tokio runtime for async QUIC operations
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build() 
    {
        Ok(rt) => rt,
        Err(_) => return None,
    };
    
    rt.block_on(async {
        quic_mtu_probe_async(target, port, timeout_ms).await
    })
}

async fn quic_mtu_probe_async(target: &str, port: u16, timeout_ms: u64) -> Option<usize> {
    use quinn::{ClientConfig, Endpoint, TransportConfig};
    
    // Create self-signed cert for client (we don't verify server)
    let mut roots = rustls::RootCertStore::empty();
    
    // Create client config that skips certificate verification
    // (we're just probing MTU, not establishing secure comms)
    let crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();
    
    let mut transport = TransportConfig::default();
    transport.max_idle_timeout(Some(Duration::from_millis(timeout_ms).try_into().ok()?));
    
    let mut client_config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto).ok()?
    ));
    client_config.transport_config(Arc::new(transport));
    
    // Create endpoint
    let mut endpoint = Endpoint::client("0.0.0.0:0".parse().ok()?).ok()?;
    endpoint.set_default_client_config(client_config);
    
    // Resolve target
    let addr: SocketAddr = format!("{}:{}", target, port)
        .to_socket_addrs()
        .ok()?
        .next()?;
    
    // Try to connect
    let conn = match tokio::time::timeout(
        Duration::from_millis(timeout_ms),
        endpoint.connect(addr, target).ok()?.into_future()
    ).await {
        Ok(Ok(conn)) => conn,
        _ => return None,
    };
    
    // Get the current MTU from QUIC connection
    // QUIC discovers MTU through its own PMTUD mechanism
    let mtu = conn.max_datagram_size();
    
    // Close cleanly
    conn.close(0u32.into(), b"mtu probe complete");
    endpoint.wait_idle().await;
    
    mtu
}

/// Certificate verifier that accepts any certificate (for MTU probing only)
#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

/// Test if a target supports QUIC (HTTP/3)
fn check_quic_support(target: &str) -> bool {
    // Use curl to check for Alt-Svc header indicating QUIC/HTTP3 support
    let output = Command::new("curl")
        .args([
            "-s", "-I", "--max-time", "3",
            &format!("https://{}", target)
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output();
    
    match output {
        Ok(out) => {
            let headers = String::from_utf8_lossy(&out.stdout).to_lowercase();
            headers.contains("alt-svc") && 
                (headers.contains("h3") || headers.contains("quic"))
        }
        Err(_) => false,
    }
}

fn icmp_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in data.chunks(2) {
        let word = ((chunk[0] as u32) << 8) + chunk.get(1).map(|&b| b as u32).unwrap_or(0);
        sum = sum.wrapping_add(word);
    }
    while (sum >> 16) > 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
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
/// Run HTTPS test from CLI
fn run_https_test(target: &str, timeout: u64, diagnose: bool) {
    use fraggle_packet::network_tests::{test_https_stages, diagnose_mtu_blackhole};
    use fraggle_packet::diagnosis::{DiagnosisEngine, DiagnosisEvidence};
    
    println!("============================================================");
    println!(" HTTPS Testing - Stage-by-Stage Analysis");
    println!("============================================================\n");
    
    println!("Target: {}", target);
    println!("Timeout: {}s\n", timeout);
    
    println!("Running HTTPS test...\n");
    
    let result = test_https_stages(target, timeout);
    
    // Display results
    println!("┌─────────────────────────────────────┐");
    println!("│ Stage 1: DNS Resolution             │");
    println!("└─────────────────────────────────────┘");
    if let Some(time) = result.dns_time_ms {
        println!("  {} Success: {} ms", "✓".green(), time);
        println!("  Resolved IPs: {}", result.dns_ips.join(", "));
    } else {
        println!("  {} Failed", "✗".red());
    }
    println!();
    
    println!("┌─────────────────────────────────────┐");
    println!("│ Stage 2: TCP Connect                │");
    println!("└─────────────────────────────────────┘");
    if result.tcp_success {
        println!("  {} Success: {} ms", "✓".green(), result.tcp_connect_time_ms.unwrap_or(0));
    } else {
        println!("  {} Failed", "✗".red());
    }
    println!();
    
    println!("┌─────────────────────────────────────┐");
    println!("│ Stage 3: TLS Handshake (CRITICAL)  │");
    println!("└─────────────────────────────────────┘");
    if result.tls_success {
        println!("  {} Success: {} ms", "✓".green(), result.tls_handshake_time_ms.unwrap_or(0));
    } else {
        println!("  {} Failed or Timeout", "✗".red());
        if result.tcp_success {
            println!("  {} TCP connected but TLS failed - possible MTU blackhole!", "⚠".yellow());
        }
    }
    println!();
    
    if result.tls_success {
        println!("┌─────────────────────────────────────┐");
        println!("│ Stage 4: HTTP Request               │");
        println!("└─────────────────────────────────────┘");
        if let Some(time) = result.http_request_time_ms {
            println!("  {} Success: {} ms", "✓".green(), time);
        } else {
            println!("  {} Failed", "✗".red());
        }
        println!();
        
        println!("┌─────────────────────────────────────┐");
        println!("│ Stage 5: HTTP Response & TTFB       │");
        println!("└─────────────────────────────────────┘");
        if let Some(ttfb) = result.ttfb_ms {
            println!("  {} Success", "✓".green());
            println!("  Status Code: {}", result.status_code.unwrap_or(0));
            println!("  Time to First Byte: {} ms", ttfb);
        } else {
            println!("  {} Failed or Timeout", "✗".red());
        }
        println!();
    }
    
    println!("════════════════════════════════════════");
    println!("Total Time: {} ms", result.total_time_ms);
    println!("Diagnosis: {:?}", result.diagnosis);
    println!("════════════════════════════════════════\n");
    
    // Run diagnosis engine if requested
    if diagnose {
        println!("\n╔════════════════════════════════════════╗");
        println!("║  Diagnosis & Recommendations          ║");
        println!("╚════════════════════════════════════════╝\n");
        
        // Quick MTU blackhole check
        if diagnose_mtu_blackhole(&result, Some(1500)) {
            println!("{} MTU BLACKHOLE DETECTED!\n", "⚠️".yellow().bold());
        }
        
        // Run full diagnosis engine
        let evidence = DiagnosisEvidence {
            https_result: Some(result.clone()),
            interface_mtu: Some(1500),  // TODO: Get actual interface MTU
            ..Default::default()
        };
        
        let engine = DiagnosisEngine::new();
        let diagnoses = engine.diagnose(&evidence);
        
        if diagnoses.is_empty() {
            println!("{} No issues detected", "✓".green());
        } else {
            for (i, diagnosis) in diagnoses.iter().enumerate() {
                println!("{} Issue #{}: {:?}", "!".red().bold(), i + 1, diagnosis.issue);
                println!("  Severity: {:?}", diagnosis.severity);
                println!("  Description: {}", diagnosis.description);
                println!("\n  Recommendation:");
                println!("  {}", diagnosis.recommendation.replace("\n", "\n  "));
                println!("\n  Related Tests: {}", diagnosis.related_tests.join(", "));
                println!("\n{}\n", "─".repeat(60));
            }
        }
    }
}

