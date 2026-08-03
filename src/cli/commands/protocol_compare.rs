use std::net::IpAddr;

use colored::*;

use fraggle_packet::network_tests::protocol_compare::{
    run_comparison, CompareConfig, ComparisonReport, HttpProtocol, LegResult,
    ProtocolComparisonResult,
};

#[derive(clap::Args, Debug)]
pub struct ProtocolCompareArgs {
    /// Target hostname to compare across protocols.
    pub host: String,

    /// Port to test.
    #[arg(long, default_value_t = 443)]
    pub port: u16,

    /// Path to request.
    #[arg(long, default_value = "/")]
    pub path: String,

    /// Protocols to test. Repeatable. Defaults to http1,http2,http3.
    #[arg(long = "protocol", value_parser = ["http1", "http2", "http3"])]
    pub protocols: Vec<String>,

    /// Force a specific resolved IP (GAP-012/GAP-017 endpoint normalization).
    #[arg(long = "force-ip")]
    pub force_ip: Option<IpAddr>,

    /// Bind to a specific interface. The default route on this class of
    /// machine is frequently a VPN tunnel; binding explicitly avoids
    /// silently measuring the tunnel instead of the network under test.
    #[arg(long)]
    pub interface: Option<String>,

    /// Per-leg timeout in seconds.
    #[arg(long, default_value_t = 10)]
    pub timeout_secs: u64,

    /// Upload payload size in bytes for the upload-only/simultaneous-upload legs.
    #[arg(long, default_value_t = 2_000_000)]
    pub upload_bytes: usize,

    /// Also run a simultaneous (bidirectional) phase per protocol, reported
    /// as separate fields from the directional legs -- never merged (GAP-004).
    #[arg(long)]
    pub simultaneous: bool,

    #[arg(long)]
    pub json: bool,
}

pub fn run(args: &ProtocolCompareArgs) {
    let protocols: Vec<HttpProtocol> = if args.protocols.is_empty() {
        vec![
            HttpProtocol::Http1,
            HttpProtocol::Http2,
            HttpProtocol::Http3,
        ]
    } else {
        args.protocols
            .iter()
            .map(|p| match p.as_str() {
                "http1" => HttpProtocol::Http1,
                "http2" => HttpProtocol::Http2,
                "http3" => HttpProtocol::Http3,
                _ => unreachable!("clap value_parser restricts this"),
            })
            .collect()
    };

    let cfg = CompareConfig {
        host: args.host.clone(),
        port: args.port,
        path: args.path.clone(),
        interface: args.interface.clone(),
        forced_ip: args.force_ip,
        timeout_secs: args.timeout_secs,
        upload_bytes: args.upload_bytes,
        protocols,
        run_simultaneous: args.simultaneous,
    };

    let report = run_comparison(&cfg);

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
    } else {
        print_human(&report);
    }
}

fn fmt_leg(label: &str, leg: Option<&LegResult>) {
    match leg {
        Some(l) => {
            let mbps = l.throughput_bps.map(|b| b / 1_000_000.0);
            println!(
                "    {:24} ip={:<16} status={:<5} throughput={} loss={:?}",
                label,
                l.connected_ip.clone().unwrap_or_else(|| "?".to_string()),
                l.http_status
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "-".to_string()),
                mbps.map(|m| format!("{:.2} Mbps", m))
                    .unwrap_or_else(|| "unavailable".to_string()),
                l.loss_indicator,
            );
            if l.redirect_count > 0 {
                println!(
                    "      followed {} redirect(s) to {}",
                    l.redirect_count,
                    l.final_url.clone().unwrap_or_else(|| "?".to_string())
                );
            }
            if let Some(e) = &l.error {
                println!("      {}", e.dimmed());
            }
        }
        None => println!("    {:24} not run", label),
    }
}

fn print_protocol(p: &ProtocolComparisonResult) {
    println!("  {}", format!("== {} ==", p.protocol).cyan().bold());
    if let Some(v) = &p.preflight_verdict {
        println!("    preflight: {}", v);
    }
    fmt_leg("download-only", p.download_only.as_ref());
    fmt_leg("upload-only", p.upload_only.as_ref());
    fmt_leg("simultaneous-download", p.simultaneous_download.as_ref());
    fmt_leg("simultaneous-upload", p.simultaneous_upload.as_ref());
    println!("    confidence: {:?}", p.confidence);
    for r in &p.confidence_reasons {
        println!("      - {}", r);
    }
}

fn print_human(report: &ComparisonReport) {
    println!(
        "protocol comparison host={} interface={}",
        report.host,
        report
            .interface
            .clone()
            .unwrap_or_else(|| "default".to_string())
    );
    if report.endpoint_mismatch {
        println!(
            "{} {}",
            "⚠ ENDPOINT MISMATCH:".red().bold(),
            report.endpoint_mismatch_detail.clone().unwrap_or_default()
        );
    }
    if report.redirected_to_different_host {
        println!(
            "{} {}",
            "⚠ REDIRECTED:".yellow().bold(),
            report.redirect_detail.clone().unwrap_or_default()
        );
    }
    for p in &report.protocols {
        print_protocol(p);
    }
}
