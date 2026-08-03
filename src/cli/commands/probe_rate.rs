//! GAP-021: probe-rate artifact detection CLI (`probe-rate`).

use colored::*;
use std::net::IpAddr;

use fraggle_packet::network_tests::probe_rate::{
    analyze, sample_icmp_cadence, CorroborationProbe, TargetCadenceComparison,
};
use fraggle_packet::probe::{resolve_hostname, test_tcp_connect};

#[derive(clap::Args, Debug)]
pub struct ProbeRateArgs {
    /// Gateway IP/hostname (first hop). No default: guessing wrong here
    /// silently measures the wrong hop.
    #[arg(long)]
    pub gateway: String,

    /// Remote/Internet target IP or hostname.
    #[arg(long)]
    pub remote: String,

    /// Normal probe rate in probes/sec.
    #[arg(long, default_value_t = 1.0)]
    pub normal_rate_hz: f64,

    /// Elevated probe rate in probes/sec. Kept modest by default -- this is
    /// meant to surface control-plane rate limiting, not to flood anything.
    #[arg(long, default_value_t = 5.0)]
    pub elevated_rate_hz: f64,

    /// Number of samples per cadence per target.
    #[arg(long, default_value_t = 10)]
    pub count: usize,

    /// TCP port used for the non-ICMP corroboration probe against the
    /// remote target.
    #[arg(long, default_value_t = 443)]
    pub tcp_port: u16,

    #[arg(long, default_value_t = 1000)]
    pub timeout_ms: u64,

    #[arg(long)]
    pub json: bool,
}

pub fn run(args: &ProbeRateArgs) {
    let gateway_ip = match resolve_hostname(&args.gateway) {
        Ok(ip) => ip,
        Err(e) => {
            eprintln!(
                "{} could not resolve gateway {}: {}",
                "✗".red(),
                args.gateway,
                e
            );
            std::process::exit(1);
        }
    };
    let remote_ip: IpAddr = match resolve_hostname(&args.remote) {
        Ok(ip) => ip,
        Err(e) => {
            eprintln!(
                "{} could not resolve remote {}: {}",
                "✗".red(),
                args.remote,
                e
            );
            std::process::exit(1);
        }
    };

    if !args.json {
        println!(
            "Sampling gateway={} remote={} at {:.1}Hz then {:.1}Hz ({} samples each)...",
            gateway_ip, remote_ip, args.normal_rate_hz, args.elevated_rate_hz, args.count
        );
    }

    let gateway = TargetCadenceComparison {
        label: "gateway".to_string(),
        normal: sample_icmp_cadence(gateway_ip, args.normal_rate_hz, args.count, args.timeout_ms),
        elevated: sample_icmp_cadence(
            gateway_ip,
            args.elevated_rate_hz,
            args.count,
            args.timeout_ms,
        ),
    };
    let remote = TargetCadenceComparison {
        label: "remote".to_string(),
        normal: sample_icmp_cadence(remote_ip, args.normal_rate_hz, args.count, args.timeout_ms),
        elevated: sample_icmp_cadence(
            remote_ip,
            args.elevated_rate_hz,
            args.count,
            args.timeout_ms,
        ),
    };

    // Non-ICMP corroboration at the elevated cadence: if the remote ICMP
    // spike is a real application-latency effect it should also show up
    // here; if it's ICMP-only rate limiting, TCP connect timing should stay
    // near baseline.
    let mut tcp_samples = Vec::with_capacity(args.count);
    let interval = std::time::Duration::from_secs_f64(1.0 / args.elevated_rate_hz.max(0.01));
    for _ in 0..args.count {
        let start = std::time::Instant::now();
        if let Ok(ms) =
            test_tcp_connect(&format!("{}:{}", remote_ip, args.tcp_port), args.timeout_ms)
        {
            tcp_samples.push(ms as f64);
        }
        let spent = start.elapsed();
        if spent < interval {
            std::thread::sleep(interval - spent);
        }
    }
    let tcp = CorroborationProbe {
        protocol: "tcp_connect".to_string(),
        port: args.tcp_port,
        rate_hz: args.elevated_rate_hz,
        avg_ms: if tcp_samples.is_empty() {
            None
        } else {
            Some(tcp_samples.iter().sum::<f64>() / tcp_samples.len() as f64)
        },
        samples: tcp_samples.len(),
    };

    let report = analyze(gateway, remote, tcp);

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
        return;
    }

    print_human(&report);
}

fn print_human(report: &fraggle_packet::network_tests::probe_rate::ProbeRateReport) {
    println!();
    for (label, cmp) in [("Gateway", &report.gateway), ("Remote", &report.remote)] {
        println!("{}", format!("== {} ==", label).cyan().bold());
        println!(
            "  normal   {:.1}Hz: avg={} stddev={} loss={:.1}%",
            cmp.normal.rate_hz,
            fmt_ms(cmp.normal.avg_ms()),
            fmt_ms(cmp.normal.stddev_ms()),
            cmp.normal.loss_percent()
        );
        println!(
            "  elevated {:.1}Hz: avg={} stddev={} loss={:.1}%",
            cmp.elevated.rate_hz,
            fmt_ms(cmp.elevated.avg_ms()),
            fmt_ms(cmp.elevated.stddev_ms()),
            cmp.elevated.loss_percent()
        );
        if cmp.spiked() {
            println!("  {}", "spiked at elevated cadence".yellow().bold());
        }
    }
    println!();
    println!(
        "  TCP corroboration @ {:.1}Hz: avg={} ({} samples)",
        report.tcp_corroboration_elevated.rate_hz,
        fmt_ms(report.tcp_corroboration_elevated.avg_ms),
        report.tcp_corroboration_elevated.samples
    );
    println!();
    if report.probable_icmp_policing {
        println!(
            "  {}",
            "PROBABLE ICMP POLICING/BATCHING (correlated across gateway + remote)"
                .red()
                .bold()
        );
    }
    if report.application_latency_confirmed {
        println!(
            "  {}",
            "APPLICATION-LATENCY EFFECT CONFIRMED (TCP-corroborated)"
                .red()
                .bold()
        );
    }
    for n in &report.notes {
        println!("  * {}", n);
    }
    println!();
}

fn fmt_ms(v: Option<f64>) -> String {
    v.map(|v| format!("{:.2}ms", v))
        .unwrap_or_else(|| "unavailable".to_string())
}
