use colored::*;

use fraggle_packet::network_tests::bufferbloat::{
    run_bufferbloat, BufferbloatConfig, BufferbloatReport, PhaseLatency,
};

#[derive(clap::Args, Debug)]
pub struct BufferbloatArgs {
    /// Interface to bind (e.g. en0). Strongly recommended: the default
    /// route on this class of machine is frequently a VPN tunnel, and an
    /// unbound run would measure the tunnel, not the network under test.
    #[arg(long)]
    pub interface: Option<String>,

    /// Per-phase max duration in seconds, passed to networkQuality's -M.
    #[arg(long, default_value_t = 10)]
    pub duration_secs: u64,

    #[arg(long)]
    pub json: bool,
}

pub fn run(args: &BufferbloatArgs) {
    let route = fraggle_packet::load_guard::detect_default_route().ok();
    let default_route_is_tunnel = route.as_ref().map(|r| r.is_tunnel).unwrap_or(false);

    let interface = args
        .interface
        .clone()
        .or_else(|| route.map(|r| r.interface));

    if default_route_is_tunnel && args.interface.is_none() {
        eprintln!(
            "{} default route is a VPN tunnel and no --interface was given; results describe the tunnel, not the physical network.",
            "⚠".yellow()
        );
    }

    let cfg = BufferbloatConfig {
        interface,
        default_route_is_tunnel,
        max_duration_secs: args.duration_secs,
    };

    let report = run_bufferbloat(&cfg);

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
    } else {
        print_human(&report);
    }
}

fn fmt_opt_f64(v: Option<f64>, suffix: &str) -> String {
    match v {
        Some(x) => format!("{:.2}{}", x, suffix),
        None => "unavailable".to_string(),
    }
}

fn print_phase(label: &str, phase: &PhaseLatency) {
    println!(
        "  {:16} responsiveness={} throughput={}",
        label,
        fmt_opt_f64(phase.responsiveness_rpm, " RPM"),
        fmt_opt_f64(phase.throughput_bps.map(|b| b / 1_000_000.0), " Mbps"),
    );
}

fn print_human(report: &BufferbloatReport) {
    println!(
        "[{}] bufferbloat interface={} endpoint={} tool={}",
        if report.tool_available {
            "OK".green().bold().to_string()
        } else {
            "UNAVAILABLE".red().bold().to_string()
        },
        report
            .interface
            .clone()
            .unwrap_or_else(|| "default".to_string()),
        report
            .test_endpoint
            .clone()
            .unwrap_or_else(|| "unavailable".to_string()),
        report.measurement_tool,
    );
    if report.default_route_is_tunnel {
        println!("  {} default route is a VPN tunnel", "⚠".yellow());
    }
    if !report.tool_available {
        println!(
            "  {}",
            report
                .unavailable_reason
                .clone()
                .unwrap_or_default()
                .dimmed()
        );
        return;
    }
    println!("  idle base_rtt={}", fmt_opt_f64(report.base_rtt_ms, "ms"));
    print_phase("upload-loaded", &report.upload_loaded);
    print_phase("download-loaded", &report.download_loaded);
    print_phase("simultaneous", &report.simultaneous);
    match report.responsiveness_grade {
        Some(g) => println!("  responsiveness grade: {:?}", g),
        None => println!("  responsiveness grade: unavailable (not computable from this run)"),
    }
    if let Some(reason) = &report.unavailable_reason {
        println!(
            "  {} some phases did not complete: {}",
            "⚠".yellow(),
            reason
        );
    }
}
