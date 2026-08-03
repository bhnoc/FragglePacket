use colored::*;

use fraggle_packet::network_tests::reference_endpoint::{
    calibrate, evaluate, ResourceLimits, ResultAcceptance, ServerHealth,
};

#[derive(clap::Args, Debug)]
pub struct ReferenceEndpointArgs {
    /// Path to endpoint health telemetry JSON captured during the client run.
    /// Without it, acceptance is undetermined rather than assumed good.
    #[arg(long)]
    pub health: Option<String>,

    /// Run calibration, which additionally requires a verified clock offset
    /// before the endpoint may back any one-way metric.
    #[arg(long)]
    pub calibrate: bool,

    /// Maximum tolerated clock offset in ms for calibration to pass.
    #[arg(long, default_value_t = 50.0)]
    pub max_skew_ms: f64,

    /// Report the resource limits this endpoint enforces on itself.
    #[arg(long)]
    pub show_limits: bool,

    /// Check whether a hypothetical session would be admitted, as
    /// active_sessions,duration_secs,rate_mbps
    #[arg(long)]
    pub admit: Option<String>,

    #[arg(long)]
    pub json: bool,
}

pub fn run(args: &ReferenceEndpointArgs) {
    let limits = ResourceLimits::default();

    if args.show_limits {
        if args.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&limits).unwrap_or_default()
            );
        } else {
            println!("\n== Reference endpoint limits ==");
            println!(
                "  max concurrent sessions: {}",
                limits.max_concurrent_sessions
            );
            println!("  max session seconds:     {}", limits.max_session_secs);
            println!(
                "  max rate:                {:.1} Mbps",
                limits.max_rate_mbps
            );
            println!("  max retained results:    {}", limits.max_retained_results);
        }
        return;
    }

    if let Some(spec) = &args.admit {
        let parts: Vec<&str> = spec.split(',').collect();
        if parts.len() != 3 {
            eprintln!(
                "{} --admit expects active_sessions,duration_secs,rate_mbps",
                "✗".red()
            );
            std::process::exit(2);
        }
        let active: u32 = parts[0].trim().parse().unwrap_or(0);
        let secs: u32 = parts[1].trim().parse().unwrap_or(0);
        let rate: f64 = parts[2].trim().parse().unwrap_or(0.0);
        match limits.admit(active, secs, rate) {
            Ok(()) => println!("{} session would be admitted", "✓".green()),
            Err(e) => {
                println!("{} session refused: {}", "✗".red(), e);
                std::process::exit(1);
            }
        }
        return;
    }

    let health: ServerHealth = match &args.health {
        Some(path) => match std::fs::read_to_string(path) {
            Ok(t) => match serde_json::from_str(&t) {
                Ok(h) => h,
                Err(e) => {
                    eprintln!("{} health telemetry is not valid JSON: {}", "✗".red(), e);
                    std::process::exit(1);
                }
            },
            Err(e) => {
                eprintln!("{} could not read {}: {}", "✗".red(), path, e);
                std::process::exit(1);
            }
        },
        None => ServerHealth::default(),
    };

    if args.calibrate {
        let report = calibrate(health, limits, args.max_skew_ms);
        if args.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&report).unwrap_or_default()
            );
            return;
        }
        println!("\n== Reference endpoint calibration ==");
        render_acceptance(&report.acceptance);
        println!("  clock verified: {}", report.clock_verified);
        for n in &report.notes {
            println!("  note: {}", n);
        }
        return;
    }

    let acceptance = evaluate(&health);
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({ "acceptance": acceptance }))
                .unwrap_or_default()
        );
        return;
    }
    println!("\n== Client result acceptance ==");
    render_acceptance(&acceptance);
}

fn render_acceptance(a: &ResultAcceptance) {
    match a {
        ResultAcceptance::Accepted => {
            println!(
                "  {} the endpoint was clean; the client result may be accepted",
                "ACCEPTED".green()
            );
        }
        ResultAcceptance::RejectedServerSide { reasons } => {
            println!(
                "  {} the endpoint, not the network, limited this run",
                "REJECTED".red()
            );
            for r in reasons {
                println!("    - {}", r);
            }
        }
        ResultAcceptance::Undetermined { missing } => {
            println!("  {} acceptance cannot be decided", "UNDETERMINED".yellow());
            println!("  missing endpoint telemetry:");
            for m in missing {
                println!("    - {}", m);
            }
            println!(
                "  an unread counter is not a healthy zero; collect these before accepting results"
            );
        }
    }
}
