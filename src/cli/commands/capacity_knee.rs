use colored::*;

use fraggle_packet::network_tests::capacity_knee::{
    build_report, CrossValidation, DriftBracket, KneeReport, KneeVerdict, SweepPoint,
};

#[derive(clap::Args, Debug)]
pub struct CapacityKneeArgs {
    /// Interface the sweep was bound to. Required rather than inferred: the
    /// default route on this class of machine is frequently a VPN tunnel, and a
    /// knee measured through a tunnel describes the tunnel.
    #[arg(long)]
    pub interface: String,

    /// Native-bidirectional sweep points as JSON (array of SweepPoint).
    #[arg(long)]
    pub native_points: Option<String>,

    /// Application-method sweep points as JSON. Without these the native knee
    /// is reported unconfirmed rather than established.
    #[arg(long)]
    pub application_points: Option<String>,

    /// Opening control's combined Mbps, for the endpoint-drift bracket.
    #[arg(long)]
    pub opening_combined_mbps: Option<f64>,

    /// Closing control's combined Mbps. Both halves are required; drift cannot
    /// be computed from one side.
    #[arg(long)]
    pub closing_combined_mbps: Option<f64>,

    /// Idle first-hop latency for comparison against the loaded points.
    #[arg(long)]
    pub idle_latency_ms: Option<f64>,

    /// Load the captured PC13 field evidence instead of reading files, for
    /// offline exercise of the verdict logic.
    #[arg(long)]
    pub inject_fixture: bool,

    #[arg(long)]
    pub json: bool,
}

fn read_points(path: &str) -> Vec<SweepPoint> {
    match std::fs::read_to_string(path) {
        Ok(t) => match serde_json::from_str(&t) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{} {} is not a valid SweepPoint array: {}", "✗".red(), path, e);
                std::process::exit(1);
            }
        },
        Err(e) => {
            eprintln!("{} could not read {}: {}", "✗".red(), path, e);
            std::process::exit(1);
        }
    }
}

fn pt(offered: f64, up: f64, down: f64, lat: f64, idx: usize) -> SweepPoint {
    SweepPoint {
        offered_mbps: offered,
        up_mbps: Some(up),
        down_mbps: Some(down),
        loaded_latency_ms: Some(lat),
        listener_label: Some(format!("listener-{}", idx)),
        execution_index: idx,
        rejected: None,
    }
}

/// PC13's measured sweeps. Native plateaus while the application method shows
/// upload collapsing, which is exactly the pair GAP-070 must keep distinct.
fn field_fixture() -> (Vec<SweepPoint>, Vec<SweepPoint>) {
    (
        vec![
            pt(40.0, 40.0, 40.0, 8.0, 0),
            pt(60.0, 59.0, 59.0, 9.0, 1),
            pt(70.0, 69.0, 68.0, 17.0, 2),
            pt(85.0, 70.0, 68.0, 22.0, 3),
            pt(100.0, 71.0, 68.0, 28.0, 4),
        ],
        vec![
            pt(40.0, 40.0, 40.0, 10.0, 0),
            pt(60.0, 58.0, 59.0, 12.0, 1),
            pt(70.0, 45.0, 72.0, 56.0, 2),
            pt(85.0, 44.0, 72.0, 68.0, 3),
        ],
    )
}

fn render_verdict(label: &str, v: &KneeVerdict) {
    print!("  {:<14} ", label);
    match v {
        KneeVerdict::CapacityPlateau { detail, .. } => {
            println!("{}", "capacity plateau".yellow());
            println!("      {}", detail);
        }
        KneeVerdict::DirectionalUnfairness { detail, .. } => {
            println!("{}", "directional unfairness".red());
            println!("      {}", detail);
        }
        KneeVerdict::NoKneeWithinTestedRange { highest_tested_mbps } => {
            println!("{}", "no knee within tested range".green());
            println!(
                "      combined throughput tracked offered load through the highest tested rate \
                 ({:.0} Mbps per direction); no plateau was reached, so no knee is reported",
                highest_tested_mbps
            );
        }
        KneeVerdict::InsufficientPoints { usable, required } => {
            println!("{}", "insufficient points".yellow());
            println!("      {} usable point(s); {} required", usable, required);
        }
    }
}

fn render(r: &KneeReport) {
    println!("\n== Capacity / Latency Knee (GAP-070) ==");
    println!("  interface: {}", r.interface);
    println!(
        "  idle first-hop latency: {}",
        match r.idle_latency_ms {
            Some(l) => format!("{:.1} ms", l),
            None => "unavailable".to_string(),
        }
    );
    println!();
    render_verdict("native:", &r.native_verdict);
    match &r.application_verdict {
        Some(v) => render_verdict("application:", v),
        None => println!("  {:<14} {}", "application:", "not run".yellow()),
    }

    println!();
    match &r.cross_validation {
        CrossValidation::Reproduced { native_knee_mbps, application_knee_mbps } => println!(
            "  cross-validation: {} native at {:.0} Mbps, application at {:.0} Mbps",
            "REPRODUCED".green(),
            native_knee_mbps,
            application_knee_mbps
        ),
        CrossValidation::NotReproduced { detail } => {
            println!("  cross-validation: {}", "NOT REPRODUCED".red());
            println!("      {}", detail);
        }
        CrossValidation::NotAttempted { reason } => {
            println!("  cross-validation: {} {}", "NOT ATTEMPTED".yellow(), reason);
        }
    }

    println!("  endpoint drift: {}", r.drift.statement());

    if !r.rejected_points.is_empty() {
        println!("\n  rejected points (excluded, not scored as zero):");
        for (rate, why) in &r.rejected_points {
            println!("    {:.0} Mbps: {}", rate, why);
        }
    }

    println!();
    match &r.established_claim {
        Some(c) => {
            println!("  {} {}", "ESTABLISHED:".green(), c);
        }
        None => {
            println!(
                "  {} no knee may be reported as established: a finding requires reproduction by a \
                 second method AND an endpoint that did not drift underneath the sweep",
                "UNCONFIRMED:".yellow()
            );
        }
    }
}

pub fn run(args: &CapacityKneeArgs) {
    let (native, application) = if args.inject_fixture {
        field_fixture()
    } else {
        (
            args.native_points.as_deref().map(read_points).unwrap_or_default(),
            args.application_points.as_deref().map(read_points).unwrap_or_default(),
        )
    };

    if native.is_empty() {
        eprintln!(
            "{} nothing to analyze: pass --native-points <json> (and ideally \
             --application-points for cross-validation), or --inject-fixture",
            "✗".red()
        );
        std::process::exit(2);
    }

    let drift = if args.inject_fixture {
        DriftBracket {
            opening_combined_mbps: Some(140.0),
            closing_combined_mbps: Some(138.0),
        }
    } else {
        DriftBracket {
            opening_combined_mbps: args.opening_combined_mbps,
            closing_combined_mbps: args.closing_combined_mbps,
        }
    };
    let idle = if args.inject_fixture { Some(8.0) } else { args.idle_latency_ms };

    let report = build_report(&args.interface, native, application, drift, idle);

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report).unwrap_or_default());
        return;
    }
    render(&report);
}
