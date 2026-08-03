//! GAP-064: synchronized clock and one-way event-correlation guard (`clock-guard`).

use colored::*;
use std::time::Duration;

use fraggle_packet::network_tests::clock_guard::{verify, SkewOutcome, DEFAULT_MAX_SKEW_MS};

#[derive(clap::Args, Debug)]
pub struct ClockGuardArgs {
    /// Label for this node in reports.
    #[arg(long, default_value = "local")]
    pub node_label: String,

    #[arg(long, default_value = "time.apple.com")]
    pub ntp_server: String,

    #[arg(long, default_value_t = DEFAULT_MAX_SKEW_MS)]
    pub max_skew_ms: f64,

    #[arg(long, default_value_t = 5)]
    pub timeout_secs: u64,

    #[arg(long)]
    pub json: bool,
}

pub fn run(args: &ClockGuardArgs) {
    let verdict = verify(&args.node_label, &args.ntp_server, args.max_skew_ms, Duration::from_secs(args.timeout_secs));

    if args.json {
        println!("{}", serde_json::to_string_pretty(&verdict).unwrap());
        return;
    }

    println!("{}", format!("== Clock guard: {} ==", verdict.node_label).cyan().bold());
    match &verdict.offset {
        Some(o) => println!("  offset: {:.3}ms +/- {:.3}ms (against {})", o.offset_ms, o.uncertainty_ms, verdict.ntp_server),
        None => println!("  offset: {}", "unavailable".yellow()),
    }
    println!("  max skew threshold: {:.1}ms", verdict.max_skew_ms);
    let outcome_str = match verdict.outcome {
        SkewOutcome::WithinTolerance => "WithinTolerance".green(),
        SkewOutcome::ExceedsTolerance => "ExceedsTolerance".red().bold(),
    };
    println!("  outcome: {}", outcome_str);
    println!("  permits one-way claim: {}", verdict.permits_one_way_claim());
    println!("  wall_clock_unix_ms: {}", verdict.timestamp.wall_clock_unix_ms);
    println!("  monotonic_nanos_since_process_start: {}", verdict.timestamp.monotonic_nanos_since_process_start);
    println!("  {}", verdict.explanation.dimmed());
}
