//! GAP-065: expected-policy and service-reachability manifest (`policy-manifest`).

use colored::*;
use std::fs;
use std::time::Duration;

use fraggle_packet::network_tests::policy_manifest::{
    DriftVerdict, ObservedOutcome, PolicyEntry, PolicyManifest, ReportMode,
};

#[derive(clap::Args, Debug)]
pub struct PolicyManifestArgs {
    /// Path to a JSON array of PolicyEntry. This is the entire allowlist
    /// -- no destination outside this file is ever contacted.
    #[arg(long)]
    pub manifest_file: String,

    #[arg(long, default_value_t = 3)]
    pub timeout_secs: u64,

    /// Redact internal hostnames/ports for an attendee-facing report.
    #[arg(long)]
    pub attendee_facing: bool,

    #[arg(long)]
    pub json: bool,
}

pub fn run(args: &PolicyManifestArgs) {
    let text = match fs::read_to_string(&args.manifest_file) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("{} could not read {}: {}", "✗".red(), args.manifest_file, e);
            std::process::exit(1);
        }
    };
    let entries: Vec<PolicyEntry> = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{} could not parse manifest JSON: {}", "✗".red(), e);
            std::process::exit(1);
        }
    };

    let manifest = PolicyManifest::new(entries);
    let results = manifest.run_all(Duration::from_secs(args.timeout_secs));
    let mode = if args.attendee_facing {
        ReportMode::AttendeeFacing
    } else {
        ReportMode::Operator
    };
    let report = manifest.report(&results, mode);

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
        return;
    }

    println!(
        "{}",
        format!(
            "== Policy manifest ({} entries, mode={:?}) ==",
            manifest.entries().len(),
            mode
        )
        .cyan()
        .bold()
    );
    for r in &report {
        let dest = match (&r.destination_host, r.destination_port) {
            (Some(h), Some(p)) => format!("{}:{}", h, p),
            _ => "(redacted)".to_string(),
        };
        let observed_str = match r.observed {
            ObservedOutcome::Reachable => "Reachable".green(),
            ObservedOutcome::Rejected => "Rejected".yellow(),
            ObservedOutcome::TimedOut => "TimedOut".yellow(),
            ObservedOutcome::Redirected => "Redirected".yellow(),
        };
        let drift_str = match r.drift {
            DriftVerdict::MatchesExpectation => "MatchesExpectation".green(),
            DriftVerdict::UnexpectedlyAllowed => "UnexpectedlyAllowed".red().bold(),
            DriftVerdict::UnexpectedlyBlocked => "UnexpectedlyBlocked".red().bold(),
            DriftVerdict::InterceptedByPortal => "InterceptedByPortal".yellow().bold(),
        };
        println!(
            "  [{}] role={} zone={} proto={:?} expected={:?} observed={} drift={} ({}ms) -> {}",
            r.entry_index,
            r.role,
            r.source_zone,
            r.protocol,
            r.expected,
            observed_str,
            drift_str,
            r.elapsed_ms,
            dest
        );
    }

    let drift_count = report
        .iter()
        .filter(|r| r.drift != DriftVerdict::MatchesExpectation)
        .count();
    if drift_count > 0 {
        println!(
            "{}",
            format!(
                "-- {} entr{} show policy drift --",
                drift_count,
                if drift_count == 1 { "y" } else { "ies" }
            )
            .red()
            .bold()
        );
    } else {
        println!("{}", "-- no policy drift detected --".green());
    }
}
