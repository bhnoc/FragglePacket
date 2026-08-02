//! GAP-046: version-aware maximum-throughput tuner CLI (`throughput-tuner`).

use colored::*;
use std::process::{Command, Stdio};

use fraggle_packet::network_tests::iperf::{parse_iperf_json, IperfParseError, IperfResult};
use fraggle_packet::network_tests::throughput_tuner::{
    build_verdict, detect_preflight_limits, evaluate_trial, preflight_candidate, randomize_candidates,
    Candidate, DriftBracket, PreflightVerdict, TrialResult,
};

#[derive(clap::Args, Debug)]
pub struct ThroughputTunerArgs {
    #[arg(long)]
    pub host: String,

    #[arg(long)]
    pub port: u16,

    /// Candidate stream counts to try, randomized order.
    #[arg(long, num_args = 1.., default_values_t = [4u32, 8, 16])]
    pub streams: Vec<u32>,

    /// Candidate block sizes (KiB) to try.
    #[arg(long, num_args = 1.., default_values_t = [128u32, 512])]
    pub block_sizes_kib: Vec<u32>,

    #[arg(long)]
    pub zero_copy: bool,

    #[arg(long, default_value_t = 5)]
    pub trial_duration_secs: u64,

    /// Candidate representing the application's actual configured rate,
    /// scored as its own field, never derived from the best trial.
    #[arg(long, default_value_t = 4)]
    pub representative_streams: u32,

    #[arg(long, default_value_t = 128)]
    pub representative_block_kib: u32,

    #[arg(long, default_value_t = 1)]
    pub seed: u64,

    /// Repeated identical-candidate baseline probes used to bracket
    /// endpoint drift, run before the candidate sweep.
    #[arg(long, default_value_t = 0)]
    pub drift_baseline_repeats: u32,

    #[arg(long)]
    pub cohort_label: Option<String>,

    #[arg(long)]
    pub json: bool,
}

/// `run_iperf_client` (GAP-039) does not expose `-P`/`-l`/`-Z`, which this
/// tuner needs to vary as its candidate dimensions, so the client is
/// invoked directly here; the output is still parsed via the shared
/// `parse_iperf_json` rather than a second parser.
fn run_iperf(host: &str, port: u16, candidate: Candidate, duration_secs: u64) -> Result<IperfResult, IperfParseError> {
    let mut args: Vec<String> = vec![
        "-c".into(), host.to_string(),
        "-p".into(), port.to_string(),
        "-P".into(), candidate.streams.to_string(),
        "-l".into(), format!("{}K", candidate.block_size_kib),
        "-t".into(), duration_secs.to_string(),
        "-J".into(),
    ];
    if candidate.zero_copy {
        args.push("-Z".into());
    }
    let output = Command::new("iperf3")
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .map_err(|e| IperfParseError::InvalidJson(format!("failed to spawn iperf3: {e}")))?;
    let text = String::from_utf8_lossy(&output.stdout);
    parse_iperf_json(&text)
}

pub fn run(args: &ThroughputTunerArgs) {
    let limits = detect_preflight_limits();

    let mut candidates = Vec::new();
    for &s in &args.streams {
        for &b in &args.block_sizes_kib {
            candidates.push(Candidate { streams: s, block_size_kib: b, zero_copy: args.zero_copy });
        }
    }
    let candidates = randomize_candidates(candidates, args.seed);

    let mut trials: Vec<TrialResult> = Vec::new();
    let mut preflight_skips: Vec<(Candidate, PreflightVerdict)> = Vec::new();

    for candidate in &candidates {
        let verdict = preflight_candidate(candidate, &limits);
        if verdict != PreflightVerdict::Ok {
            preflight_skips.push((*candidate, verdict));
            continue;
        }
        let parsed = run_iperf(&args.host, args.port, *candidate, args.trial_duration_secs);
        trials.push(evaluate_trial(*candidate, args.trial_duration_secs as f64, &parsed));
    }

    let representative = Candidate {
        streams: args.representative_streams,
        block_size_kib: args.representative_block_kib,
        zero_copy: args.zero_copy,
    };
    if !trials.iter().any(|t| t.candidate == representative) {
        let parsed = run_iperf(&args.host, args.port, representative, args.trial_duration_secs);
        trials.push(evaluate_trial(representative, args.trial_duration_secs as f64, &parsed));
    }

    let drift = if args.drift_baseline_repeats >= 2 {
        let mut samples = Vec::new();
        for _ in 0..args.drift_baseline_repeats {
            if let Ok(result) = run_iperf(&args.host, args.port, representative, args.trial_duration_secs) {
                if let Some(r) = result.forward.received {
                    samples.push(r.bits_per_second);
                }
            }
        }
        Some(DriftBracket { samples_bps: samples })
    } else {
        None
    };

    let cohort_label = args.cohort_label.clone().unwrap_or_else(|| "unspecified-cohort".to_string());
    let verdict = build_verdict(&cohort_label, trials, representative, drift);

    if args.json {
        let report = serde_json::json!({
            "verdict": verdict,
            "preflight_skips": preflight_skips.iter().map(|(c, v)| serde_json::json!({"candidate": c, "verdict": v})).collect::<Vec<_>>(),
            "preflight_limits": limits,
        });
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
        return;
    }

    println!("{}", "== Throughput Tuner ==".cyan().bold());
    println!("  cohort: {}", verdict.cohort.cohort_label);
    match (verdict.synthetic_maximum_bps, verdict.synthetic_maximum_candidate) {
        (Some(bps), Some(c)) => println!(
            "  synthetic maximum: {:.1} Mbps @ {} streams / {} KiB / zero_copy={}",
            bps / 1_000_000.0, c.streams, c.block_size_kib, c.zero_copy
        ),
        _ => println!("  synthetic maximum: {}", "no valid trial completed".yellow()),
    }
    match verdict.representative_application_bps {
        Some(bps) => println!("  representative-application: {:.1} Mbps @ {:?}", bps / 1_000_000.0, verdict.representative_candidate),
        None => println!("  representative-application: {}", "no valid trial completed".yellow()),
    }
    if verdict.drift_provisional {
        println!("  {}", "WARNING: endpoint drift is severe; this profile is provisional".yellow());
    }
    if !verdict.rejected_trials.is_empty() {
        println!("  rejected trials (never scored):");
        for t in &verdict.rejected_trials {
            println!(
                "    {:?} streams/{} KiB -- {}",
                t.candidate.streams, t.candidate.block_size_kib,
                t.rejected_reason.as_deref().unwrap_or("unknown")
            );
        }
    }
    if !preflight_skips.is_empty() {
        println!("  preflight-skipped candidates (never attempted):");
        for (c, v) in &preflight_skips {
            println!("    {} streams/{} KiB -- {:?}", c.streams, c.block_size_kib, v);
        }
    }
}
