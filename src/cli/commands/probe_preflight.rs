//! GAP-041: remote probe health/dependency preflight CLI (`probe-preflight`).

use colored::*;

use fraggle_packet::network_tests::probe_preflight::{
    classify_dependency_check, classify_ssh_error, confirm_host_key_rotation, evaluate_clock_skew, summarize_preflight,
    ClockCheck, NodePreflightResult, PreflightOutcome,
};

#[derive(clap::Args, Debug)]
pub struct ProbePreflightArgs {
    /// Use a fixture set of nodes reproducing the field evidence: one
    /// healthy, one with a broken iperf binary, one that times out, and
    /// one with a changed SSH host key. No live SSH connection is
    /// attempted by this command.
    #[arg(long)]
    pub mock_nodes: bool,

    /// Attempts to clear a specific mock node's HostKeyChanged quarantine
    /// by supplying an operator-confirmed fingerprint out of band. Only
    /// meaningful with --mock-nodes.
    #[arg(long)]
    pub confirm_host_key_for: Option<String>,

    #[arg(long)]
    pub confirmed_fingerprint: Option<String>,

    #[arg(long)]
    pub json: bool,
}

fn mock_results() -> Vec<NodePreflightResult> {
    vec![
        NodePreflightResult { label: "node-healthy01".to_string(), outcome: PreflightOutcome::Healthy },
        NodePreflightResult {
            label: "node-brokenlib1".to_string(),
            outcome: classify_dependency_check(
                "iperf3: error while loading shared libraries: libiperf.so.0: cannot open shared object file",
                Some(127),
            ),
        },
        NodePreflightResult {
            label: "node-timesout01".to_string(),
            outcome: classify_ssh_error("ssh: connect to host 10.0.0.9 port 22: Operation timed out", None),
        },
        NodePreflightResult {
            label: "node-hostkey001".to_string(),
            outcome: classify_ssh_error(
                "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n\
                 @    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\n\
                 @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n\
                 Fingerprint SHA256:mocked-changed-fingerprint\n\
                 Host key verification failed.",
                Some(255),
            ),
        },
    ]
}

pub fn run(args: &ProbePreflightArgs) {
    if !args.mock_nodes {
        eprintln!(
            "{} only --mock-nodes is supported; this command never originates a real SSH connection on its own",
            "✗".red()
        );
        std::process::exit(1);
    }

    let mut results = mock_results();

    let clock_check = ClockCheck { remote_unix_secs: 1000.0, local_unix_secs: 1002.5 };
    let clock_outcome = evaluate_clock_skew(&clock_check);
    if !clock_outcome.is_healthy() {
        results.push(NodePreflightResult { label: "node-clockskew1".to_string(), outcome: clock_outcome });
    }

    if let (Some(label), Some(fp)) = (&args.confirm_host_key_for, &args.confirmed_fingerprint) {
        if let Some(r) = results.iter_mut().find(|r| &r.label == label) {
            if let PreflightOutcome::HostKeyChanged { .. } = &r.outcome {
                match confirm_host_key_rotation("SHA256:mocked-changed-fingerprint", fp) {
                    Ok(()) => r.outcome = PreflightOutcome::Healthy,
                    Err(e) => {
                        eprintln!("{} host key rotation not confirmed: {}", "✗".red(), e);
                        std::process::exit(1);
                    }
                }
            }
        }
    }

    let summary = summarize_preflight(&results);

    if args.json {
        let report = serde_json::json!({ "results": results, "summary": summary });
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
        return;
    }

    println!("{}", "== Probe Preflight (mock nodes) ==".cyan().bold());
    for r in &results {
        let marker = if r.outcome.is_healthy() { "PASS".green().to_string() } else { "QUARANTINE".yellow().to_string() };
        println!("  [{}] {}: {}", marker, r.label, r.outcome.reason());
    }
    println!();
    println!("  healthy: {}/{}", summary.healthy_labels.len(), summary.total);
    if !summary.excluded_with_reason.is_empty() {
        println!("  excluded (never counted as a zero measurement):");
        for (label, reason) in &summary.excluded_with_reason {
            println!("    {}: {}", label, reason);
        }
    }
    println!();
    println!(
        "  {}",
        "no flag on this command auto-accepts a changed host key; use --confirm-host-key-for/--confirmed-fingerprint with an independently-sourced value"
            .dimmed()
    );
}
