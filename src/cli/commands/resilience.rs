//! GAP-062: controlled resilience/failover validation CLI (`resilience`).
//!
//! There is no flag on this command that performs, requests, or targets a
//! component action. `--run` accepts an operator-prepared JSON file
//! describing a `ResilienceRun` (the labeled change plus continuously
//! observed session samples) -- this tool only ever judges evidence the
//! operator already collected while THEY performed the change.

use colored::*;

use fraggle_packet::network_tests::resilience::{
    judge_resilience, require_authorization, ResilienceRun,
};

#[derive(clap::Args, Debug)]
pub struct ResilienceArgs {
    /// Path to an operator-prepared JSON `ResilienceRun` describing the
    /// component change (as a label the operator supplies) and the
    /// continuous session samples taken across it.
    #[arg(long)]
    pub run: String,

    /// Non-empty, operator-supplied description of the approved window.
    /// Required: this command refuses to judge a continuous session bundle
    /// without it. There is no boolean shortcut.
    #[arg(long)]
    pub authorized: Option<String>,

    #[arg(long)]
    pub json: bool,
}

pub fn run(args: &ResilienceArgs) {
    if let Err(e) = require_authorization(args.authorized.as_deref()) {
        eprintln!("{} {}", "✗".red(), e);
        std::process::exit(1);
    }

    let text = match std::fs::read_to_string(&args.run) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("{} could not read run file {}: {}", "✗".red(), args.run, e);
            std::process::exit(1);
        }
    };

    let run_data: ResilienceRun = match serde_json::from_str(&text) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{} run file is not valid resilience JSON: {}", "✗".red(), e);
            std::process::exit(1);
        }
    };

    let verdict = judge_resilience(&run_data);

    if args.json {
        let out = serde_json::json!({
            "component_label": run_data.change.component_label,
            "verdict": verdict,
            "note": "this command observes and labels a component change performed by the operator; it never initiates a failover",
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
        return;
    }

    println!();
    println!("{}", "== Resilience / Failover Validation ==".cyan().bold());
    println!("  component: {}", run_data.change.component_label);
    println!("  action:    {}", run_data.change.action_description);
    println!();
    match verdict.outage_duration_secs {
        Some(d) => println!("  outage duration: {:.2}s", d),
        None => println!(
            "  outage duration: {} (no bracketed outage observed)",
            "not measured".yellow()
        ),
    }
    println!("  sessions survived:      {}", verdict.sessions_survived);
    println!("  sessions lost:          {}", verdict.sessions_lost);
    println!(
        "  sessions never sampled: {}",
        verdict.sessions_never_sampled
    );
    println!("  route identity:  {:?}", verdict.route_identity);
    println!("  nat identity:    {:?}", verdict.nat_identity);
    println!(
        "  state resync observed: {:?}",
        verdict.state_resync_observed
    );
    println!();
    println!(
        "  note: component state is operator-supplied. This command never initiates a failover \
         on production infrastructure."
    );
}
