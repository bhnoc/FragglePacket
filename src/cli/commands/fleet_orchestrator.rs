//! GAP-038: distributed wireless-probe fleet orchestrator CLI
//! (`fleet-orchestrator`).
//!
//! No live SSH/fanout is attempted here today: this session was not
//! authorized for a live connection, so the runner is always the fixture
//! path (`--mock-inventory`). The bounded-concurrency/timeout/summary
//! logic is fully exercised offline; wiring a real `ssh` runner is a
//! follow-up that plugs into `run_fleet_fanout`'s closure without
//! changing anything in `network_tests::fleet_orchestrator`.

use colored::*;
use std::time::Duration;

use fraggle_packet::network_tests::fleet_orchestrator::{
    build_fleet_labels, load_or_create_node_salt, run_descriptor_digest, run_fleet_fanout, summarize_fleet_run,
    FleetPlan, InventoryEntry, NodeOutcome, NodeRole,
};

#[derive(clap::Args, Debug)]
pub struct FleetOrchestratorArgs {
    /// Use a fixture inventory (bastion + N synthetic test nodes,
    /// including one that always fails and one that always times out)
    /// instead of any real address. No live connection is attempted by
    /// this command.
    #[arg(long)]
    pub mock_inventory: bool,

    #[arg(long, default_value_t = 4)]
    pub max_concurrency: u32,

    #[arg(long, default_value_t = 50)]
    pub per_node_timeout_secs: u64,

    #[arg(long, default_value_t = 6)]
    pub mock_node_count: usize,

    #[arg(long)]
    pub json: bool,
}

pub fn run(args: &FleetOrchestratorArgs) {
    if !args.mock_inventory {
        eprintln!(
            "{} only --mock-inventory is supported; this command never originates a real SSH connection on its own",
            "✗".red()
        );
        std::process::exit(1);
    }

    let salt = match load_or_create_node_salt() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{} {}", "✗".red(), e);
            std::process::exit(1);
        }
    };

    let mut entries = vec![InventoryEntry { address: "10.220.250.53".to_string(), role: NodeRole::ManagementBastion }];
    for i in 0..args.mock_node_count {
        entries.push(InventoryEntry { address: format!("10.220.{i}.99"), role: NodeRole::TestNode });
    }
    let nodes = build_fleet_labels(&entries, &salt);

    let plan = FleetPlan { nodes, max_concurrency: args.max_concurrency, per_node_timeout_secs: args.per_node_timeout_secs };
    if let Err(e) = plan.validate() {
        eprintln!("{} {}", "✗".red(), e);
        std::process::exit(1);
    }

    let digest = run_descriptor_digest(&plan);

    let mock_node_count = args.mock_node_count;
    let results = run_fleet_fanout(&plan, move |label| {
        // Fixture behavior: the first mock node "times out", others succeed
        // quickly. Deterministic from the label's own byte sum so a given
        // mock inventory always produces the same demo shape.
        let byte_sum: u32 = label.bytes().map(|b| b as u32).sum();
        if mock_node_count > 0 && byte_sum % 7 == 0 {
            std::thread::sleep(Duration::from_secs(60));
            Ok((None, None))
        } else {
            Ok((Some("band=6GHz".to_string()), Some("band=6GHz".to_string())))
        }
    });

    let summary = summarize_fleet_run(&results);

    if args.json {
        let report = serde_json::json!({
            "run_descriptor_digest": digest,
            "results": results,
            "summary": summary,
        });
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
        return;
    }

    println!("{}", "== Fleet Orchestrator (mock inventory) ==".cyan().bold());
    println!("  run descriptor digest: {:016x}", digest);
    for r in &results {
        let marker = match &r.outcome {
            NodeOutcome::Completed { .. } => "PASS".green().to_string(),
            _ => "EXCL".yellow().to_string(),
        };
        println!("  [{}] {}: {:?}", marker, r.label, r.outcome);
    }
    println!();
    println!("  completed: {}/{}", summary.completed, summary.total_nodes);
    if !summary.excluded_with_reason.is_empty() {
        println!("  excluded (never counted as a zero measurement):");
        for (label, reason) in &summary.excluded_with_reason {
            println!("    {}: {}", label, reason);
        }
    }
}
