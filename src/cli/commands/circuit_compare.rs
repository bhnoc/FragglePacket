use colored::*;

use fraggle_packet::network_tests::circuit_workflow::{
    by_state, judge_circuits, CircuitManifest, CircuitVerdict,
};

#[derive(clap::Args, Debug)]
pub struct CircuitCompareArgs {
    /// Path to an operator-prepared manifest JSON describing each phase's
    /// labeled circuit state, client result, and per-member telemetry.
    ///
    /// This command never changes routing. Circuit state is a label the
    /// operator supplies after performing the failover in an approved window;
    /// there is no flag that makes FragglePacket touch a production circuit.
    #[arg(long)]
    pub manifest: String,

    /// Print the manifest's reproducibility digest and exit without judging.
    #[arg(long)]
    pub digest_only: bool,

    #[arg(long)]
    pub json: bool,
}

pub fn run(args: &CircuitCompareArgs) {
    let text = match std::fs::read_to_string(&args.manifest) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("{} could not read manifest {}: {}", "✗".red(), args.manifest, e);
            std::process::exit(1);
        }
    };

    let manifest: CircuitManifest = match serde_json::from_str(&text) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("{} manifest is not valid circuit-comparison JSON: {}", "✗".red(), e);
            std::process::exit(1);
        }
    };

    let digest = manifest.digest();
    if args.digest_only {
        if args.json {
            println!("{}", serde_json::json!({ "digest": digest }));
        } else {
            println!("manifest digest: {}", digest);
        }
        return;
    }

    let verdict = judge_circuits(&manifest);

    if args.json {
        let out = serde_json::json!({
            "bundle_name": manifest.bundle_name,
            "digest": digest,
            "phases_by_state": by_state(&manifest),
            "verdict": verdict,
            "routing_note": "this command observes and labels circuit state; it never initiates a failover",
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
        return;
    }

    println!("\n== Circuit Comparison ==");
    println!("  bundle: {}", manifest.bundle_name);
    println!("  digest: {}", digest);
    for (state, count) in by_state(&manifest) {
        println!("  phase {:<12} x{}", state, count);
    }
    println!();

    match verdict {
        CircuitVerdict::Refused { missing } => {
            println!("  {} no A-vs-B verdict", "REFUSED:".yellow());
            println!("  missing evidence ({}):", missing.len());
            for m in &missing {
                println!("    - {}", m);
            }
            println!(
                "  collect the above and re-run; a verdict from partial evidence would point at a \
                 circuit the data cannot implicate"
            );
        }
        CircuitVerdict::MemberSpecific { detail } => {
            println!("  verdict: {}", "member-specific".red());
            println!("  {}", detail);
        }
        CircuitVerdict::SharedRatherThanMemberSpecific { detail } => {
            println!("  verdict: {}", "shared, not member-specific".green());
            println!("  {}", detail);
        }
    }

    println!(
        "\n  note: circuit state is operator-supplied. This command never initiates a failover on \
         production infrastructure."
    );
}
