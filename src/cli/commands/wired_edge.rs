//! GAP-058: wired edge/AP-uplink/LLDP/PoE health bundle CLI (`wired-edge`).

use colored::*;

use fraggle_packet::network_tests::wired_edge::{compute_delta, judge_wired_edge, WiredEdgeBracket, WiredEdgeVerdict};

#[derive(clap::Args, Debug)]
pub struct WiredEdgeArgs {
    /// Path to an operator-supplied JSON bracket: `{"before": {...},
    /// "after": {...}}`, each a `WiredEdgeSnapshot`. This tool never reads
    /// switch/AP counters itself -- there is no live-query mode, only
    /// ingest, because a client cannot read another device's counters.
    #[arg(long)]
    pub bracket: String,

    #[arg(long)]
    pub json: bool,
}

pub fn run(args: &WiredEdgeArgs) {
    let text = match std::fs::read_to_string(&args.bracket) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("{} could not read bracket file {}: {}", "✗".red(), args.bracket, e);
            std::process::exit(1);
        }
    };

    let bracket: WiredEdgeBracket = match serde_json::from_str(&text) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("{} bracket is not valid wired-edge JSON: {}", "✗".red(), e);
            std::process::exit(1);
        }
    };

    let verdict = judge_wired_edge(&bracket);
    let delta = compute_delta(&bracket);

    if args.json {
        let out = serde_json::json!({
            "verdict": verdict,
            "delta": delta,
            "note": "read-only ingest; never modifies switch or AP configuration",
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
        return;
    }

    println!();
    println!("{}", "== Wired Edge Health ==".cyan().bold());
    match verdict {
        WiredEdgeVerdict::Refused { missing } => {
            println!("  {} no wired-edge conclusion", "REFUSED:".yellow());
            println!("  missing evidence ({}):", missing.len());
            for m in &missing {
                println!("    - {}", m);
            }
        }
        WiredEdgeVerdict::Healthy => println!("  verdict: {}", "healthy".green().bold()),
        WiredEdgeVerdict::Degraded { detail } => {
            println!("  verdict: {}", "degraded".red().bold());
            println!("  {}", detail);
        }
    }
    println!();
    println!("  counter delta (bracketed around the client test timeline):");
    println!("    crc_errors:      {:?}", delta.crc_errors);
    println!("    input_discards:  {:?}", delta.input_discards);
    println!("    output_discards: {:?}", delta.output_discards);
    println!("    queue_drops:     {:?}", delta.queue_drops);
    println!("    link_flap_count: {:?}", delta.link_flap_count);
    println!();
    println!("  note: read-only ingest; this command never modifies switch or AP configuration.");
}
