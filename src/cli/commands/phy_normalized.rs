//! GAP-042: PHY-normalized fleet comparison (`phy-normalized`).

use colored::*;
use std::fs;

use fraggle_packet::network_tests::phy_normalized::{
    attribute_cohort_difference, normalize, stratify, AttributionVerdict, PhaseMeasurement,
};

#[derive(clap::Args, Debug)]
pub struct PhyNormalizedArgs {
    /// Path to a JSON array of operator-supplied per-node phase
    /// measurements. GAP-038's live fleet orchestrator (Sprint 8) will
    /// produce this shape directly; until then this command takes
    /// already-collected data in.
    #[arg(long)]
    pub measurements_file: String,

    /// Compare two cohorts by 0-based index groups, e.g. "0,1" vs "2,3"
    /// into the measurements array, for an attribution verdict. Without
    /// this, only the normalized/stratified report is printed.
    #[arg(long)]
    pub cohort_a: Option<String>,
    #[arg(long)]
    pub cohort_b: Option<String>,

    #[arg(long)]
    pub json: bool,
}

fn parse_indices(s: &str) -> Vec<usize> {
    s.split(',').filter_map(|t| t.trim().parse().ok()).collect()
}

pub fn run(args: &PhyNormalizedArgs) {
    let text = match fs::read_to_string(&args.measurements_file) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("{} could not read {}: {}", "✗".red(), args.measurements_file, e);
            std::process::exit(1);
        }
    };
    let raw: Vec<PhaseMeasurement> = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{} could not parse measurements JSON: {}", "✗".red(), e);
            std::process::exit(1);
        }
    };

    let normalized: Vec<_> = raw.iter().map(normalize).collect();
    let strata = stratify(&normalized);

    let attribution = match (&args.cohort_a, &args.cohort_b) {
        (Some(a_spec), Some(b_spec)) => {
            let a_idx = parse_indices(a_spec);
            let b_idx = parse_indices(b_spec);
            let a_items: Vec<_> = a_idx.iter().filter_map(|&i| normalized.get(i)).collect();
            let b_items: Vec<_> = b_idx.iter().filter_map(|&i| normalized.get(i)).collect();
            if a_items.is_empty() || b_items.is_empty() {
                eprintln!("{} cohort-a/cohort-b indices did not resolve to any measurements", "✗".red());
                std::process::exit(1);
            }
            let a_strata = stratify(&a_items.iter().map(|m| (*m).clone()).collect::<Vec<_>>());
            let b_strata = stratify(&b_items.iter().map(|m| (*m).clone()).collect::<Vec<_>>());
            let a_strong_directional = a_items.iter().all(|m| m.directional_control && matches!(m.rf_quality, fraggle_packet::load_guard::radio::RfQuality::Strong));
            let b_strong_directional = b_items.iter().all(|m| m.directional_control && matches!(m.rf_quality, fraggle_packet::load_guard::radio::RfQuality::Strong));
            Some(attribute_cohort_difference(
                a_strata.into_iter().next().unwrap(),
                b_strata.into_iter().next().unwrap(),
                a_strong_directional,
                b_strong_directional,
            ))
        }
        _ => None,
    };

    if args.json {
        let payload = serde_json::json!({"normalized": normalized, "strata": strata, "attribution": attribution});
        println!("{}", serde_json::to_string_pretty(&payload).unwrap());
        return;
    }

    println!("{}", "== PHY-normalized fleet comparison ==".cyan().bold());
    for m in &normalized {
        println!(
            "  {} [{:?}/{}/{}]: offered {:.1} Mbps of {:.1} Mbps capacity ({:.1}% of PHY), loss {:.2}%, rf={:?} directional={}",
            m.node_id, m.phy_generation, m.driver, m.kernel,
            m.offered_mbps, m.phy_capacity_mbps, m.offered_phy_fraction * 100.0, m.loss_percent, m.rf_quality, m.directional_control
        );
    }
    println!("{}", "-- Strata (generation/driver/kernel) --".white().bold());
    for s in &strata {
        println!(
            "  {:?}/{}/{}: n={} mean_phy_fraction={:.2} mean_loss={:.2}%",
            s.phy_generation, s.driver, s.kernel, s.sample_count, s.mean_offered_phy_fraction, s.mean_loss_percent
        );
    }
    if let Some(a) = &attribution {
        println!("{}", "-- Cohort attribution --".white().bold());
        let verdict_str = match a.verdict {
            AttributionVerdict::Attributable => "Attributable".green().bold(),
            AttributionVerdict::WithheldMissingControls => "WITHHELD (missing strong-RF/directional controls)".yellow().bold(),
            AttributionVerdict::WithheldIncomparableTargets => "WITHHELD (incomparable PHY fractions)".yellow().bold(),
        };
        println!("  verdict: {}", verdict_str);
        println!("  {}", a.explanation.dimmed());
    }
}
