//! GAP-051: coordinated multi-client capacity/fairness (`multiclient-fairness`).
//!
//! Ported from `scripts/bhusa-peer-impact-test.zsh`'s method: a role writes
//! its own descriptor file (JSON, not the script's tab-separated log, but
//! the same idea) so a second invocation on another machine can be
//! combined offline. This command never coordinates the actual load itself
//! across a network -- that stays out of scope; it only ingests and
//! evaluates descriptors, matching GAP-067's requirement that both roles
//! must exist and overlap before any cross-client number is trusted.

use colored::*;
use std::io::Write as _;

use fraggle_packet::load_guard::{
    evaluate_cross_client, jain_fairness_index, ClientRole, CrossClientVerdict, PhaseMark, RoleDescriptor,
};

#[derive(clap::Args, Debug)]
pub struct MulticlientFairnessArgs {
    /// Write this client's own role descriptor to the given path (JSON) and
    /// exit, instead of evaluating a cross-client verdict.
    #[arg(long)]
    pub emit_descriptor: Option<String>,

    #[arg(long, value_enum)]
    pub role: Option<Expectation>,

    #[arg(long)]
    pub client_id: Option<String>,

    #[arg(long)]
    pub interface: Option<String>,

    #[arg(long, value_delimiter = ',')]
    pub listener_endpoints: Vec<String>,

    /// Evaluate a cross-client verdict from two previously emitted
    /// descriptor files.
    #[arg(long)]
    pub descriptor_a: Option<String>,

    #[arg(long)]
    pub descriptor_b: Option<String>,

    /// Per-client achieved rates (Mbps) for Jain fairness, only used
    /// alongside --descriptor-a/--descriptor-b once the verdict is
    /// Comparable.
    #[arg(long, value_delimiter = ',')]
    pub rates_mbps: Vec<f64>,

    #[arg(long)]
    pub inject_fixture: Option<String>,

    #[arg(long)]
    pub json: bool,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Expectation {
    Loading,
    Observing,
}

impl From<Expectation> for ClientRole {
    fn from(e: Expectation) -> Self {
        match e {
            Expectation::Loading => ClientRole::Loading,
            Expectation::Observing => ClientRole::Observing,
        }
    }
}

fn now_epoch() -> f64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

fn emit(args: &MulticlientFairnessArgs) {
    let Some(path) = &args.emit_descriptor else { return };
    let role = match args.role {
        Some(r) => ClientRole::from(r),
        None => {
            eprintln!("{} --role is required with --emit-descriptor", "✗".red());
            std::process::exit(1);
        }
    };
    let client_id = args.client_id.clone().unwrap_or_else(|| "unnamed-client".to_string());
    let interface = args.interface.clone().unwrap_or_else(|| "unspecified".to_string());
    let now = now_epoch();
    let descriptor = RoleDescriptor {
        client_id,
        role,
        interface,
        association_label: None,
        listener_endpoints: args.listener_endpoints.clone(),
        reported_start_epoch: now,
        phase_marks: vec![PhaseMark { phase: "load_start".to_string(), epoch_secs: now }],
    };
    let text = serde_json::to_string_pretty(&descriptor).unwrap();
    let mut f = match std::fs::File::create(path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("{} failed to write descriptor: {}", "✗".red(), e);
            std::process::exit(1);
        }
    };
    f.write_all(text.as_bytes()).unwrap();
    println!("{} descriptor written to {}", "✓".green(), path);
}

fn load_descriptor(path: &str) -> Option<RoleDescriptor> {
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

fn synthetic_pair(seed: &str) -> (Option<RoleDescriptor>, Option<RoleDescriptor>) {
    let base = |id: &str, marks: &[f64], listeners: &[&str], start: f64| RoleDescriptor {
        client_id: id.to_string(),
        role: ClientRole::Loading,
        interface: "en0".to_string(),
        association_label: Some("ap-deadbeef".to_string()),
        listener_endpoints: listeners.iter().map(|s| s.to_string()).collect(),
        reported_start_epoch: start,
        phase_marks: marks.iter().map(|t| PhaseMark { phase: "load".to_string(), epoch_secs: *t }).collect(),
    };
    match seed {
        "missing-b" => (Some(base("a", &[100.0, 120.0], &["s:5201"], 100.0)), None),
        "no-overlap" => (
            Some(base("a", &[100.0, 120.0], &["s:5201"], 100.0)),
            Some(base("b", &[900.0, 920.0], &["s:5202"], 900.0)),
        ),
        "shared-listener" => (
            Some(base("a", &[100.0, 120.0], &["s:5201", "s:5202"], 100.0)),
            Some(base("b", &[110.0, 130.0], &["s:5202"], 110.0)),
        ),
        _ => (
            Some(base("a", &[100.0, 120.0], &["s:5201"], 100.0)),
            Some(base("b", &[110.0, 130.0], &["s:5202"], 110.0)),
        ),
    }
}

pub fn run(args: &MulticlientFairnessArgs) {
    if args.emit_descriptor.is_some() {
        emit(args);
        return;
    }

    let (a, b) = if let Some(seed) = &args.inject_fixture {
        synthetic_pair(seed)
    } else {
        (
            args.descriptor_a.as_deref().and_then(load_descriptor),
            args.descriptor_b.as_deref().and_then(load_descriptor),
        )
    };

    let verdict = evaluate_cross_client(a.as_ref(), b.as_ref());
    let fairness = match &verdict {
        CrossClientVerdict::Comparable { .. } if args.rates_mbps.len() >= 2 => jain_fairness_index(&args.rates_mbps),
        _ => None,
    };

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "verdict": verdict,
                "jain_fairness_index": fairness,
                "rates_supplied": args.rates_mbps.len(),
            }))
            .unwrap()
        );
        return;
    }

    println!();
    println!("{}", "== Multi-Client Capacity / Fairness ==".cyan().bold());
    match &verdict {
        CrossClientVerdict::Refused { reason } => {
            println!("  {} {}", "REFUSED".red().bold(), reason);
        }
        CrossClientVerdict::Comparable { clock_offset_secs, shared_listeners } => {
            println!("  {} clock_offset_secs={:.2}", "COMPARABLE".green().bold(), clock_offset_secs);
            if shared_listeners.is_empty() {
                println!("  shared listeners: none");
            } else {
                println!("  {} shared listeners: {:?} (contention confound, not a network fault)", "⚠".yellow(), shared_listeners);
            }
            match fairness {
                Some(f) => println!("  Jain fairness index: {f:.4} (from {} rate samples)", args.rates_mbps.len()),
                None => println!(
                    "  Jain fairness index: unavailable ({} rate samples supplied; need >= 2 from independent roles)",
                    args.rates_mbps.len()
                ),
            }
        }
    }
    println!();
}
