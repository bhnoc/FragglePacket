//! GAP-043: telemetry-counter liveness validation (`counter-liveness`).

use colored::*;

use fraggle_packet::network_tests::counter_liveness::{
    classify_delta, qualify_zero_drop_claim, read_rx_packets, send_loopback_stimulus, LivenessVerdict,
};

#[derive(clap::Args, Debug)]
pub struct CounterLivenessArgs {
    /// Interface to bracket, e.g. lo0 for a self-contained local proof, or
    /// en0/utunN to bracket a real adapter's counters. The stimulus is
    /// always a small local burst -- never real network load.
    #[arg(long, default_value = "lo0")]
    pub interface: String,

    /// Number of stimulus packets to send. Kept small (a few thousand is
    /// plenty to prove a counter advances) -- this is a liveness check,
    /// not a load test.
    #[arg(long, default_value_t = 2000)]
    pub stimulus_packets: u64,

    /// For the offline/test harness: instead of sampling a real counter,
    /// use an operator-supplied before/after pair to exercise the
    /// classifier deterministically (e.g. to demonstrate a frozen source).
    #[arg(long)]
    pub inject_before: Option<u64>,
    #[arg(long)]
    pub inject_after: Option<u64>,

    /// Drops reported by the primary source, for the zero-drop
    /// corroboration gate.
    #[arg(long, default_value_t = 0)]
    pub primary_drops: u64,

    /// name=drops pairs from independent corroborating sources (AP/
    /// controller telemetry, a capture-derived count, etc).
    #[arg(long = "corroborate")]
    pub corroborate: Vec<String>,

    #[arg(long)]
    pub json: bool,
}

pub fn run(args: &CounterLivenessArgs) {
    let (before, after, stimulus) = if let (Some(b), Some(a)) = (args.inject_before, args.inject_after) {
        (b, a, args.stimulus_packets)
    } else {
        let before = match read_rx_packets(&args.interface) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("{} could not read counters for {}: {}", "✗".red(), args.interface, e);
                std::process::exit(1);
            }
        };
        let sent = match send_loopback_stimulus(args.stimulus_packets, 64) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("{} stimulus generation failed: {}", "✗".red(), e);
                std::process::exit(1);
            }
        };
        std::thread::sleep(std::time::Duration::from_millis(100));
        let after = match read_rx_packets(&args.interface) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("{} could not re-read counters for {}: {}", "✗".red(), args.interface, e);
                std::process::exit(1);
            }
        };
        (before, after, sent)
    };

    let bracket = classify_delta(&args.interface, stimulus, before, after);

    let corroborating: Vec<(String, u64)> = args
        .corroborate
        .iter()
        .filter_map(|s| {
            let (name, drops) = s.split_once('=')?;
            Some((name.to_string(), drops.parse().ok()?))
        })
        .collect();
    let zero_drop = qualify_zero_drop_claim(&args.interface, &bracket, args.primary_drops, &corroborating);

    if args.json {
        let payload = serde_json::json!({"bracket": bracket, "zero_drop_verdict": zero_drop});
        println!("{}", serde_json::to_string_pretty(&payload).unwrap());
        return;
    }

    println!("{}", format!("== Counter liveness: {} ==", args.interface).cyan().bold());
    println!("  stimulus packets: {}", bracket.stimulus_packets_sent);
    println!("  counter before/after: {} -> {}", bracket.counter_before, bracket.counter_after);
    let verdict_str = match bracket.verdict {
        LivenessVerdict::Live => "Live".green(),
        LivenessVerdict::Frozen => "Frozen".red().bold(),
        LivenessVerdict::Reset => "Reset".yellow(),
        LivenessVerdict::Wrapped => "Wrapped".yellow(),
        LivenessVerdict::Unattributable => "Unattributable".yellow(),
    };
    println!("  verdict: {}", verdict_str);
    println!("  {}", bracket.detail.dimmed());

    println!("{}", "-- Zero-drop verdict --".white().bold());
    println!("  primary live: {}", zero_drop.primary_live);
    println!("  corroborating sources: {:?}", zero_drop.corroborating_sources);
    match zero_drop.verdict {
        Some(true) => println!("  {}", "zero drops: CORROBORATED".green().bold()),
        Some(false) => println!("  {}", "zero drops: DISAGREEMENT/NONZERO -- not clean".red()),
        None => println!("  {}", "zero drops: WITHHELD (no verdict)".yellow().bold()),
    }
    println!("  {}", zero_drop.explanation.dimmed());
}
