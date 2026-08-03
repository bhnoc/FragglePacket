//! GAP-045: barrier-synchronized public-listener admission validation CLI
//! (`admission-fanout`).

use colored::*;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use fraggle_packet::network_tests::listener_admission::{
    run_admission_fanout, AdmissionCohort, ListenerTarget, SessionRunner,
};

#[derive(clap::Args, Debug)]
pub struct AdmissionFanoutArgs {
    /// host:port pairs to fan out against, e.g. speedtest.xmission.com:5201.
    /// Only ports named here are ever contacted -- there is no discovery.
    #[arg(long, required = true, num_args = 1..)]
    pub target: Vec<String>,

    #[arg(long, default_value_t = 4)]
    pub streams: u64,

    #[arg(long, default_value_t = 5)]
    pub duration_secs: u64,

    /// Hard per-session cap so one stuck listener cannot stall the fanout.
    #[arg(long, default_value_t = 50)]
    pub safety_timeout_secs: u64,

    /// Minimum number of fully-admitted sessions required before any
    /// aggregate figure is produced.
    #[arg(long, default_value_t = 1)]
    pub minimum_valid_cohort: usize,

    #[arg(long, default_value_t = 2000)]
    pub max_start_skew_ms: i64,

    #[arg(long)]
    pub json: bool,
}

struct Iperf3Runner {
    duration_secs: u64,
}

impl SessionRunner for Iperf3Runner {
    fn run(&self, target: &ListenerTarget, requested_streams: u64) -> Result<String, String> {
        let output = Command::new("iperf3")
            .args([
                "-c", &target.host,
                "-p", &target.port.to_string(),
                "-P", &requested_streams.to_string(),
                "-t", &self.duration_secs.to_string(),
                "-J",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()
            .map_err(|e| format!("failed to spawn iperf3: {e}"))?;
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }
}

fn parse_targets(raw: &[String]) -> Result<Vec<ListenerTarget>, String> {
    raw.iter()
        .map(|s| {
            let (host, port) = s.rsplit_once(':').ok_or_else(|| format!("expected host:port, got '{s}'"))?;
            let port: u16 = port.parse().map_err(|_| format!("invalid port in '{s}'"))?;
            Ok(ListenerTarget { host: host.to_string(), port, pool_label: host.to_string() })
        })
        .collect()
}

pub fn run(args: &AdmissionFanoutArgs) {
    let targets = match parse_targets(&args.target) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("{} {}", "✗".red(), e);
            std::process::exit(1);
        }
    };

    let runner: Arc<dyn SessionRunner + Send + Sync> = Arc::new(Iperf3Runner { duration_secs: args.duration_secs });
    let results = run_admission_fanout(
        targets,
        args.streams,
        Duration::from_secs(args.safety_timeout_secs),
        runner,
    );

    let cohort = AdmissionCohort {
        requested_streams: args.streams,
        results,
        minimum_valid_cohort: args.minimum_valid_cohort,
        max_start_skew_ms: args.max_start_skew_ms,
    };

    if args.json {
        println!("{}", serde_json::to_string_pretty(&cohort).unwrap());
        return;
    }

    println!("{}", "== Admission Fanout ==".cyan().bold());
    for r in &cohort.results {
        let admitted = r.outcome.is_admitted();
        let marker = if admitted { "PASS".green() } else { "EXCL".yellow() };
        println!(
            "  [{}] {}:{} ({}) skew={}ms {}",
            marker,
            r.target.host,
            r.target.port,
            r.outcome.reason(),
            r.start_skew_ms,
            r.receiver_bits_per_second
                .map(|b| format!("{:.1} Mbps", b / 1_000_000.0))
                .unwrap_or_else(|| "no throughput (excluded)".to_string())
        );
    }
    println!();
    println!("fully admitted: {}/{}", cohort.fully_admitted_count(), cohort.results.len());
    match cohort.aggregate_receiver_bps() {
        Some(bps) => println!("aggregate receiver throughput: {:.1} Mbps", bps / 1_000_000.0),
        None => println!(
            "{}",
            format!(
                "aggregate throughput WITHHELD: fewer than minimum_valid_cohort ({}) sessions fully admitted",
                cohort.minimum_valid_cohort
            )
            .yellow()
        ),
    }
    if !cohort.excluded_with_reason().is_empty() {
        println!("excluded (never counted as zero throughput):");
        for (t, reason) in cohort.excluded_with_reason() {
            println!("  {}:{} -- {}", t.host, t.port, reason);
        }
    }
}
