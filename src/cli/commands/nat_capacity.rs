//! GAP-054: firewall/NAT/session-state capacity matrix CLI (`nat-capacity`).

use colored::*;
use std::net::IpAddr;

use fraggle_packet::load_guard::LoadBudget;
use fraggle_packet::network_tests::nat_capacity::{
    correlate_with_telemetry, observe_idle_mapping_survival, require_authorization, run_session_rate_probe,
    CorrelationVerdict, FirewallTelemetry,
};

#[derive(clap::Args, Debug)]
pub struct NatCapacityArgs {
    #[arg(long)]
    pub target: IpAddr,

    #[arg(long, default_value_t = 443)]
    pub port: u16,

    #[arg(long)]
    pub interface: Option<String>,

    /// Enables the disruptive session-creation-rate probe. Requires
    /// --authorized; refuses to run without it. Safe-by-default: omitting
    /// this flag runs only the observational idle-mapping check below.
    #[arg(long)]
    pub probe_session_rate: bool,

    /// Non-empty, operator-supplied description of the approved window.
    /// There is no boolean shortcut for this.
    #[arg(long)]
    pub authorized: Option<String>,

    #[arg(long, default_value_t = 1.0)]
    pub rate_mbps: f64,

    #[arg(long, default_value_t = 5)]
    pub max_duration_secs: u64,

    #[arg(long, default_value_t = 4)]
    pub max_concurrency: u32,

    #[arg(long)]
    pub maintenance: bool,

    #[arg(long, default_value_t = 3)]
    pub idle_secs: u64,

    #[arg(long)]
    pub keepalive: bool,

    /// Operator-supplied firewall/NAT telemetry JSON for the correlation
    /// half of this gap. Never read from the network by this tool.
    #[arg(long)]
    pub telemetry: Option<String>,

    #[arg(long)]
    pub json: bool,
}

pub fn run(args: &NatCapacityArgs) {
    let idle_result = observe_idle_mapping_survival(
        args.target,
        args.port,
        args.idle_secs,
        args.keepalive,
        std::time::Duration::from_secs(2),
    );

    let session_result = if args.probe_session_rate {
        match require_authorization(args.authorized.as_deref()) {
            Ok(_statement) => {
                let budget = if args.maintenance {
                    LoadBudget::maintenance(args.rate_mbps, args.max_duration_secs, args.max_concurrency)
                } else {
                    LoadBudget::live_event(args.rate_mbps, args.max_duration_secs, args.max_concurrency)
                };
                let interface = args.interface.clone().unwrap_or_else(|| "unspecified".to_string());
                Some(run_session_rate_probe(args.target, args.port, budget, &interface))
            }
            Err(e) => {
                eprintln!("{} {}", "✗".red(), e);
                std::process::exit(1);
            }
        }
    } else {
        None
    };

    let telemetry: Option<FirewallTelemetry> = args.telemetry.as_ref().and_then(|path| {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
    });

    let correlation = session_result.as_ref().and_then(|r| r.as_ref().ok()).map(|r| correlate_with_telemetry(r, &telemetry));

    if args.json {
        let report = serde_json::json!({
            "idle_mapping": idle_result,
            "session_rate": session_result.as_ref().map(|r| r.as_ref().ok()),
            "session_rate_error": session_result.as_ref().and_then(|r| r.as_ref().err()),
            "correlation": correlation,
        });
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
        return;
    }

    println!("{}", "== NAT/Firewall Capacity Matrix ==".cyan().bold());
    match idle_result {
        Ok(r) => {
            println!("  idle mapping ({}s, keepalive={}):", r.idle_secs_attempted, r.keepalive_sent);
            match r.still_responsive_after_idle {
                Some(true) => println!("    still responsive: {}", "yes".green()),
                Some(false) => println!("    still responsive: {}", "no".red()),
                None => println!("    still responsive: {}", "unknown (no reply observed)".yellow()),
            }
        }
        Err(e) => println!("  idle mapping check failed: {}", e),
    }

    if !args.probe_session_rate {
        println!(
            "  {}",
            "session-rate probe not run (safe default); pass --probe-session-rate --authorized \"...\" to enable"
                .yellow()
        );
        return;
    }

    match session_result {
        Some(Ok(r)) => {
            println!("  session rate: attempted={} created={} elapsed={:.2}s", r.attempted, r.created, r.elapsed_secs);
            println!(
                "    remote_refused={} remote_timed_out={} local_resource_exhausted={}",
                r.remote_refused, r.remote_timed_out, r.local_resource_exhausted
            );
            match r.remote_ceiling_evidence() {
                Some(n) => println!("    remote ceiling evidence: {} sessions", n),
                None => println!(
                    "    {}",
                    "remote ceiling evidence: WITHHELD (either no stoppage observed, or local resource exhaustion, not a confirmed remote ceiling)".yellow()
                ),
            }
            match correlation {
                Some(CorrelationVerdict::Correlated { table_usage_pct }) => {
                    println!("    telemetry correlation: table usage {:.1}%", table_usage_pct)
                }
                Some(CorrelationVerdict::TelemetryAbsent { missing }) => {
                    println!("    {}", format!("telemetry correlation WITHHELD: missing {}", missing.join(", ")).yellow())
                }
                None => {}
            }
        }
        Some(Err(e)) => println!("  session-rate probe error: {}", e),
        None => {}
    }
}
