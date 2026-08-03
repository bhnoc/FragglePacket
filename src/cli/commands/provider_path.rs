//! GAP-061: provider, geography, and path-stability comparison (`provider-path`).

use colored::*;
use std::time::Duration;

use fraggle_packet::network_tests::provider_path::{
    assess_path_stability, operator_geo_override, probe_connect, reverse_dns_region_hint,
    run_traceroute, HopOutcome, HopStabilityVerdict,
};
use fraggle_packet::network_tests::run_confidence::{confidence_from_stats, RunStats, WarmUpState};
use fraggle_packet::redact::RedactionPolicy;

#[derive(clap::Args, Debug)]
pub struct ProviderPathArgs {
    pub target: String,

    #[arg(long, default_value_t = 443)]
    pub port: u16,

    /// Interface bound for the traceroute. Required to state which path
    /// was actually measured -- the default route on this class of
    /// machine is frequently a VPN tunnel.
    #[arg(long)]
    pub interface: Option<String>,

    /// Local IP address on --interface to bind the TCP connect probe to.
    /// Without this, the connect probe follows the OS default route,
    /// which may differ from --interface.
    #[arg(long)]
    pub local_ip: Option<String>,

    #[arg(long, default_value_t = 3)]
    pub trace_samples: u32,

    #[arg(long, default_value_t = 20)]
    pub max_hops: u8,

    #[arg(long, default_value_t = 2)]
    pub wait_secs: u8,

    /// Operator-supplied ASN, since no client-side ASN source exists here
    /// without an external dependency/API.
    #[arg(long)]
    pub operator_asn: Option<String>,
    #[arg(long)]
    pub operator_region: Option<String>,

    #[arg(long)]
    pub json: bool,

    /// GAP-018: by default, hop addresses (which are IPs/hostnames) are
    /// redacted in human-readable output. Pass this to see raw values.
    #[arg(long)]
    pub retain_identifiers: bool,
}

pub fn run(args: &ProviderPathArgs) {
    let policy = RedactionPolicy::from_retain_flag(args.retain_identifiers)
        .with_literal(args.target.clone());
    if args.interface.is_none() {
        eprintln!(
            "{} --interface not specified; the default route on this class of machine is frequently a VPN tunnel, so the path measured below may not be the one intended",
            "!".yellow()
        );
    }

    let mut runs = Vec::new();
    for _ in 0..args.trace_samples.max(1) {
        match run_traceroute(
            &args.target,
            args.max_hops,
            args.wait_secs,
            args.interface.as_deref(),
        ) {
            Ok(run) => runs.push(run),
            Err(e) => {
                eprintln!("{} traceroute failed: {}", "✗".red(), e);
                std::process::exit(1);
            }
        }
    }
    let stability = assess_path_stability(&args.target, &runs);

    // GAP-017: sample count/variance for this run set. The scalar sampled
    // across runs is each trace's count of hops that actually responded --
    // a stand-in for "how much of the path did this sample see", which is
    // the dimension that varies run-to-run in a flaky path. A single
    // trace-sample run structurally cannot exceed Low confidence.
    let responded_per_run: Vec<f64> = runs
        .iter()
        .map(|r| {
            r.hops
                .iter()
                .filter(|h| h.outcome == HopOutcome::Responded)
                .count() as f64
        })
        .collect();
    let run_stats: RunStats = fraggle_packet::network_tests::run_confidence::stats_from_samples(
        &responded_per_run,
        WarmUpState::NotApplicable,
    );
    let (run_confidence, run_confidence_reasons) = confidence_from_stats(&run_stats);

    let connect = probe_connect(
        &args.target,
        args.port,
        Duration::from_secs(3),
        args.local_ip.as_deref(),
    );

    let geo = match (&args.operator_asn, &args.operator_region) {
        (None, None) => {
            let ip = std::net::ToSocketAddrs::to_socket_addrs(&(args.target.as_str(), 0))
                .ok()
                .and_then(|mut a| a.next())
                .map(|a| a.ip().to_string());
            match ip {
                Some(ip) => reverse_dns_region_hint(&ip),
                None => reverse_dns_region_hint(&args.target),
            }
        }
        (asn, region) => operator_geo_override(asn.clone(), region.clone()),
    };

    if args.json {
        let payload = serde_json::json!({
            "target": args.target,
            "interface": args.interface,
            "runs": runs,
            "stability": stability,
            "connect": connect,
            "geo": geo,
            "run_stats": run_stats,
            "run_confidence": run_confidence,
            "run_confidence_reasons": run_confidence_reasons,
        });
        println!("{}", serde_json::to_string_pretty(&payload).unwrap());
        return;
    }

    let mut buf = String::new();
    buf.push_str(&format!(
        "== Provider/path comparison: {} ==\n",
        args.target
    ));
    buf.push_str(&format!(
        "  interface: {}\n",
        args.interface.as_deref().unwrap_or("(unspecified)")
    ));
    buf.push_str(&format!(
        "  geo: asn={} region={} source={:?}\n",
        geo.asn.as_deref().unwrap_or("unavailable"),
        geo.region_hint.as_deref().unwrap_or("unavailable"),
        geo.source
    ));
    buf.push_str(&format!(
        "  connect {}:{} -> {}\n",
        args.target,
        args.port,
        if connect.connect_ok {
            format!("ok ({}ms)", connect.connect_ms.unwrap_or(0))
        } else {
            "failed".to_string()
        }
    ));

    buf.push_str(&format!(
        "  run confidence: {:?} (sample_count={} variance={})\n",
        run_confidence,
        run_stats.sample_count,
        run_stats
            .variance
            .map(|v| format!("{:.2}", v))
            .unwrap_or_else(|| "unavailable".to_string())
    ));
    for reason in &run_confidence_reasons {
        buf.push_str(&format!("    - {}\n", reason));
    }
    buf.push_str(&format!(
        "-- Path stability ({} samples) --\n",
        stability.sample_count
    ));
    for hop in &stability.per_hop {
        let verdict_str = match hop.verdict {
            HopStabilityVerdict::Stable => "Stable".to_string(),
            HopStabilityVerdict::Changed => "Changed".to_string(),
            HopStabilityVerdict::ConsistentlyNonResponsive => {
                "ConsistentlyNonResponsive (not loss)".to_string()
            }
            HopStabilityVerdict::IntermittentResponse { responded, total } => {
                format!(
                    "IntermittentResponse {}/{} responded (not a loss percentage)",
                    responded, total
                )
            }
        };
        buf.push_str(&format!(
            "  hop {}: {} addrs={:?}\n",
            hop.hop_number, verdict_str, hop.addresses_seen
        ));
    }

    if let Some(last_run) = runs.last() {
        let non_responsive = last_run
            .hops
            .iter()
            .filter(|h| h.outcome == HopOutcome::NoResponse)
            .count();
        if non_responsive > 0 {
            buf.push_str(&format!(
                "  {} hop(s) in the last trace had no response -- non-response, not loss; routers/endpoints may decline TTL-expiry probes\n",
                non_responsive
            ));
        }
    }

    print!("{}", policy.apply(&buf));
}
