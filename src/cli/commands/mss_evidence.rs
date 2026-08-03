//! GAP-010 (SYN/SYN-ACK MSS evidence, local/peer/middlebox attribution) and
//! GAP-026 (multi-destination MSS clustering vs confirmed route/path MTU).

use colored::*;
use std::net::IpAddr;
use std::time::Duration;

use fraggle_packet::network_tests::mss_evidence::{
    cluster_destination_mss, ingest_syn_mss, ClusterVerdict, DestinationMss, MiddleboxVerdict,
};
use fraggle_packet::redact::RedactionPolicy;

#[derive(clap::Args, Debug)]
pub struct MssEvidenceArgs {
    /// Ingest SYN/SYN-ACK MSS evidence from a pcap/pcapng file (GAP-010).
    /// Capturing live needs root; this flag reads an operator-provided
    /// capture instead of escalating privilege itself.
    #[arg(long)]
    pub ingest: Option<String>,

    /// Local IP address(es) to attribute as "local" in the ingested
    /// capture. Without this, the SYN (non-ACK) sender of each flow is
    /// treated as local.
    #[arg(long = "local-ip")]
    pub local_ips: Vec<IpAddr>,

    /// GAP-026: destination=mss pairs to cluster, e.g.
    /// --destination apple=1238 --destination cloudflare=1238
    #[arg(long = "destination")]
    pub destinations: Vec<String>,

    /// Route/path MTU confirmed for the path under test (informational;
    /// does not itself change the verdict, only the report of what was
    /// measured against).
    #[arg(long)]
    pub route_mtu: Option<u16>,

    /// Interface the route MTU was measured against (e.g. en0). Surfacing
    /// this matters because the default route on this class of machine is
    /// frequently a VPN tunnel.
    #[arg(long)]
    pub route_interface: Option<String>,

    /// Manually assert whether a large (near-1500-byte) DF-marked probe on
    /// the same path was confirmed to succeed. This is the discriminator
    /// between a uniform TCP clamp/proxy and a true PMTU ceiling. Prefer
    /// `--confirm-df-target`, which runs the probe instead of trusting an
    /// operator assertion.
    #[arg(long)]
    pub large_df_probe_confirmed: Option<bool>,

    /// Run a real response-validated DF probe (`probe::pmtu_evidence`)
    /// against this host at a near-1500-byte size to determine
    /// large_df_probe_confirmed automatically instead of an operator
    /// assertion. Requires network access; QUIC/UDP 443 must be reachable.
    #[arg(long)]
    pub confirm_df_target: Option<String>,

    #[arg(long)]
    pub json: bool,

    /// GAP-018: by default, IP addresses and MAC/BSSID-shaped strings in
    /// human-readable output are redacted. Pass this to see raw values.
    #[arg(long)]
    pub retain_identifiers: bool,
}

fn parse_destination(raw: &str) -> Option<DestinationMss> {
    let (name, mss_str) = raw.split_once('=')?;
    let mss: u16 = mss_str.trim().parse().ok()?;
    Some(DestinationMss { destination: name.trim().to_string(), negotiated_mss: mss })
}

pub fn run(args: &MssEvidenceArgs) {
    let mut ran_something = false;
    let policy = RedactionPolicy::from_retain_flag(args.retain_identifiers);

    if let Some(path) = &args.ingest {
        ran_something = true;
        match ingest_syn_mss(path, &args.local_ips) {
            Ok(report) => {
                if args.json {
                    println!("{}", serde_json::to_string_pretty(&report).unwrap());
                } else {
                    let mut buf = String::new();
                    buf.push_str(&format!("== GAP-010 MSS evidence: {} ==\n", report.source));
                    buf.push_str(&format!(
                        "  flows: {} total, {} with both SYN directions observed\n",
                        report.flows_total, report.flows_with_both_directions
                    ));
                    for (flow, attribution) in report.flows.iter().zip(report.attributions.iter()) {
                        buf.push_str(&format!(
                            "  {}:{} <-> {}:{}\n",
                            flow.local_ip, flow.local_port, flow.peer_ip, flow.peer_port
                        ));
                        buf.push_str(&format!(
                            "    local_advertised={:?} peer_advertised={:?} both_directions={}\n",
                            flow.local_advertised, flow.peer_advertised, flow.both_directions_observed
                        ));
                        let verdict_str = match attribution.verdict {
                            MiddleboxVerdict::NoRewriteEvidence => "no-rewrite-evidence",
                            MiddleboxVerdict::Ambiguous => "ambiguous",
                            MiddleboxVerdict::InsufficientEvidence => "insufficient-evidence",
                        };
                        buf.push_str(&format!("    verdict={} confidence={:?}\n", verdict_str, attribution.confidence));
                        buf.push_str(&format!("    {}\n", attribution.explanation));
                    }
                    print!("{}", policy.apply(&buf));
                }
            }
            Err(e) => {
                eprintln!("{} mss-evidence ingest error: {}", "✗".red(), e);
                std::process::exit(1);
            }
        }
    }

    if !args.destinations.is_empty() {
        ran_something = true;
        let dests: Vec<DestinationMss> = args
            .destinations
            .iter()
            .filter_map(|d| {
                let parsed = parse_destination(d);
                if parsed.is_none() {
                    eprintln!("{} could not parse --destination '{}' (expected name=mss)", "✗".red(), d);
                }
                parsed
            })
            .collect();

        let large_df_confirmed = if let Some(target) = &args.confirm_df_target {
            match resolve_and_confirm_df(target) {
                Some(confirmed) => Some(confirmed),
                None => {
                    eprintln!(
                        "{} could not resolve/probe --confirm-df-target {}; falling back to --large-df-probe-confirmed",
                        "!".yellow(),
                        target
                    );
                    args.large_df_probe_confirmed
                }
            }
        } else {
            args.large_df_probe_confirmed
        };

        let report = cluster_destination_mss(
            dests,
            args.route_mtu,
            args.route_interface.clone(),
            args.route_interface
                .as_deref()
                .map(fraggle_packet::load_guard::route::is_tunnel_interface)
                .unwrap_or(false),
            large_df_confirmed,
        );

        if args.json {
            println!("{}", serde_json::to_string_pretty(&report).unwrap());
        } else {
            println!("{}", "== GAP-026 multi-destination MSS clustering ==".cyan().bold());
            for d in &report.destinations {
                println!("  {}: MSS {}", d.destination, d.negotiated_mss);
            }
            println!("  spread: {} bytes", report.mss_spread);
            match (&report.route_mtu, &report.route_interface) {
                (Some(mtu), Some(iface)) => {
                    println!(
                        "  route MTU measured against: {} on interface {}{}",
                        mtu,
                        iface,
                        if report.route_is_tunnel { " (TUNNEL -- not the physical network under test)".yellow().to_string() } else { String::new() }
                    );
                }
                (Some(mtu), None) => println!("  route MTU: {} (interface not specified)", mtu),
                _ => println!("  route MTU: {}", "not measured".yellow()),
            }
            let verdict_str = match report.verdict {
                ClusterVerdict::PeerSpecific => "peer-specific".green(),
                ClusterVerdict::UniformClampOrProxy => "uniform-clamp-or-proxy".yellow(),
                ClusterVerdict::TruePmtuCeiling => "true-pmtu-ceiling".red(),
                ClusterVerdict::Inconclusive => "inconclusive".yellow(),
            };
            println!("  verdict: {}", verdict_str);
            println!("  {}", report.explanation.dimmed());
        }
    }

    if !ran_something {
        eprintln!(
            "{} nothing to do: pass --ingest <pcap> for GAP-010 or --destination name=mss (repeatable) for GAP-026",
            "✗".red()
        );
        std::process::exit(2);
    }
}

/// Runs a real response-validated DF probe at a near-1500-byte size to
/// decide whether large frames still cross the path. `None` on any
/// resolution/probe setup failure so the caller can fall back honestly
/// rather than fabricate a confirmation.
fn resolve_and_confirm_df(target: &str) -> Option<bool> {
    use fraggle_packet::probe::pmtu_evidence::{probe_pmtu_evidence, SizeOutcome};

    let ip = std::net::ToSocketAddrs::to_socket_addrs(&(target, 443))
        .ok()?
        .next()
        .map(|a| a.ip())?;

    let evidence = probe_pmtu_evidence(target, ip, 443, &[1472], Duration::from_secs(5));
    evidence
        .sizes
        .first()
        .map(|s| s.outcome == SizeOutcome::Confirmed)
}
