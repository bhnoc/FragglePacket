use std::net::IpAddr;
use std::time::Duration;

use colored::*;

use fraggle_packet::probe::{
    default_h3_endpoints, network_verdict, preflight_one, EndpointResult, EndpointVerdict,
    NetworkVerdict, PreflightReport, Protocol, ProtocolReport,
};

#[derive(clap::Args, Debug)]
pub struct PreflightArgs {
    /// Additional endpoint hostname to test (repeatable). Extends, does not
    /// replace, the built-in known-h3-capable list unless --no-defaults is set.
    #[arg(long = "endpoint")]
    pub endpoints: Vec<String>,

    /// Skip the built-in known-capable endpoint list, testing only --endpoint values.
    #[arg(long)]
    pub no_defaults: bool,

    /// Protocols to test. Repeatable. Defaults to http1,http2,http3.
    #[arg(long = "protocol", value_parser = ["http1", "http2", "http3"])]
    pub protocols: Vec<String>,

    /// Force a specific resolved IP for every endpoint tested (GAP-012/GAP-017
    /// endpoint normalization). Applies to all endpoints in this run.
    #[arg(long = "force-ip")]
    pub force_ip: Option<IpAddr>,

    /// Port to test (default 443 for all three protocols in this tool).
    #[arg(long, default_value_t = 443)]
    pub port: u16,

    /// Per-attempt timeout in milliseconds.
    #[arg(long, default_value_t = 4000)]
    pub timeout_ms: u64,

    /// Emit machine-readable JSON instead of the human report.
    #[arg(long)]
    pub json: bool,
}

pub fn run(args: &PreflightArgs) {
    let mut endpoints: Vec<String> = Vec::new();
    if !args.no_defaults {
        endpoints.extend(default_h3_endpoints());
    }
    endpoints.extend(args.endpoints.iter().cloned());
    endpoints.dedup();

    if endpoints.is_empty() {
        eprintln!("{} no endpoints to test (pass --endpoint or drop --no-defaults)", "✗".red());
        return;
    }

    let protocols: Vec<Protocol> = if args.protocols.is_empty() {
        vec![Protocol::Http1, Protocol::Http2, Protocol::Http3]
    } else {
        args.protocols
            .iter()
            .map(|p| match p.as_str() {
                "http1" => Protocol::Http1,
                "http2" => Protocol::Http2,
                "http3" => Protocol::Http3,
                _ => unreachable!("clap value_parser restricts this"),
            })
            .collect()
    };

    let timeout = Duration::from_millis(args.timeout_ms);

    let mut per_protocol_results: Vec<(Protocol, Vec<EndpointResult>)> = Vec::new();
    for protocol in &protocols {
        let mut results = Vec::new();
        for host in &endpoints {
            let r = preflight_one(host, args.force_ip, *protocol, args.port, timeout);
            results.push(r);
        }
        per_protocol_results.push((*protocol, results));
    }

    // Control protocol for corroboration: prefer HTTP/2 results (or HTTP/1.1
    // if H2 wasn't tested) to prove a host is reachable at all on this
    // network before letting its h3/h2 failure count as network evidence.
    let control_ok_hosts: Vec<String> = per_protocol_results
        .iter()
        .find(|(p, _)| *p == Protocol::Http2)
        .or_else(|| per_protocol_results.iter().find(|(p, _)| *p == Protocol::Http1))
        .map(|(_, results)| {
            results
                .iter()
                .filter(|r| r.verdict == EndpointVerdict::Ok)
                .map(|r| r.host.clone())
                .collect()
        })
        .unwrap_or_default();

    let reports: Vec<ProtocolReport> = per_protocol_results
        .into_iter()
        .map(|(protocol, results)| {
            let verdict = network_verdict(&results, &control_ok_hosts);
            ProtocolReport {
                protocol: protocol.as_str().to_string(),
                endpoints: results,
                network_verdict: verdict,
            }
        })
        .collect();

    let report = PreflightReport { protocols: reports };

    if args.json {
        match serde_json::to_string_pretty(&report) {
            Ok(s) => println!("{}", s),
            Err(e) => eprintln!("{} failed to serialize report: {}", "✗".red(), e),
        }
        return;
    }

    print_human_report(&report);
}

fn print_human_report(report: &PreflightReport) {
    for proto in &report.protocols {
        println!();
        println!("{}", format!("== {} ==", proto.protocol).cyan().bold());
        for ep in &proto.endpoints {
            let verdict_str = match ep.verdict {
                EndpointVerdict::Ok => ep.verdict.as_str().green().to_string(),
                EndpointVerdict::Unsupported => ep.verdict.as_str().dimmed().to_string(),
                EndpointVerdict::Filtered => ep.verdict.as_str().red().bold().to_string(),
                EndpointVerdict::HandshakeRejected | EndpointVerdict::Timeout => {
                    ep.verdict.as_str().yellow().to_string()
                }
            };
            println!(
                "  {:32} ip={:<16} advertised={:<14} negotiated_alpn={:<8} verdict={}",
                ep.host,
                ep.resolved_ip.clone().unwrap_or_else(|| "?".to_string()),
                ep.advertised.map(|a| a.as_str().to_string()).unwrap_or_else(|| "n/a".to_string()),
                ep.negotiated_alpn.clone().unwrap_or_else(|| "-".to_string()),
                verdict_str
            );
            println!("      {}", ep.detail.dimmed());
        }
        match &proto.network_verdict {
            NetworkVerdict::Usable => {
                println!("  {} protocol appears usable on this network", "network verdict:".bold());
            }
            NetworkVerdict::Filtered { corroborating_endpoints } => {
                println!(
                    "  {} {} (corroborated by: {})",
                    "network verdict:".bold(),
                    "FILTERED".red().bold(),
                    corroborating_endpoints.join(", ")
                );
            }
            NetworkVerdict::Inconclusive { reason } => {
                println!(
                    "  {} {} -- {}",
                    "network verdict:".bold(),
                    "inconclusive".yellow(),
                    reason
                );
            }
        }
    }
}
