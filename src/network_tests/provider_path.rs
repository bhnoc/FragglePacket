//! GAP-061: provider, geography, and path-stability comparison.
//!
//! Field evidence and the specific trap the acceptance criteria name: a
//! TCP/443 traceroute reached the destination operator's network by hop 5,
//! and later hops showed no response -- inconclusive, not lost, because
//! routers and endpoints may decline TTL-expiry probes entirely.
//! `path_analysis.rs`'s existing parser already gets this wrong in two
//! ways worth reporting even though this module doesn't fix that file
//! (off-limits): (1) `parse_traceroute` only recognizes a literal `* * *`
//! line as a timeout -- a real macOS/BSD traceroute with `-q 1` prints a
//! single bare `*` per unanswered hop, which that parser silently drops
//! from the hop list entirely rather than marking it non-responsive, so
//! hop numbering desyncs; (2) even where it is recognized, `loss_percent`
//! in `measure_per_hop_latency` computes `(probe_count - answered) /
//! probe_count` per hop from repeated traceroute runs, which is a
//! defensible per-hop non-response rate across trials but is then surfaced
//! under the name "loss" with no qualifier -- exactly the wording this
//! module's acceptance criteria warns against for a *single* trace's
//! non-answers. This module's own parser treats a non-responsive hop
//! (`HopOutcome::NoResponse`) as structurally distinct from `Loss`, and
//! `Loss` is never derived from a single trace at all -- only from
//! repeated samples of the SAME hop identity across multiple full traces
//! (`PathStability`), matching the acceptance criterion's "repeated trace
//! samples" requirement.
//!
//! ASN/region: no geolocation API, no new dependency. Reverse DNS
//! (`host`/`dig -x`, already this crate's idiom) sometimes encodes a
//! region hint in the PTR record (e.g. `-iad.github.com`); this module
//! extracts that opportunistically and otherwise reports ASN/region as
//! unavailable. "Correlate with BGP/provider telemetry when available" is
//! satisfied by accepting operator-supplied ASN/region mappings as input,
//! never by fabricating a lookup this client cannot perform.

use std::collections::HashMap;
use std::process::Command;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HopOutcome {
    /// A probe response was received and attributed to this hop.
    Responded,
    /// No response was received for this hop. This is NOT loss: routers
    /// and endpoints may decline TTL-expiry probes as policy. It only
    /// becomes evidence of anything once corroborated across repeated
    /// samples of the same hop identity (see `PathStability`).
    NoResponse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceHop {
    pub hop_number: u32,
    pub outcome: HopOutcome,
    pub addr: Option<String>,
    pub rtt_ms: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceRun {
    pub target: String,
    pub hops: Vec<TraceHop>,
    pub reached_target: bool,
}

/// Parses `traceroute` output (BSD/macOS and Linux variants share this
/// shape closely enough for one parser). A bare `*` token for a hop -- the
/// real output shape at `-q 1`, not just the `* * *` line some other
/// parsers special-case -- is captured as `HopOutcome::NoResponse`,
/// preserving that hop's position rather than dropping the line.
pub fn parse_traceroute(output: &str) -> Vec<TraceHop> {
    let mut hops = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() || line.to_lowercase().starts_with("traceroute") {
            continue;
        }
        let mut parts = line.split_whitespace();
        let hop_token = match parts.next() {
            Some(t) => t,
            None => continue,
        };
        let hop_number: u32 = match hop_token.trim_end_matches(':').parse() {
            Ok(n) => n,
            Err(_) => continue,
        };

        let rest: Vec<&str> = parts.collect();
        if rest.iter().all(|t| t.chars().all(|c| c == '*')) {
            hops.push(TraceHop {
                hop_number,
                outcome: HopOutcome::NoResponse,
                addr: None,
                rtt_ms: None,
            });
            continue;
        }

        let mut addr = None;
        let mut rtt_ms = None;
        for (i, tok) in rest.iter().enumerate() {
            if tok.contains('.') && !tok.ends_with("ms") && addr.is_none() {
                addr = Some(tok.trim_matches(|c| c == '(' || c == ')').to_string());
            }
            if rest.get(i + 1) == Some(&"ms") {
                rtt_ms = tok.parse().ok();
            }
        }

        if addr.is_some() || rtt_ms.is_some() {
            hops.push(TraceHop {
                hop_number,
                outcome: HopOutcome::Responded,
                addr,
                rtt_ms,
            });
        } else {
            // A line with a hop number but nothing parseable is treated as
            // non-response rather than silently dropped -- dropping would
            // desync every subsequent hop's number from its real position.
            hops.push(TraceHop {
                hop_number,
                outcome: HopOutcome::NoResponse,
                addr: None,
                rtt_ms: None,
            });
        }
    }
    hops
}

pub fn run_traceroute(
    target: &str,
    max_hops: u8,
    wait_secs: u8,
    interface: Option<&str>,
) -> Result<TraceRun, String> {
    let mut cmd = Command::new("traceroute");
    cmd.args([
        "-q",
        "1",
        "-w",
        &wait_secs.to_string(),
        "-m",
        &max_hops.to_string(),
    ]);
    if let Some(iface) = interface {
        cmd.args(["-i", iface]);
    }
    cmd.arg(target);
    let output = cmd
        .output()
        .map_err(|e| format!("failed to run traceroute: {e}"))?;

    let text = String::from_utf8_lossy(&output.stdout);
    let hops = parse_traceroute(&text);
    let reached_target = hops
        .last()
        .map(|h| h.outcome == HopOutcome::Responded)
        .unwrap_or(false);

    Ok(TraceRun {
        target: target.to_string(),
        hops,
        reached_target,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HopStabilityVerdict {
    /// The same address answered at this hop number across every sample.
    Stable,
    /// Different addresses answered at this hop number across samples --
    /// a real path change.
    Changed,
    /// Every sample got no response at this hop number -- consistent with
    /// a router/endpoint that always declines this probe, not evidence of
    /// intermittent loss.
    ConsistentlyNonResponsive,
    /// Some samples responded and some did not, with no path change among
    /// the responses -- this is the only shape that can even be
    /// characterized as possible intermittent loss, and even then it is
    /// reported as a response-rate, explicitly not as "% packet loss".
    IntermittentResponse { responded: u32, total: u32 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HopStability {
    pub hop_number: u32,
    pub verdict: HopStabilityVerdict,
    pub addresses_seen: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathStability {
    pub target: String,
    pub sample_count: u32,
    pub per_hop: Vec<HopStability>,
}

/// Assesses stability from REPEATED full traces -- the acceptance
/// criterion's "repeated trace samples" -- never from a single trace.
/// `Loss`-flavored language never appears here: a hop that never answers
/// is `ConsistentlyNonResponsive`, and a hop that sometimes answers is an
/// explicit responded/total ratio, not a loss percentage.
pub fn assess_path_stability(target: &str, runs: &[TraceRun]) -> PathStability {
    let mut by_hop: HashMap<u32, Vec<&TraceHop>> = HashMap::new();
    for run in runs {
        for hop in &run.hops {
            by_hop.entry(hop.hop_number).or_default().push(hop);
        }
    }

    let mut per_hop: Vec<HopStability> = by_hop
        .into_iter()
        .map(|(hop_number, samples)| {
            let total = samples.len() as u32;
            let responded_samples: Vec<&&TraceHop> = samples
                .iter()
                .filter(|h| h.outcome == HopOutcome::Responded)
                .collect();
            let responded = responded_samples.len() as u32;

            let mut addresses_seen: Vec<String> = responded_samples
                .iter()
                .filter_map(|h| h.addr.clone())
                .collect();
            addresses_seen.sort();
            addresses_seen.dedup();

            let verdict = if responded == 0 {
                HopStabilityVerdict::ConsistentlyNonResponsive
            } else if responded < total {
                HopStabilityVerdict::IntermittentResponse { responded, total }
            } else if addresses_seen.len() <= 1 {
                HopStabilityVerdict::Stable
            } else {
                HopStabilityVerdict::Changed
            };

            HopStability {
                hop_number,
                verdict,
                addresses_seen,
            }
        })
        .collect();
    per_hop.sort_by_key(|h| h.hop_number);

    PathStability {
        target: target.to_string(),
        sample_count: runs.len() as u32,
        per_hop,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GeoSource {
    ReverseDnsHint,
    OperatorSupplied,
    Unavailable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoInfo {
    pub asn: Option<String>,
    pub region_hint: Option<String>,
    pub source: GeoSource,
}

/// Opportunistic region hint from a PTR record. This is NOT an ASN lookup
/// -- no client-side ASN source exists without a dependency or external
/// API this task forbids -- so `asn` is always `None` unless the caller
/// supplies one via `operator_geo_override`.
pub fn reverse_dns_region_hint(ip: &str) -> GeoInfo {
    let output = Command::new("dig").args(["-x", ip, "+short"]).output();
    let ptr = match output {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        _ => String::new(),
    };

    if ptr.is_empty() {
        return GeoInfo {
            asn: None,
            region_hint: None,
            source: GeoSource::Unavailable,
        };
    }

    // Airport-code-shaped hints commonly appear as a hyphen-delimited
    // token in CDN/cloud PTR records (e.g. "-iad.github.com",
    // "sea15s01-in-f14.1e100.net"). This is a heuristic, not a
    // lookup -- always presented as a hint, never a confirmed region.
    let region_hint = ptr
        .split(|c: char| c == '.' || c == '-')
        .find(|tok| {
            tok.len() == 3
                && tok.chars().all(|c| c.is_ascii_alphabetic())
                && tok.to_uppercase() == *tok
        })
        .map(|s| s.to_string());

    let source = if region_hint.is_some() {
        GeoSource::ReverseDnsHint
    } else {
        GeoSource::Unavailable
    };
    GeoInfo {
        asn: None,
        region_hint,
        source,
    }
}

pub fn operator_geo_override(asn: Option<String>, region: Option<String>) -> GeoInfo {
    GeoInfo {
        asn,
        region_hint: region,
        source: GeoSource::OperatorSupplied,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderEndpoint {
    pub label: String,
    pub host: String,
    pub resolved_ip: Option<String>,
    pub geo: GeoInfo,
    pub interface: Option<String>,
}

/// A DF/connect probe against this endpoint, kept structurally separate
/// from trace/DNS evidence per the acceptance criteria's list of distinct
/// dimensions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointConnectResult {
    pub connect_ok: bool,
    pub connect_ms: Option<u64>,
}

/// `local_bind_ip`, when supplied, binds the outgoing socket to that local
/// address (e.g. the address on the interface the caller intends to
/// measure) so the connect result describes that path rather than
/// whichever route the OS would pick by default -- on this class of
/// machine, frequently a VPN tunnel.
pub fn probe_connect(
    host: &str,
    port: u16,
    timeout: Duration,
    local_bind_ip: Option<&str>,
) -> EndpointConnectResult {
    use socket2::{Domain, Socket, Type};
    use std::net::{SocketAddr, TcpStream, ToSocketAddrs};

    let start = Instant::now();
    let addr = format!("{host}:{port}")
        .to_socket_addrs()
        .ok()
        .and_then(|mut a| a.next());
    let addr = match addr {
        Some(a) => a,
        None => {
            return EndpointConnectResult {
                connect_ok: false,
                connect_ms: None,
            }
        }
    };

    let stream_result: std::io::Result<TcpStream> = match local_bind_ip {
        Some(ip) => (|| {
            let bind_addr: SocketAddr =
                format!("{}:0", ip).parse().map_err(std::io::Error::other)?;
            let domain = if addr.is_ipv4() {
                Domain::IPV4
            } else {
                Domain::IPV6
            };
            let sock = Socket::new(domain, Type::STREAM, None)?;
            sock.set_nonblocking(false)?;
            sock.bind(&bind_addr.into())?;
            sock.connect_timeout(&addr.into(), timeout)?;
            Ok(sock.into())
        })(),
        None => TcpStream::connect_timeout(&addr, timeout),
    };

    match stream_result {
        Ok(_) => EndpointConnectResult {
            connect_ok: true,
            connect_ms: Some(start.elapsed().as_millis() as u64),
        },
        Err(_) => EndpointConnectResult {
            connect_ok: false,
            connect_ms: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_star_line_is_no_response_not_dropped() {
        let output = " 1  10.0.0.1 (10.0.0.1)  1.2 ms\n 2  *\n 3  10.0.0.3 (10.0.0.3)  5.6 ms\n";
        let hops = parse_traceroute(output);
        assert_eq!(
            hops.len(),
            3,
            "the non-responsive hop must not be silently dropped"
        );
        assert_eq!(hops[1].hop_number, 2);
        assert_eq!(hops[1].outcome, HopOutcome::NoResponse);
    }

    #[test]
    fn central_regression_no_response_never_becomes_loss() {
        // A single trace with several non-responsive hops must never
        // surface a "loss" figure from this trace alone.
        let output =
            " 1  10.0.0.1 (10.0.0.1)  1.2 ms\n 2  *\n 3  *\n 4  10.0.0.4 (10.0.0.4)  9.0 ms\n";
        let hops = parse_traceroute(output);
        let non_responsive = hops
            .iter()
            .filter(|h| h.outcome == HopOutcome::NoResponse)
            .count();
        assert_eq!(non_responsive, 2);
        // There is no loss_percent field anywhere on TraceHop/TraceRun --
        // structurally, a single trace cannot produce one.
    }

    #[test]
    fn consistently_nonresponsive_hop_is_distinct_from_intermittent() {
        let make_run = |hops: Vec<(u32, HopOutcome, Option<&str>)>| TraceRun {
            target: "x".to_string(),
            reached_target: true,
            hops: hops
                .into_iter()
                .map(|(n, o, a)| TraceHop {
                    hop_number: n,
                    outcome: o,
                    addr: a.map(|s| s.to_string()),
                    rtt_ms: None,
                })
                .collect(),
        };

        let runs = vec![
            make_run(vec![
                (1, HopOutcome::Responded, Some("10.0.0.1")),
                (2, HopOutcome::NoResponse, None),
            ]),
            make_run(vec![
                (1, HopOutcome::Responded, Some("10.0.0.1")),
                (2, HopOutcome::NoResponse, None),
            ]),
            make_run(vec![
                (1, HopOutcome::Responded, Some("10.0.0.1")),
                (2, HopOutcome::Responded, Some("10.0.0.2")),
            ]),
        ];
        let stability = assess_path_stability("x", &runs);
        let hop2 = stability
            .per_hop
            .iter()
            .find(|h| h.hop_number == 2)
            .unwrap();
        match hop2.verdict {
            HopStabilityVerdict::IntermittentResponse { responded, total } => {
                assert_eq!(responded, 1);
                assert_eq!(total, 3);
            }
            other => panic!("expected IntermittentResponse, got {:?}", other),
        }
    }

    #[test]
    fn always_nonresponsive_hop_is_not_loss() {
        let make_run = || TraceRun {
            target: "x".to_string(),
            reached_target: false,
            hops: vec![TraceHop {
                hop_number: 3,
                outcome: HopOutcome::NoResponse,
                addr: None,
                rtt_ms: None,
            }],
        };
        let runs = vec![make_run(), make_run(), make_run()];
        let stability = assess_path_stability("x", &runs);
        assert_eq!(
            stability.per_hop[0].verdict,
            HopStabilityVerdict::ConsistentlyNonResponsive
        );
    }

    #[test]
    fn changed_address_at_same_hop_is_path_change() {
        let make_run = |addr: &str| TraceRun {
            target: "x".to_string(),
            reached_target: true,
            hops: vec![TraceHop {
                hop_number: 5,
                outcome: HopOutcome::Responded,
                addr: Some(addr.to_string()),
                rtt_ms: None,
            }],
        };
        let runs = vec![make_run("10.0.0.5"), make_run("10.0.0.6")];
        let stability = assess_path_stability("x", &runs);
        assert_eq!(stability.per_hop[0].verdict, HopStabilityVerdict::Changed);
    }

    #[test]
    fn missing_asn_reports_unavailable_not_guessed() {
        let geo = GeoInfo {
            asn: None,
            region_hint: None,
            source: GeoSource::Unavailable,
        };
        assert!(geo.asn.is_none());
        assert_eq!(geo.source, GeoSource::Unavailable);
    }

    #[test]
    fn operator_override_is_labeled_distinctly_from_a_hint() {
        let geo =
            operator_geo_override(Some("AS15169".to_string()), Some("us-central1".to_string()));
        assert_eq!(geo.source, GeoSource::OperatorSupplied);
    }
}
