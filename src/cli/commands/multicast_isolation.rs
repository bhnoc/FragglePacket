//! GAP-057: discovery/multicast/peer-isolation policy diagnostic (`multicast-isolation`).

use colored::*;
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;

use fraggle_packet::load_guard::route::is_tunnel_interface;
use fraggle_packet::network_tests::multicast_isolation::{
    judge, observe_group_delivery, probe_multicast_group, probe_peer_reachability, tally_responses, ExpectedReachability, Observation, ResponderTally, Verdict,
    MAX_PROBES_PER_KIND, MDNS_GROUP, MDNS_PORT, SSDP_GROUP, SSDP_PORT, TUNNEL_INTERFACE_WARNING,
};

#[derive(clap::Args, Debug)]
pub struct MulticastIsolationArgs {
    /// Interface under test, only used for the tunnel-interface warning.
    #[arg(long)]
    pub interface: Option<String>,

    /// Explicitly named peer for the isolation check (host:port). Required
    /// for peer isolation -- there is no discovery/enumeration path into
    /// that check, since probing an unnamed peer on a shared network
    /// without authorization is scanning someone else's device. Pass a
    /// loopback address (e.g. 127.0.0.1:9) to validate the mechanism
    /// without a second host.
    #[arg(long)]
    pub peer: Option<String>,

    /// Declared expected reachability for mDNS. Omit to report the
    /// observation without a pass/fail judgment.
    #[arg(long, value_enum)]
    pub expect_mdns: Option<Expectation>,

    #[arg(long, value_enum)]
    pub expect_ssdp: Option<Expectation>,

    #[arg(long, value_enum)]
    pub expect_multicast_delivery: Option<Expectation>,

    #[arg(long, value_enum)]
    pub expect_peer_isolation: Option<Expectation>,

    /// Probes per discovery kind. Hard-capped regardless of this value
    /// (GAP-047) -- mDNS/SSDP queries are a handful of packets, not a sweep.
    #[arg(long, default_value_t = 3)]
    pub probe_count: u32,

    #[arg(long, default_value_t = 800)]
    pub listen_ms: u64,

    /// For the demo/test harness only: skip real sockets and return a
    /// deterministic synthetic observation set.
    #[arg(long)]
    pub inject_fixture: Option<String>,

    #[arg(long)]
    pub json: bool,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Expectation {
    Reachable,
    Blocked,
}

impl From<Expectation> for ExpectedReachability {
    fn from(e: Expectation) -> Self {
        match e {
            Expectation::Reachable => ExpectedReachability::ExpectedReachable,
            Expectation::Blocked => ExpectedReachability::ExpectedBlocked,
        }
    }
}

#[derive(serde::Serialize)]
struct CheckResult {
    observation: &'static str,
    verdict: &'static str,
}

fn obs_label(o: Observation) -> &'static str {
    match o {
        Observation::Reachable => "reachable",
        Observation::NoResponse => "no_response",
        Observation::ConfirmedBlocked => "confirmed_blocked",
    }
}

fn verdict_label(v: Verdict) -> &'static str {
    match v {
        Verdict::NoExpectationDeclared => "no_expectation_declared",
        Verdict::MatchesExpectation => "matches_expectation",
        Verdict::UnexpectedlyReachable => "UNEXPECTEDLY_REACHABLE",
        Verdict::UnexpectedlyBlocked => "UNEXPECTEDLY_BLOCKED",
        Verdict::ObservationInconclusive => "observation_inconclusive",
    }
}

fn check_result(observed: Observation, expected: Option<ExpectedReachability>) -> CheckResult {
    CheckResult {
        observation: obs_label(observed),
        verdict: verdict_label(judge(observed, expected)),
    }
}

fn resolve(host_port: &str) -> Result<SocketAddr, String> {
    host_port
        .to_socket_addrs()
        .map_err(|e| format!("failed to resolve {host_port}: {e}"))?
        .next()
        .ok_or_else(|| format!("{host_port} resolved to no addresses"))
}

fn synthetic_observation(seed: &str, kind: &str) -> Observation {
    match (seed, kind) {
        ("all-blocked", _) => Observation::ConfirmedBlocked,
        ("all-reachable", _) => Observation::Reachable,
        ("no-response", _) => Observation::NoResponse,
        ("mixed", "mdns") => Observation::Reachable,
        ("mixed", "ssdp") => Observation::ConfirmedBlocked,
        ("mixed", "multicast_delivery") => Observation::NoResponse,
        ("mixed", "peer") => Observation::ConfirmedBlocked,
        _ => Observation::NoResponse,
    }
}

fn synthetic_tally(seed: &str) -> ResponderTally {
    use fraggle_packet::network_tests::multicast_isolation::ServiceClass;
    match seed {
        "all-reachable" | "mixed" => ResponderTally {
            total_responses: 2,
            by_class: vec![(ServiceClass::Printer, 1), (ServiceClass::Airplay, 1)],
        },
        _ => ResponderTally {
            total_responses: 0,
            by_class: vec![],
        },
    }
}

pub fn run(args: &MulticastIsolationArgs) {
    let interface_is_tunnel = args
        .interface
        .as_deref()
        .map(is_tunnel_interface)
        .unwrap_or(false);
    if interface_is_tunnel {
        eprintln!("{} {}", "⚠".yellow().bold(), TUNNEL_INTERFACE_WARNING);
    }

    let listen_for = Duration::from_millis(args.listen_ms);
    let expected_mdns = args.expect_mdns.map(ExpectedReachability::from);
    let expected_ssdp = args.expect_ssdp.map(ExpectedReachability::from);
    let expected_multicast = args
        .expect_multicast_delivery
        .map(ExpectedReachability::from);
    let expected_peer = args.expect_peer_isolation.map(ExpectedReachability::from);

    let (mdns_obs, mdns_tally, ssdp_obs, ssdp_tally, multicast_obs) =
        if let Some(seed) = &args.inject_fixture {
            (
                synthetic_observation(seed, "mdns"),
                synthetic_tally(seed),
                synthetic_observation(seed, "ssdp"),
                synthetic_tally(seed),
                synthetic_observation(seed, "multicast_delivery"),
            )
        } else {
            let query = b"fraggle-packet-discovery-probe";
            let mdns_responses =
                probe_multicast_group(MDNS_GROUP, MDNS_PORT, query, args.probe_count, listen_for)
                    .unwrap_or_default();
            let mdns_obs = if mdns_responses.is_empty() {
                Observation::NoResponse
            } else {
                Observation::Reachable
            };
            let mdns_tally = tally_responses(&mdns_responses);

            let ssdp_responses =
                probe_multicast_group(SSDP_GROUP, SSDP_PORT, query, args.probe_count, listen_for)
                    .unwrap_or_default();
            let ssdp_obs = if ssdp_responses.is_empty() {
                Observation::NoResponse
            } else {
                Observation::Reachable
            };
            let ssdp_tally = tally_responses(&ssdp_responses);

            let multicast_obs = observe_group_delivery(MDNS_GROUP, MDNS_PORT, listen_for)
                .unwrap_or(Observation::NoResponse);

            (mdns_obs, mdns_tally, ssdp_obs, ssdp_tally, multicast_obs)
        };

    let peer_result: Option<CheckResult> = if let Some(seed) = &args.inject_fixture {
        args.peer
            .as_ref()
            .map(|_| check_result(synthetic_observation(seed, "peer"), expected_peer))
    } else if let Some(peer_str) = &args.peer {
        match resolve(peer_str) {
            Ok(peer_addr) => {
                let obs = probe_peer_reachability(
                    peer_addr,
                    args.probe_count,
                    Duration::from_millis(args.listen_ms),
                )
                .unwrap_or(Observation::NoResponse);
                Some(check_result(obs, expected_peer))
            }
            Err(e) => {
                eprintln!("{} peer resolution failed: {}", "✗".red(), e);
                None
            }
        }
    } else {
        None
    };

    let mdns_result = check_result(mdns_obs, expected_mdns);
    let ssdp_result = check_result(ssdp_obs, expected_ssdp);
    let multicast_result = check_result(multicast_obs, expected_multicast);
    let probe_cap = MAX_PROBES_PER_KIND;

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "interface": args.interface,
                "interface_is_tunnel": interface_is_tunnel,
                "mdns": { "result": mdns_result, "responders": mdns_tally },
                "ssdp": { "result": ssdp_result, "responders": ssdp_tally },
                "multicast_delivery": multicast_result,
                "peer_isolation": peer_result,
                "probe_cap_per_kind": probe_cap,
            }))
            .unwrap()
        );
        return;
    }

    println!();
    println!(
        "{}",
        "== Discovery / Multicast / Peer Isolation ==".cyan().bold()
    );
    if interface_is_tunnel {
        println!("  {} {}", "⚠".yellow(), TUNNEL_INTERFACE_WARNING);
    }
    print_check("mDNS", &mdns_result, Some(&mdns_tally));
    print_check("SSDP", &ssdp_result, Some(&ssdp_tally));
    print_check("multicast delivery", &multicast_result, None);
    match &peer_result {
        Some(r) => print_check("peer isolation", r, None),
        None => println!("  [peer isolation] not run -- pass --peer host:port to check (requires an explicitly named peer)"),
    }
    println!("  probe cap per discovery kind: {probe_cap}");
    println!();
}

fn print_check(label: &str, result: &CheckResult, tally: Option<&ResponderTally>) {
    let verdict_display = match result.verdict {
        "UNEXPECTEDLY_REACHABLE" | "UNEXPECTEDLY_BLOCKED" => {
            result.verdict.red().bold().to_string()
        }
        "matches_expectation" => result.verdict.green().to_string(),
        _ => result.verdict.dimmed().to_string(),
    };
    println!(
        "  [{label}] observation={} verdict={}",
        result.observation, verdict_display
    );
    if let Some(t) = tally {
        println!(
            "    responders: {} (by class: {:?})",
            t.total_responses, t.by_class
        );
    }
}
