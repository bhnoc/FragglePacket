//! GAP-006: controlled TCP-versus-UDP throughput/loss comparison
//! (`tcp-vs-udp`) against a user-supplied iperf3-compatible endpoint.

use colored::*;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use fraggle_packet::load_guard::guard::RadioTimeline;
use fraggle_packet::load_guard::radio::RadioSnapshot;
use fraggle_packet::load_guard::{tcp_result, udp_result, TcpVsUdpComparison};
use fraggle_packet::network_tests::iperf::{parse_iperf_json, IperfParseError, IperfResult};

#[derive(clap::Args, Debug)]
pub struct TcpVsUdpArgs {
    /// iperf3-compatible server hostname/IP. No hardcoded default.
    #[arg(long)]
    pub server: Option<String>,

    #[arg(long)]
    pub interface: Option<String>,

    #[arg(long)]
    pub local_ip: Option<String>,

    #[arg(long, default_value_t = 5201)]
    pub tcp_port: u16,

    #[arg(long, default_value_t = 5202)]
    pub udp_port: u16,

    /// Target rate in Mbps, applied to both the TCP and UDP session. Kept
    /// tiny -- GAP-047 forbids heavy load by default.
    #[arg(long, default_value_t = 1.0)]
    pub rate_mbps: f64,

    #[arg(long, default_value_t = 1)]
    pub duration_secs: u64,

    /// For the demo/test harness only: parse the repo's captured iperf3
    /// fixtures instead of running real sessions.
    #[arg(long)]
    pub inject_fixture: bool,

    #[arg(long)]
    pub json: bool,
}

fn run_iperf(server: &str, port: u16, local_ip: &str, interface: &str, rate_mbps: f64, duration_secs: u64, udp: bool) -> Result<IperfResult, IperfParseError> {
    let bind = format!("{local_ip}%{interface}");
    let rate_arg = format!("{rate_mbps}M");
    let mut cmd = Command::new("iperf3");
    cmd.args(["-c", server, "-p", &port.to_string(), "-4", "-B", &bind, "-b", &rate_arg, "-t", &duration_secs.to_string(), "-J", "--connect-timeout", "3000"]);
    if udp {
        cmd.arg("-u");
    }
    run_with_hard_timeout(cmd, Duration::from_secs(duration_secs.max(1) + 10))
}

/// A listener that never admits (GAP-045's known failure shape) must not
/// hang this process indefinitely -- iperf3 has no default connect
/// deadline. `--connect-timeout` (set by the caller) bounds admission; this
/// wall-clock kill is the unconditional backstop behind it.
fn run_with_hard_timeout(mut cmd: Command, hard_timeout: Duration) -> Result<IperfResult, IperfParseError> {
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return Err(IperfParseError::InvalidJson(format!("failed to run iperf3: {e}"))),
    };

    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_status)) => break,
            Ok(None) => {
                if start.elapsed() >= hard_timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(IperfParseError::InvalidJson(format!("iperf3 did not exit within {hard_timeout:?}; killed")));
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => return Err(IperfParseError::InvalidJson(format!("failed to poll iperf3: {e}"))),
        }
    }

    let output = match child.wait_with_output() {
        Ok(o) => o,
        Err(e) => return Err(IperfParseError::InvalidJson(format!("failed to collect iperf3 output: {e}"))),
    };
    parse_iperf_json(&String::from_utf8_lossy(&output.stdout))
}

fn load_fixture(name: &str) -> Result<IperfResult, IperfParseError> {
    let path = format!("{}/harness/fixtures/iperf/{}", env!("CARGO_MANIFEST_DIR"), name);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        eprintln!("fixture {path} unreadable: {e}");
        std::process::exit(2);
    });
    parse_iperf_json(&text)
}

pub fn run(args: &TcpVsUdpArgs) {
    let mut radio_timeline: Option<RadioTimeline> = None;
    let (tcp_parsed, udp_parsed, endpoint, data_source) = if args.inject_fixture {
        (
            load_fixture("tcp-forward-3.21.json"),
            load_fixture("udp-reverse-3.21.json"),
            "fixture:harness/fixtures/iperf/*.json".to_string(),
            "fixture",
        )
    } else {
        let server = match &args.server {
            Some(s) => s.clone(),
            None => {
                eprintln!("{} --server is required; there is no hardcoded default endpoint.", "✗".red());
                std::process::exit(1);
            }
        };
        let interface = match &args.interface {
            Some(i) => i.clone(),
            None => {
                eprintln!(
                    "{} --interface is required; the default route on this class of machine is \
                     frequently a VPN tunnel, not the interface you intend to test through.",
                    "✗".red()
                );
                std::process::exit(1);
            }
        };
        let local_ip = match &args.local_ip {
            Some(ip) => ip.clone(),
            None => {
                eprintln!("{} --local-ip is required to bind sessions to --interface explicitly.", "✗".red());
                std::process::exit(1);
            }
        };
        // GAP-035: snapshot radio state before and after the two sessions.
        // Neither iperf3 call runs through LoadGuard (they're bare
        // subprocess calls, not a LoadPhase), so this command brackets them
        // directly rather than silently skipping radio coverage.
        let before_radio = fraggle_packet::load_guard::radio::snapshot_live().unwrap_or_else(|_| RadioSnapshot::unavailable());
        let tcp = run_iperf(&server, args.tcp_port, &local_ip, &interface, args.rate_mbps, args.duration_secs, false);
        let udp = run_iperf(&server, args.udp_port, &local_ip, &interface, args.rate_mbps, args.duration_secs, true);
        let after_radio = fraggle_packet::load_guard::radio::snapshot_live().unwrap_or_else(|_| RadioSnapshot::unavailable());
        radio_timeline = Some(RadioTimeline { before: before_radio, during: Vec::new(), after: after_radio });
        (tcp, udp, server, "live")
    };

    let comparison = TcpVsUdpComparison {
        endpoint,
        tcp: tcp_result(args.tcp_port, args.rate_mbps, &tcp_parsed),
        udp: udp_result(args.udp_port, args.rate_mbps, &udp_parsed),
    };

    let radio_validity = radio_validity_for(&radio_timeline);

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "comparison": comparison,
                "achieved_mbps_delta": comparison.achieved_mbps_delta(),
                "data_source": data_source,
                "radio_validity": radio_validity,
            }))
            .unwrap()
        );
        return;
    }
    print_human(&comparison, data_source, &radio_validity);
}

/// `None` when no radio bracketing ran at all (e.g. --inject-fixture),
/// distinct from `Some("stable")` -- a fixture-driven run makes no claim
/// about any radio state, real or otherwise.
fn radio_validity_for(timeline: &Option<RadioTimeline>) -> String {
    match timeline {
        None => "not-applicable (fixture-driven run, no radio bracketed)".to_string(),
        Some(t) => {
            if !t.before.associated || !t.after.associated {
                "invalid: radio state unavailable".to_string()
            } else if t.roamed() {
                "invalid: association roamed during the phase".to_string()
            } else {
                "stable".to_string()
            }
        }
    }
}

fn fmt_mbps(v: Option<f64>) -> String {
    v.map(|v| format!("{v:.1} Mbps")).unwrap_or_else(|| "unavailable".to_string())
}

fn fmt_pct(v: Option<f64>) -> String {
    v.map(|v| format!("{v:.3}%")).unwrap_or_else(|| "unavailable".to_string())
}

fn print_human(comparison: &TcpVsUdpComparison, data_source: &str, radio_validity: &str) {
    println!();
    println!("{}", "== TCP vs UDP ==".cyan().bold());
    println!("  endpoint: {} source={}", comparison.endpoint, data_source);
    println!("  radio validity: {radio_validity}");
    println!(
        "  TCP: usable={} achieved={} {}",
        comparison.tcp.usable,
        fmt_mbps(comparison.tcp.achieved_mbps),
        comparison.tcp.unusable_reason.as_deref().map(|r| format!("({r})")).unwrap_or_default()
    );
    println!(
        "  UDP: usable={} achieved={} loss={} {}",
        comparison.udp.usable,
        fmt_mbps(comparison.udp.achieved_mbps),
        fmt_pct(comparison.udp.loss_percent),
        comparison.udp.unusable_reason.as_deref().map(|r| format!("({r})")).unwrap_or_default()
    );
    match comparison.achieved_mbps_delta() {
        Some(d) => println!("  achieved_mbps_delta (TCP - UDP): {d:.2}"),
        None => println!("  achieved_mbps_delta: unavailable (one or both sides unusable)"),
    }
    println!();
}
