//! GAP-069: process-model equivalence and receive-path artifact guard
//! (`process-model`).
//!
//! Compares a native `iperf3 --bidir` trial against `independent_rates`'
//! paired-process trial at the same target rate and withholds a
//! network-attributable directional-collapse verdict unless it reproduces
//! across both process models. See `load_guard::process_model` for the
//! judged logic; this command wires it to real iperf3 invocations (kept
//! tiny by default -- GAP-047 forbids heavy load by default) and to
//! operator-supplied Linux receive-path telemetry.

use colored::*;
use std::io::Read;
use std::process::Command;
use std::time::Duration;

use fraggle_packet::load_guard::{
    judge_collapse, receive_path_from_external, sample_receive_path_live, CollapseVerdict,
    ExternalReceivePathTelemetry, HostResourceCounters, ProcessModel, ProcessModelTrial,
};
use fraggle_packet::network_tests::iperf::{parse_iperf_json, IperfResult};

#[derive(clap::Args, Debug)]
pub struct ProcessModelArgs {
    /// iperf3-compatible server hostname/IP. No hardcoded default.
    #[arg(long)]
    pub server: Option<String>,

    /// Local interface to bind sessions to (e.g. en0). Required: the
    /// default route on this class of machine is frequently a VPN tunnel.
    #[arg(long)]
    pub interface: Option<String>,

    /// Local IP address on --interface to bind to (iperf3 `-B ip%iface`).
    #[arg(long)]
    pub local_ip: Option<String>,

    /// Target rate per direction in Mbps. Kept tiny by default -- the
    /// 250 Mbps field evidence needs an authorized window, not a default
    /// invocation.
    #[arg(long, default_value_t = 2.0)]
    pub target_mbps: f64,

    #[arg(long, default_value_t = 5201)]
    pub bidir_port: u16,

    #[arg(long, default_value_t = 5202)]
    pub upload_port: u16,

    #[arg(long, default_value_t = 5203)]
    pub download_port: u16,

    /// Seconds per trial. Kept tiny.
    #[arg(long, default_value_t = 2)]
    pub duration_secs: u64,

    /// For the demo/test harness only: inject the PV10 field-evidence shape
    /// instead of running real iperf3 sessions, so the comparison logic is
    /// exercisable offline. One of: "pv10-collapse" (paired-only collapse,
    /// the field finding), "reproduces" (collapses in both models),
    /// "balanced" (no collapse in either).
    #[arg(long)]
    pub inject_fixture: Option<String>,

    /// Path to a JSON file (or "-" for stdin) with operator-supplied Linux
    /// receive-path telemetry (`ExternalReceivePathTelemetry`) for the
    /// paired-process trial, e.g. exported from a Precog probe's
    /// `/proc/net/netstat`. Overlaid onto whatever this host measured
    /// natively (nothing, on macOS).
    #[arg(long)]
    pub paired_receive_path_in: Option<String>,

    /// Same, for the native-bidir trial.
    #[arg(long)]
    pub native_receive_path_in: Option<String>,

    #[arg(long)]
    pub json: bool,
}

fn load_external_telemetry(path: &str) -> Result<ExternalReceivePathTelemetry, String> {
    let text = if path == "-" {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| e.to_string())?;
        buf
    } else {
        std::fs::read_to_string(path).map_err(|e| e.to_string())?
    };
    serde_json::from_str(&text).map_err(|e| e.to_string())
}

fn fixture_trials(seed: &str, target_mbps: f64) -> (ProcessModelTrial, ProcessModelTrial) {
    let platform_limited = fraggle_packet::load_guard::ReceivePathCounters::platform_limited();
    match seed {
        "reproduces" => (
            ProcessModelTrial {
                model: ProcessModel::NativeBidir,
                target_mbps_per_direction: target_mbps,
                upload_mbps: Some(target_mbps * 1.2),
                download_mbps: Some(target_mbps * 0.08),
                receive_path: platform_limited.clone(),
                host_resources: HostResourceCounters::platform_limited(),
            },
            ProcessModelTrial {
                model: ProcessModel::PairedProcess,
                target_mbps_per_direction: target_mbps,
                upload_mbps: Some(target_mbps * 1.18),
                download_mbps: Some(target_mbps * 0.10),
                receive_path: platform_limited,
                host_resources: HostResourceCounters::platform_limited(),
            },
        ),
        "balanced" => (
            ProcessModelTrial {
                model: ProcessModel::NativeBidir,
                target_mbps_per_direction: target_mbps,
                upload_mbps: Some(target_mbps * 0.64),
                download_mbps: Some(target_mbps * 0.62),
                receive_path: platform_limited.clone(),
                host_resources: HostResourceCounters::platform_limited(),
            },
            ProcessModelTrial {
                model: ProcessModel::PairedProcess,
                target_mbps_per_direction: target_mbps,
                upload_mbps: Some(target_mbps * 0.63),
                download_mbps: Some(target_mbps * 0.61),
                receive_path: platform_limited,
                host_resources: HostResourceCounters::platform_limited(),
            },
        ),
        // "pv10-collapse" and any other value: the field-evidence shape.
        _ => (
            ProcessModelTrial {
                model: ProcessModel::NativeBidir,
                target_mbps_per_direction: target_mbps,
                upload_mbps: Some(161.0),
                download_mbps: Some(145.0),
                receive_path: platform_limited,
                host_resources: HostResourceCounters::platform_limited(),
            },
            ProcessModelTrial {
                model: ProcessModel::PairedProcess,
                target_mbps_per_direction: target_mbps,
                upload_mbps: Some(300.0),
                download_mbps: Some(20.0),
                receive_path: fraggle_packet::load_guard::ReceivePathCounters {
                    tcp_rcv_collapsed:
                        fraggle_packet::network_tests::rf_survey::Metric::operator_supplied(86),
                    softnet_drops:
                        fraggle_packet::network_tests::rf_survey::Metric::platform_limited(),
                    qdisc_drops: fraggle_packet::network_tests::rf_survey::Metric::platform_limited(
                    ),
                },
                host_resources: HostResourceCounters::platform_limited(),
            },
        ),
    }
}

/// Runs a bounded native `iperf3 --bidir` trial. Requires `--server`,
/// `--interface`, and `--local-ip`; this never runs by default.
fn run_native_bidir(
    server: &str,
    interface: &str,
    local_ip: &str,
    port: u16,
    rate_mbps: f64,
    duration_secs: u64,
) -> Result<IperfResult, String> {
    let bind = format!("{local_ip}%{interface}");
    let rate_arg = format!("{rate_mbps}M");
    let mut cmd = Command::new("iperf3");
    cmd.args([
        "-c",
        server,
        "-p",
        &port.to_string(),
        "-4",
        "-B",
        &bind,
        "-u",
        "-b",
        &rate_arg,
        "-t",
        &duration_secs.to_string(),
        "--bidir",
        "-J",
        "--connect-timeout",
        "3000",
    ]);
    run_with_timeout(cmd, Duration::from_secs(duration_secs.max(1) + 10))
}

fn run_paired(
    server: &str,
    interface: &str,
    local_ip: &str,
    upload_port: u16,
    download_port: u16,
    rate_mbps: f64,
    duration_secs: u64,
) -> (Result<IperfResult, String>, Result<IperfResult, String>) {
    let barrier = std::time::Instant::now() + Duration::from_millis(200);
    let up_server = server.to_string();
    let up_local_ip = local_ip.to_string();
    let up_interface = interface.to_string();
    let handle = std::thread::spawn(move || {
        let now = std::time::Instant::now();
        if barrier > now {
            std::thread::sleep(barrier - now);
        }
        let bind = format!("{up_local_ip}%{up_interface}");
        let rate_arg = format!("{rate_mbps}M");
        let mut cmd = Command::new("iperf3");
        cmd.args([
            "-c",
            &up_server,
            "-p",
            &upload_port.to_string(),
            "-4",
            "-B",
            &bind,
            "-u",
            "-b",
            &rate_arg,
            "-t",
            &duration_secs.to_string(),
            "-J",
            "--connect-timeout",
            "3000",
        ]);
        run_with_timeout(cmd, Duration::from_secs(duration_secs.max(1) + 10))
    });

    let now = std::time::Instant::now();
    if barrier > now {
        std::thread::sleep(barrier - now);
    }
    let bind = format!("{local_ip}%{interface}");
    let rate_arg = format!("{rate_mbps}M");
    let mut cmd = Command::new("iperf3");
    cmd.args([
        "-c",
        server,
        "-p",
        &download_port.to_string(),
        "-4",
        "-B",
        &bind,
        "-u",
        "-b",
        &rate_arg,
        "-t",
        &duration_secs.to_string(),
        "-R",
        "-J",
        "--connect-timeout",
        "3000",
    ]);
    let download_result = run_with_timeout(cmd, Duration::from_secs(duration_secs.max(1) + 10));
    let upload_result = handle
        .join()
        .unwrap_or_else(|_| Err("upload thread panicked".to_string()));
    (upload_result, download_result)
}

fn run_with_timeout(mut cmd: Command, hard_timeout: Duration) -> Result<IperfResult, String> {
    use std::process::Stdio;
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("failed to run iperf3: {e}"))?;
    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if start.elapsed() >= hard_timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!(
                        "iperf3 did not exit within {hard_timeout:?}; killed"
                    ));
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => return Err(format!("failed to poll iperf3: {e}")),
        }
    }
    let output = child
        .wait_with_output()
        .map_err(|e| format!("failed to collect iperf3 output: {e}"))?;
    parse_iperf_json(&String::from_utf8_lossy(&output.stdout)).map_err(|e| format!("{e:?}"))
}

fn mbps_of(sample: Option<fraggle_packet::network_tests::iperf::RateSample>) -> Option<f64> {
    sample.map(|s| s.bits_per_second / 1e6)
}

fn native_trial_from_result(
    target_mbps: f64,
    result: &Result<IperfResult, String>,
) -> ProcessModelTrial {
    let mut upload = None;
    let mut download = None;
    if let Ok(r) = result {
        // Forward is the client's own send direction (upload); bidir_reverse
        // is what the client received back (download). Prefer the receiver
        // side per GAP-039's guidance -- only the receiver saw what actually
        // arrived -- falling back to the estimated block if hollow.
        upload = mbps_of(r.forward.sent.or(r.forward.estimated_received));
        download = r
            .bidir_reverse
            .as_ref()
            .and_then(|rev| mbps_of(rev.received.or(rev.estimated_received)));
    }
    ProcessModelTrial {
        model: ProcessModel::NativeBidir,
        target_mbps_per_direction: target_mbps,
        upload_mbps: upload,
        download_mbps: download,
        receive_path: sample_receive_path_live(),
        host_resources: HostResourceCounters::sample_live(),
    }
}

fn paired_trial_from_results(
    target_mbps: f64,
    upload: &Result<IperfResult, String>,
    download: &Result<IperfResult, String>,
) -> ProcessModelTrial {
    let upload_mbps = upload
        .as_ref()
        .ok()
        .and_then(|r| mbps_of(r.forward.sent.or(r.forward.estimated_received)));
    let download_mbps = download
        .as_ref()
        .ok()
        .and_then(|r| mbps_of(r.forward.received.or(r.forward.estimated_received)));
    ProcessModelTrial {
        model: ProcessModel::PairedProcess,
        target_mbps_per_direction: target_mbps,
        upload_mbps,
        download_mbps,
        receive_path: sample_receive_path_live(),
        host_resources: HostResourceCounters::sample_live(),
    }
}

pub fn run(args: &ProcessModelArgs) {
    let (mut native, mut paired) = if let Some(seed) = &args.inject_fixture {
        fixture_trials(seed, args.target_mbps)
    } else {
        let interface = match &args.interface {
            Some(i) => i.clone(),
            None => {
                eprintln!(
                    "{} --interface is required (default route is frequently a VPN tunnel).",
                    "✗".red()
                );
                std::process::exit(1);
            }
        };
        let server = match &args.server {
            Some(s) => s.clone(),
            None => {
                eprintln!(
                    "{} --server is required; there is no hardcoded default endpoint.",
                    "✗".red()
                );
                std::process::exit(1);
            }
        };
        let local_ip = match &args.local_ip {
            Some(ip) => ip.clone(),
            None => {
                eprintln!(
                    "{} --local-ip is required to bind sessions to --interface explicitly.",
                    "✗".red()
                );
                std::process::exit(1);
            }
        };

        let native_result = run_native_bidir(
            &server,
            &interface,
            &local_ip,
            args.bidir_port,
            args.target_mbps,
            args.duration_secs,
        );
        let (up_result, down_result) = run_paired(
            &server,
            &interface,
            &local_ip,
            args.upload_port,
            args.download_port,
            args.target_mbps,
            args.duration_secs,
        );

        (
            native_trial_from_result(args.target_mbps, &native_result),
            paired_trial_from_results(args.target_mbps, &up_result, &down_result),
        )
    };

    if let Some(path) = &args.native_receive_path_in {
        match load_external_telemetry(path) {
            Ok(ext) => native.receive_path = receive_path_from_external(&ext),
            Err(e) => {
                eprintln!(
                    "{} failed to load --native-receive-path-in: {}",
                    "✗".red(),
                    e
                );
                std::process::exit(1);
            }
        }
    }
    if let Some(path) = &args.paired_receive_path_in {
        match load_external_telemetry(path) {
            Ok(ext) => paired.receive_path = receive_path_from_external(&ext),
            Err(e) => {
                eprintln!(
                    "{} failed to load --paired-receive-path-in: {}",
                    "✗".red(),
                    e
                );
                std::process::exit(1);
            }
        }
    }

    let verdict = judge_collapse(Some(&native), Some(&paired));

    if args.json {
        let out = serde_json::json!({
            "native_bidir": native,
            "paired_process": paired,
            "verdict": verdict,
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
        return;
    }

    print_human(&native, &paired, &verdict);
}

fn fmt_mbps(v: Option<f64>) -> String {
    v.map(|v| format!("{v:.1} Mbps"))
        .unwrap_or_else(|| "unavailable".to_string())
}

fn fmt_metric_u64(m: &fraggle_packet::network_tests::rf_survey::Metric<u64>) -> String {
    use fraggle_packet::network_tests::rf_survey::Obtainability;
    match (m.value, m.obtainability) {
        (Some(v), Obtainability::Measured) => format!("{v} (measured)"),
        (Some(v), Obtainability::OperatorSupplied) => format!("{v} (operator-supplied)"),
        (None, Obtainability::PlatformLimited) => "platform-limited".yellow().to_string(),
        _ => "unavailable".dimmed().to_string(),
    }
}

fn print_human(native: &ProcessModelTrial, paired: &ProcessModelTrial, verdict: &CollapseVerdict) {
    println!();
    println!(
        "{}",
        "== Process-Model Equivalence Guard (GAP-069) =="
            .cyan()
            .bold()
    );
    println!(
        "  native --bidir:      up={} down={} TCPRcvCollapsed={}",
        fmt_mbps(native.upload_mbps),
        fmt_mbps(native.download_mbps),
        fmt_metric_u64(&native.receive_path.tcp_rcv_collapsed)
    );
    println!(
        "  paired-process:      up={} down={} TCPRcvCollapsed={}",
        fmt_mbps(paired.upload_mbps),
        fmt_mbps(paired.download_mbps),
        fmt_metric_u64(&paired.receive_path.tcp_rcv_collapsed)
    );
    println!();
    match verdict {
        CollapseVerdict::Withheld { missing } => {
            println!("  verdict: {}", "WITHHELD".red().bold());
            for m in missing {
                println!("    missing: {}", m);
            }
        }
        CollapseVerdict::MethodSpecificUnfairness { detail } => {
            println!(
                "  verdict: {}",
                "METHOD-SPECIFIC UNFAIRNESS (not a network finding)"
                    .yellow()
                    .bold()
            );
            println!("  {}", detail);
        }
        CollapseVerdict::ReproducesAcrossProcessModels { detail } => {
            println!(
                "  verdict: {}",
                "REPRODUCES ACROSS PROCESS MODELS (network-attributable)"
                    .red()
                    .bold()
            );
            println!("  {}", detail);
        }
        CollapseVerdict::NoCollapseObserved => {
            println!(
                "  verdict: {}",
                "no directional collapse observed in either model".green()
            );
        }
    }
    println!();
}
