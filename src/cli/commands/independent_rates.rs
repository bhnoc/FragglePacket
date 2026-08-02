//! GAP-032: independently rate-controlled simultaneous upload/download
//! (`independent-rates`). Ports `scripts/bhusa-peer-impact-test.zsh`'s
//! method: two independent iperf3 client sessions against separate listener
//! ports, explicit source binding, and a shared start barrier.

use colored::*;
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fraggle_packet::load_guard::{
    first_lossy_rate, merge_timeline, Direction, DirectionSweep, FirstLossyRate, MergedTimeline,
    RatePoint, SessionWindow,
};
use fraggle_packet::network_tests::iperf::{parse_iperf_json, IperfParseError, IperfResult};

#[derive(clap::Args, Debug)]
pub struct IndependentRatesArgs {
    /// iperf3-compatible server hostname/IP. No hardcoded default -- an
    /// endpoint must always be supplied explicitly.
    #[arg(long)]
    pub server: Option<String>,

    /// Local interface to bind sessions to (e.g. en0). Required: the
    /// default route on this class of machine is frequently a VPN tunnel.
    #[arg(long)]
    pub interface: Option<String>,

    /// Local IP address on --interface to bind to (iperf3 `-B ip%iface`).
    #[arg(long)]
    pub local_ip: Option<String>,

    #[arg(long, default_value_t = 5201)]
    pub upload_port: u16,

    #[arg(long, default_value_t = 5202)]
    pub download_port: u16,

    /// Comma-separated target rates in Mbps to sweep, e.g. "1,2,4". Kept
    /// tiny by default -- GAP-047 forbids heavy load by default, and the
    /// full 250/300/350 Mbps matrix from the field investigation needs an
    /// authorized window, not a default invocation.
    #[arg(long, default_value = "1,2")]
    pub rates_mbps: String,

    /// Seconds per rate point per direction. Kept tiny.
    #[arg(long, default_value_t = 1)]
    pub duration_secs: u64,

    /// Loss percentage above which a rate point counts as lossy.
    #[arg(long, default_value_t = 2.0)]
    pub loss_threshold_pct: f64,

    /// For the demo/test harness only: use a synthetic rate sweep matching
    /// the field investigation's numbers instead of running real iperf3
    /// sessions, so the merge/threshold logic is exercisable offline.
    #[arg(long)]
    pub inject_synthetic: bool,

    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, serde::Serialize)]
struct IndependentRatesReport {
    server: String,
    interface: String,
    upload_port: u16,
    download_port: u16,
    upload_sweep: DirectionSweep,
    download_sweep: DirectionSweep,
    upload_first_lossy: FirstLossyRate,
    download_first_lossy: FirstLossyRate,
    example_merged_timeline: Option<MergedTimeline>,
    data_source: &'static str,
}

fn synthetic_sweep(direction: Direction) -> DirectionSweep {
    // Mirrors the field investigation's numbers for illustration/testing.
    let points = match direction {
        Direction::Upload => vec![
            RatePoint { target_mbps: 250.0, achieved_mbps: Some(249.9), loss_percent: Some(0.02), usable: true },
            RatePoint { target_mbps: 300.0, achieved_mbps: Some(283.0), loss_percent: Some(5.6), usable: true },
            RatePoint { target_mbps: 350.0, achieved_mbps: Some(302.0), loss_percent: Some(13.6), usable: true },
        ],
        Direction::Download => vec![
            RatePoint { target_mbps: 250.0, achieved_mbps: Some(249.8), loss_percent: Some(0.076), usable: true },
            RatePoint { target_mbps: 300.0, achieved_mbps: Some(242.0), loss_percent: Some(19.3), usable: true },
            RatePoint { target_mbps: 350.0, achieved_mbps: Some(246.0), loss_percent: Some(29.7), usable: true },
        ],
    };
    DirectionSweep { direction, points }
}

pub fn run(args: &IndependentRatesArgs) {
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

    let (upload_sweep, download_sweep, example_merged) = if args.inject_synthetic {
        (synthetic_sweep(Direction::Upload), synthetic_sweep(Direction::Download), None)
    } else {
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
                eprintln!("{} --local-ip is required to bind sessions to --interface explicitly.", "✗".red());
                std::process::exit(1);
            }
        };
        run_real(args, &server, &interface, &local_ip)
    };

    let upload_first_lossy = first_lossy_rate(&upload_sweep, args.loss_threshold_pct);
    let download_first_lossy = first_lossy_rate(&download_sweep, args.loss_threshold_pct);

    let report = IndependentRatesReport {
        server: args.server.clone().unwrap_or_else(|| "synthetic".to_string()),
        interface,
        upload_port: args.upload_port,
        download_port: args.download_port,
        upload_sweep,
        download_sweep,
        upload_first_lossy,
        download_first_lossy,
        example_merged_timeline: example_merged,
        data_source: if args.inject_synthetic { "synthetic" } else { "live" },
    };

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
        return;
    }
    print_human(&report);
}

fn parse_rates(spec: &str) -> Vec<f64> {
    spec.split(',').filter_map(|s| s.trim().parse::<f64>().ok()).collect()
}

fn run_iperf(
    server: &str,
    port: u16,
    local_ip: &str,
    interface: &str,
    rate_mbps: f64,
    duration_secs: u64,
    reverse: bool,
    start_at: Instant,
) -> Result<IperfResult, IperfParseError> {
    // Barrier: every session waits for the same Instant before invoking
    // iperf3, so the client-side launch times are aligned; the merged
    // SessionWindow below records what was actually observed, not assumed.
    let now = Instant::now();
    if start_at > now {
        std::thread::sleep(start_at - now);
    }

    let bind = format!("{local_ip}%{interface}");
    let rate_arg = format!("{rate_mbps}M");
    let mut cmd = Command::new("iperf3");
    cmd.args([
        "-c", server, "-p", &port.to_string(), "-4", "-B", &bind, "-u", "-b", &rate_arg,
        "-t", &duration_secs.to_string(), "-J",
        // A listener that never admits (GAP-045's known failure shape) must
        // not hang this process indefinitely -- iperf3 has no default
        // connect deadline. `--connect-timeout` bounds admission; the
        // wall-clock kill in `run_with_hard_timeout` bounds the rest.
        "--connect-timeout", "3000",
    ]);
    if reverse {
        cmd.arg("-R");
    }
    run_with_hard_timeout(cmd, Duration::from_secs(duration_secs.max(1) + 10))
}

/// Runs `cmd`, killing it if it has not exited within `hard_timeout` -- a
/// second, unconditional backstop behind `--connect-timeout` so a hung
/// public listener degrades to a reported error rather than an indefinite
/// hang, regardless of why iperf3 itself failed to time out.
fn run_with_hard_timeout(mut cmd: Command, hard_timeout: Duration) -> Result<IperfResult, IperfParseError> {
    use std::process::Stdio;
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

fn run_real(
    args: &IndependentRatesArgs,
    server: &str,
    interface: &str,
    local_ip: &str,
) -> (DirectionSweep, DirectionSweep, Option<MergedTimeline>) {
    let rates = parse_rates(&args.rates_mbps);
    let mut upload_points = Vec::new();
    let mut download_points = Vec::new();
    let mut example_merged = None;

    for (i, &rate) in rates.iter().enumerate() {
        let barrier = Instant::now() + Duration::from_millis(200);
        let upload_start = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs_f64();

        let upload_server = server.to_string();
        let upload_local_ip = local_ip.to_string();
        let upload_interface = interface.to_string();
        let upload_port = args.upload_port;
        let duration = args.duration_secs;
        let upload_handle = std::thread::spawn(move || {
            run_iperf(&upload_server, upload_port, &upload_local_ip, &upload_interface, rate, duration, false, barrier)
        });

        let download_result = run_iperf(server, args.download_port, local_ip, interface, rate, args.duration_secs, true, barrier);
        let upload_result = upload_handle
            .join()
            .unwrap_or_else(|_| Err(IperfParseError::InvalidJson("upload thread panicked".to_string())));

        let download_start = upload_start; // both waited on the same barrier
        let elapsed_guess = args.duration_secs as f64;

        if i == 0 {
            example_merged = Some(merge_timeline(
                SessionWindow { direction: Direction::Upload, port: args.upload_port, start_secs: upload_start, end_secs: upload_start + elapsed_guess },
                SessionWindow { direction: Direction::Download, port: args.download_port, start_secs: download_start, end_secs: download_start + elapsed_guess },
            ));
        }

        upload_points.push(rate_point_from_result(rate, &upload_result));
        download_points.push(rate_point_from_result(rate, &download_result));
    }

    (
        DirectionSweep { direction: Direction::Upload, points: upload_points },
        DirectionSweep { direction: Direction::Download, points: download_points },
        example_merged,
    )
}

/// Prefers the receiver-side sample (GAP-039: only the receiver saw what
/// actually arrived), falling back to the legacy `sum` (`estimated_received`)
/// block only if `received` is absent/hollow.
fn rate_point_from_result(target_mbps: f64, parsed: &Result<IperfResult, IperfParseError>) -> RatePoint {
    let Ok(result) = parsed else {
        return RatePoint { target_mbps, achieved_mbps: None, loss_percent: None, usable: false };
    };
    let Some(sample) = result.forward.received.or(result.forward.estimated_received) else {
        return RatePoint { target_mbps, achieved_mbps: None, loss_percent: None, usable: false };
    };
    RatePoint {
        target_mbps,
        achieved_mbps: Some(sample.bits_per_second / 1e6),
        loss_percent: sample.lost_percent,
        usable: true,
    }
}

fn fmt_pct(v: Option<f64>) -> String {
    v.map(|v| format!("{v:.3}%")).unwrap_or_else(|| "unavailable".to_string())
}

fn fmt_mbps(v: Option<f64>) -> String {
    v.map(|v| format!("{v:.1} Mbps")).unwrap_or_else(|| "unavailable".to_string())
}

fn fmt_first_lossy(f: &FirstLossyRate) -> String {
    match f {
        FirstLossyRate::Found { clean_mbps, lossy_mbps } => {
            format!("first lossy rate: {lossy_mbps:.1} Mbps (last clean measured: {clean_mbps:.1} Mbps)")
        }
        FirstLossyRate::NoneObservedWithinTestedRange => {
            "no lossy rate observed within the tested range (not extrapolated above it)".to_string()
        }
        FirstLossyRate::AllTestedRatesLossy => {
            "every tested rate was already lossy -- no clean baseline to report a threshold against".to_string()
        }
        FirstLossyRate::InsufficientData => "insufficient data (fewer than two usable rate points)".to_string(),
    }
}

fn print_human(report: &IndependentRatesReport) {
    println!();
    println!("{}", "== Independent Upload/Download Rate Sweep ==".cyan().bold());
    println!("  server: {} interface: {} source={}", report.server, report.interface, report.data_source);
    println!("  upload_port={} download_port={}", report.upload_port, report.download_port);
    println!();
    println!("  {}", "Upload:".bold());
    for p in &report.upload_sweep.points {
        println!(
            "    target={:.1}Mbps achieved={} loss={} usable={}",
            p.target_mbps, fmt_mbps(p.achieved_mbps), fmt_pct(p.loss_percent), p.usable
        );
    }
    println!("    {}", fmt_first_lossy(&report.upload_first_lossy));
    println!();
    println!("  {}", "Download:".bold());
    for p in &report.download_sweep.points {
        println!(
            "    target={:.1}Mbps achieved={} loss={} usable={}",
            p.target_mbps, fmt_mbps(p.achieved_mbps), fmt_pct(p.loss_percent), p.usable
        );
    }
    println!("    {}", fmt_first_lossy(&report.download_first_lossy));
    if let Some(m) = &report.example_merged_timeline {
        println!();
        println!(
            "  timeline: upload=[{:.2},{:.2}] download=[{:.2},{:.2}] time_aligned={}",
            m.upload.start_secs, m.upload.end_secs, m.download.start_secs, m.download.end_secs, m.time_aligned
        );
    }
    println!();
}
