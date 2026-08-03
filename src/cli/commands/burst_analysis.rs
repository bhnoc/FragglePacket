//! GAP-066: bounded burst/reordering/duplication probe (`burst-analysis`).
//!
//! Generates a bounded, timestamped UDP sequence at a representative rate
//! and, optionally, a ramped rate for comparison, then runs the GAP-066
//! analysis over the receiver-side arrival log. Pacing and the safety
//! envelope come entirely from `fraggle_packet::load_guard::LoadGuard` --
//! this command supplies a `LoadPhase` closure and never rolls its own
//! rate control, so the same budget caps, live-event/maintenance modes, and
//! abort thresholds that bound every other load-generating command in this
//! tool also bound this one.

use colored::*;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fraggle_packet::load_guard::{
    CounterSource, InterfaceCounters, LoadBudget, LoadGuard, PhaseTick, RadioSource,
};
use fraggle_packet::network_tests::burst_analysis::{
    analyze, Arrival, BoundedSample, BurstAnalysisReport,
};

#[derive(clap::Args, Debug)]
pub struct BurstAnalysisArgs {
    /// Interface to bind the probe socket to (e.g. en0). Required: the
    /// default route on this class of machine is frequently a VPN tunnel,
    /// and binding implicitly would silently measure the tunnel instead.
    #[arg(long)]
    pub interface: String,

    /// UDP echo target. Must echo back exactly what it receives (e.g. this
    /// tool's own `Serve` loopback echo, or any UDP echo service) --
    /// one-way delay is derived from send/receive timestamps of the same
    /// logical probe, which requires an echo.
    #[arg(long)]
    pub target: IpAddr,

    #[arg(long, default_value_t = 9)]
    pub port: u16,

    /// Representative send rate in probes/sec. Kept modest by default --
    /// this verifies the analysis mechanism, not the network's ceiling.
    #[arg(long, default_value_t = 20.0)]
    pub rate_pps: f64,

    /// Bounded sequence length. This is the "bounded" in "bounded
    /// timestamped sequences" -- there is no unbounded/continuous mode.
    #[arg(long, default_value_t = 200)]
    pub count: u64,

    /// Also run a second, ramped-rate pass (2x --rate-pps) for comparison,
    /// per the "representative and ramped rates" acceptance clause.
    #[arg(long)]
    pub ramped: bool,

    #[arg(long, default_value_t = 200)]
    pub timeout_ms: u64,

    #[arg(long)]
    pub live_event: bool,

    #[arg(long)]
    pub maintenance: bool,

    #[arg(long)]
    pub json: bool,
}

fn run_one_pass(
    interface: &str,
    target: IpAddr,
    port: u16,
    rate_pps: f64,
    count: u64,
    timeout_ms: u64,
    live_event: bool,
) -> Result<BoundedSample, String> {
    // Budget is derived from the probe's own tiny byte volume, not a
    // throughput target -- this command's "load" is a bounded count of
    // small datagrams, not a sustained Mbps rate. duration_secs is sized
    // generously above the expected wall time so the guard's own
    // duration-overrun invalidation doesn't fire on normal jitter.
    let duration_secs = ((count as f64 / rate_pps.max(1.0)) * 2.0).ceil().max(1.0) as u64;
    let budget = if live_event {
        LoadBudget::live_event(1.0, duration_secs.min(30), 1)
    } else {
        LoadBudget::maintenance(1.0, duration_secs, 1)
    };

    let radio =
        RadioSource::new(|| Ok(fraggle_packet::load_guard::radio::RadioSnapshot::unavailable()));
    let iface_for_counters = interface.to_string();
    let counters = CounterSource::new(move || {
        fraggle_packet::load_guard::counters::snapshot_live(&iface_for_counters)
            .or_else(|_| Ok(InterfaceCounters::zero()))
    });

    let guard =
        LoadGuard::new(budget, interface, false, radio, counters).map_err(|e| e.to_string())?;

    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    socket
        .set_read_timeout(Some(Duration::from_millis(timeout_ms)))
        .ok();
    let dest = SocketAddr::new(target, port);

    let arrivals: Arc<Mutex<Vec<Arrival>>> = Arc::new(Mutex::new(Vec::new()));
    let arrivals_writer = arrivals.clone();
    let socket_clone = socket.try_clone().map_err(|e| e.to_string())?;
    let start = Instant::now();

    // Pacing is elapsed-wall-clock-driven, not sleep-per-probe: the guard's
    // own tick loop already sleeps on its own schedule between calls (up to
    // its sample_interval), so an additional fixed per-probe sleep inside
    // this closure would compound with that and starve the probe rate far
    // below --rate-pps. Instead, each tick sends however many probes are
    // "due" by now given elapsed time and the target rate, with no sleep of
    // its own -- the guard's cadence provides all the pacing.
    let interval_secs = 1.0 / rate_pps.max(0.01);
    let seq: Arc<Mutex<u64>> = Arc::new(Mutex::new(0));
    let seq_writer = seq.clone();
    let cancel = Arc::new(AtomicBool::new(false));

    let _report = guard.run(
        move |_ramp_rate_mbps: f64, elapsed: Duration| {
            let due = ((elapsed.as_secs_f64() / interval_secs) as u64 + 1).min(count);
            let mut bytes_sent = 0u64;
            let mut current = seq_writer.lock().unwrap();
            while *current < due {
                let this_seq = *current;
                let sent_at_ms = start.elapsed().as_secs_f64() * 1000.0;
                let mut payload = Vec::with_capacity(16);
                payload.extend_from_slice(&this_seq.to_be_bytes());
                payload.extend_from_slice(&sent_at_ms.to_be_bytes());
                let _ = socket_clone.send_to(&payload, dest);
                bytes_sent += payload.len() as u64;

                let mut buf = [0u8; 64];
                if let Ok((n, _)) = socket_clone.recv_from(&mut buf) {
                    if n >= 16 {
                        let echoed_seq = u64::from_be_bytes(buf[0..8].try_into().unwrap());
                        let echoed_sent_at = f64::from_be_bytes(buf[8..16].try_into().unwrap());
                        let received_at_ms = start.elapsed().as_secs_f64() * 1000.0;
                        arrivals_writer.lock().unwrap().push(Arrival {
                            seq: echoed_seq,
                            sent_at_ms: echoed_sent_at,
                            received_at_ms,
                        });
                    }
                }
                *current += 1;
            }
            PhaseTick {
                bytes_sent_delta: bytes_sent,
                ..Default::default()
            }
        },
        cancel,
    );

    // sent_count reflects how many probes were actually attempted, not the
    // requested --count: if the run stopped early (duration budget, abort),
    // reporting the requested count would fabricate loss for probes that
    // were never sent at all -- the same unknown-rendered-as-a-number trap
    // this whole gap list exists to close.
    let sent_count = *seq.lock().unwrap();
    let arrivals = Arc::try_unwrap(arrivals)
        .map(|m| m.into_inner().unwrap())
        .unwrap_or_default();
    Ok(BoundedSample {
        sent_count,
        arrivals,
    })
}

pub fn run(args: &BurstAnalysisArgs) {
    if args.live_event == args.maintenance {
        eprintln!(
            "{} pass exactly one of --live-event or --maintenance to select the applicable safety caps.",
            "✗".red()
        );
        std::process::exit(2);
    }

    if !args.json {
        println!(
            "Bounded burst probe: interface={} target={}:{} rate={:.1}pps count={}{}",
            args.interface,
            args.target,
            args.port,
            args.rate_pps,
            args.count,
            if args.ramped { " (+ ramped pass)" } else { "" }
        );
    }

    let normal = match run_one_pass(
        &args.interface,
        args.target,
        args.port,
        args.rate_pps,
        args.count,
        args.timeout_ms,
        args.live_event,
    ) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{} normal-rate pass failed: {}", "✗".red(), e);
            std::process::exit(1);
        }
    };
    let normal_report = analyze(&normal, None);

    let ramped_report = if args.ramped {
        match run_one_pass(
            &args.interface,
            args.target,
            args.port,
            args.rate_pps * 2.0,
            args.count,
            args.timeout_ms,
            args.live_event,
        ) {
            Ok(s) => Some(analyze(&s, None)),
            Err(e) => {
                eprintln!("{} ramped-rate pass failed: {}", "✗".red(), e);
                None
            }
        }
    } else {
        None
    };

    if args.json {
        let out = serde_json::json!({
            "normal_rate_pps": args.rate_pps,
            "normal": normal_report,
            "ramped_rate_pps": if args.ramped { Some(args.rate_pps * 2.0) } else { None },
            "ramped": ramped_report,
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
        return;
    }

    print_human("normal", args.rate_pps, &normal_report);
    if let Some(r) = &ramped_report {
        print_human("ramped", args.rate_pps * 2.0, r);
    }
}

fn fmt_opt(v: &Option<f64>) -> String {
    match v {
        Some(x) => format!("{:.2}", x),
        None => "unavailable".dimmed().to_string(),
    }
}

fn print_human(label: &str, rate_pps: f64, report: &BurstAnalysisReport) {
    println!();
    println!(
        "{}",
        format!("== {} pass @ {:.1}pps ==", label, rate_pps)
            .cyan()
            .bold()
    );
    println!(
        "  sent={} received={} loss={:.1}%",
        report.sent_count, report.received_count, report.loss_percent
    );
    println!(
        "  burst_count={} total_lost={} max_run_length={} mean_run_length={}",
        report.burst.burst_count,
        report.burst.total_lost,
        report.burst.max_run_length,
        fmt_opt(&report.burst.mean_run_length)
    );
    for b in &report.burst.bursts {
        println!(
            "    burst start_seq={} run_length={} gap_ms={}",
            b.start_seq,
            b.run_length,
            fmt_opt(&b.gap_duration_ms)
        );
    }
    println!(
        "  reordering: {} event(s), max_depth={}",
        report.reordering.len(),
        report.max_reorder_depth
    );
    println!("  duplicates: {}", report.duplicate_count);
    println!(
        "  jitter: mean={} stddev={} max={}",
        fmt_opt(&report.jitter.mean_ms),
        fmt_opt(&report.jitter.stddev_ms),
        fmt_opt(&report.jitter.max_ms)
    );
    for c in &report.queue_delay_correlation {
        let verdict = match c.delay_rising_before_burst {
            Some(true) => "RISING (queueing-consistent)".yellow().to_string(),
            Some(false) => "flat".to_string(),
            None => "unavailable".dimmed().to_string(),
        };
        println!(
            "  queue-delay @ burst seq={}: {}",
            c.burst_start_seq, verdict
        );
    }
    for n in &report.notes {
        println!("  * {}", n);
    }
}
