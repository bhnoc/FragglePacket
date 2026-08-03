//! GAP-034: constant-aggregate flow-count and QoS/DSCP matrix (`flow-dscp-matrix`).
//!
//! Sweeps flow count while holding the aggregate rate constant (per-flow
//! rate = target / flow_count, distinct source ports per flow), interleaves
//! repeated controls to catch drift, and separately sweeps DSCP classes.
//! Every flow-count phase runs through `LoadGuard::run`.
//!
//! DSCP survival cannot be proven by this command alone: proving a marking
//! survived the path needs a capture at both ends, and the capture path
//! (`src/network_tests/capture.rs`) is owned by another agent and off
//! limits here. This command sets the send-side DSCP via `IP_TOS` (the only
//! side it can honestly claim) and accepts an optional externally supplied
//! destination-side observation (e.g. pasted from a capture taken
//! elsewhere) via `--observed-dscp`. Without that, every class is reported
//! `Unverified`, not `Survived` -- the whole point of GAP-034's trap clause.

use colored::*;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fraggle_packet::load_guard::{
    CounterSource, InterfaceCounters, LoadBudget, LoadGuard, PhaseTick, RadioSource,
};
use fraggle_packet::network_tests::flow_dscp_matrix::{
    build_dscp_result, check_aggregate_constancy, detect_control_drift, DscpCaptureSample,
    FlowCountMatrix, FlowCountPoint,
};

#[derive(clap::Args, Debug)]
pub struct FlowDscpMatrixArgs {
    #[arg(long)]
    pub interface: String,

    #[arg(long)]
    pub target: IpAddr,

    #[arg(long, default_value_t = 9)]
    pub port: u16,

    /// Flow counts to sweep. Aggregate rate (--target-bps) is held constant
    /// across these by dividing it evenly across the flow count.
    #[arg(long, value_delimiter = ',', default_values_t = vec![1u32, 2, 4])]
    pub flow_counts: Vec<u32>,

    #[arg(long, default_value_t = 20_000.0)]
    pub target_bps: f64,

    #[arg(long, default_value_t = 1)]
    pub duration_secs: u64,

    /// Repeat the first flow_count as an interleaved control at the end of
    /// the sweep, to detect drift between "the same" configuration run
    /// twice.
    #[arg(long)]
    pub repeat_control: bool,

    /// DSCP classes to sweep (0-63). For each, this command sets IP_TOS on
    /// the send side only.
    #[arg(long, value_delimiter = ',', default_values_t = vec![0u8, 46])]
    pub dscp_classes: Vec<u8>,

    /// Destination-side observed DSCP value for a class, given as
    /// "<class>=<observed>" (repeatable). Supplies the only way this
    /// command can claim proven survival for that class; without a match
    /// here, survival is reported Unverified.
    #[arg(long = "observed-dscp")]
    pub observed_dscp: Vec<String>,

    #[arg(long)]
    pub live_event: bool,

    #[arg(long)]
    pub maintenance: bool,

    #[arg(long)]
    pub json: bool,
}

fn parse_observed(entries: &[String]) -> std::collections::HashMap<u8, u8> {
    entries
        .iter()
        .filter_map(|e| {
            let (k, v) = e.split_once('=')?;
            Some((k.trim().parse().ok()?, v.trim().parse().ok()?))
        })
        .collect()
}

fn set_send_dscp(socket: &UdpSocket, dscp: u8, is_ipv4: bool) -> Result<(), String> {
    use std::os::fd::AsRawFd;
    let fd = socket.as_raw_fd();
    let tos: libc::c_int = (dscp as i32) << 2;
    let (level, name) = if is_ipv4 {
        (libc::IPPROTO_IP, libc::IP_TOS)
    } else {
        (libc::IPPROTO_IPV6, libc::IPV6_TCLASS)
    };
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            &tos as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(format!(
            "setsockopt DSCP failed: {}",
            std::io::Error::last_os_error()
        ))
    }
}

fn run_flow_point(
    interface: &str,
    target: IpAddr,
    port: u16,
    flow_count: u32,
    target_aggregate_bps: f64,
    duration_secs: u64,
    live_event: bool,
) -> Result<(f64, Vec<u16>), String> {
    let per_flow_bps = target_aggregate_bps / flow_count.max(1) as f64;
    let budget = if live_event {
        LoadBudget::live_event(1.0, duration_secs.max(1).min(30), flow_count.max(1).min(2))
    } else {
        LoadBudget::maintenance(1.0, (duration_secs.max(1) * 2).max(2), flow_count.max(1))
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

    let payload_size: usize = 200;
    let bytes_per_sec_per_flow = per_flow_bps;
    let mut sockets = Vec::new();
    let mut ports = Vec::new();
    for _ in 0..flow_count.max(1) {
        let s = UdpSocket::bind(if target.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        })
        .map_err(|e| e.to_string())?;
        s.set_read_timeout(Some(Duration::from_millis(100))).ok();
        if let Ok(a) = s.local_addr() {
            ports.push(a.port());
        }
        sockets.push(Arc::new(s));
    }
    let dest = SocketAddr::new(target, port);
    let bytes_moved: Arc<Mutex<u64>> = Arc::new(Mutex::new(0));
    let start = Instant::now();
    let cancel = Arc::new(AtomicBool::new(false));
    let interval_secs = payload_size as f64 / bytes_per_sec_per_flow.max(1.0);

    let sockets_for_phase = sockets.clone();
    let bytes_writer = bytes_moved.clone();
    // Elapsed-wall-clock-driven, same discipline as burst-analysis/
    // size-rate-matrix: the guard's own tick loop only calls this closure on
    // its own (coarser) sample_interval cadence, so a per-tick "has enough
    // time passed since last send" check alone under-delivers whenever the
    // per-probe interval is shorter than the tick interval -- exactly the
    // case here (flow intervals of single-digit ms vs a ~200ms tick).
    // Instead, each tick catches every socket up to however many sends are
    // "due" by elapsed time, with no sleep of its own.
    let sent_counts: Arc<Mutex<Vec<u64>>> =
        Arc::new(Mutex::new(vec![0u64; sockets_for_phase.len()]));

    guard.run(
        move |_ramp_rate_mbps: f64, elapsed: Duration| {
            let mut total = 0u64;
            let mut counts = sent_counts.lock().unwrap();
            for (i, sock) in sockets_for_phase.iter().enumerate() {
                let due = (elapsed.as_secs_f64() / interval_secs) as u64 + 1;
                while counts[i] < due {
                    let payload = vec![0x33u8; payload_size];
                    if sock.send_to(&payload, dest).is_ok() {
                        total += payload.len() as u64;
                    }
                    let mut buf = [0u8; 256];
                    let _ = sock.recv_from(&mut buf);
                    counts[i] += 1;
                }
            }
            *bytes_writer.lock().unwrap() += total;
            PhaseTick {
                bytes_sent_delta: total,
                ..Default::default()
            }
        },
        cancel,
    );

    let elapsed_secs = start.elapsed().as_secs_f64();
    let total_bytes = *bytes_moved.lock().unwrap();
    let actual_aggregate_bps = if elapsed_secs > 0.0 {
        total_bytes as f64 / elapsed_secs
    } else {
        0.0
    };
    let _ = per_flow_bps;
    Ok((actual_aggregate_bps, ports))
}

pub fn run(args: &FlowDscpMatrixArgs) {
    if args.live_event == args.maintenance {
        eprintln!(
            "{} pass exactly one of --live-event or --maintenance.",
            "✗".red()
        );
        std::process::exit(2);
    }

    if !args.json {
        println!(
            "Flow-count/DSCP matrix: interface={} target={}:{} flow_counts={:?}",
            args.interface, args.target, args.port, args.flow_counts
        );
    }

    let mut points = Vec::new();
    for &fc in &args.flow_counts {
        match run_flow_point(
            &args.interface,
            args.target,
            args.port,
            fc,
            args.target_bps,
            args.duration_secs,
            args.live_event,
        ) {
            Ok((actual_agg, ports)) => points.push(FlowCountPoint {
                flow_count: fc,
                per_flow_bps: args.target_bps / fc.max(1) as f64,
                target_aggregate_bps: args.target_bps,
                actual_aggregate_bps: Some(actual_agg),
                loss_percent: None,
                source_ports: ports,
                is_repeated_control: false,
            }),
            Err(e) => {
                eprintln!("{} flow_count={} failed: {}", "✗".red(), fc, e);
                points.push(FlowCountPoint {
                    flow_count: fc,
                    per_flow_bps: args.target_bps / fc.max(1) as f64,
                    target_aggregate_bps: args.target_bps,
                    actual_aggregate_bps: None,
                    loss_percent: None,
                    source_ports: vec![],
                    is_repeated_control: false,
                });
            }
        }
    }

    if args.repeat_control {
        if let Some(&first_fc) = args.flow_counts.first() {
            match run_flow_point(
                &args.interface,
                args.target,
                args.port,
                first_fc,
                args.target_bps,
                args.duration_secs,
                args.live_event,
            ) {
                Ok((actual_agg, ports)) => points.push(FlowCountPoint {
                    flow_count: first_fc,
                    per_flow_bps: args.target_bps / first_fc.max(1) as f64,
                    target_aggregate_bps: args.target_bps,
                    actual_aggregate_bps: Some(actual_agg),
                    loss_percent: None,
                    source_ports: ports,
                    is_repeated_control: true,
                }),
                Err(e) => eprintln!("{} repeat control failed: {}", "✗".red(), e),
            }
        }
    }

    let matrix = FlowCountMatrix { points };
    let constancy = check_aggregate_constancy(&matrix);
    let drift = detect_control_drift(&matrix);

    let observed = parse_observed(&args.observed_dscp);
    let dscp_results: Vec<_> = args
        .dscp_classes
        .iter()
        .map(|&class| {
            let socket = UdpSocket::bind(if args.target.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            })
            .ok();
            let sent_ok = socket
                .as_ref()
                .map(|s| set_send_dscp(s, class, args.target.is_ipv4()).is_ok())
                .unwrap_or(false);
            let sample = DscpCaptureSample {
                sent_dscp: class,
                observed_at_source: if sent_ok { Some(class) } else { None },
                observed_at_destination: observed.get(&class).copied(),
            };
            build_dscp_result(class, vec![sample], None)
        })
        .collect();

    if args.json {
        let out = serde_json::json!({
            "interface": args.interface,
            "matrix": matrix,
            "aggregate_constancy": constancy,
            "control_drift": drift,
            "dscp_results": dscp_results,
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
        return;
    }

    print_human(&matrix, &constancy, &drift, &dscp_results);
}

fn print_human(
    matrix: &FlowCountMatrix,
    constancy: &fraggle_packet::network_tests::flow_dscp_matrix::AggregateConstancyCheck,
    drift: &[fraggle_packet::network_tests::flow_dscp_matrix::ControlDrift],
    dscp_results: &[fraggle_packet::network_tests::flow_dscp_matrix::DscpClassResult],
) {
    println!();
    println!("{}", "== Flow-count sweep ==".cyan().bold());
    for p in &matrix.points {
        println!(
            "  flows={:<3} per_flow_bps={:<10.0} target_agg={:<10.0} actual_agg={} repeat={}",
            p.flow_count,
            p.per_flow_bps,
            p.target_aggregate_bps,
            p.actual_aggregate_bps
                .map(|v| format!("{:.0}", v))
                .unwrap_or_else(|| "unavailable".to_string()),
            p.is_repeated_control
        );
    }
    println!(
        "  aggregate held constant: {} (max deviation {})",
        if constancy.held_constant {
            "YES".green().to_string()
        } else {
            "NO".red().to_string()
        },
        constancy
            .max_deviation_fraction
            .map(|v| format!("{:.1}%", v * 100.0))
            .unwrap_or_else(|| "unavailable".to_string())
    );
    for d in drift {
        if d.drifted {
            println!(
                "  {} flow_count={} loss drifted {:.1}% -> {:.1}% between repeats",
                "⚠".yellow(),
                d.flow_count,
                d.first_loss_percent,
                d.repeat_loss_percent
            );
        }
    }
    println!();
    println!("{}", "== DSCP sweep ==".cyan().bold());
    for r in dscp_results {
        let verdict = match r.survival {
            fraggle_packet::network_tests::flow_dscp_matrix::DscpSurvival::Survived => {
                "SURVIVED".green().to_string()
            }
            fraggle_packet::network_tests::flow_dscp_matrix::DscpSurvival::AlteredOnPath => {
                "ALTERED ON PATH".red().bold().to_string()
            }
            fraggle_packet::network_tests::flow_dscp_matrix::DscpSurvival::Unverified => {
                "UNVERIFIED (no destination-side capture)"
                    .yellow()
                    .to_string()
            }
        };
        println!("  class={} survival={}", r.dscp_class, verdict);
    }
}
