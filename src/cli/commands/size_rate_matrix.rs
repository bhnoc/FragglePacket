//! GAP-033: datagram-size and packet-rate pressure matrix (`size-rate-matrix`).
//!
//! Runs two complementary UDP echo sweeps over the same set of payload
//! sizes -- one holding byte rate constant (packet rate rises as size
//! shrinks), one holding packet rate constant (byte rate rises as size
//! grows) -- through `LoadGuard::run`, then classifies which pressure
//! signature (if any) the results show. Never rolls its own pacing loop:
//! each tick sends however many probes are due by elapsed wall time, same
//! discipline as `burst-analysis`.

use colored::*;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::process::Command;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fraggle_packet::load_guard::{CounterSource, InterfaceCounters, LoadBudget, LoadGuard, PhaseTick, RadioSource};
use fraggle_packet::network_tests::size_rate_matrix::{
    classify_pressure, max_safe_payload, DirectionMode, IpFamily, PressureVerdict, SizePoint, SizeRateMatrix,
};

const IP_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;

#[derive(clap::Args, Debug)]
pub struct SizeRateMatrixArgs {
    /// Interface to bind and measure. Required: the default route on this
    /// class of machine is frequently a VPN tunnel.
    #[arg(long)]
    pub interface: String,

    /// UDP echo target.
    #[arg(long)]
    pub target: IpAddr,

    #[arg(long, default_value_t = 9)]
    pub port: u16,

    /// Payload sizes to sweep, in bytes. Each is checked against the
    /// interface's actually-measured MTU before use; a size that would
    /// fragment is skipped, not silently sent fragmented.
    #[arg(long, value_delimiter = ',', default_values_t = vec![1400usize, 800, 400, 200])]
    pub sizes: Vec<usize>,

    /// Target aggregate byte rate (bytes/sec) held constant across the
    /// size sweep for the constant-byte-rate pass.
    #[arg(long, default_value_t = 50_000.0)]
    pub target_bps: f64,

    /// Target packet rate (packets/sec) held constant across the size
    /// sweep for the constant-packet-rate pass.
    #[arg(long, default_value_t = 50.0)]
    pub target_pps: f64,

    #[arg(long, default_value_t = 1)]
    pub duration_secs: u64,

    #[arg(long)]
    pub bidirectional: bool,

    #[arg(long)]
    pub live_event: bool,

    #[arg(long)]
    pub maintenance: bool,

    #[arg(long)]
    pub json: bool,
}

fn interface_mtu(interface: &str) -> Option<usize> {
    let out = Command::new("ifconfig").arg(interface).output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let tokens: Vec<&str> = text.split_whitespace().collect();
    tokens.windows(2).find(|w| w[0] == "mtu").and_then(|w| w[1].parse().ok())
}

fn run_udp_size_point(
    interface: &str,
    target: IpAddr,
    port: u16,
    payload_size: usize,
    rate_pps: f64,
    duration_secs: u64,
    live_event: bool,
) -> Result<(u64, u64, f64, Option<IpFamily>), String> {
    let count = ((rate_pps.max(1.0)) * duration_secs as f64) as u64;
    let budget = if live_event {
        LoadBudget::live_event(1.0, duration_secs.max(1).min(30), 1)
    } else {
        LoadBudget::maintenance(1.0, (duration_secs.max(1) * 2).max(2), 1)
    };
    let radio = RadioSource::new(|| Ok(fraggle_packet::load_guard::radio::RadioSnapshot::unavailable()));
    let iface_for_counters = interface.to_string();
    let counters = CounterSource::new(move || {
        fraggle_packet::load_guard::counters::snapshot_live(&iface_for_counters).or_else(|_| Ok(InterfaceCounters::zero()))
    });
    let guard = LoadGuard::new(budget, interface, false, radio, counters).map_err(|e| e.to_string())?;

    let socket = UdpSocket::bind(if target.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }).map_err(|e| e.to_string())?;
    socket.set_read_timeout(Some(Duration::from_millis(200))).ok();
    let dest = SocketAddr::new(target, port);
    let observed_family = match socket.local_addr() {
        Ok(a) if a.is_ipv4() => Some(IpFamily::V4),
        Ok(_) => Some(IpFamily::V6),
        Err(_) => None,
    };

    let socket_clone = socket.try_clone().map_err(|e| e.to_string())?;
    let received: Arc<Mutex<u64>> = Arc::new(Mutex::new(0));
    let received_writer = received.clone();
    let start = Instant::now();
    let interval_secs = 1.0 / rate_pps.max(0.01);
    let seq: Arc<Mutex<u64>> = Arc::new(Mutex::new(0));
    let seq_writer = seq.clone();
    let cancel = Arc::new(AtomicBool::new(false));

    guard.run(
        move |_ramp_rate_mbps: f64, elapsed: Duration| {
            let due = ((elapsed.as_secs_f64() / interval_secs) as u64 + 1).min(count);
            let mut bytes_sent = 0u64;
            let mut current = seq_writer.lock().unwrap();
            while *current < due {
                let payload = vec![0x5Au8; payload_size];
                let _ = socket_clone.send_to(&payload, dest);
                bytes_sent += payload.len() as u64;
                let mut buf = vec![0u8; payload_size.max(64)];
                if socket_clone.recv_from(&mut buf).is_ok() {
                    *received_writer.lock().unwrap() += 1;
                }
                *current += 1;
            }
            PhaseTick { bytes_sent_delta: bytes_sent, ..Default::default() }
        },
        cancel,
    );

    let offered = *seq.lock().unwrap();
    let received_count = *received.lock().unwrap();
    let elapsed_secs = start.elapsed().as_secs_f64();
    Ok((offered, received_count, elapsed_secs, observed_family))
}

fn build_sweep(
    interface: &str,
    target: IpAddr,
    port: u16,
    sizes: &[usize],
    measured_mtu: Option<usize>,
    rate_for_size: impl Fn(usize) -> f64,
    duration_secs: u64,
    live_event: bool,
) -> Vec<SizePoint> {
    sizes
        .iter()
        .filter_map(|&size| {
            let mtu_safe = measured_mtu.map(|mtu| size <= max_safe_payload(mtu, IP_HEADER_LEN, UDP_HEADER_LEN)).unwrap_or(false);
            if !mtu_safe {
                eprintln!(
                    "{} skipping payload size {} bytes: exceeds non-fragmenting limit for measured MTU {}",
                    "⚠".yellow(),
                    size,
                    measured_mtu.map(|m| m.to_string()).unwrap_or_else(|| "unknown".to_string())
                );
                return None;
            }
            let rate = rate_for_size(size);
            match run_udp_size_point(interface, target, port, size, rate, duration_secs, live_event) {
                Ok((offered, received, elapsed, family)) => {
                    Some(SizePoint::from_counts(size, offered, elapsed, received, family, mtu_safe))
                }
                Err(e) => {
                    eprintln!("{} size {} failed: {}", "✗".red(), size, e);
                    None
                }
            }
        })
        .collect()
}

pub fn run(args: &SizeRateMatrixArgs) {
    if args.live_event == args.maintenance {
        eprintln!("{} pass exactly one of --live-event or --maintenance.", "✗".red());
        std::process::exit(2);
    }

    let measured_mtu = interface_mtu(&args.interface);
    if !args.json {
        println!(
            "Size/rate pressure matrix: interface={} mtu={} target={}:{} sizes={:?}",
            args.interface,
            measured_mtu.map(|m| m.to_string()).unwrap_or_else(|| "unknown".to_string()),
            args.target,
            args.port,
            args.sizes
        );
    }

    let target_bps = args.target_bps;
    let constant_byte_rate = build_sweep(
        &args.interface,
        args.target,
        args.port,
        &args.sizes,
        measured_mtu,
        move |size| (target_bps / size.max(1) as f64).max(1.0),
        args.duration_secs,
        args.live_event,
    );

    let target_pps = args.target_pps;
    let constant_packet_rate = build_sweep(
        &args.interface,
        args.target,
        args.port,
        &args.sizes,
        measured_mtu,
        move |_size| target_pps,
        args.duration_secs,
        args.live_event,
    );

    let matrix = SizeRateMatrix {
        mode: if args.bidirectional { DirectionMode::Bidirectional } else { DirectionMode::Directional },
        constant_byte_rate,
        constant_packet_rate,
    };
    let verdict = classify_pressure(&matrix);

    if args.json {
        let out = serde_json::json!({
            "interface": args.interface,
            "measured_mtu": measured_mtu,
            "matrix": matrix,
            "verdict": verdict,
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
        return;
    }

    print_human(&matrix, &verdict);
}

fn fmt_opt(v: Option<f64>) -> String {
    v.map(|x| format!("{:.2}", x)).unwrap_or_else(|| "unavailable".dimmed().to_string())
}

fn print_sweep(label: &str, points: &[SizePoint]) {
    println!("{}", format!("== {} ==", label).cyan().bold());
    for p in points {
        println!(
            "  size={:<5} offered_pps={:<8.1} received_pps={:<10} loss={:<8} family={:?} mtu_safe={}",
            p.payload_size,
            p.offered_pps,
            fmt_opt(p.received_pps),
            fmt_opt(p.loss_percent),
            p.ip_family,
            p.mtu_safe
        );
    }
}

fn print_human(matrix: &SizeRateMatrix, verdict: &PressureVerdict) {
    println!();
    print_sweep("constant byte rate (packet rate rises as size shrinks)", &matrix.constant_byte_rate);
    print_sweep("constant packet rate (byte rate rises as size grows)", &matrix.constant_packet_rate);
    println!();
    match verdict {
        PressureVerdict::PacketRateCeiling { evidence } => {
            println!("{} {}", "VERDICT: packet-rate ceiling".red().bold(), evidence);
        }
        PressureVerdict::ByteRatePolicing { evidence } => {
            println!("{} {}", "VERDICT: byte-rate policing".red().bold(), evidence);
        }
        PressureVerdict::Inconclusive { reason } => {
            println!("{} {}", "VERDICT: inconclusive".yellow().bold(), reason);
        }
    }
}
