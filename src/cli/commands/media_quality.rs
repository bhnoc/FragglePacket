//! GAP-052: synthetic RTP/WebRTC media-quality probe (`media-quality`).
//!
//! Sends a bounded, synthetic RTP-shaped UDP sequence (audio or video
//! packet-size/rate profile) through `LoadGuard`, reusing the exact
//! elapsed-wall-clock pacing discipline from `burst-analysis` -- no per-tick
//! sleep of its own, so the guard's cadence is the only pacing authority.
//! ICE candidate paths (direct UDP, TURN/UDP, TURN/TCP, TURN/TLS) are
//! probed as connectivity checks only: a TCP/TLS connect-timing sample
//! against the caller-supplied relay endpoint, never a real media session
//! or sign-in to any conferencing service.

use colored::*;
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fraggle_packet::load_guard::{
    CounterSource, InterfaceCounters, LoadBudget, LoadGuard, PhaseTick, RadioSource,
};
use fraggle_packet::network_tests::burst_analysis::{Arrival, BoundedSample};
use fraggle_packet::network_tests::media_quality::{
    build_report, IceCandidateResult, MediaProfile, PathKind, SetupOutcome,
};

#[derive(clap::Args, Debug)]
pub struct MediaQualityArgs {
    #[arg(long)]
    pub interface: String,

    /// UDP echo target simulating the media path (this tool's own `serve`
    /// loopback echo, or any UDP echo service).
    #[arg(long)]
    pub target: IpAddr,

    #[arg(long, default_value_t = 9)]
    pub port: u16,

    #[arg(long, value_enum, default_value = "audio")]
    pub profile: ProfileArg,

    /// Bounded sequence length.
    #[arg(long, default_value_t = 150)]
    pub count: u64,

    #[arg(long, default_value_t = 200)]
    pub timeout_ms: u64,

    /// TURN relay host:port to connectivity-check for TURN/TCP and
    /// TURN/TLS candidate paths. Connect-timing only -- no TURN allocation,
    /// no media relay, no real call.
    #[arg(long)]
    pub turn_relay: Option<String>,

    #[arg(long)]
    pub live_event: bool,

    #[arg(long)]
    pub maintenance: bool,

    #[arg(long)]
    pub json: bool,
}

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum ProfileArg {
    Audio,
    Video,
}

impl From<ProfileArg> for MediaProfile {
    fn from(p: ProfileArg) -> Self {
        match p {
            ProfileArg::Audio => MediaProfile::Audio,
            ProfileArg::Video => MediaProfile::Video,
        }
    }
}

fn probe_direct_udp(target: IpAddr, port: u16, timeout_ms: u64) -> IceCandidateResult {
    let start = Instant::now();
    let socket = match UdpSocket::bind(if target.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    }) {
        Ok(s) => s,
        Err(e) => {
            return IceCandidateResult {
                path: PathKind::DirectUdp,
                setup: SetupOutcome::Refused {
                    detail: e.to_string(),
                },
                setup_rtt_ms: None,
            }
        }
    };
    socket
        .set_read_timeout(Some(Duration::from_millis(timeout_ms)))
        .ok();
    let dest = SocketAddr::new(target, port);
    let probe = b"media-quality-setup-probe";
    if socket.send_to(probe, dest).is_err() {
        return IceCandidateResult {
            path: PathKind::DirectUdp,
            setup: SetupOutcome::TimedOut,
            setup_rtt_ms: None,
        };
    }
    let mut buf = [0u8; 64];
    match socket.recv_from(&mut buf) {
        Ok(_) => IceCandidateResult {
            path: PathKind::DirectUdp,
            setup: SetupOutcome::Established,
            setup_rtt_ms: Some(start.elapsed().as_secs_f64() * 1000.0),
        },
        Err(_) => IceCandidateResult {
            path: PathKind::DirectUdp,
            setup: SetupOutcome::TimedOut,
            setup_rtt_ms: None,
        },
    }
}

fn probe_turn_tcp(relay: &str, timeout_ms: u64, tls: bool) -> IceCandidateResult {
    let path = if tls {
        PathKind::TurnTls
    } else {
        PathKind::TurnTcp
    };
    let addr: SocketAddr = match relay.parse() {
        Ok(a) => a,
        Err(_) => {
            // Allow "host:port" via to_socket_addrs.
            match relay.to_socket_addrs_first() {
                Some(a) => a,
                None => {
                    return IceCandidateResult {
                        path,
                        setup: SetupOutcome::Refused {
                            detail: format!("could not resolve '{}'", relay),
                        },
                        setup_rtt_ms: None,
                    }
                }
            }
        }
    };
    let start = Instant::now();
    match TcpStream::connect_timeout(&addr, Duration::from_millis(timeout_ms)) {
        Ok(_) => IceCandidateResult {
            path,
            setup: SetupOutcome::Established,
            setup_rtt_ms: Some(start.elapsed().as_secs_f64() * 1000.0),
        },
        Err(e) => IceCandidateResult {
            path,
            setup: SetupOutcome::Refused {
                detail: e.to_string(),
            },
            setup_rtt_ms: None,
        },
    }
}

trait ToSocketAddrFirst {
    fn to_socket_addrs_first(&self) -> Option<SocketAddr>;
}
impl ToSocketAddrFirst for str {
    fn to_socket_addrs_first(&self) -> Option<SocketAddr> {
        use std::net::ToSocketAddrs;
        self.to_socket_addrs().ok()?.next()
    }
}

pub fn run(args: &MediaQualityArgs) {
    if args.live_event == args.maintenance {
        eprintln!(
            "{} pass exactly one of --live-event or --maintenance.",
            "✗".red()
        );
        std::process::exit(2);
    }

    let profile: MediaProfile = args.profile.clone().into();
    let rate_pps = profile.packets_per_sec();
    let payload_size = profile.payload_bytes();

    if !args.json {
        println!(
            "Media-quality probe: interface={} target={}:{} profile={:?} rate={:.0}pps payload={}B count={}",
            args.interface, args.target, args.port, profile, rate_pps, payload_size, args.count
        );
    }

    let mut ice_candidates = vec![probe_direct_udp(args.target, args.port, args.timeout_ms)];
    // TURN/UDP is connectivity-checked the same way as direct UDP against
    // the same target when no relay is supplied -- distinguishing it from
    // "not attempted" would require a real TURN allocation, which this
    // command deliberately never performs. Reported explicitly as Refused
    // with that reason rather than silently omitted.
    if let Some(relay) = &args.turn_relay {
        ice_candidates.push(probe_turn_tcp(relay, args.timeout_ms, false));
        ice_candidates.push(probe_turn_tcp(relay, args.timeout_ms, true));
    } else {
        for path in [PathKind::TurnUdp, PathKind::TurnTcp, PathKind::TurnTls] {
            ice_candidates.push(IceCandidateResult {
                path,
                setup: SetupOutcome::Refused { detail: "no --turn-relay supplied; this path was not attempted, not merely unavailable".to_string() },
                setup_rtt_ms: None,
            });
        }
    }

    let sample = match run_media_sequence(
        &args.interface,
        args.target,
        args.port,
        rate_pps,
        payload_size,
        args.count,
        args.timeout_ms,
        args.live_event,
    ) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{} media sequence failed: {}", "✗".red(), e);
            std::process::exit(1);
        }
    };

    let direct_rtt = ice_candidates.first().and_then(|c| c.setup_rtt_ms);
    let report = build_report(profile, ice_candidates, &sample, direct_rtt, false);

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
        return;
    }

    print_human(&report);
}

fn run_media_sequence(
    interface: &str,
    target: IpAddr,
    port: u16,
    rate_pps: f64,
    payload_size: usize,
    count: u64,
    timeout_ms: u64,
    live_event: bool,
) -> Result<BoundedSample, String> {
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

    let socket = UdpSocket::bind(if target.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .map_err(|e| e.to_string())?;
    socket
        .set_read_timeout(Some(Duration::from_millis(timeout_ms)))
        .ok();
    let dest = SocketAddr::new(target, port);
    let socket_clone = socket.try_clone().map_err(|e| e.to_string())?;

    let arrivals: Arc<Mutex<Vec<Arrival>>> = Arc::new(Mutex::new(Vec::new()));
    let arrivals_writer = arrivals.clone();
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
                let this_seq = *current;
                let sent_at_ms = start.elapsed().as_secs_f64() * 1000.0;
                let mut payload = vec![0x52u8; payload_size.max(16)];
                payload[0..8].copy_from_slice(&this_seq.to_be_bytes());
                payload[8..16].copy_from_slice(&sent_at_ms.to_be_bytes());
                let _ = socket_clone.send_to(&payload, dest);
                bytes_sent += payload.len() as u64;

                let mut buf = vec![0u8; payload_size.max(64)];
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

    let sent_count = *seq.lock().unwrap();
    let arrivals = Arc::try_unwrap(arrivals)
        .map(|m| m.into_inner().unwrap())
        .unwrap_or_default();
    Ok(BoundedSample {
        sent_count,
        arrivals,
    })
}

fn print_human(report: &fraggle_packet::network_tests::media_quality::MediaQualityReport) {
    println!();
    println!("{}", "== ICE candidates ==".cyan().bold());
    for c in &report.ice_candidates {
        let status = match &c.setup {
            fraggle_packet::network_tests::media_quality::SetupOutcome::Established => {
                "ESTABLISHED".green().to_string()
            }
            fraggle_packet::network_tests::media_quality::SetupOutcome::TimedOut => {
                "TIMED OUT".yellow().to_string()
            }
            fraggle_packet::network_tests::media_quality::SetupOutcome::Refused { detail } => {
                format!("REFUSED ({})", detail).red().to_string()
            }
        };
        println!(
            "  {:?}: {} rtt={}",
            c.path,
            status,
            c.setup_rtt_ms
                .map(|v| format!("{:.1}ms", v))
                .unwrap_or_else(|| "n/a".to_string())
        );
    }
    println!();
    println!(
        "setup_success: {}",
        if report.setup_success {
            "yes".green().to_string()
        } else {
            "no".red().to_string()
        }
    );
    match &report.one_way_delay {
        fraggle_packet::network_tests::media_quality::OneWayDelay::Measured { delay_ms } => {
            println!("one_way_delay_ms: {:.1}", delay_ms)
        }
        fraggle_packet::network_tests::media_quality::OneWayDelay::Unavailable { reason } => {
            println!("one_way_delay: {} ({})", "unavailable".dimmed(), reason)
        }
    }
    println!(
        "rtt_ms: {}",
        report
            .rtt_ms
            .map(|v| format!("{:.1}", v))
            .unwrap_or_else(|| "unavailable".to_string())
    );
    println!(
        "loss={:.1}% burst_count={} max_run_length={} jitter_mean={}",
        report.burst.loss_percent,
        report.burst.burst.burst_count,
        report.burst.burst.max_run_length,
        report
            .burst
            .jitter
            .mean_ms
            .map(|v| format!("{:.2}ms", v))
            .unwrap_or_else(|| "unavailable".to_string())
    );
    println!("concealment: {:?}", report.concealment);
    println!("freeze_risk: {:?}", report.freeze_risk);
    println!(
        "mos: {:.2} ({})",
        report.mos.estimated_score, report.mos.label
    );
    for n in &report.notes {
        println!("  * {}", n);
    }
}
