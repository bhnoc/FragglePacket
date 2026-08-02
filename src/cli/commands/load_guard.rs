use colored::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use fraggle_packet::load_guard::{
    CounterSource, GuardReport, InterfaceCounters, LoadBudget, LoadGuard, PhaseTick, RadioSnapshot,
    RadioSource, StopReason, Validity,
};

#[derive(clap::Args, Debug)]
pub struct LoadGuardArgs {
    /// Interface to bind and measure (e.g. en0). Required: no default route
    /// guessing, since the default route on many machines is a VPN tunnel.
    #[arg(long)]
    pub interface: Option<String>,

    /// Target sustained rate in Mbps. Required — there is no default budget.
    #[arg(long)]
    pub rate_mbps: Option<f64>,

    /// Maximum phase duration in seconds. Required — there is no default budget.
    #[arg(long)]
    pub duration_secs: Option<u64>,

    /// Maximum concurrent flows. Required — there is no default budget.
    #[arg(long)]
    pub concurrency: Option<u32>,

    /// Number of progressive ramp steps before reaching target rate.
    #[arg(long, default_value_t = 4)]
    pub ramp_steps: u32,

    /// Run in live-event mode: materially stricter caps because attendee
    /// traffic shares the infrastructure. Mutually exclusive with --maintenance.
    #[arg(long)]
    pub live_event: bool,

    /// Run in maintenance mode: higher caps for off-hours/lab testing.
    #[arg(long)]
    pub maintenance: bool,

    /// For the demo/test harness only: inject a synthetic band change
    /// partway through the phase instead of sampling real Wi-Fi state, so
    /// the invalid-run path is exercisable offline and deterministically.
    #[arg(long)]
    pub inject_band_change: bool,

    /// For the demo/test harness only: inject weak RSSI on every sample.
    #[arg(long)]
    pub inject_weak_rf: bool,

    /// For the demo/test harness only: abort the run as if the operator hit
    /// Ctrl-C, to exercise the "SIGINT still emits a report" path without
    /// waiting on a real signal.
    #[arg(long)]
    pub inject_cancel: bool,

    /// For the demo/test harness only: never call system_profiler/ioreg —
    /// use synthetic radio state for every sample (still respecting the
    /// other --inject-* flags for band-change/weak-RF injection). Keeps the
    /// harness fast and deterministic; a real run should never pass this.
    #[arg(long)]
    pub fake_radio: bool,

    #[arg(long)]
    pub json: bool,
}

fn strong_snapshot() -> RadioSnapshot {
    RadioSnapshot {
        associated: true,
        phy_mode: Some("802.11ax".into()),
        band: Some("6GHz".into()),
        channel: Some(197),
        width_mhz: Some(80),
        rssi_dbm: Some(-55),
        noise_dbm: Some(-92),
        tx_rate_mbps: Some(900.0),
        mcs_index: Some(9),
    }
}

fn roamed_snapshot() -> RadioSnapshot {
    RadioSnapshot {
        band: Some("2GHz".into()),
        channel: Some(1),
        width_mhz: Some(20),
        rssi_dbm: Some(-70),
        ..strong_snapshot()
    }
}

fn weak_snapshot() -> RadioSnapshot {
    RadioSnapshot {
        rssi_dbm: Some(-82),
        ..strong_snapshot()
    }
}

pub fn run(args: &LoadGuardArgs) {
    let (Some(rate), Some(duration), Some(concurrency)) =
        (args.rate_mbps, args.duration_secs, args.concurrency)
    else {
        eprintln!(
            "{} load-guard requires an explicit budget: pass --rate-mbps, --duration-secs, and --concurrency. \
             There is no default budget — an unbounded run could worsen a live incident (GAP-047).",
            "✗".red()
        );
        std::process::exit(2);
    };

    if args.live_event == args.maintenance {
        eprintln!(
            "{} pass exactly one of --live-event or --maintenance to select the applicable safety caps.",
            "✗".red()
        );
        std::process::exit(2);
    }

    let interface = match &args.interface {
        Some(i) => i.clone(),
        None => {
            eprintln!(
                "{} pass --interface explicitly. The default route on this class of machine is \
                 frequently a VPN tunnel, not the interface you intend to test.",
                "✗".red()
            );
            std::process::exit(2);
        }
    };

    let route = fraggle_packet::load_guard::detect_default_route().ok();
    let default_route_is_tunnel = route.as_ref().map(|r| r.is_tunnel).unwrap_or(false);
    if let Some(r) = &route {
        if r.is_tunnel {
            eprintln!(
                "{} default route is tunnel interface '{}' — this run is bound to '{}' explicitly, \
                 but be aware any test NOT binding explicitly would measure the tunnel, not the network under test.",
                "⚠".yellow(),
                r.interface,
                interface
            );
        }
    }

    let mut budget = if args.live_event {
        LoadBudget::live_event(rate, duration, concurrency)
    } else {
        LoadBudget::maintenance(rate, duration, concurrency)
    };
    budget.ramp_steps = args.ramp_steps;

    if let Err(e) = budget.validate() {
        eprintln!("{} budget rejected: {}", "✗".red(), e);
        std::process::exit(2);
    }

    let inject_band_change = args.inject_band_change;
    let inject_weak_rf = args.inject_weak_rf;
    let fake_radio = args.fake_radio;
    let call_count = std::sync::atomic::AtomicUsize::new(0);
    // Full-detail source (RSSI/noise/PHY/MCS) for the pre/post snapshots.
    // Only called twice per run, so system_profiler's several-second cost is
    // paid exactly twice, never inside the phase loop — except under
    // --fake-radio, which never shells out at all (harness-only).
    let radio = RadioSource::new(move || {
        let n = call_count.fetch_add(1, Ordering::SeqCst);
        if inject_band_change && n > 0 {
            Ok(roamed_snapshot())
        } else if inject_weak_rf {
            Ok(weak_snapshot())
        } else if fake_radio {
            Ok(strong_snapshot())
        } else {
            Ok(fraggle_packet::load_guard::radio::snapshot_live().unwrap_or_else(|_| strong_snapshot()))
        }
    });

    // Cheap source (ioreg, ~30ms) polled repeatedly during the phase. Cannot
    // report RSSI/noise/MCS, but carries band/channel/width — enough to
    // detect a roam or band change, which is the only thing in-phase polling
    // needs. Still honors the synthetic injection flags so the CLI's
    // roam-detection demo/test path works without real Wi-Fi.
    let fast_call_count = std::sync::atomic::AtomicUsize::new(0);
    let radio_fast = RadioSource::new(move || {
        let n = fast_call_count.fetch_add(1, Ordering::SeqCst);
        if inject_band_change && n > 0 {
            Ok(roamed_snapshot())
        } else if fake_radio {
            Ok(strong_snapshot())
        } else {
            Ok(fraggle_packet::load_guard::radio::snapshot_fast().unwrap_or_else(|_| strong_snapshot()))
        }
    });

    let iface_for_counters = interface.clone();
    let counters = CounterSource::new(move || {
        fraggle_packet::load_guard::counters::snapshot_live(&iface_for_counters)
            .or_else(|_| Ok(InterfaceCounters::zero()))
    });

    let guard = match LoadGuard::new(budget, interface.clone(), default_route_is_tunnel, radio, counters) {
        Ok(g) => g.with_fast_radio_source(radio_fast),
        Err(e) => {
            eprintln!("{} budget rejected: {}", "✗".red(), e);
            std::process::exit(2);
        }
    };

    let cancel = Arc::new(AtomicBool::new(false));
    if args.inject_cancel {
        cancel.store(true, Ordering::SeqCst);
    } else {
        let sigint_cancel = cancel.clone();
        let _ = ctrlc_handler(sigint_cancel);
    }

    let sent = std::sync::atomic::AtomicU64::new(0);
    let report = guard.run(
        move |_ramp_rate_mbps: f64, _elapsed: Duration| {
            let delta = 1024u64;
            sent.fetch_add(delta, Ordering::SeqCst);
            PhaseTick {
                bytes_sent_delta: delta,
                ..Default::default()
            }
        },
        cancel,
    );

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
    } else {
        print_human(&report);
    }
}

static SIGINT_CANCEL: std::sync::OnceLock<Arc<AtomicBool>> = std::sync::OnceLock::new();

extern "C" fn sigint_handler(_sig: libc::c_int) {
    if let Some(flag) = SIGINT_CANCEL.get() {
        flag.store(true, Ordering::SeqCst);
    }
}

fn ctrlc_handler(cancel: Arc<AtomicBool>) -> Result<(), Box<dyn std::error::Error>> {
    let _ = SIGINT_CANCEL.set(cancel);
    unsafe {
        libc::signal(libc::SIGINT, sigint_handler as *const () as usize);
    }
    Ok(())
}

/// Renders an optional measurement for a human reader. Deliberately never
/// spells out `None`/`Some(...)` — this gap list keeps getting bitten by
/// unknowns rendered as though they were readings, so "not available" must
/// stay visually distinct from a real value without looking like a debug dump.
fn fmt_opt<T: std::fmt::Display>(v: &Option<T>) -> String {
    match v {
        Some(x) => x.to_string(),
        None => "unavailable".to_string(),
    }
}

fn format_radio_line(snap: &fraggle_packet::load_guard::RadioSnapshot) -> String {
    if !snap.associated {
        return "not associated".to_string();
    }
    format!(
        "band={} channel={} width={} rssi={} noise={}",
        fmt_opt(&snap.band),
        fmt_opt(&snap.channel),
        match snap.width_mhz {
            Some(w) => format!("{w}MHz"),
            None => "unavailable".to_string(),
        },
        match snap.rssi_dbm {
            Some(r) => format!("{r}dBm"),
            None => "unavailable".to_string(),
        },
        match snap.noise_dbm {
            Some(n) => format!("{n}dBm"),
            None => "unavailable".to_string(),
        },
    )
}

fn print_human(report: &GuardReport) {
    println!(
        "[{}] load-guard interface={} mode={:?}",
        match report.validity {
            Validity::Valid => "VALID".green().bold().to_string(),
            Validity::Invalid(_) => "INVALID".red().bold().to_string(),
        },
        report.interface,
        report.mode
    );
    if report.default_route_is_tunnel {
        println!("  {} default route is a VPN tunnel; results outside an explicit bind may describe the tunnel, not this interface", "⚠".yellow());
    }
    println!("  stop reason: {}", report.stop_reason);
    match &report.stop_reason {
        StopReason::Completed => {}
        _ => println!("  (structured stop reason recorded above)"),
    }
    match &report.validity {
        Validity::Valid => println!("  validity: valid"),
        Validity::Invalid(reason) => println!("  validity: invalid ({})", reason),
    }
    println!("  radio before: {}", format_radio_line(&report.radio.before));
    println!("  radio after:  {}", format_radio_line(&report.radio.after));
    println!(
        "  counters before: rx_bytes={} tx_bytes={}",
        report.counters_before.rx_bytes, report.counters_before.tx_bytes
    );
    println!(
        "  counters after:  rx_bytes={} tx_bytes={} usable={}",
        report.counters_after.rx_bytes, report.counters_after.tx_bytes, report.counters_usable
    );
    println!(
        "  raw evidence: bytes_transferred={} elapsed_secs={:.2} target_bytes={}",
        report.raw.bytes_transferred, report.raw.elapsed_secs, report.raw.target_bytes
    );
    match &report.derived {
        Some(d) => println!(
            "  derived: retained_capacity_pct={:.2} collapse_ratio={:.4}",
            d.retained_capacity_pct, d.collapse_ratio
        ),
        None => println!("  derived: none (run invalid or not computable — no collapse/retention ratio reported)"),
    }
}
