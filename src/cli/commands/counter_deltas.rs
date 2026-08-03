//! GAP-031: normalized, qualified interface-counter deltas (`counter-deltas`).

use colored::*;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use fraggle_packet::load_guard::{
    compute_delta, real_sources_for_interface, CounterDelta, CounterSource, DeltaQualification,
    LoadBudget, LoadGuard, PhaseTick, RadioSnapshot, RadioSource, Validity,
};

/// GAP-035: pairs the counter delta with the phase's own radio-validity
/// verdict, so a caller cannot read a counter delta as attributable to a
/// stable radio state when the phase actually roamed or hit weak RF.
#[derive(serde::Serialize)]
struct CounterDeltasReport {
    #[serde(flatten)]
    delta: CounterDelta,
    radio_validity: Validity,
}

#[derive(clap::Args, Debug)]
pub struct CounterDeltasArgs {
    /// Interface to snapshot before/after the phase (e.g. en0).
    #[arg(long)]
    pub interface: Option<String>,

    /// Target rate for the demo phase, in Mbps. Kept small -- this command
    /// demonstrates the delta/qualification mechanism, not a real load
    /// generator (see GAP-032/033/034 for the actual matrix).
    #[arg(long, default_value_t = 1.0)]
    pub rate_mbps: f64,

    #[arg(long, default_value_t = 2)]
    pub duration_secs: u64,

    /// States that the interface is known to carry only this phase's
    /// traffic (e.g. a dedicated test link), overriding the default
    /// shared-traffic qualification for common adapter name prefixes
    /// (en/eth/wlan). Do not pass this for a normal laptop Wi-Fi/Ethernet
    /// adapter that also serves OS/background traffic.
    #[arg(long)]
    pub assume_isolated: bool,

    /// For the demo/test harness only: inject a synthetic backwards counter
    /// pair (wrap/reset) instead of sampling real counters.
    #[arg(long)]
    pub inject_wrap: bool,

    /// For the demo/test harness only: never call system_profiler/ioreg --
    /// use synthetic strong-RF radio state for every sample. Keeps the
    /// harness fast and deterministic (system_profiler costs ~8s/call, paid
    /// twice per real run); a real run should never pass this. Marks the
    /// report's radio source as synthetic (GAP-027's provenance rule), so
    /// this can never be mistaken for a real RF measurement.
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

pub fn run(args: &CounterDeltasArgs) {
    let interface = match &args.interface {
        Some(i) => i.clone(),
        None => {
            eprintln!(
                "{} --interface is required; the default route on this class of machine is \
                 frequently a VPN tunnel, not the interface you intend to measure.",
                "✗".red()
            );
            std::process::exit(1);
        }
    };

    let budget = LoadBudget::maintenance(args.rate_mbps, args.duration_secs.max(1), 1);
    if let Err(e) = budget.validate() {
        eprintln!("{} budget rejected: {}", "✗".red(), e);
        std::process::exit(2);
    }

    // GAP-035: real radio bracketing, not a stubbed-unavailable source --
    // this phase now participates in roam/RF invalidation like every other
    // load command, instead of always landing on Invalid(RadioUnavailable).
    // --fake-radio (harness-only) substitutes a synthetic strong-RF source
    // so the harness never pays system_profiler's ~8s/call cost.
    let (radio, radio_fast, _unused_counters) = if args.fake_radio {
        (
            RadioSource::new(|| Ok(strong_snapshot())),
            RadioSource::new(|| Ok(strong_snapshot())),
            CounterSource::new(|| {
                Err("counter-deltas: unused when --fake-radio is set".to_string())
            }),
        )
    } else {
        real_sources_for_interface(&interface)
    };
    let iface_for_counters = interface.clone();
    let inject_wrap = args.inject_wrap;
    let call_count = std::sync::atomic::AtomicUsize::new(0);
    let counters = CounterSource::new(move || {
        let n = call_count.fetch_add(1, Ordering::SeqCst);
        if inject_wrap && n > 0 {
            // A synthetic backwards value on the second (post-phase) sample,
            // relative to whatever the first live sample returned.
            Err("counter-deltas: injected wrap".to_string())
        } else {
            fraggle_packet::load_guard::counters::snapshot_live(&iface_for_counters)
        }
    });

    let guard = match LoadGuard::new(budget, interface.clone(), false, radio, counters) {
        Ok(g) => g
            .with_fast_radio_source(radio_fast)
            .with_synthetic_radio_marker(args.fake_radio),
        Err(e) => {
            eprintln!("{} budget rejected: {}", "✗".red(), e);
            std::process::exit(2);
        }
    };

    let sent = Arc::new(AtomicU64::new(0));
    let sent_for_closure = sent.clone();
    let report = guard.run(
        move |_rate: f64, _elapsed: Duration| {
            let delta = 512u64;
            sent_for_closure.fetch_add(delta, Ordering::SeqCst);
            PhaseTick {
                bytes_sent_delta: delta,
                ..Default::default()
            }
        },
        Arc::new(AtomicBool::new(false)),
    );

    let counter_delta = if args.inject_wrap {
        // The injected-wrap path never got a real "after" sample from the
        // guard (the second CounterSource call errors out, so the guard
        // falls back to InterfaceCounters::zero() for `counters_after`).
        // Build a delta directly from a synthetic backwards pair so the
        // wrap-qualification path is exercisable deterministically offline.
        let before = report.counters_before;
        let mut after = before;
        after.rx_packets = before.rx_packets.saturating_sub(1);
        compute_delta(
            &interface,
            before,
            after,
            report.raw.elapsed_secs,
            args.assume_isolated,
        )
    } else {
        compute_delta(
            &interface,
            report.counters_before,
            report.counters_after,
            report.raw.elapsed_secs,
            args.assume_isolated,
        )
    };

    let out = CounterDeltasReport {
        delta: counter_delta,
        radio_validity: report.validity,
    };

    if args.json {
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
        return;
    }
    print_human(&out);
}

fn print_human(out: &CounterDeltasReport) {
    let delta = &out.delta;
    println!();
    println!("{}", "== Interface Counter Delta ==".cyan().bold());
    println!("  interface: {}", delta.interface);
    println!("  elapsed_secs: {:.2}", delta.elapsed_secs);
    match &out.radio_validity {
        Validity::Valid => println!("  radio validity: {}", "stable".green().bold()),
        Validity::Invalid(reason) => println!(
            "  radio validity: {} ({}) -- this counter delta cannot be attributed to a stable radio state",
            "INVALID".red().bold(),
            reason
        ),
    }
    match &delta.qualification {
        DeltaQualification::Clean => println!("  qualification: {}", "clean".green().bold()),
        DeltaQualification::CounterWrappedOrReset => println!(
            "  qualification: {}",
            "COUNTER WRAPPED OR RESET -- delta withheld, raw before/after retained below"
                .yellow()
                .bold()
        ),
        DeltaQualification::SharedInterfaceUnrelatedTraffic => println!(
            "  qualification: {}",
            "SHARED INTERFACE -- may carry traffic this phase did not generate; delta withheld"
                .yellow()
                .bold()
        ),
    }
    println!(
        "  before: rx_packets={} tx_packets={} rx_bytes={} tx_bytes={} rx_errors={} tx_errors={}",
        delta.before.rx_packets,
        delta.before.tx_packets,
        delta.before.rx_bytes,
        delta.before.tx_bytes,
        delta.before.rx_errors,
        delta.before.tx_errors
    );
    println!(
        "  after:  rx_packets={} tx_packets={} rx_bytes={} tx_bytes={} rx_errors={} tx_errors={}",
        delta.after.rx_packets,
        delta.after.tx_packets,
        delta.after.rx_bytes,
        delta.after.tx_bytes,
        delta.after.rx_errors,
        delta.after.tx_errors
    );
    match &delta.normalized {
        Some(n) => {
            println!(
                "  normalized: rx_bytes/sec={:.1} tx_bytes/sec={:.1} rx_errors/1k_packets={:.4} tx_errors/1k_packets={:.4}",
                n.rx_bytes_per_sec, n.tx_bytes_per_sec, n.rx_errors_per_1k_packets, n.tx_errors_per_1k_packets
            );
            println!(
                "  host/driver errors this phase: rx={} tx={} (local NIC/driver only -- not a remote-loss measurement)",
                n.host_driver_rx_errors, n.host_driver_tx_errors
            );
        }
        None => println!("  normalized: none (see qualification above -- a rate computed from this delta would have no referent)"),
    }
    println!();
}
