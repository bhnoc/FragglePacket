//! GAP-055: bounded time-based RF spectrum/interference/coverage survey
//! (`rf-survey`).
//!
//! Samples radio state at a fixed interval for a fixed count -- no
//! unbounded/daemon mode exists. On this platform that means `ioreg`'s
//! ~30ms band/channel/width-only read (`--fast`) or `system_profiler`'s
//! ~8-9s read carrying RSSI/noise/PHY/MCS as well (default). Channel
//! utilization, retries, DFS events, neighboring-BSS load, non-Wi-Fi
//! utilization, and client count have no unprivileged source on this
//! platform at all; every sample reports them `platform_limited`, never a
//! fabricated 0, unless `--telemetry-in` supplies operator/AP data to fill
//! the gaps.

use colored::*;
use std::io::Read;
use std::time::{Duration, Instant};

use fraggle_packet::load_guard::radio::{snapshot_fast, snapshot_live};
use fraggle_packet::network_tests::rf_survey::{
    build_coverage_map, correlate_change_points, detect_utilization_change_points, EventWindow, ExternalTelemetry, RfSample,
    RfTimeSeries, SurveyPlan,
};

#[derive(clap::Args, Debug)]
pub struct RfSurveyArgs {
    /// Number of samples to take. Bounded by construction -- there is no
    /// flag that requests continuous/unbounded sampling.
    #[arg(long, default_value_t = 5)]
    pub sample_count: u32,

    /// Seconds between samples.
    #[arg(long, default_value_t = 10.0)]
    pub interval_secs: f64,

    /// Use the fast (~30ms) ioreg-backed source instead of the slow
    /// (~8-9s) system_profiler source. Faster but cannot report
    /// RSSI/noise/PHY/MCS at all -- those metrics report platform_limited
    /// even though the reason differs from the slow path's real gaps
    /// (utilization/retries/DFS/etc).
    #[arg(long)]
    pub fast: bool,

    /// Non-identifying location label attached to every sample in this run
    /// (e.g. "room-a"). Never an SSID, BSSID, or MAC -- rejected if it
    /// looks like one.
    #[arg(long)]
    pub location: Option<String>,

    /// Path to a JSON file (or "-" for stdin) with operator-supplied
    /// telemetry (e.g. exported from an AP/controller) to fill metrics this
    /// platform cannot sample. Expected shape: a JSON array of
    /// `ExternalTelemetry` objects, one per sample in order.
    #[arg(long)]
    pub telemetry_in: Option<String>,

    /// Change-point threshold in percentage points for channel utilization.
    #[arg(long, default_value_t = 15.0)]
    pub change_threshold_pct: f64,

    /// Event windows to correlate against, given as
    /// "<label>=<start_secs>-<end_secs>" (repeatable).
    #[arg(long = "event")]
    pub events: Vec<String>,

    #[arg(long)]
    pub json: bool,
}

fn parse_events(entries: &[String]) -> Vec<EventWindow> {
    entries
        .iter()
        .filter_map(|e| {
            let (label, range) = e.split_once('=')?;
            let (start, end) = range.split_once('-')?;
            Some(EventWindow {
                label: label.trim().to_string(),
                start_elapsed_secs: start.trim().parse().ok()?,
                end_elapsed_secs: end.trim().parse().ok()?,
            })
        })
        .collect()
}

fn load_telemetry(path: &str) -> Result<Vec<ExternalTelemetry>, String> {
    let text = if path == "-" {
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf).map_err(|e| e.to_string())?;
        buf
    } else {
        std::fs::read_to_string(path).map_err(|e| e.to_string())?
    };
    serde_json::from_str(&text).map_err(|e| e.to_string())
}

pub fn run(args: &RfSurveyArgs) {
    if let Some(loc) = &args.location {
        for bad in ["SSID", "BSSID", "MAC"] {
            if loc.contains(bad) {
                eprintln!("{} --location must not contain '{}' (looks like a network identifier)", "✗".red(), bad);
                std::process::exit(2);
            }
        }
    }

    let plan = SurveyPlan { sample_count: args.sample_count, interval_secs: args.interval_secs };
    let telemetry = match &args.telemetry_in {
        Some(p) => match load_telemetry(p) {
            Ok(t) => Some(t),
            Err(e) => {
                eprintln!("{} failed to load --telemetry-in: {}", "✗".red(), e);
                std::process::exit(1);
            }
        },
        None => None,
    };

    if !args.json {
        println!(
            "RF survey: {} samples every {:.1}s ({:.1}s bounded total), source={}",
            plan.sample_count,
            plan.interval_secs,
            plan.duration_secs(),
            if args.fast { "ioreg (fast)" } else { "system_profiler (slow, full detail)" }
        );
    }

    let mut samples = Vec::with_capacity(plan.sample_count as usize);
    let start = Instant::now();
    for i in 0..plan.sample_count {
        let snap_result = if args.fast { snapshot_fast() } else { snapshot_live() };
        let snap = match snap_result {
            Ok(s) => s,
            Err(e) => {
                eprintln!("{} sample {} failed: {}", "⚠".yellow(), i, e);
                fraggle_packet::load_guard::radio::RadioSnapshot::unavailable()
            }
        };
        let mut sample = RfSample::from_radio_snapshot(start.elapsed().as_secs_f64(), &snap, args.location.clone());
        if let Some(t) = telemetry.as_ref().and_then(|v| v.get(i as usize)) {
            sample.merge_operator_supplied(t);
        }
        samples.push(sample);

        if i + 1 < plan.sample_count {
            std::thread::sleep(Duration::from_secs_f64(args.interval_secs));
        }
    }

    let series = RfTimeSeries { plan, samples };
    let change_points = detect_utilization_change_points(&series, args.change_threshold_pct);
    let events = parse_events(&args.events);
    let correlations = correlate_change_points(&change_points, &events);
    let coverage = build_coverage_map(&series);

    if args.json {
        let out = serde_json::json!({
            "series": series,
            "change_points": change_points,
            "correlations": correlations,
            "coverage_map": coverage.as_ref().ok(),
            "coverage_map_error": coverage.as_ref().err(),
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
        return;
    }

    print_human(&series, &correlations, &coverage);
}

fn fmt_metric<T: std::fmt::Display>(m: &fraggle_packet::network_tests::rf_survey::Metric<T>) -> String {
    use fraggle_packet::network_tests::rf_survey::Obtainability;
    match (&m.value, m.obtainability) {
        (Some(v), Obtainability::Measured) => format!("{}", v),
        (Some(v), Obtainability::OperatorSupplied) => format!("{} (operator)", v),
        (None, Obtainability::PlatformLimited) => "platform-limited".dimmed().to_string(),
        _ => "unavailable".dimmed().to_string(),
    }
}

fn print_human(
    series: &RfTimeSeries,
    correlations: &[fraggle_packet::network_tests::rf_survey::Correlation],
    coverage: &Result<Vec<fraggle_packet::network_tests::rf_survey::CoveragePoint>, String>,
) {
    println!();
    println!("{}", "== Samples ==".cyan().bold());
    for s in &series.samples {
        println!(
            "  t={:<7.1} channel={:<10} rssi={:<20} util={:<20} retries={:<20} dfs={}",
            s.elapsed_secs,
            fmt_metric(&s.channel),
            fmt_metric(&s.rssi_dbm),
            fmt_metric(&s.channel_utilization_pct),
            fmt_metric(&s.retries_pct),
            fmt_metric(&s.dfs_radar_event)
        );
    }
    println!();
    println!("{}", "== Change points ==".cyan().bold());
    if correlations.is_empty() {
        println!("  none detected (or fewer than two usable samples)");
    }
    for c in correlations {
        println!(
            "  {} {:.1} -> {:.1} at t={:.1}s->{:.1}s{}",
            c.change_point.metric,
            c.change_point.from_value,
            c.change_point.to_value,
            c.change_point.from_elapsed_secs,
            c.change_point.to_elapsed_secs,
            if c.overlapping_events.is_empty() {
                " (no overlapping event window -- unexplained)".yellow().to_string()
            } else {
                format!(" [{}]", c.overlapping_events.join(", "))
            }
        );
    }
    println!();
    match coverage {
        Ok(points) => {
            println!("{}", "== Coverage map ==".cyan().bold());
            for p in points {
                println!(
                    "  {:<16} samples={:<4} mean_rssi={} mean_util={}",
                    p.location_label,
                    p.sample_count,
                    p.mean_rssi_dbm.map(|v| format!("{:.1}", v)).unwrap_or_else(|| "unavailable".to_string()),
                    p.mean_utilization_pct.map(|v| format!("{:.1}", v)).unwrap_or_else(|| "unavailable".to_string())
                );
            }
        }
        Err(e) => println!("{} coverage map rejected: {}", "✗".red(), e),
    }
}
