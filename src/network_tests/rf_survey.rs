//! GAP-055: bounded time-based RF spectrum, interference, and coverage
//! survey.
//!
//! One radio snapshot cannot reveal intermittent interference: strong RSSI
//! (-53 to -63 dBm throughout the investigation) did not prevent the
//! observed loss, and a single sample showed 0% channel utilization at the
//! instant it was taken. Co-channel contention, hidden nodes, DFS events,
//! and load that tracks a class schedule are all invisible to a point
//! sample -- they only show up as a time series.
//!
//! Platform reality on macOS, load-bearing for this whole module: `ioreg`
//! answers in ~30ms but only ever carries band/channel/width -- never RSSI,
//! noise, retries, or utilization. `system_profiler SPAirPortDataType`
//! carries RSSI/noise/PHY/MCS but costs 8-9 seconds per call, which bounds
//! the practical sample rate for anything using it. Channel utilization,
//! retry counters, DFS/radar events, and neighboring-BSS load are
//! privilege-gated (`wdutil`, needs root) and were never obtained during
//! the field investigation at all. This module's `Obtainability` type
//! exists so every metric says, per sample, whether it was actually
//! measured, is platform-limited on this host, or was supplied externally
//! -- never silently rendered as a measured zero. A 0% utilization reading
//! from a source that cannot report utilization at all is the single most
//! dangerous failure mode here: it reads as "the channel is clear" and
//! would exonerate the exact thing under investigation.

use serde::{Deserialize, Serialize};

use crate::load_guard::radio::RadioSnapshot;

/// Whether a given metric in a sample was actually measured on this
/// platform, is known to be unobtainable here, or was filled in from an
/// operator-supplied (e.g. AP/controller) source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Obtainability {
    Measured,
    PlatformLimited,
    OperatorSupplied,
}

/// One optional metric value plus how it was obtained. `value: None` with
/// `Obtainability::PlatformLimited` is the only correct way to say "this
/// host cannot see this" -- never a bare 0.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metric<T> {
    pub value: Option<T>,
    pub obtainability: Obtainability,
}

impl<T> Metric<T> {
    pub fn measured(value: T) -> Self {
        Self { value: Some(value), obtainability: Obtainability::Measured }
    }
    pub fn platform_limited() -> Self {
        Self { value: None, obtainability: Obtainability::PlatformLimited }
    }
    pub fn operator_supplied(value: T) -> Self {
        Self { value: Some(value), obtainability: Obtainability::OperatorSupplied }
    }
}

/// One point in the time series. Every field the acceptance criteria names
/// is present; on this platform most start life `platform_limited` and get
/// filled from `RadioSnapshot` (band/channel/width always; RSSI/noise/MCS
/// only from the slow `system_profiler` path) or from operator-supplied
/// JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RfSample {
    pub elapsed_secs: f64,
    pub channel: Metric<u32>,
    pub band: Metric<String>,
    pub rssi_dbm: Metric<i32>,
    pub noise_dbm: Metric<i32>,
    pub channel_utilization_pct: Metric<f64>,
    pub retries_pct: Metric<f64>,
    pub dfs_radar_event: Metric<bool>,
    pub neighboring_bss_count: Metric<u32>,
    pub non_wifi_utilization_pct: Metric<f64>,
    pub client_count: Metric<u32>,
    /// A caller-assigned, non-identifying location label (e.g. "room-a",
    /// "hallway-3"). Never a coordinate tied to a person or device.
    pub location_label: Option<String>,
}

impl RfSample {
    /// Builds a sample from a `RadioSnapshot`, the only always-available
    /// source on this platform. Fields the snapshot cannot carry (from
    /// either the fast or slow path) are explicitly `platform_limited`.
    pub fn from_radio_snapshot(elapsed_secs: f64, snap: &RadioSnapshot, location_label: Option<String>) -> Self {
        Self {
            elapsed_secs,
            channel: snap.channel.map(Metric::measured).unwrap_or_else(Metric::platform_limited),
            band: snap.band.clone().map(Metric::measured).unwrap_or_else(Metric::platform_limited),
            rssi_dbm: snap.rssi_dbm.map(Metric::measured).unwrap_or_else(Metric::platform_limited),
            noise_dbm: snap.noise_dbm.map(Metric::measured).unwrap_or_else(Metric::platform_limited),
            // None of these are ever obtainable from RadioSnapshot on this
            // platform (ioreg and system_profiler both lack them), so they
            // are unconditionally platform-limited from this constructor.
            channel_utilization_pct: Metric::platform_limited(),
            retries_pct: Metric::platform_limited(),
            dfs_radar_event: Metric::platform_limited(),
            neighboring_bss_count: Metric::platform_limited(),
            non_wifi_utilization_pct: Metric::platform_limited(),
            client_count: Metric::platform_limited(),
            location_label,
        }
    }

    /// Overlays operator-supplied values (e.g. from an AP/controller export)
    /// onto whatever fields are still platform-limited. Never overwrites a
    /// field that was actually measured on this host.
    pub fn merge_operator_supplied(&mut self, ext: &ExternalTelemetry) {
        if self.channel_utilization_pct.value.is_none() {
            if let Some(v) = ext.channel_utilization_pct {
                self.channel_utilization_pct = Metric::operator_supplied(v);
            }
        }
        if self.retries_pct.value.is_none() {
            if let Some(v) = ext.retries_pct {
                self.retries_pct = Metric::operator_supplied(v);
            }
        }
        if self.dfs_radar_event.value.is_none() {
            if let Some(v) = ext.dfs_radar_event {
                self.dfs_radar_event = Metric::operator_supplied(v);
            }
        }
        if self.neighboring_bss_count.value.is_none() {
            if let Some(v) = ext.neighboring_bss_count {
                self.neighboring_bss_count = Metric::operator_supplied(v);
            }
        }
        if self.non_wifi_utilization_pct.value.is_none() {
            if let Some(v) = ext.non_wifi_utilization_pct {
                self.non_wifi_utilization_pct = Metric::operator_supplied(v);
            }
        }
        if self.client_count.value.is_none() {
            if let Some(v) = ext.client_count {
                self.client_count = Metric::operator_supplied(v);
            }
        }
    }
}

/// Operator-supplied telemetry for one point in time, matched to a sample
/// by index or timestamp by the caller. Fields are all optional: partial
/// AP/controller exports are the common case.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ExternalTelemetry {
    pub channel_utilization_pct: Option<f64>,
    pub retries_pct: Option<f64>,
    pub dfs_radar_event: Option<bool>,
    pub neighboring_bss_count: Option<u32>,
    pub non_wifi_utilization_pct: Option<f64>,
    pub client_count: Option<u32>,
}

/// A bounded survey: an explicit sample count and interval, never an
/// unbounded/continuous mode. `duration_secs()` is a derived fact used to
/// prove boundedness, not a separate field a caller could set
/// inconsistently.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SurveyPlan {
    pub sample_count: u32,
    pub interval_secs: f64,
}

impl SurveyPlan {
    pub fn duration_secs(&self) -> f64 {
        self.sample_count as f64 * self.interval_secs
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RfTimeSeries {
    pub plan: SurveyPlan,
    pub samples: Vec<RfSample>,
}

/// A detected change point: a metric whose value moved materially between
/// two adjacent (or specified) samples.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangePoint {
    pub metric: String,
    pub from_elapsed_secs: f64,
    pub to_elapsed_secs: f64,
    pub from_value: f64,
    pub to_value: f64,
}

/// Detects change points in channel utilization across the series. Requires
/// at least two samples with a *measured or operator-supplied* value for
/// this metric; fewer than two returns an empty list with no claim of "no
/// change" -- that would misrepresent "we don't know" as "we checked and
/// nothing changed."
pub fn detect_utilization_change_points(series: &RfTimeSeries, threshold_pct: f64) -> Vec<ChangePoint> {
    let usable: Vec<&RfSample> = series.samples.iter().filter(|s| s.channel_utilization_pct.value.is_some()).collect();
    if usable.len() < 2 {
        return Vec::new();
    }
    let mut points = Vec::new();
    for pair in usable.windows(2) {
        let (a, b) = (pair[0], pair[1]);
        let av = a.channel_utilization_pct.value.unwrap();
        let bv = b.channel_utilization_pct.value.unwrap();
        if (bv - av).abs() >= threshold_pct {
            points.push(ChangePoint {
                metric: "channel_utilization_pct".to_string(),
                from_elapsed_secs: a.elapsed_secs,
                to_elapsed_secs: b.elapsed_secs,
                from_value: av,
                to_value: bv,
            });
        }
    }
    points
}

/// A named event window (e.g. from an event schedule or a recorded test
/// failure) to correlate against change points.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventWindow {
    pub label: String,
    pub start_elapsed_secs: f64,
    pub end_elapsed_secs: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Correlation {
    pub change_point: ChangePoint,
    pub overlapping_events: Vec<String>,
}

/// Correlates change points with event windows (test failures, schedule
/// entries). A change point overlapping zero events is still returned with
/// an empty `overlapping_events` -- that is itself informative (unexplained
/// interference), distinct from there being no change points to begin with.
pub fn correlate_change_points(change_points: &[ChangePoint], events: &[EventWindow]) -> Vec<Correlation> {
    change_points
        .iter()
        .map(|cp| {
            let overlapping: Vec<String> = events
                .iter()
                .filter(|e| cp.to_elapsed_secs >= e.start_elapsed_secs && cp.from_elapsed_secs <= e.end_elapsed_secs)
                .map(|e| e.label.clone())
                .collect();
            Correlation { change_point: cp.clone(), overlapping_events: overlapping }
        })
        .collect()
}

/// One privacy-safe coverage/capacity entry: a location label, a summary RF
/// quality figure, and nothing that could identify a network or device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoveragePoint {
    pub location_label: String,
    pub mean_rssi_dbm: Option<f64>,
    pub mean_utilization_pct: Option<f64>,
    pub sample_count: usize,
}

const FORBIDDEN_SUBSTRINGS: &[&str] = &["SSID", "BSSID", "MAC Address"];

/// Builds a coverage map from a time series, grouped by `location_label`.
/// Refuses (returns an error) if any sample's location label itself
/// contains an obviously identifying substring -- a caller passing a raw
/// SSID as the label is a real failure mode this guards against structurally,
/// not just by omission elsewhere in the struct.
pub fn build_coverage_map(series: &RfTimeSeries) -> Result<Vec<CoveragePoint>, String> {
    use std::collections::HashMap;
    let mut groups: HashMap<String, Vec<&RfSample>> = HashMap::new();
    for s in &series.samples {
        let label = s.location_label.clone().unwrap_or_else(|| "unlabeled".to_string());
        for bad in FORBIDDEN_SUBSTRINGS {
            if label.contains(bad) {
                return Err(format!("location label contains forbidden identifier substring '{}'", bad));
            }
        }
        groups.entry(label).or_default().push(s);
    }

    let mut points: Vec<CoveragePoint> = groups
        .into_iter()
        .map(|(label, samples)| {
            let rssi_vals: Vec<f64> = samples.iter().filter_map(|s| s.rssi_dbm.value).map(|v| v as f64).collect();
            let util_vals: Vec<f64> = samples.iter().filter_map(|s| s.channel_utilization_pct.value).collect();
            CoveragePoint {
                location_label: label,
                mean_rssi_dbm: if rssi_vals.is_empty() { None } else { Some(rssi_vals.iter().sum::<f64>() / rssi_vals.len() as f64) },
                mean_utilization_pct: if util_vals.is_empty() { None } else { Some(util_vals.iter().sum::<f64>() / util_vals.len() as f64) },
                sample_count: samples.len(),
            }
        })
        .collect();
    points.sort_by(|a, b| a.location_label.cmp(&b.location_label));
    Ok(points)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(elapsed: f64, util: Option<f64>, rssi: Option<i32>, label: Option<&str>) -> RfSample {
        RfSample {
            elapsed_secs: elapsed,
            channel: Metric::platform_limited(),
            band: Metric::platform_limited(),
            rssi_dbm: rssi.map(Metric::measured).unwrap_or_else(Metric::platform_limited),
            noise_dbm: Metric::platform_limited(),
            channel_utilization_pct: util.map(Metric::operator_supplied).unwrap_or_else(Metric::platform_limited),
            retries_pct: Metric::platform_limited(),
            dfs_radar_event: Metric::platform_limited(),
            neighboring_bss_count: Metric::platform_limited(),
            non_wifi_utilization_pct: Metric::platform_limited(),
            client_count: Metric::platform_limited(),
            location_label: label.map(|s| s.to_string()),
        }
    }

    #[test]
    fn platform_limited_metric_is_none_never_a_fabricated_zero() {
        let m: Metric<f64> = Metric::platform_limited();
        assert_eq!(m.value, None);
        assert_eq!(m.obtainability, Obtainability::PlatformLimited);
    }

    #[test]
    fn radio_snapshot_conversion_marks_utilization_platform_limited() {
        let snap = RadioSnapshot { associated: true, band: Some("6GHz".into()), channel: Some(197), width_mhz: Some(80), rssi_dbm: Some(-59), noise_dbm: Some(-94), tx_rate_mbps: Some(680.0), mcs_index: Some(7), phy_mode: Some("802.11ax".into()) };
        let s = RfSample::from_radio_snapshot(0.0, &snap, None);
        assert_eq!(s.rssi_dbm.value, Some(-59));
        assert_eq!(s.channel_utilization_pct.obtainability, Obtainability::PlatformLimited);
        assert_eq!(s.channel_utilization_pct.value, None);
        assert_eq!(s.retries_pct.obtainability, Obtainability::PlatformLimited);
    }

    #[test]
    fn operator_supplied_telemetry_fills_gaps_without_overwriting_measured() {
        let snap = RadioSnapshot { associated: true, band: Some("6GHz".into()), channel: Some(197), width_mhz: Some(80), rssi_dbm: Some(-59), noise_dbm: Some(-94), tx_rate_mbps: None, mcs_index: None, phy_mode: None };
        let mut s = RfSample::from_radio_snapshot(0.0, &snap, None);
        let ext = ExternalTelemetry { channel_utilization_pct: Some(42.0), ..Default::default() };
        s.merge_operator_supplied(&ext);
        assert_eq!(s.channel_utilization_pct.value, Some(42.0));
        assert_eq!(s.channel_utilization_pct.obtainability, Obtainability::OperatorSupplied);
        // rssi was already measured -- must not be touched by the merge.
        assert_eq!(s.rssi_dbm.value, Some(-59));
        assert_eq!(s.rssi_dbm.obtainability, Obtainability::Measured);
    }

    #[test]
    fn change_point_detection_requires_at_least_two_usable_samples() {
        let series = RfTimeSeries {
            plan: SurveyPlan { sample_count: 1, interval_secs: 1.0 },
            samples: vec![sample(0.0, Some(10.0), None, None)],
        };
        assert!(detect_utilization_change_points(&series, 5.0).is_empty());
    }

    #[test]
    fn change_point_detected_on_material_utilization_jump() {
        let series = RfTimeSeries {
            plan: SurveyPlan { sample_count: 3, interval_secs: 60.0 },
            samples: vec![
                sample(0.0, Some(5.0), None, None),
                sample(60.0, Some(8.0), None, None),
                sample(120.0, Some(55.0), None, None),
            ],
        };
        let points = detect_utilization_change_points(&series, 20.0);
        assert_eq!(points.len(), 1);
        assert_eq!(points[0].from_elapsed_secs, 60.0);
        assert_eq!(points[0].to_elapsed_secs, 120.0);
    }

    #[test]
    fn correlation_links_change_point_to_overlapping_event_window() {
        let cp = ChangePoint { metric: "channel_utilization_pct".to_string(), from_elapsed_secs: 60.0, to_elapsed_secs: 120.0, from_value: 8.0, to_value: 55.0 };
        let events = vec![EventWindow { label: "09:00 training room fills".to_string(), start_elapsed_secs: 90.0, end_elapsed_secs: 200.0 }];
        let correlations = correlate_change_points(&[cp], &events);
        assert_eq!(correlations[0].overlapping_events, vec!["09:00 training room fills".to_string()]);
    }

    #[test]
    fn correlation_reports_empty_overlap_distinct_from_no_change_points() {
        let cp = ChangePoint { metric: "channel_utilization_pct".to_string(), from_elapsed_secs: 60.0, to_elapsed_secs: 120.0, from_value: 8.0, to_value: 55.0 };
        let correlations = correlate_change_points(&[cp], &[]);
        assert_eq!(correlations.len(), 1);
        assert!(correlations[0].overlapping_events.is_empty());
    }

    #[test]
    fn coverage_map_never_contains_ssid_bssid_mac() {
        let series = RfTimeSeries {
            plan: SurveyPlan { sample_count: 2, interval_secs: 1.0 },
            samples: vec![sample(0.0, Some(10.0), Some(-60), Some("room-a")), sample(1.0, Some(12.0), Some(-62), Some("room-a"))],
        };
        let map = build_coverage_map(&series).unwrap();
        let serialized = serde_json::to_string(&map).unwrap();
        assert!(!serialized.contains("SSID"));
        assert!(!serialized.contains("BSSID"));
        assert!(!serialized.contains("MAC"));
    }

    #[test]
    fn coverage_map_rejects_identifying_location_label() {
        let series = RfTimeSeries {
            plan: SurveyPlan { sample_count: 1, interval_secs: 1.0 },
            samples: vec![sample(0.0, Some(10.0), Some(-60), Some("MyHomeSSID"))],
        };
        assert!(build_coverage_map(&series).is_err());
    }

    #[test]
    fn survey_plan_duration_is_derived_and_bounded() {
        let plan = SurveyPlan { sample_count: 10, interval_secs: 30.0 };
        assert_eq!(plan.duration_secs(), 300.0);
    }
}
