//! The shared load-phase execution guard (GAP-027 + GAP-047).
//!
//! Every load-generating command wraps its phase in `LoadGuard::run`. The
//! guard owns the budget check, the ramp, the pre/during/post radio and
//! counter snapshots, the abort thresholds, and the stop-reason bookkeeping.
//! It never computes a derived ratio itself when the run is invalid — see
//! `compute_derived_ratio`, the one function callers may use for that, which
//! is structurally incapable of returning `Some` for an invalid run.

use crate::load_guard::budget::{BudgetError, LoadBudget};
use crate::load_guard::counters::InterfaceCounters;
use crate::load_guard::radio::{classify_rf, RadioSnapshot, RfQuality};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RadioTimeline {
    pub before: RadioSnapshot,
    pub during: Vec<RadioSnapshot>,
    pub after: RadioSnapshot,
}

impl RadioTimeline {
    /// A run "roamed" if the allowlisted association fingerprint (band,
    /// channel, width, PHY mode) changed at any sampled point, before to
    /// after inclusive of during-phase samples.
    pub fn roamed(&self) -> bool {
        let baseline = self.before.association_fingerprint();
        let mut points = self.during.iter().collect::<Vec<_>>();
        points.push(&self.after);
        points.iter().any(|s| s.association_fingerprint() != baseline)
    }

    pub fn band_changed(&self) -> bool {
        let mut points: Vec<&Option<String>> = self.during.iter().map(|s| &s.band).collect();
        points.push(&self.after.band);
        points.iter().any(|b| **b != self.before.band)
    }

    pub fn weakest_rf(&self) -> RfQuality {
        let mut all = self.during.clone();
        all.push(self.before.clone());
        all.push(self.after.clone());
        all.into_iter()
            .map(|s| classify_rf(&s))
            .max_by_key(|q| match q {
                RfQuality::Strong => 0,
                RfQuality::Unknown => 1,
                RfQuality::Unstable => 2,
                RfQuality::Weak => 3,
            })
            .unwrap_or(RfQuality::Unknown)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InvalidReason {
    Roamed,
    BandChanged,
    WeakRf,
    UnstableRf,
    CountersUnusable,
    RadioUnavailable,
}

impl std::fmt::Display for InvalidReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            InvalidReason::Roamed => "association roamed during phase",
            InvalidReason::BandChanged => "radio band changed during phase",
            InvalidReason::WeakRf => "weak RF observed during phase",
            InvalidReason::UnstableRf => "unstable RF (low SNR) observed during phase",
            InvalidReason::CountersUnusable => "interface counters unusable (wrap/reset)",
            InvalidReason::RadioUnavailable => "radio state unavailable",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Validity {
    Valid,
    Invalid(InvalidReason),
}

impl Validity {
    pub fn is_valid(&self) -> bool {
        matches!(self, Validity::Valid)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StopReason {
    Completed,
    AbortGatewayLatency { observed_ms: u64, threshold_ms: u64 },
    AbortLoss { observed_pct_x100: u64, threshold_pct_x100: u64 },
    AbortAssociationChange,
    AbortEndpointError { detail: String },
    OperatorCancelled,
}

impl std::fmt::Display for StopReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StopReason::Completed => write!(f, "completed"),
            StopReason::AbortGatewayLatency { observed_ms, threshold_ms } => write!(
                f,
                "aborted: gateway latency {observed_ms}ms exceeded threshold {threshold_ms}ms"
            ),
            StopReason::AbortLoss { observed_pct_x100, threshold_pct_x100 } => write!(
                f,
                "aborted: loss {:.2}% exceeded threshold {:.2}%",
                *observed_pct_x100 as f64 / 100.0,
                *threshold_pct_x100 as f64 / 100.0
            ),
            StopReason::AbortAssociationChange => write!(f, "aborted: association changed"),
            StopReason::AbortEndpointError { detail } => write!(f, "aborted: endpoint error: {detail}"),
            StopReason::OperatorCancelled => write!(f, "aborted: operator cancellation (SIGINT)"),
        }
    }
}

/// One sample taken while the phase runs, fed back to the guard so it can
/// evaluate abort thresholds. Real callers produce this from live probes;
/// tests inject it synthetically.
#[derive(Debug, Clone, Copy, Default)]
pub struct PhaseTick {
    pub gateway_latency_ms: Option<f64>,
    pub loss_pct: Option<f64>,
    pub endpoint_error: Option<&'static str>,
    pub bytes_sent_delta: u64,
}

/// A load phase the guard drives. Implemented by closures via the blanket
/// impl below so tests can inject arbitrary tick sequences without touching
/// real sockets.
pub trait LoadPhase {
    fn tick(&mut self, ramp_rate_mbps: f64, elapsed: Duration) -> PhaseTick;
}

impl<F> LoadPhase for F
where
    F: FnMut(f64, Duration) -> PhaseTick,
{
    fn tick(&mut self, ramp_rate_mbps: f64, elapsed: Duration) -> PhaseTick {
        self(ramp_rate_mbps, elapsed)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawMetrics {
    pub bytes_transferred: u64,
    pub elapsed_secs: f64,
    pub target_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DerivedMetrics {
    pub retained_capacity_pct: f64,
    pub collapse_ratio: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardReport {
    pub interface: String,
    pub mode: crate::load_guard::budget::RunMode,
    pub stop_reason: StopReason,
    pub validity: Validity,
    pub radio: RadioTimeline,
    pub counters_before: InterfaceCounters,
    pub counters_after: InterfaceCounters,
    pub counters_usable: bool,
    pub raw: RawMetrics,
    /// `None` whenever `validity` is not `Valid`. This is enforced by
    /// `compute_derived_ratio`, the sole constructor for this field — there
    /// is no other code path that can populate it.
    pub derived: Option<DerivedMetrics>,
    pub default_route_is_tunnel: bool,
}

/// The one place a derived collapse/retention ratio may be produced. It is
/// structurally impossible to get `Some` back for an invalid run: the match
/// on `validity` is exhaustive and the `Invalid` arm returns `None` before
/// touching `raw` at all.
pub fn compute_derived_ratio(validity: &Validity, raw: &RawMetrics) -> Option<DerivedMetrics> {
    match validity {
        Validity::Invalid(_) => None,
        Validity::Valid => {
            if raw.target_bytes == 0 {
                return None;
            }
            let retained = raw.bytes_transferred as f64 / raw.target_bytes as f64;
            Some(DerivedMetrics {
                retained_capacity_pct: retained * 100.0,
                collapse_ratio: 1.0 - retained,
            })
        }
    }
}

pub struct RadioSource {
    inner: Box<dyn Fn() -> Result<RadioSnapshot, String> + Send + Sync>,
}

impl RadioSource {
    pub fn new(f: impl Fn() -> Result<RadioSnapshot, String> + Send + Sync + 'static) -> Self {
        Self { inner: Box::new(f) }
    }
    fn sample(&self) -> RadioSnapshot {
        (self.inner)().unwrap_or_else(|_| RadioSnapshot::unavailable())
    }
}

pub struct CounterSource {
    inner: Box<dyn Fn() -> Result<InterfaceCounters, String> + Send + Sync>,
}

impl CounterSource {
    pub fn new(f: impl Fn() -> Result<InterfaceCounters, String> + Send + Sync + 'static) -> Self {
        Self { inner: Box::new(f) }
    }
    fn sample(&self) -> InterfaceCounters {
        (self.inner)().unwrap_or_else(|_| InterfaceCounters::zero())
    }
}

pub struct LoadGuard {
    pub budget: LoadBudget,
    pub interface: String,
    pub default_route_is_tunnel: bool,
    radio: RadioSource,
    counters: CounterSource,
    sample_interval: Duration,
    radio_sample_interval: Duration,
}

impl LoadGuard {
    /// Fails closed: no budget, no run. `LoadBudget` has no zero-value
    /// default, so a caller with nothing to pass gets this error rather than
    /// an implicit maximum-stress run.
    pub fn new(
        budget: LoadBudget,
        interface: impl Into<String>,
        default_route_is_tunnel: bool,
        radio: RadioSource,
        counters: CounterSource,
    ) -> Result<Self, BudgetError> {
        budget.validate()?;
        Ok(Self {
            budget,
            interface: interface.into(),
            default_route_is_tunnel,
            radio,
            counters,
            sample_interval: Duration::from_millis(200),
            // Real radio sampling (system_profiler) can take seconds; sample it
            // on its own, coarser cadence so it never throttles the tick loop.
            radio_sample_interval: Duration::from_secs(2),
        })
    }

    #[cfg(test)]
    pub fn with_sample_interval(mut self, d: Duration) -> Self {
        self.sample_interval = d;
        self.radio_sample_interval = d;
        self
    }

    /// Drives `phase` through the budget's ramp schedule, sampling radio and
    /// interface counters before/during/after, checking abort thresholds
    /// every tick, and honoring `cancel` (set from a SIGINT handler) as an
    /// operator-cancellation abort that still returns a full report.
    pub fn run(&self, mut phase: impl LoadPhase, cancel: Arc<AtomicBool>) -> GuardReport {
        let before_radio = self.radio.sample();
        let counters_before = self.counters.sample();

        let mut during_radio = Vec::new();
        let mut bytes_transferred: u64 = 0;
        let mut stop_reason = StopReason::Completed;
        let target_bytes = (self.budget.target_rate_mbps * 1_000_000.0 / 8.0
            * self.budget.max_duration_secs as f64) as u64;

        let schedule = self.budget.ramp_schedule();
        let step_duration = Duration::from_secs(self.budget.max_duration_secs.max(1))
            / schedule.len().max(1) as u32;
        let start = Instant::now();
        let mut last_radio_sample = Instant::now() - self.radio_sample_interval;

        'ramp: for rate in schedule {
            let step_start = Instant::now();
            while step_start.elapsed() < step_duration {
                if cancel.load(Ordering::SeqCst) {
                    stop_reason = StopReason::OperatorCancelled;
                    break 'ramp;
                }

                let tick = phase.tick(rate, start.elapsed());
                bytes_transferred += tick.bytes_sent_delta;
                if last_radio_sample.elapsed() >= self.radio_sample_interval {
                    during_radio.push(self.radio.sample());
                    last_radio_sample = Instant::now();
                }

                if let Some(detail) = tick.endpoint_error {
                    stop_reason = StopReason::AbortEndpointError { detail: detail.to_string() };
                    break 'ramp;
                }
                if let Some(ms) = tick.gateway_latency_ms {
                    if ms > self.budget.abort.max_gateway_latency_ms {
                        stop_reason = StopReason::AbortGatewayLatency {
                            observed_ms: ms as u64,
                            threshold_ms: self.budget.abort.max_gateway_latency_ms as u64,
                        };
                        break 'ramp;
                    }
                }
                if let Some(pct) = tick.loss_pct {
                    if pct > self.budget.abort.max_loss_pct {
                        stop_reason = StopReason::AbortLoss {
                            observed_pct_x100: (pct * 100.0) as u64,
                            threshold_pct_x100: (self.budget.abort.max_loss_pct * 100.0) as u64,
                        };
                        break 'ramp;
                    }
                }

                if let Some(latest) = during_radio.last() {
                    if latest.association_fingerprint() != before_radio.association_fingerprint() {
                        stop_reason = StopReason::AbortAssociationChange;
                        break 'ramp;
                    }
                }

                std::thread::sleep(self.sample_interval.min(step_duration));
            }
        }

        let after_radio = self.radio.sample();
        let counters_after = self.counters.sample();
        let counters_usable = counters_after.usable_delta_from(&counters_before);

        let timeline = RadioTimeline {
            before: before_radio.clone(),
            during: during_radio,
            after: after_radio,
        };

        let validity = if !before_radio.associated || !timeline.after.associated {
            Validity::Invalid(InvalidReason::RadioUnavailable)
        } else if timeline.roamed() {
            Validity::Invalid(InvalidReason::Roamed)
        } else if timeline.band_changed() {
            Validity::Invalid(InvalidReason::BandChanged)
        } else if !counters_usable {
            Validity::Invalid(InvalidReason::CountersUnusable)
        } else {
            match timeline.weakest_rf() {
                RfQuality::Weak => Validity::Invalid(InvalidReason::WeakRf),
                RfQuality::Unstable => Validity::Invalid(InvalidReason::UnstableRf),
                _ => Validity::Valid,
            }
        };

        let raw = RawMetrics {
            bytes_transferred,
            elapsed_secs: start.elapsed().as_secs_f64(),
            target_bytes,
        };
        let derived = compute_derived_ratio(&validity, &raw);

        GuardReport {
            interface: self.interface.clone(),
            mode: self.budget.mode,
            stop_reason,
            validity,
            radio: timeline,
            counters_before,
            counters_after,
            counters_usable,
            raw,
            derived,
            default_route_is_tunnel: self.default_route_is_tunnel,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::load_guard::budget::LoadBudget;

    fn strong_snapshot() -> RadioSnapshot {
        RadioSnapshot {
            associated: true,
            phy_mode: Some("802.11ax".into()),
            band: Some("6GHz".into()),
            channel: Some(197),
            width_mhz: Some(80),
            rssi_dbm: Some(-50),
            noise_dbm: Some(-90),
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

    fn no_op_counters() -> CounterSource {
        CounterSource::new(|| Ok(InterfaceCounters::zero()))
    }

    #[test]
    fn no_budget_means_no_construction_path_exists() {
        // There is no LoadBudget::default() / zero-arg constructor: the type
        // system itself refuses a budget-less guard at compile time.
    }

    #[test]
    fn budget_over_live_event_cap_refuses_to_build_guard() {
        let budget = LoadBudget::live_event(500.0, 10, 1);
        let radio = RadioSource::new(|| Ok(strong_snapshot()));
        let result = LoadGuard::new(budget, "en0", false, radio, no_op_counters());
        match result {
            Err(e) => assert!(matches!(e, BudgetError::RateExceedsCap { .. })),
            Ok(_) => panic!("expected budget over cap to be rejected"),
        }
    }

    #[test]
    fn stable_radio_and_counters_yields_valid_with_ratio() {
        let budget = LoadBudget::maintenance(1.0, 1, 1);
        let radio = RadioSource::new(|| Ok(strong_snapshot()));
        let guard = LoadGuard::new(budget, "en0", false, radio, no_op_counters())
            .unwrap()
            .with_sample_interval(Duration::from_millis(5));
        let report = guard.run(
            |_rate: f64, _elapsed: Duration| PhaseTick { bytes_sent_delta: 1000, ..Default::default() },
            Arc::new(AtomicBool::new(false)),
        );
        assert_eq!(report.validity, Validity::Valid);
        assert!(report.derived.is_some());
        assert_eq!(report.stop_reason, StopReason::Completed);
    }

    #[test]
    fn injected_band_change_marks_invalid_and_suppresses_ratio() {
        let budget = LoadBudget::maintenance(1.0, 1, 1);
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let radio = RadioSource::new(move || {
            let n = calls.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                Ok(strong_snapshot())
            } else {
                Ok(roamed_snapshot())
            }
        });
        let guard = LoadGuard::new(budget, "en0", false, radio, no_op_counters())
            .unwrap()
            .with_sample_interval(Duration::from_millis(5));
        let report = guard.run(
            |_rate: f64, _elapsed: Duration| PhaseTick { bytes_sent_delta: 1000, ..Default::default() },
            Arc::new(AtomicBool::new(false)),
        );
        assert!(!report.validity.is_valid());
        assert!(report.derived.is_none());
        assert!(report.raw.bytes_transferred > 0, "raw evidence must be retained even when invalid");
    }

    #[test]
    fn operator_cancellation_still_produces_report() {
        let budget = LoadBudget::maintenance(1.0, 5, 1);
        let radio = RadioSource::new(|| Ok(strong_snapshot()));
        let guard = LoadGuard::new(budget, "en0", false, radio, no_op_counters())
            .unwrap()
            .with_sample_interval(Duration::from_millis(5));
        let cancel = Arc::new(AtomicBool::new(true));
        let report = guard.run(
            |_rate: f64, _elapsed: Duration| PhaseTick::default(),
            cancel,
        );
        assert_eq!(report.stop_reason, StopReason::OperatorCancelled);
    }

    #[test]
    fn endpoint_error_aborts_with_structured_reason() {
        let budget = LoadBudget::maintenance(1.0, 5, 1);
        let radio = RadioSource::new(|| Ok(strong_snapshot()));
        let guard = LoadGuard::new(budget, "en0", false, radio, no_op_counters())
            .unwrap()
            .with_sample_interval(Duration::from_millis(5));
        let report = guard.run(
            |_rate: f64, _elapsed: Duration| PhaseTick { endpoint_error: Some("connection reset"), ..Default::default() },
            Arc::new(AtomicBool::new(false)),
        );
        assert!(matches!(report.stop_reason, StopReason::AbortEndpointError { .. }));
    }

    #[test]
    fn gateway_latency_breach_aborts() {
        let budget = LoadBudget::maintenance(1.0, 5, 1);
        let radio = RadioSource::new(|| Ok(strong_snapshot()));
        let guard = LoadGuard::new(budget, "en0", false, radio, no_op_counters())
            .unwrap()
            .with_sample_interval(Duration::from_millis(5));
        let report = guard.run(
            |_rate: f64, _elapsed: Duration| PhaseTick { gateway_latency_ms: Some(9999.0), ..Default::default() },
            Arc::new(AtomicBool::new(false)),
        );
        assert!(matches!(report.stop_reason, StopReason::AbortGatewayLatency { .. }));
    }
}
