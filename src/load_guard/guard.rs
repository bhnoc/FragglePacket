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
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// A "completed" phase whose measured wall time overshoots its budgeted
/// duration by more than this factor cannot be trusted as having run at the
/// intended rate for the intended time.
const DURATION_OVERRUN_TOLERANCE: f64 = 1.25;
/// A "completed" phase that moved less than this fraction of its target byte
/// volume did not present the configured load, regardless of why.
const MIN_TARGET_FRACTION: f64 = 0.10;

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
    /// The phase reported normal completion but took materially longer than
    /// the budgeted `max_duration_secs`. A "completed" run whose own clock
    /// cannot be trusted must not produce a ratio.
    PhaseDurationExceeded,
    /// The phase reported normal completion but moved far less than its
    /// target byte volume. Whatever the cause (generator stall, real
    /// collapse, or something else), the guard cannot attest that the
    /// configured load was actually presented, so no derived ratio may be
    /// read off it — same failure shape as a roam invalidating a run.
    PhaseTargetUndershoot,
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
            InvalidReason::PhaseDurationExceeded => "phase ran materially longer than the requested duration",
            InvalidReason::PhaseTargetUndershoot => "phase moved far less than its target byte volume",
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
    /// `"synthetic"` when the radio source was fabricated (harness
    /// `--fake-radio`/`--inject-*`), `"live"` otherwise. A caller reading
    /// only this artifact -- no access to the command line that produced it
    /// -- must be able to tell a faked run from a real measurement.
    pub radio_source: &'static str,
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

#[derive(Clone)]
pub struct RadioSource {
    inner: Arc<dyn Fn() -> Result<RadioSnapshot, String> + Send + Sync>,
}

impl RadioSource {
    pub fn new(f: impl Fn() -> Result<RadioSnapshot, String> + Send + Sync + 'static) -> Self {
        Self { inner: Arc::new(f) }
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
    /// Full-detail source (RSSI/noise/PHY/MCS) for the pre/post snapshots.
    /// On macOS this is `system_profiler`, costing several seconds per call —
    /// paid exactly twice per run, never inside the phase loop.
    radio: RadioSource,
    /// Cheap source polled repeatedly during the phase for roam/band-change
    /// detection. Defaults to `radio` if no faster source is supplied (e.g.
    /// in tests), so behavior is correct even without a fast path — just not
    /// fast. On macOS the CLI supplies `radio::snapshot_fast` (`ioreg`, ~30ms)
    /// here, which cannot report RSSI/noise/MCS but is 200+x cheaper and
    /// sufficient for the in-phase signal this guard actually needs.
    radio_fast: RadioSource,
    counters: CounterSource,
    sample_interval: Duration,
    radio_sample_interval: Duration,
    /// Set by the caller when `radio`/`radio_fast` are fabricated (harness
    /// `--fake-radio`/`--inject-*` flags) rather than sampled from real
    /// hardware. Carried into every `GuardReport` so a saved artifact
    /// declares its own provenance and can never be mistaken for a real
    /// measurement -- the same failure shape as reporting an unmeasurable
    /// value as zero, just for "is this real" instead of "what is the value".
    radio_source_is_synthetic: bool,
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
            radio_fast: radio.clone(),
            radio,
            counters,
            sample_interval: Duration::from_millis(200),
            // In-phase polling cadence for the (cheap) fast radio source.
            radio_sample_interval: Duration::from_millis(500),
            radio_source_is_synthetic: false,
        })
    }

    /// Marks the radio source(s) as fabricated rather than sampled from real
    /// hardware. The CLI calls this whenever `--fake-radio` or any
    /// `--inject-*` flag is passed, so every artifact from that run declares
    /// its own provenance instead of looking identical to a real measurement.
    pub fn with_synthetic_radio_marker(mut self, is_synthetic: bool) -> Self {
        self.radio_source_is_synthetic = is_synthetic;
        self
    }

    /// Supplies a cheap radio source for in-phase polling, distinct from the
    /// full-detail source used for the pre/post snapshots. See the `radio_fast`
    /// field doc for why this split exists.
    pub fn with_fast_radio_source(mut self, radio_fast: RadioSource) -> Self {
        self.radio_fast = radio_fast;
        self
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
    ///
    /// Radio sampling runs on its own background thread rather than inline in
    /// the tick loop: a real `system_profiler` call can take several seconds,
    /// and calling it synchronously inside the phase loop was stealing wall
    /// time from the budgeted duration — a 2s-budget request was measured
    /// taking 17s because each in-loop radio sample blocked the phase. The
    /// background thread samples on its own cadence and the phase loop only
    /// ever reads the latest snapshot a `Mutex` away, never blocking on it.
    pub fn run(&self, mut phase: impl LoadPhase, cancel: Arc<AtomicBool>) -> GuardReport {
        let before_radio = self.radio.sample();
        let counters_before = self.counters.sample();

        let during_radio: Arc<Mutex<Vec<RadioSnapshot>>> = Arc::new(Mutex::new(Vec::new()));
        let radio_thread_stop = Arc::new(AtomicBool::new(false));
        // In-phase polling uses the cheap fast source (ioreg on macOS, ~30ms)
        // rather than the full-detail source (system_profiler, ~8s) used for
        // before/after — see the `radio_fast` field doc.
        let radio_source = self.radio_fast.clone();
        let radio_interval = self.radio_sample_interval;
        let during_radio_writer = during_radio.clone();
        let radio_thread_stop_reader = radio_thread_stop.clone();
        let radio_thread = std::thread::spawn(move || {
            while !radio_thread_stop_reader.load(Ordering::SeqCst) {
                std::thread::sleep(radio_interval);
                if radio_thread_stop_reader.load(Ordering::SeqCst) {
                    break;
                }
                let snap = radio_source.sample();
                during_radio_writer.lock().unwrap().push(snap);
            }
        });

        let mut bytes_transferred: u64 = 0;
        let mut stop_reason = StopReason::Completed;
        let target_bytes = (self.budget.target_rate_mbps * 1_000_000.0 / 8.0
            * self.budget.max_duration_secs as f64) as u64;

        let schedule = self.budget.ramp_schedule();
        let step_duration = Duration::from_secs(self.budget.max_duration_secs.max(1))
            / schedule.len().max(1) as u32;
        let start = Instant::now();

        'ramp: for rate in schedule {
            let step_start = Instant::now();
            while step_start.elapsed() < step_duration {
                if cancel.load(Ordering::SeqCst) {
                    stop_reason = StopReason::OperatorCancelled;
                    break 'ramp;
                }

                let tick = phase.tick(rate, start.elapsed());
                bytes_transferred += tick.bytes_sent_delta;

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

                {
                    let guard = during_radio.lock().unwrap();
                    if let Some(latest) = guard.last() {
                        if latest.association_fingerprint() != before_radio.association_fingerprint() {
                            stop_reason = StopReason::AbortAssociationChange;
                            break 'ramp;
                        }
                    }
                }

                // Sleep only for however much of the step actually remains,
                // not a flat `sample_interval`. Capping to `step_duration`
                // alone still let each iteration overshoot the step boundary
                // by up to a full `sample_interval` when the interval didn't
                // divide the step evenly — compounded across every ramp step,
                // a short budget could overrun materially even in a
                // perfectly healthy run, which is exactly the false-positive
                // this guard exists to prevent, just self-inflicted.
                let remaining = step_duration.saturating_sub(step_start.elapsed());
                if remaining.is_zero() {
                    break;
                }
                std::thread::sleep(self.sample_interval.min(remaining));
            }
        }

        // Captured the instant the phase loop itself ends, before the
        // (multi-second, on macOS) post-phase radio/counter snapshots run —
        // those measure the guard's own bookkeeping overhead, not the phase,
        // and must not count against the requested duration.
        let elapsed_secs = start.elapsed().as_secs_f64();

        radio_thread_stop.store(true, Ordering::SeqCst);
        let _ = radio_thread.join();

        let after_radio = self.radio.sample();
        let counters_after = self.counters.sample();
        let counters_usable = counters_after.usable_delta_from(&counters_before);

        let timeline = RadioTimeline {
            before: before_radio.clone(),
            during: Arc::try_unwrap(during_radio)
                .map(|m| m.into_inner().unwrap())
                .unwrap_or_default(),
            after: after_radio,
        };

        let budgeted_secs = self.budget.max_duration_secs as f64;
        let duration_exceeded =
            budgeted_secs > 0.0 && elapsed_secs > budgeted_secs * DURATION_OVERRUN_TOLERANCE;
        // Only judge a phase against its own budget when it actually ran to
        // completion under that budget. A run that stopped early for an
        // abort reason (loss, latency, roam, cancellation) already carries
        // that specific StopReason and is correctly short on bytes/time as a
        // consequence — it should not be relabeled as a duration/undershoot
        // defect on top of that.
        let ran_to_completion = matches!(stop_reason, StopReason::Completed);
        let target_undershoot = ran_to_completion
            && target_bytes > 0
            && (bytes_transferred as f64) < (target_bytes as f64) * MIN_TARGET_FRACTION;
        let duration_exceeded = ran_to_completion && duration_exceeded;

        let validity = if !before_radio.associated || !timeline.after.associated {
            Validity::Invalid(InvalidReason::RadioUnavailable)
        } else if timeline.roamed() {
            Validity::Invalid(InvalidReason::Roamed)
        } else if timeline.band_changed() {
            Validity::Invalid(InvalidReason::BandChanged)
        } else if !counters_usable {
            Validity::Invalid(InvalidReason::CountersUnusable)
        } else if duration_exceeded {
            Validity::Invalid(InvalidReason::PhaseDurationExceeded)
        } else if target_undershoot {
            Validity::Invalid(InvalidReason::PhaseTargetUndershoot)
        } else {
            match timeline.weakest_rf() {
                RfQuality::Weak => Validity::Invalid(InvalidReason::WeakRf),
                RfQuality::Unstable => Validity::Invalid(InvalidReason::UnstableRf),
                _ => Validity::Valid,
            }
        };

        let raw = RawMetrics {
            bytes_transferred,
            elapsed_secs,
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
            radio_source: if self.radio_source_is_synthetic { "synthetic" } else { "live" },
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

    #[test]
    fn phase_that_undershoots_target_is_invalid_with_no_ratio() {
        let budget = LoadBudget::maintenance(1000.0, 5, 1);
        let radio = RadioSource::new(|| Ok(strong_snapshot()));
        let guard = LoadGuard::new(budget, "en0", false, radio, no_op_counters())
            .unwrap()
            .with_sample_interval(Duration::from_millis(5));
        // Completes normally but only ever sends a trickle relative to the
        // 1000 Mbps / 5s target — this is the "0.82% of target" shape from
        // the field report, not an abort.
        let report = guard.run(
            |_rate: f64, _elapsed: Duration| PhaseTick { bytes_sent_delta: 1, ..Default::default() },
            Arc::new(AtomicBool::new(false)),
        );
        assert_eq!(report.stop_reason, StopReason::Completed);
        assert_eq!(
            report.validity,
            Validity::Invalid(InvalidReason::PhaseTargetUndershoot)
        );
        assert!(report.derived.is_none());
        assert!(report.raw.bytes_transferred > 0, "raw evidence retained even when invalid");
    }

    #[test]
    fn phase_that_overruns_duration_is_invalid_with_no_ratio() {
        let budget = LoadBudget::maintenance(1.0, 1, 1);
        let radio = RadioSource::new(|| Ok(strong_snapshot()));
        let guard = LoadGuard::new(budget, "en0", false, radio, no_op_counters())
            .unwrap()
            .with_sample_interval(Duration::from_millis(5));
        // The injected phase itself blocks well past the 1s budget on every
        // tick. Unlike the guard's own bookkeeping sleep (which is capped to
        // the remaining step duration), time spent inside the caller's phase
        // callback is not something the guard can throttle — this is the
        // realistic shape of "a blocking send made the phase run long."
        let report = guard.run(
            |_rate: f64, _elapsed: Duration| {
                std::thread::sleep(Duration::from_millis(1500));
                PhaseTick { bytes_sent_delta: 1_000_000, ..Default::default() }
            },
            Arc::new(AtomicBool::new(false)),
        );
        assert_eq!(report.stop_reason, StopReason::Completed);
        assert_eq!(
            report.validity,
            Validity::Invalid(InvalidReason::PhaseDurationExceeded)
        );
        assert!(report.derived.is_none());
    }

    #[test]
    fn aborted_run_is_not_relabeled_as_undershoot() {
        // An abort (endpoint error here) legitimately produces few bytes and
        // short elapsed time; that must surface as the abort's own StopReason
        // / validity path, not get double-labeled as a duration/undershoot
        // defect on top of it.
        let budget = LoadBudget::maintenance(1000.0, 5, 1);
        let radio = RadioSource::new(|| Ok(strong_snapshot()));
        let guard = LoadGuard::new(budget, "en0", false, radio, no_op_counters())
            .unwrap()
            .with_sample_interval(Duration::from_millis(5));
        let report = guard.run(
            |_rate: f64, _elapsed: Duration| PhaseTick { endpoint_error: Some("reset"), ..Default::default() },
            Arc::new(AtomicBool::new(false)),
        );
        assert!(matches!(report.stop_reason, StopReason::AbortEndpointError { .. }));
        assert_ne!(
            report.validity,
            Validity::Invalid(InvalidReason::PhaseTargetUndershoot)
        );
    }
}
