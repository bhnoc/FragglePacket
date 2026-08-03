//! GAP-045: barrier-synchronized public-listener admission validation.
//!
//! Field evidence: 21 probes started four-stream TCP tests on 21 ports in
//! the same second, right after port-open checks passed. Only 12 completed.
//! Eight never established a test connection at all; one admitted three of
//! four streams and one interval before hitting a 50-second safety timeout.
//! Completion clustered by endpoint pool (5/9 primary, 7/9 Colorado, 0/3
//! Montana) -- proof this was the *endpoint's* concurrency/capacity limit,
//! not nine broken clients. A 512 KiB repeat that simply dropped the nine
//! failing assignments had all 12 remaining complete cleanly.
//!
//! The one rule this module exists to enforce: a listener that never
//! admitted a connection, or admitted fewer streams than requested, is an
//! `AdmissionOutcome` with a reason -- never a throughput number, and never
//! zero throughput. Zero is not "no data"; it is a specific, false claim
//! that the listener returned no traffic when in fact no valid session ever
//! started.
//!
//! Reuses the GAP-039 parser (`network_tests::iperf`) for error/rate
//! extraction rather than re-parsing iperf3 JSON here. The one thing that
//! parser does not track -- how many streams `start.connected` actually
//! lists -- is read locally in `streams_established`, since that admission
//! count is this gap's own concern, not a rate-evidence question.

use std::sync::{Arc, Barrier, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::network_tests::iperf::{parse_iperf_json, IperfParseError};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenerTarget {
    pub host: String,
    pub port: u16,
    pub pool_label: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AdmissionOutcome {
    /// All requested streams connected and the session ran to a normal end.
    FullyAdmitted { streams_established: u64 },
    /// Fewer streams connected than requested -- the field's "one admitted
    /// three of four" case. Distinct from full admission and from total
    /// failure; must not be averaged into either.
    PartiallyAdmitted { streams_established: u64, streams_requested: u64 },
    /// No connection was ever established. This must never be reported as
    /// 0 Mbps -- see module doc.
    NeverAdmitted { detail: String },
    /// Hit the fanout's own safety timeout before iperf3 itself returned.
    /// Distinct from `NeverAdmitted`: the process may have been making
    /// progress (as the field case that admitted 3 streams was) and simply
    /// ran out of the safety window, vs. never connecting at all.
    SafetyTimeout { elapsed_secs: f64 },
}

impl AdmissionOutcome {
    pub fn is_admitted(&self) -> bool {
        matches!(self, AdmissionOutcome::FullyAdmitted { .. })
    }

    pub fn reason(&self) -> &'static str {
        match self {
            AdmissionOutcome::FullyAdmitted { .. } => "fully admitted",
            AdmissionOutcome::PartiallyAdmitted { .. } => "partial stream admission",
            AdmissionOutcome::NeverAdmitted { .. } => "connection never admitted",
            AdmissionOutcome::SafetyTimeout { .. } => "safety timeout before completion",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionResult {
    pub target: ListenerTarget,
    pub outcome: AdmissionOutcome,
    /// Wall-clock offset from the fanout's shared start barrier to when this
    /// session actually began sending. Large skew across a supposedly
    /// synchronized fanout means the barrier itself did not hold.
    pub start_skew_ms: i64,
    /// `Some` only for `FullyAdmitted` sessions -- see
    /// `AdmissionCohort::valid_throughput_results`.
    pub receiver_bits_per_second: Option<f64>,
}

/// A closure-driven single session: run a probe against `target`, given the
/// shared barrier and a safety timeout, and return the raw iperf3 `-J` JSON
/// text so the outcome can be classified uniformly regardless of transport.
/// Tests supply a synthetic version; a real caller shells out to iperf3.
pub trait SessionRunner {
    fn run(&self, target: &ListenerTarget, requested_streams: u64) -> Result<String, String>;
}

impl<F> SessionRunner for F
where
    F: Fn(&ListenerTarget, u64) -> Result<String, String>,
{
    fn run(&self, target: &ListenerTarget, requested_streams: u64) -> Result<String, String> {
        self(target, requested_streams)
    }
}

/// Number of entries in `start.connected`: one per TCP stream the server
/// actually accepted. Not exposed by the GAP-039 `IperfResult` (which is
/// about rate evidence, not admission counting), so read directly here.
fn streams_established(raw_json: &str) -> u64 {
    serde_json::from_str::<serde_json::Value>(raw_json)
        .ok()
        .and_then(|v| v.get("start")?.get("connected")?.as_array().map(|a| a.len() as u64))
        .unwrap_or(0)
}

pub fn classify_result(raw_json: &str, requested_streams: u64) -> AdmissionOutcome {
    let established = streams_established(raw_json);

    match parse_iperf_json(raw_json) {
        Err(IperfParseError::ServerError(detail)) => AdmissionOutcome::NeverAdmitted { detail },
        Err(e) => AdmissionOutcome::NeverAdmitted { detail: e.to_string() },
        Ok(_) if established == 0 => {
            AdmissionOutcome::NeverAdmitted { detail: "no streams reported in start.connected".to_string() }
        }
        Ok(_) if established < requested_streams => AdmissionOutcome::PartiallyAdmitted {
            streams_established: established,
            streams_requested: requested_streams,
        },
        Ok(_) => AdmissionOutcome::FullyAdmitted { streams_established: established },
    }
}

fn receiver_bps(raw_json: &str) -> Option<f64> {
    let result = parse_iperf_json(raw_json).ok()?;
    result.forward.received.map(|r| r.bits_per_second)
}

/// Runs every target through `runner` in parallel, all released from a
/// shared `Barrier` at once (the "start every probe at the exact same
/// epoch" requirement), each individually bounded by `safety_timeout` so one
/// stuck listener cannot stall the whole fanout indefinitely.
pub fn run_admission_fanout(
    targets: Vec<ListenerTarget>,
    requested_streams: u64,
    safety_timeout: Duration,
    runner: Arc<dyn SessionRunner + Send + Sync>,
) -> Vec<SessionResult> {
    let n = targets.len();
    if n == 0 {
        return Vec::new();
    }
    let barrier = Arc::new(Barrier::new(n));
    // First thread through the barrier claims 0 skew and stamps this as the
    // fanout's actual release instant; every other thread's skew is its
    // distance from that -- skew is about how synchronized the releases
    // were relative to each other, not about setup cost before the barrier.
    let release_reference: Arc<Mutex<Option<Instant>>> = Arc::new(Mutex::new(None));

    let handles: Vec<_> = targets
        .into_iter()
        .map(|target| {
            let barrier = barrier.clone();
            let runner = runner.clone();
            let release_reference = release_reference.clone();
            std::thread::spawn(move || {
                barrier.wait();
                let released_at = Instant::now();
                let start_skew_ms = {
                    let mut reference = release_reference.lock().unwrap();
                    let r = reference.get_or_insert(released_at);
                    released_at.saturating_duration_since(*r).as_millis() as i64
                };

                let (tx, rx) = std::sync::mpsc::channel();
                let target_for_thread = target.clone();
                let runner_thread = runner.clone();
                std::thread::spawn(move || {
                    let result = runner_thread.run(&target_for_thread, requested_streams);
                    let _ = tx.send(result);
                });

                let outcome_result = rx.recv_timeout(safety_timeout);
                let elapsed = released_at.elapsed();

                let (outcome, receiver_bits_per_second) = match outcome_result {
                    Ok(Ok(raw_json)) => {
                        let outcome = classify_result(&raw_json, requested_streams);
                        let bps = if outcome.is_admitted() { receiver_bps(&raw_json) } else { None };
                        (outcome, bps)
                    }
                    Ok(Err(e)) => (AdmissionOutcome::NeverAdmitted { detail: e }, None),
                    Err(_) => (
                        AdmissionOutcome::SafetyTimeout { elapsed_secs: elapsed.as_secs_f64() },
                        None,
                    ),
                };

                SessionResult { target, outcome, start_skew_ms, receiver_bits_per_second }
            })
        })
        .collect();

    handles.into_iter().filter_map(|h| h.join().ok()).collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmissionCohort {
    pub requested_streams: u64,
    pub results: Vec<SessionResult>,
    pub minimum_valid_cohort: usize,
    /// A session whose start skew exceeds this is excluded from the
    /// aggregate even if it fully admitted -- "started in the same second"
    /// is part of what this fanout is claiming to have measured, and a
    /// session that actually started materially later isn't comparable to
    /// the rest of the cohort.
    pub max_start_skew_ms: i64,
}

impl AdmissionCohort {
    pub fn fully_admitted_count(&self) -> usize {
        self.results.iter().filter(|r| self.session_is_valid(r)).count()
    }

    fn session_is_valid(&self, r: &SessionResult) -> bool {
        r.outcome.is_admitted() && r.start_skew_ms.unsigned_abs() as i64 <= self.max_start_skew_ms
    }

    /// The only throughput figures this cohort may present. Never includes a
    /// `NeverAdmitted`/`SafetyTimeout`/`PartiallyAdmitted` session, and never
    /// substitutes 0 for any of them -- they are absent from this list
    /// entirely, not present-as-zero.
    pub fn valid_throughput_results(&self) -> Vec<&SessionResult> {
        self.results.iter().filter(|r| self.session_is_valid(r)).collect()
    }

    /// `None` means the cohort verdict is blocked: too few sessions
    /// completed to support an aggregate claim, regardless of how good the
    /// completed ones look. This is the minimum-valid-cohort rule.
    pub fn aggregate_receiver_bps(&self) -> Option<f64> {
        if self.fully_admitted_count() < self.minimum_valid_cohort {
            return None;
        }
        let sum: f64 = self
            .valid_throughput_results()
            .iter()
            .filter_map(|r| r.receiver_bits_per_second)
            .sum();
        Some(sum)
    }

    pub fn excluded_with_reason(&self) -> Vec<(&ListenerTarget, &'static str)> {
        self.results
            .iter()
            .filter(|r| !self.session_is_valid(r))
            .map(|r| {
                let reason = if r.outcome.is_admitted() {
                    "start skew exceeded fanout tolerance"
                } else {
                    r.outcome.reason()
                };
                (&r.target, reason)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(port: u16, pool: &str) -> ListenerTarget {
        ListenerTarget { host: "example.test".to_string(), port, pool_label: pool.to_string() }
    }

    fn ok_json(streams: usize, bps: f64) -> String {
        let connected: Vec<_> = (0..streams).map(|i| serde_json::json!({"socket": i})).collect();
        serde_json::json!({
            "start": {"connected": connected, "version": "iperf 3.21", "test_start": {"num_streams": 4, "protocol": "TCP", "reverse": 0, "bidir": 0}},
            "end": {"sum_sent": {"bytes": 1000, "seconds": 1.0, "bits_per_second": bps}, "sum_received": {"bytes": 1000, "seconds": 1.0, "bits_per_second": bps}}
        })
        .to_string()
    }

    fn refused_json() -> String {
        serde_json::json!({
            "start": {"connected": [], "version": "iperf 3.21"},
            "end": {},
            "error": "unable to connect to server: Connection refused"
        })
        .to_string()
    }

    #[test]
    fn never_admitted_is_not_zero_throughput() {
        let outcome = classify_result(&refused_json(), 4);
        assert!(matches!(outcome, AdmissionOutcome::NeverAdmitted { .. }));
        assert!(!outcome.is_admitted());
    }

    #[test]
    fn partial_admission_detected_distinctly_from_full_and_none() {
        let outcome = classify_result(&ok_json(3, 500_000.0), 4);
        assert_eq!(
            outcome,
            AdmissionOutcome::PartiallyAdmitted { streams_established: 3, streams_requested: 4 }
        );
        assert!(!outcome.is_admitted());
    }

    #[test]
    fn full_admission_classified_correctly() {
        let outcome = classify_result(&ok_json(4, 500_000.0), 4);
        assert_eq!(outcome, AdmissionOutcome::FullyAdmitted { streams_established: 4 });
        assert!(outcome.is_admitted());
    }

    #[test]
    fn minimum_valid_cohort_blocks_aggregate_when_too_few_admitted() {
        let results = vec![
            SessionResult {
                target: target(1, "a"),
                outcome: AdmissionOutcome::FullyAdmitted { streams_established: 4 },
                start_skew_ms: 0,
                receiver_bits_per_second: Some(1_000_000.0),
            },
            SessionResult {
                target: target(2, "a"),
                outcome: AdmissionOutcome::NeverAdmitted { detail: "refused".to_string() },
                start_skew_ms: 0,
                receiver_bits_per_second: None,
            },
        ];
        let cohort = AdmissionCohort { requested_streams: 4, results, minimum_valid_cohort: 2, max_start_skew_ms: 1000 };
        assert_eq!(cohort.fully_admitted_count(), 1);
        assert_eq!(cohort.aggregate_receiver_bps(), None);
        assert_eq!(cohort.excluded_with_reason().len(), 1);
    }

    #[test]
    fn cohort_meeting_minimum_produces_aggregate_from_admitted_only() {
        let results = vec![
            SessionResult {
                target: target(1, "a"),
                outcome: AdmissionOutcome::FullyAdmitted { streams_established: 4 },
                start_skew_ms: 0,
                receiver_bits_per_second: Some(1_000_000.0),
            },
            SessionResult {
                target: target(2, "a"),
                outcome: AdmissionOutcome::FullyAdmitted { streams_established: 4 },
                start_skew_ms: 0,
                receiver_bits_per_second: Some(2_000_000.0),
            },
            SessionResult {
                target: target(3, "a"),
                outcome: AdmissionOutcome::NeverAdmitted { detail: "timeout".to_string() },
                start_skew_ms: 0,
                receiver_bits_per_second: None,
            },
        ];
        let cohort = AdmissionCohort { requested_streams: 4, results, minimum_valid_cohort: 2, max_start_skew_ms: 1000 };
        assert_eq!(cohort.aggregate_receiver_bps(), Some(3_000_000.0));
        assert_eq!(cohort.valid_throughput_results().len(), 2);
    }

    #[test]
    fn safety_timeout_excludes_without_becoming_zero() {
        let outcome = AdmissionOutcome::SafetyTimeout { elapsed_secs: 50.0 };
        assert!(!outcome.is_admitted());
        assert_eq!(outcome.reason(), "safety timeout before completion");
    }

    #[test]
    fn fanout_barrier_runs_all_targets_and_classifies_each() {
        let targets = vec![target(1, "a"), target(2, "a"), target(3, "b")];
        let runner: Arc<dyn SessionRunner + Send + Sync> = Arc::new(
            |t: &ListenerTarget, _streams: u64| -> Result<String, String> {
                if t.port == 3 {
                    Err("refused".to_string())
                } else {
                    Ok(ok_json(4, 1_000_000.0))
                }
            },
        );
        let results = run_admission_fanout(targets, 4, Duration::from_secs(5), runner);
        assert_eq!(results.len(), 3);
        let admitted = results.iter().filter(|r| r.outcome.is_admitted()).count();
        assert_eq!(admitted, 2);
    }
}
