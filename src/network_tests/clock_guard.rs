//! GAP-064: synchronized clock and one-way event-correlation guard.
//!
//! `media_quality.rs` and `burst_analysis.rs` already refuse to derive a
//! one-way delay from RTT/2, and instead take a `clock_offset_verified:
//! bool` gate -- this module is what produces that gate honestly. GAP-059
//! (`dependency_health.rs`) already measures NTP offset via `sntp` and
//! returns `offset_ms: Option<f64>`, never a defaulted 0.0 on failure;
//! this module builds the skew-gating decision on top of that measurement
//! rather than re-implementing NTP querying.
//!
//! The one discipline that matters here: an offset without its
//! uncertainty is false precision, and an offset within tolerance is not
//! itself permission to trust a one-way claim forever -- `ClockVerdict`
//! carries both the offset+bound and the pass/fail decision against a
//! caller-set (or default) skew threshold, and there is no path in this
//! module that reports `Verified` without both a nonzero-uncertainty
//! sample and a skew comparison having actually run.

use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::network_tests::dependency_health::{
    measure_ntp_offset, NtpOffsetResult, Verdict as DependencyVerdict,
};

/// Default maximum tolerated clock skew, in milliseconds, before a one-way
/// metric is refused rather than qualified. 50ms is chosen because it is
/// far larger than sane LAN/WAN NTP sync error yet far smaller than the
/// one-way delays (typically >100ms for anything queueing-related) this
/// gate exists to protect -- a skew anywhere near the metric it is meant
/// to bound would make the metric meaningless even if "passed".
pub const DEFAULT_MAX_SKEW_MS: f64 = 50.0;

/// `Instant` is intentionally not `Serialize` upstream -- it is only ever
/// meaningful relative to another `Instant` in the SAME process, so
/// exposing it as JSON would invite exactly the cross-host monotonic
/// comparison this module forbids. `monotonic_nanos_since_process_start`
/// is a process-local counter safe to serialize for display/debugging; any
/// in-process comparison logic uses the real `Instant` value below.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct DualTimestamp {
    /// Wall-clock time, which can jump (NTP step, sleep/wake) but is
    /// comparable across hosts once clock offset is known.
    pub wall_clock_unix_ms: u128,
    /// Monotonic time, which cannot jump but is only meaningful on the
    /// SAME host -- never compared directly across two machines.
    pub monotonic_nanos_since_process_start: u128,
    #[serde(skip)]
    pub monotonic: Option<Instant>,
}

impl DualTimestamp {
    pub fn now() -> Self {
        static PROCESS_START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
        let start = *PROCESS_START.get_or_init(Instant::now);
        let now = Instant::now();
        DualTimestamp {
            wall_clock_unix_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
                .as_millis(),
            monotonic_nanos_since_process_start: now.saturating_duration_since(start).as_nanos(),
            monotonic: Some(now),
        }
    }
}

/// One offset measurement with its uncertainty. Never constructed with a
/// bare 0.0 uncertainty from a failed query -- see `ClockVerdict::measure`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct OffsetWithBound {
    pub offset_ms: f64,
    /// Half-width of the reported confidence interval, in milliseconds
    /// (sntp's `+/-` round-trip-delay-derived bound). This is always
    /// present alongside `offset_ms` -- there is no field or accessor in
    /// this module that exposes an offset without it.
    pub uncertainty_ms: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SkewOutcome {
    /// Measured |offset| + uncertainty stayed within the configured
    /// threshold -- a one-way claim MAY proceed.
    WithinTolerance,
    /// Measured skew (or its uncertainty-inflated bound) exceeded the
    /// threshold -- a one-way claim is refused, not adjusted for the
    /// measured offset. Correcting for an imprecisely measured offset
    /// only moves the error, it does not remove it.
    ExceedsTolerance,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClockVerdict {
    pub node_label: String,
    pub ntp_server: String,
    /// `None` whenever the underlying NTP query failed for any reason --
    /// the same never-default-to-zero rule GAP-059 already enforces.
    pub offset: Option<OffsetWithBound>,
    pub max_skew_ms: f64,
    pub outcome: SkewOutcome,
    pub timestamp: DualTimestamp,
    pub explanation: String,
}

impl ClockVerdict {
    /// The single question a one-way-delay caller needs answered.
    pub fn permits_one_way_claim(&self) -> bool {
        self.offset.is_some() && self.outcome == SkewOutcome::WithinTolerance
    }
}

/// Measures NTP offset against `ntp_server` (reusing GAP-059's `sntp`
/// wrapper) and gates it against `max_skew_ms`. This is the function
/// `media-quality`/`burst-analysis` should call before setting their
/// `clock_offset_verified: bool` input:
/// `clock_guard::verify(node_label, ntp_server, max_skew_ms, timeout).permits_one_way_claim()`.
pub fn verify(
    node_label: &str,
    ntp_server: &str,
    max_skew_ms: f64,
    timeout: Duration,
) -> ClockVerdict {
    let ntp_result = measure_ntp_offset(ntp_server, timeout);
    from_ntp_result(node_label, max_skew_ms, ntp_result)
}

/// Pure decision logic, factored out of `verify` so the skew-gating
/// behavior is testable without shelling out to `sntp`.
fn from_ntp_result(
    node_label: &str,
    max_skew_ms: f64,
    ntp_result: NtpOffsetResult,
) -> ClockVerdict {
    let timestamp = DualTimestamp::now();

    let offset = match (ntp_result.offset_ms, ntp_result.round_trip_delay_ms) {
        (Some(offset_ms), Some(delay_ms)) => Some(OffsetWithBound {
            offset_ms,
            uncertainty_ms: delay_ms,
        }),
        _ => None,
    };

    let (outcome, explanation) = match &offset {
        None => (
            SkewOutcome::ExceedsTolerance,
            format!(
                "NTP query to {} did not produce a usable offset ({:?}); a one-way claim cannot be gated by an unmeasured skew, so it is refused",
                ntp_result.server,
                match ntp_result.verdict {
                    DependencyVerdict::BlockedByPolicy { .. } => "blocked by policy",
                    DependencyVerdict::Unhealthy { .. } => "unhealthy/unreachable",
                    _ => "no result",
                }
            ),
        ),
        Some(o) => {
            let bound = o.offset_ms.abs() + o.uncertainty_ms;
            if bound <= max_skew_ms {
                (
                    SkewOutcome::WithinTolerance,
                    format!(
                        "offset {:.3}ms +/- {:.3}ms against {} is within the {:.1}ms configured skew threshold",
                        o.offset_ms, o.uncertainty_ms, ntp_result.server, max_skew_ms
                    ),
                )
            } else {
                (
                    SkewOutcome::ExceedsTolerance,
                    format!(
                        "offset {:.3}ms +/- {:.3}ms against {} exceeds the {:.1}ms configured skew threshold; refusing the one-way claim rather than correcting for an imprecisely measured offset",
                        o.offset_ms, o.uncertainty_ms, ntp_result.server, max_skew_ms
                    ),
                )
            }
        }
    };

    ClockVerdict {
        node_label: node_label.to_string(),
        ntp_server: ntp_result.server.clone(),
        offset,
        max_skew_ms,
        outcome,
        timestamp,
        explanation,
    }
}

/// One event from a client, server, or infrastructure source, carried with
/// both timestamp kinds and (if the event's own node has one) a clock
/// verdict. Correlating events across nodes requires either the same node
/// (monotonic is valid) or a `ClockVerdict::permits_one_way_claim()` on
/// both nodes (wall-clock + offset makes cross-node ordering meaningful).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelatedEvent {
    pub source_label: String,
    pub description: String,
    pub timestamp: DualTimestamp,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum CorrelationConfidence {
    /// Both events came from the same node (monotonic ordering is exact).
    SameNodeMonotonic,
    /// Events came from different nodes, both with `permits_one_way_claim`
    /// clock verdicts -- ordering is trustworthy within the combined
    /// uncertainty bound.
    CrossNodeVerified { combined_uncertainty_ms: f64 },
    /// Events came from different nodes and at least one lacks a
    /// verified-within-tolerance clock offset -- ordering across them is
    /// not asserted.
    CrossNodeUnverified,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergedEvents {
    pub events: Vec<CorrelatedEvent>,
    pub confidence: CorrelationConfidence,
}

/// Merges events from up to two distinct nodes. `verdict_a`/`verdict_b`
/// are `None` when the corresponding events all came from ONE node
/// (monotonic-only correlation, no cross-node clock claim needed).
pub fn merge_events(
    events_a: Vec<CorrelatedEvent>,
    events_b: Vec<CorrelatedEvent>,
    verdict_a: Option<&ClockVerdict>,
    verdict_b: Option<&ClockVerdict>,
) -> MergedEvents {
    let mut events = events_a;
    events.extend(events_b);

    let confidence = if verdict_a.is_none() && verdict_b.is_none() {
        CorrelationConfidence::SameNodeMonotonic
    } else {
        match (verdict_a, verdict_b) {
            (Some(a), Some(b)) if a.permits_one_way_claim() && b.permits_one_way_claim() => {
                let ua = a.offset.map(|o| o.uncertainty_ms).unwrap_or(f64::INFINITY);
                let ub = b.offset.map(|o| o.uncertainty_ms).unwrap_or(f64::INFINITY);
                CorrelationConfidence::CrossNodeVerified {
                    combined_uncertainty_ms: ua + ub,
                }
            }
            _ => CorrelationConfidence::CrossNodeUnverified,
        }
    };

    MergedEvents { events, confidence }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network_tests::dependency_health::DetailKind;

    fn ok_ntp(offset_ms: f64, delay_ms: f64) -> NtpOffsetResult {
        NtpOffsetResult {
            server: "time.example.test".to_string(),
            offset_ms: Some(offset_ms),
            round_trip_delay_ms: Some(delay_ms),
            verdict: DependencyVerdict::Healthy,
        }
    }

    fn failed_ntp() -> NtpOffsetResult {
        NtpOffsetResult {
            server: "time.example.test".to_string(),
            offset_ms: None,
            round_trip_delay_ms: None,
            verdict: DependencyVerdict::Unhealthy {
                detail_kind: DetailKind::TimedOut,
            },
        }
    }

    #[test]
    fn within_tolerance_permits_one_way_claim() {
        let verdict = from_ntp_result("node-a", 50.0, ok_ntp(10.0, 5.0));
        assert_eq!(verdict.outcome, SkewOutcome::WithinTolerance);
        assert!(verdict.permits_one_way_claim());
    }

    #[test]
    fn exceeds_tolerance_refuses_one_way_claim_and_names_skew() {
        let verdict = from_ntp_result("node-a", 50.0, ok_ntp(80.0, 5.0));
        assert_eq!(verdict.outcome, SkewOutcome::ExceedsTolerance);
        assert!(!verdict.permits_one_way_claim());
        assert!(verdict.explanation.contains("80"));
        assert!(verdict.explanation.contains("50"));
    }

    #[test]
    fn uncertainty_inflates_the_bound_past_tolerance() {
        // offset alone (45ms) is under the 50ms threshold, but its
        // uncertainty (10ms) pushes the bound to 55ms -- must refuse.
        let verdict = from_ntp_result("node-a", 50.0, ok_ntp(45.0, 10.0));
        assert_eq!(verdict.outcome, SkewOutcome::ExceedsTolerance);
    }

    #[test]
    fn failed_ntp_query_never_defaults_to_zero_offset() {
        let verdict = from_ntp_result("node-a", 50.0, failed_ntp());
        assert!(verdict.offset.is_none());
        assert_eq!(verdict.outcome, SkewOutcome::ExceedsTolerance);
        assert!(!verdict.permits_one_way_claim());
    }

    #[test]
    fn offset_is_never_reported_without_its_uncertainty() {
        let verdict = from_ntp_result("node-a", 50.0, ok_ntp(10.0, 3.0));
        let offset = verdict.offset.expect("offset must be present");
        assert_eq!(offset.uncertainty_ms, 3.0);
    }

    #[test]
    fn both_timestamp_kinds_are_always_present() {
        let ts = DualTimestamp::now();
        assert!(ts.wall_clock_unix_ms > 0);
        assert!(ts.monotonic.is_some());
    }

    #[test]
    fn same_node_events_correlate_monotonically_without_a_clock_verdict() {
        let events_a = vec![CorrelatedEvent {
            source_label: "client".to_string(),
            description: "send".to_string(),
            timestamp: DualTimestamp::now(),
        }];
        let merged = merge_events(events_a, vec![], None, None);
        assert_eq!(merged.confidence, CorrelationConfidence::SameNodeMonotonic);
    }

    #[test]
    fn cross_node_merge_without_verified_clocks_is_unverified() {
        let a = vec![CorrelatedEvent {
            source_label: "client".to_string(),
            description: "send".to_string(),
            timestamp: DualTimestamp::now(),
        }];
        let b = vec![CorrelatedEvent {
            source_label: "server".to_string(),
            description: "recv".to_string(),
            timestamp: DualTimestamp::now(),
        }];
        let bad_verdict = from_ntp_result("server", 50.0, failed_ntp());
        let merged = merge_events(a, b, None, Some(&bad_verdict));
        assert_eq!(
            merged.confidence,
            CorrelationConfidence::CrossNodeUnverified
        );
    }

    #[test]
    fn cross_node_merge_with_both_verified_reports_combined_uncertainty() {
        let a = vec![CorrelatedEvent {
            source_label: "client".to_string(),
            description: "send".to_string(),
            timestamp: DualTimestamp::now(),
        }];
        let b = vec![CorrelatedEvent {
            source_label: "server".to_string(),
            description: "recv".to_string(),
            timestamp: DualTimestamp::now(),
        }];
        let va = from_ntp_result("client", 50.0, ok_ntp(5.0, 3.0));
        let vb = from_ntp_result("server", 50.0, ok_ntp(-4.0, 2.0));
        let merged = merge_events(a, b, Some(&va), Some(&vb));
        match merged.confidence {
            CorrelationConfidence::CrossNodeVerified {
                combined_uncertainty_ms,
            } => {
                assert!((combined_uncertainty_ms - 5.0).abs() < 1e-9);
            }
            other => panic!("expected CrossNodeVerified, got {:?}", other),
        }
    }
}
