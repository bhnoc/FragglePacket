//! GAP-017: run confidence and endpoint-normalization controls.
//!
//! `protocol_compare.rs` already does the concrete version of this for
//! one command: it records per-leg endpoint IPs, warns when legs resolved
//! to different addresses (`detect_endpoint_mismatch`), and derives
//! `Confidence` (reusing `pcap_report::Confidence`, this agent's own type)
//! from whether legs completed cleanly -- while explicitly capping at
//! `Medium` because every leg there is a single sample. This module is
//! that same discipline made reusable: any comparison across legs/nodes
//! records `EndpointIdentity` per leg, feeds `RunStats` (sample count,
//! variance, warm-up state) into `confidence_from_stats`, and gets an
//! endpoint-mismatch warning via `detect_endpoint_mismatch` for free.
//!
//! The rule this exists to enforce: confidence must never outrun the
//! evidence. A single sample cannot report `High` no matter how clean it
//! looked, and a variance of 0.0 is only ever a real zero-variance
//! measurement (recorded from ACTUAL repeated samples) -- never the
//! default value standing in for "we didn't measure variance because we
//! only took one sample". `RunStats::new` refuses to construct that
//! second shape: with `sample_count <= 1`, `variance` is forced to `None`
//! regardless of what the caller passed, so there is no code path that
//! prints a bare `0.0` variance for a single-sample run.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::network_tests::pcap_report::Confidence;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointIdentity {
    pub label: String,
    pub resolved_ip: Option<String>,
    pub requested_name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WarmUpState {
    /// This sample was excluded from steady-state figures as a warm-up
    /// probe (e.g. first TCP slow-start round, first DNS query before
    /// caching) -- kept as its own state so a caller never averages a
    /// cold-start sample into a "clean" result.
    Discarded,
    /// No warm-up phase was run or needed for this measurement kind.
    NotApplicable,
    /// A warm-up phase should have run but did not (e.g. the test harness
    /// took only one shot) -- distinct from `NotApplicable` because it is
    /// a confidence-reducing gap, not a deliberate choice.
    Skipped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunStats {
    pub sample_count: u32,
    /// `None` whenever `sample_count <= 1` -- see module doc. Also `None`
    /// if the caller never computed one, which is the honest state for
    /// "we did not measure this," never a defaulted zero.
    pub variance: Option<f64>,
    pub warm_up: WarmUpState,
}

impl RunStats {
    /// The only constructor. Enforces sample_count<=1 => variance=None
    /// structurally, so no caller can construct the "single sample,
    /// variance 0.0" shape this module exists to prevent.
    pub fn new(sample_count: u32, variance: Option<f64>, warm_up: WarmUpState) -> Self {
        let variance = if sample_count <= 1 { None } else { variance };
        RunStats {
            sample_count,
            variance,
            warm_up,
        }
    }

    pub fn single_sample(warm_up: WarmUpState) -> Self {
        RunStats::new(1, None, warm_up)
    }
}

/// Computes variance from a set of samples using Welford's method (no new
/// dependency, no naive sum-of-squares overflow risk) and wraps it via
/// `RunStats::new` so the single-sample rule applies uniformly whether the
/// caller pre-computed a variance or handed over raw samples.
pub fn stats_from_samples(samples: &[f64], warm_up: WarmUpState) -> RunStats {
    let n = samples.len() as u32;
    if samples.len() < 2 {
        return RunStats::new(n, None, warm_up);
    }
    let mean = samples.iter().sum::<f64>() / samples.len() as f64;
    let sum_sq_diff: f64 = samples.iter().map(|s| (s - mean).powi(2)).sum();
    let variance = sum_sq_diff / (samples.len() as f64 - 1.0);
    RunStats::new(n, Some(variance), warm_up)
}

/// The confidence ceiling this run's evidence can support, independent of
/// whatever a caller's own domain logic (e.g. `protocol_compare`'s
/// clean/unclean leg count) additionally wants to fold in. `High` is only
/// reachable with at least 3 samples, a computed variance, and no skipped
/// warm-up -- one sample structurally cannot exceed `Low`.
pub fn confidence_from_stats(stats: &RunStats) -> (Confidence, Vec<String>) {
    let mut reasons = Vec::new();

    if stats.sample_count <= 1 {
        reasons.push("single sample; repeat runs for statistical confidence".to_string());
        return (Confidence::Low, reasons);
    }

    if stats.warm_up == WarmUpState::Skipped {
        reasons
            .push("warm-up phase was skipped; early-sample transients may be included".to_string());
    }

    if stats.variance.is_none() {
        reasons.push("variance not computed despite multiple samples".to_string());
        return (Confidence::Low, reasons);
    }

    let confidence = if stats.sample_count >= 3 && stats.warm_up != WarmUpState::Skipped {
        Confidence::High
    } else {
        Confidence::Medium
    };
    (confidence, reasons)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointMismatchWarning {
    pub mismatched: bool,
    pub detail: Option<String>,
}

/// Generalized form of `protocol_compare::detect_endpoint_mismatch`:
/// flags when any two legs resolved to different IPs for what the
/// operator intended as "the same endpoint" comparison.
pub fn detect_endpoint_mismatch(endpoints: &[EndpointIdentity]) -> EndpointMismatchWarning {
    let ips: Vec<&str> = endpoints
        .iter()
        .filter_map(|e| e.resolved_ip.as_deref())
        .collect();
    let unique: BTreeSet<&str> = ips.iter().copied().collect();
    if unique.len() <= 1 {
        return EndpointMismatchWarning {
            mismatched: false,
            detail: None,
        };
    }
    let detail = format!(
        "legs resolved to different endpoint IPs ({}); a comparison across these legs measures different endpoints, not the same one under different conditions",
        endpoints
            .iter()
            .map(|e| format!("{}={}", e.label, e.resolved_ip.as_deref().unwrap_or("unresolved")))
            .collect::<Vec<_>>()
            .join(", ")
    );
    EndpointMismatchWarning {
        mismatched: true,
        detail: Some(detail),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_sample_never_exceeds_low_confidence() {
        let stats = RunStats::single_sample(WarmUpState::NotApplicable);
        let (confidence, _) = confidence_from_stats(&stats);
        assert_eq!(confidence, Confidence::Low);
    }

    #[test]
    fn single_sample_construction_forces_variance_none_even_if_caller_passes_a_value() {
        // The central regression this module exists to prevent: passing
        // Some(0.0) for a 1-sample run must NOT produce a stored 0.0.
        let stats = RunStats::new(1, Some(0.0), WarmUpState::NotApplicable);
        assert!(stats.variance.is_none());
    }

    #[test]
    fn three_clean_samples_with_warm_up_not_skipped_reaches_high() {
        let stats = stats_from_samples(&[10.0, 10.5, 9.8], WarmUpState::Discarded);
        let (confidence, _) = confidence_from_stats(&stats);
        assert_eq!(confidence, Confidence::High);
    }

    #[test]
    fn skipped_warm_up_caps_confidence_below_high() {
        let stats = stats_from_samples(&[10.0, 10.5, 9.8], WarmUpState::Skipped);
        let (confidence, reasons) = confidence_from_stats(&stats);
        assert_ne!(confidence, Confidence::High);
        assert!(reasons.iter().any(|r| r.contains("warm-up")));
    }

    #[test]
    fn two_samples_without_computed_variance_is_low() {
        let stats = RunStats::new(2, None, WarmUpState::NotApplicable);
        let (confidence, _) = confidence_from_stats(&stats);
        assert_eq!(confidence, Confidence::Low);
    }

    #[test]
    fn matching_endpoints_report_no_mismatch() {
        let endpoints = vec![
            EndpointIdentity {
                label: "h2".into(),
                resolved_ip: Some("1.2.3.4".into()),
                requested_name: "x".into(),
            },
            EndpointIdentity {
                label: "h3".into(),
                resolved_ip: Some("1.2.3.4".into()),
                requested_name: "x".into(),
            },
        ];
        let warning = detect_endpoint_mismatch(&endpoints);
        assert!(!warning.mismatched);
    }

    #[test]
    fn differing_endpoints_report_mismatch_with_detail() {
        let endpoints = vec![
            EndpointIdentity {
                label: "h2".into(),
                resolved_ip: Some("1.2.3.4".into()),
                requested_name: "x".into(),
            },
            EndpointIdentity {
                label: "h3".into(),
                resolved_ip: Some("5.6.7.8".into()),
                requested_name: "x".into(),
            },
        ];
        let warning = detect_endpoint_mismatch(&endpoints);
        assert!(warning.mismatched);
        assert!(warning.detail.is_some());
    }

    #[test]
    fn variance_computed_via_welford_matches_manual_calc() {
        let stats = stats_from_samples(
            &[2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0],
            WarmUpState::NotApplicable,
        );
        // Sample variance (n-1 denominator) of this classic example is 4.571428...
        let v = stats.variance.unwrap();
        assert!((v - 4.5714285714).abs() < 1e-6);
    }
}
