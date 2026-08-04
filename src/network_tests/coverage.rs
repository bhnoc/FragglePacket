//! GAP-073: aggregate verdicts must be computed over what was ATTEMPTED, not
//! over what happened to answer.
//!
//! Field evidence: `kitchen-sink` collected "all successful MTU measurements"
//! and derived `pct_ok = at_1500 / measured.len()`. A target that never
//! answered contributed no entry, so it left the denominator entirely. With 18
//! of 20 targets unreachable and the 2 that answered at 1500, the run printed
//! `PASS - No MTU changes needed` at "100% of tests at 1500 MTU": a near-total
//! connectivity failure reported as a clean bill of health.
//!
//! This is the same unknown-presented-as-a-measurement failure behind GAP-009
//! (zero latency from a parse miss), GAP-019 (phantom oversize frames), and
//! GAP-031 (a clean qualification from counters that were never read). The rule
//! it locks: a probe that did not answer is missing evidence, never a silent
//! pass, and an all-skipped set must never aggregate to success.

use serde::{Deserialize, Serialize};

/// Why an attempted probe produced no value. Kept distinct from "measured a
/// bad value" so a summary can say which it was.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MissReason {
    /// The probe ran and the target did not answer.
    NoAnswer,
    /// The probe was never run: unsupported on this target/platform, or a
    /// prerequisite (name resolution, privilege, open port) was absent.
    NotAttempted,
}

/// How much of what we set out to measure we actually measured.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Coverage {
    /// Probes we set out to run. This is the denominator for every derived
    /// ratio -- never `measured`.
    pub attempted: usize,
    /// Probes that produced a usable value.
    pub measured: usize,
    /// Attempted, ran, no answer.
    pub no_answer: usize,
    /// Never attempted (unsupported or prerequisite missing).
    pub not_attempted: usize,
}

impl Coverage {
    pub fn new() -> Self {
        Coverage { attempted: 0, measured: 0, no_answer: 0, not_attempted: 0 }
    }

    pub fn record_measured(&mut self) {
        self.attempted += 1;
        self.measured += 1;
    }

    pub fn record_miss(&mut self, reason: MissReason) {
        self.attempted += 1;
        match reason {
            MissReason::NoAnswer => self.no_answer += 1,
            MissReason::NotAttempted => self.not_attempted += 1,
        }
    }

    /// Fraction of attempted probes that yielded a value. `None` when nothing
    /// was attempted -- 0/0 is not 0%, it is unknown.
    pub fn measured_fraction(&self) -> Option<f64> {
        if self.attempted == 0 {
            return None;
        }
        Some(self.measured as f64 / self.attempted as f64)
    }

    /// True when no probe produced a value. An aggregate verdict over this set
    /// is vacuous and must not read as success.
    pub fn is_vacuous(&self) -> bool {
        self.measured == 0
    }
}

impl Default for Coverage {
    fn default() -> Self {
        Self::new()
    }
}

/// Whether coverage is sufficient to stand behind an aggregate verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CoverageVerdict {
    /// Enough probes answered to support a conclusion.
    Sufficient,
    /// Some answered, but too few to generalize. A conclusion may be reported
    /// only if it is explicitly qualified by this state.
    Degraded { measured_pct: u32, required_pct: u32 },
    /// Nothing answered. No aggregate conclusion is permitted at all.
    Vacuous,
}

impl CoverageVerdict {
    /// A conclusion drawn from this coverage may be presented as a finding
    /// about the network, rather than about the run.
    pub fn supports_conclusion(&self) -> bool {
        matches!(self, CoverageVerdict::Sufficient)
    }
}

/// Default minimum fraction of attempted probes that must answer before an
/// aggregate percentage is treated as describing the network. Below this, the
/// figure describes the surviving sample, not the target population.
pub const DEFAULT_REQUIRED_COVERAGE: f64 = 0.70;

/// Classifies coverage against a required fraction.
///
/// `required` is clamped into `0.0..=1.0`; a non-finite value falls back to
/// [`DEFAULT_REQUIRED_COVERAGE`] rather than silently admitting everything.
pub fn classify_coverage(cov: &Coverage, required: f64) -> CoverageVerdict {
    let required = if required.is_finite() { required.clamp(0.0, 1.0) } else { DEFAULT_REQUIRED_COVERAGE };
    match cov.measured_fraction() {
        // Nothing attempted and nothing measured: there is no sample at all.
        None => CoverageVerdict::Vacuous,
        Some(_) if cov.is_vacuous() => CoverageVerdict::Vacuous,
        Some(f) if f + f64::EPSILON >= required => CoverageVerdict::Sufficient,
        Some(f) => CoverageVerdict::Degraded {
            measured_pct: (f * 100.0).round() as u32,
            required_pct: (required * 100.0).round() as u32,
        },
    }
}

/// One line stating what was attempted versus measured, for the artifact. A
/// consumer reading only the report must be able to tell that probes were
/// missing, so this is never omitted when coverage is imperfect.
pub fn coverage_note(cov: &Coverage) -> String {
    let mut s = format!("{} of {} characterized", cov.measured, cov.attempted);
    if cov.no_answer > 0 {
        s.push_str(&format!("; {} did not answer", cov.no_answer));
    }
    if cov.not_attempted > 0 {
        s.push_str(&format!("; {} were not attempted", cov.not_attempted));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact GAP-073 field case: 18 of 20 unreachable, the 2 that answered
    /// both at 1500. The old code computed 2/2 = 100% and printed PASS.
    #[test]
    fn unreachable_targets_stay_in_the_denominator() {
        let mut cov = Coverage::new();
        cov.record_measured();
        cov.record_measured();
        for _ in 0..18 {
            cov.record_miss(MissReason::NoAnswer);
        }
        assert_eq!(cov.attempted, 20);
        assert_eq!(cov.measured, 2);
        let f = cov.measured_fraction().expect("attempted > 0");
        assert!((f - 0.10).abs() < 1e-9, "got {f}");
        assert!(!classify_coverage(&cov, DEFAULT_REQUIRED_COVERAGE).supports_conclusion());
    }

    #[test]
    fn all_skipped_never_aggregates_to_success() {
        let mut cov = Coverage::new();
        for _ in 0..5 {
            cov.record_miss(MissReason::NoAnswer);
        }
        assert!(cov.is_vacuous());
        assert_eq!(classify_coverage(&cov, DEFAULT_REQUIRED_COVERAGE), CoverageVerdict::Vacuous);
        assert!(!classify_coverage(&cov, DEFAULT_REQUIRED_COVERAGE).supports_conclusion());
    }

    /// 0/0 is unknown, not 0%.
    #[test]
    fn nothing_attempted_is_unknown_not_zero_percent() {
        let cov = Coverage::new();
        assert_eq!(cov.measured_fraction(), None);
        assert_eq!(classify_coverage(&cov, DEFAULT_REQUIRED_COVERAGE), CoverageVerdict::Vacuous);
    }

    #[test]
    fn full_coverage_supports_a_conclusion() {
        let mut cov = Coverage::new();
        for _ in 0..10 {
            cov.record_measured();
        }
        assert_eq!(classify_coverage(&cov, DEFAULT_REQUIRED_COVERAGE), CoverageVerdict::Sufficient);
    }

    /// A required fraction of exactly the measured fraction must pass, not fail
    /// on a float comparison.
    #[test]
    fn coverage_exactly_at_the_threshold_is_sufficient() {
        let mut cov = Coverage::new();
        for _ in 0..7 {
            cov.record_measured();
        }
        for _ in 0..3 {
            cov.record_miss(MissReason::NoAnswer);
        }
        assert_eq!(classify_coverage(&cov, 0.70), CoverageVerdict::Sufficient);
    }

    #[test]
    fn degraded_coverage_reports_both_percentages() {
        let mut cov = Coverage::new();
        for _ in 0..5 {
            cov.record_measured();
        }
        for _ in 0..5 {
            cov.record_miss(MissReason::NotAttempted);
        }
        match classify_coverage(&cov, 0.90) {
            CoverageVerdict::Degraded { measured_pct, required_pct } => {
                assert_eq!(measured_pct, 50);
                assert_eq!(required_pct, 90);
            }
            other => panic!("expected Degraded, got {other:?}"),
        }
    }

    #[test]
    fn the_note_distinguishes_no_answer_from_not_attempted() {
        let mut cov = Coverage::new();
        cov.record_measured();
        cov.record_miss(MissReason::NoAnswer);
        cov.record_miss(MissReason::NotAttempted);
        let note = coverage_note(&cov);
        assert!(note.contains("1 of 3"), "{note}");
        assert!(note.contains("did not answer"), "{note}");
        assert!(note.contains("not attempted"), "{note}");
    }

    /// A non-finite requirement must not admit a vacuous set.
    #[test]
    fn a_nonsense_requirement_falls_back_to_the_default() {
        let mut cov = Coverage::new();
        cov.record_measured();
        for _ in 0..99 {
            cov.record_miss(MissReason::NoAnswer);
        }
        assert!(!classify_coverage(&cov, f64::NAN).supports_conclusion());
    }
}
