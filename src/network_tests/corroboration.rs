//! GAP-074: when two independent sources describe the same property and
//! disagree, the disagreement is the finding.
//!
//! Commands that hold both an actively measured value and an operator-supplied
//! one for the same property used to pick whichever was present and continue.
//! `wired_edge.rs` and `ap_compat_matrix.rs` ingest operator telemetry as
//! vendor-neutral fields, and `probe`/`mss-evidence` measure comparable
//! properties directly, but nothing compared the two.
//!
//! A switch reporting a 1 Gb link while the client measures 5 Gb, or an
//! operator-declared MTU 9000 against a probed 1500, is the single most
//! diagnostic observation available: exactly one of those two sources is wrong
//! about this network, and which one is wrong changes the remediation entirely.
//! Silently preferring either discards that.
//!
//! The model borrows NOC's bilateral-confirmation rule for topology links: it
//! will not assert a link that one side denies, recording a pending state
//! instead of guessing. The analogue here is that a contested property yields
//! `Contradicted` and blocks any figure derived from it, rather than resolving
//! to a winner.

use serde::{Deserialize, Serialize};

/// Where a value came from. Provenance is carried alongside every compared
/// value so a contradiction can name both sides.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Provenance {
    /// This host measured it directly (probe, capture, syscall).
    Measured,
    /// An operator supplied it (switch/AP telemetry, manifest, CLI flag).
    OperatorSupplied,
    /// A peer or remote node reported it about itself.
    PeerReported,
}

impl Provenance {
    pub fn label(&self) -> &'static str {
        match self {
            Provenance::Measured => "measured here",
            Provenance::OperatorSupplied => "operator-supplied",
            Provenance::PeerReported => "peer-reported",
        }
    }
}

/// One source's claim about a property.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Claim {
    pub value: f64,
    pub provenance: Provenance,
}

impl Claim {
    pub fn new(value: f64, provenance: Provenance) -> Self {
        Claim { value, provenance }
    }
}

/// Result of comparing two sources for one property.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Corroboration {
    /// Both sources present and within tolerance. The strongest evidence this
    /// tool can produce for a single property.
    Corroborated { value: f64, sources: usize },
    /// Exactly one source present. Usable, but not cross-checked -- and it must
    /// never be presented as though it had been.
    Uncorroborated { value: f64, provenance: Provenance },
    /// Both sources present and outside tolerance. This is a finding in its own
    /// right; any figure derived from the property must be withheld.
    Contradicted { a: Claim, b: Claim, relative_difference: f64 },
    /// Neither source produced a value. Distinct from `Contradicted`: there is
    /// nothing to disagree about, and distinct from a zero value.
    Unknown,
}

impl Corroboration {
    /// The agreed value, if the property is settled enough to use. Returns
    /// `None` for `Contradicted` and `Unknown` -- a contested property has no
    /// usable value by definition, which is what stops a derived figure from
    /// silently inheriting one side of the disagreement.
    pub fn usable_value(&self) -> Option<f64> {
        match self {
            Corroboration::Corroborated { value, .. } => Some(*value),
            Corroboration::Uncorroborated { value, .. } => Some(*value),
            Corroboration::Contradicted { .. } | Corroboration::Unknown => None,
        }
    }

    /// True when the sources actively disagree, as opposed to merely being
    /// absent. Callers use this to decide whether to emit a finding.
    pub fn is_contradicted(&self) -> bool {
        matches!(self, Corroboration::Contradicted { .. })
    }

    /// True when a derived figure may be computed from this property.
    pub fn supports_derived_figure(&self) -> bool {
        self.usable_value().is_some()
    }
}

/// Default tolerance for comparing two reports of the same property: 5%
/// relative. Two sources sampling at different instants, with different
/// rounding, legitimately differ slightly; a real disagreement (1 Gb vs 5 Gb,
/// MTU 1500 vs 9000) is far outside this.
pub const DEFAULT_RELATIVE_TOLERANCE: f64 = 0.05;

/// Compares two optional claims about one property.
///
/// `relative_tolerance` is a fraction of the larger magnitude. A non-finite or
/// negative tolerance falls back to [`DEFAULT_RELATIVE_TOLERANCE`] rather than
/// admitting every disagreement as agreement.
pub fn corroborate(a: Option<Claim>, b: Option<Claim>, relative_tolerance: f64) -> Corroboration {
    let tol = if relative_tolerance.is_finite() && relative_tolerance >= 0.0 {
        relative_tolerance
    } else {
        DEFAULT_RELATIVE_TOLERANCE
    };

    match (a, b) {
        (None, None) => Corroboration::Unknown,
        (Some(c), None) | (None, Some(c)) => {
            // A single non-finite claim is no claim at all.
            if !c.value.is_finite() {
                return Corroboration::Unknown;
            }
            Corroboration::Uncorroborated { value: c.value, provenance: c.provenance }
        }
        (Some(ca), Some(cb)) => {
            if !ca.value.is_finite() && !cb.value.is_finite() {
                return Corroboration::Unknown;
            }
            // One side unusable degrades to the other, never to a comparison
            // against a garbage number.
            if !ca.value.is_finite() {
                return Corroboration::Uncorroborated { value: cb.value, provenance: cb.provenance };
            }
            if !cb.value.is_finite() {
                return Corroboration::Uncorroborated { value: ca.value, provenance: ca.provenance };
            }

            let diff = (ca.value - cb.value).abs();
            let scale = ca.value.abs().max(cb.value.abs());
            // Both exactly zero: agreement, and no division.
            if scale == 0.0 {
                return Corroboration::Corroborated { value: 0.0, sources: 2 };
            }
            let rel = diff / scale;
            if rel <= tol {
                // Report the more conservative (smaller) value: if a switch says
                // 1000 and we measure 1000.4, the lower figure cannot overstate
                // capacity.
                Corroboration::Corroborated { value: ca.value.min(cb.value), sources: 2 }
            } else {
                Corroboration::Contradicted { a: ca, b: cb, relative_difference: rel }
            }
        }
    }
}

/// A human-readable finding for a contradicted property. Returns `None` when
/// there is no contradiction, so callers can emit unconditionally.
pub fn contradiction_finding(property: &str, c: &Corroboration) -> Option<String> {
    match c {
        Corroboration::Contradicted { a, b, relative_difference } => Some(format!(
            "{property}: sources disagree by {:.0}% -- {} reports {}, {} reports {}. \
             Exactly one of these is wrong about this network; any figure derived from \
             {property} is withheld until they are reconciled.",
            relative_difference * 100.0,
            a.provenance.label(),
            trim_float(a.value),
            b.provenance.label(),
            trim_float(b.value),
        )),
        _ => None,
    }
}

/// Formats a value without a trailing `.0` on whole numbers, so a link speed
/// prints as `1000` rather than `1000.0`.
fn trim_float(v: f64) -> String {
    if v.fract() == 0.0 && v.abs() < 1e15 {
        format!("{}", v as i64)
    } else {
        format!("{v}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The motivating case: a switch reporting a 1 Gb uplink while the client
    /// measures 5 Gb. Neither value may quietly win.
    #[test]
    fn a_switch_and_client_link_speed_disagreement_is_contradicted() {
        let c = corroborate(
            Some(Claim::new(1000.0, Provenance::OperatorSupplied)),
            Some(Claim::new(5000.0, Provenance::Measured)),
            DEFAULT_RELATIVE_TOLERANCE,
        );
        assert!(c.is_contradicted());
        assert_eq!(c.usable_value(), None, "a contested property has no usable value");
        assert!(!c.supports_derived_figure());
    }

    /// Operator-declared jumbo frames against a probed 1500 must not resolve to
    /// either number.
    #[test]
    fn declared_jumbo_mtu_against_probed_1500_is_contradicted() {
        let c = corroborate(
            Some(Claim::new(9000.0, Provenance::OperatorSupplied)),
            Some(Claim::new(1500.0, Provenance::Measured)),
            DEFAULT_RELATIVE_TOLERANCE,
        );
        assert!(c.is_contradicted());
        let finding = contradiction_finding("path MTU", &c).expect("contradiction must yield a finding");
        assert!(finding.contains("9000"), "{finding}");
        assert!(finding.contains("1500"), "{finding}");
        assert!(finding.contains("operator-supplied"), "{finding}");
        assert!(finding.contains("measured here"), "{finding}");
    }

    #[test]
    fn small_sampling_differences_still_corroborate() {
        let c = corroborate(
            Some(Claim::new(1000.0, Provenance::OperatorSupplied)),
            Some(Claim::new(1000.4, Provenance::Measured)),
            DEFAULT_RELATIVE_TOLERANCE,
        );
        match c {
            // The conservative value is reported, never the optimistic one.
            Corroboration::Corroborated { value, sources } => {
                assert_eq!(sources, 2);
                assert!((value - 1000.0).abs() < 1e-9, "got {value}");
            }
            other => panic!("expected Corroborated, got {other:?}"),
        }
    }

    #[test]
    fn one_source_is_usable_but_marked_uncorroborated() {
        let c = corroborate(Some(Claim::new(1500.0, Provenance::Measured)), None, DEFAULT_RELATIVE_TOLERANCE);
        assert_eq!(c.usable_value(), Some(1500.0));
        assert!(!c.is_contradicted());
        match c {
            Corroboration::Uncorroborated { provenance, .. } => {
                assert_eq!(provenance, Provenance::Measured);
            }
            other => panic!("expected Uncorroborated, got {other:?}"),
        }
    }

    /// Absent is not the same as disagreeing, and not the same as zero.
    #[test]
    fn no_source_is_unknown_not_contradicted_and_not_zero() {
        let c = corroborate(None, None, DEFAULT_RELATIVE_TOLERANCE);
        assert_eq!(c, Corroboration::Unknown);
        assert!(!c.is_contradicted());
        assert_eq!(c.usable_value(), None);
        assert!(contradiction_finding("link speed", &c).is_none());
    }

    #[test]
    fn both_zero_agree_without_dividing_by_zero() {
        let c = corroborate(
            Some(Claim::new(0.0, Provenance::OperatorSupplied)),
            Some(Claim::new(0.0, Provenance::Measured)),
            DEFAULT_RELATIVE_TOLERANCE,
        );
        assert_eq!(c, Corroboration::Corroborated { value: 0.0, sources: 2 });
    }

    /// Zero against nonzero is a real disagreement, not a rounding artifact.
    #[test]
    fn zero_against_nonzero_is_contradicted() {
        let c = corroborate(
            Some(Claim::new(0.0, Provenance::OperatorSupplied)),
            Some(Claim::new(1000.0, Provenance::Measured)),
            DEFAULT_RELATIVE_TOLERANCE,
        );
        assert!(c.is_contradicted());
    }

    #[test]
    fn a_nonfinite_claim_never_corroborates_a_real_one() {
        let c = corroborate(
            Some(Claim::new(f64::NAN, Provenance::OperatorSupplied)),
            Some(Claim::new(1000.0, Provenance::Measured)),
            DEFAULT_RELATIVE_TOLERANCE,
        );
        match c {
            Corroboration::Uncorroborated { value, provenance } => {
                assert!((value - 1000.0).abs() < 1e-9);
                assert_eq!(provenance, Provenance::Measured);
            }
            other => panic!("expected Uncorroborated from the finite side, got {other:?}"),
        }
    }

    /// A nonsense tolerance must not silently admit every disagreement.
    #[test]
    fn a_nonsense_tolerance_falls_back_to_the_default() {
        let c = corroborate(
            Some(Claim::new(1000.0, Provenance::OperatorSupplied)),
            Some(Claim::new(5000.0, Provenance::Measured)),
            f64::NAN,
        );
        assert!(c.is_contradicted(), "NaN tolerance must not swallow a 5x disagreement");
    }

    /// Provenance must survive into the finding: "these disagree" is far less
    /// actionable than "the switch and the client disagree".
    #[test]
    fn the_finding_names_both_provenances() {
        let c = corroborate(
            Some(Claim::new(100.0, Provenance::PeerReported)),
            Some(Claim::new(400.0, Provenance::Measured)),
            DEFAULT_RELATIVE_TOLERANCE,
        );
        let f = contradiction_finding("throughput", &c).expect("must yield a finding");
        assert!(f.contains("peer-reported"), "{f}");
        assert!(f.contains("measured here"), "{f}");
        assert!(f.contains("withheld"), "{f}");
    }
}
