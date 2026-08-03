//! GAP-050: controlled roaming/session-continuity measurement.
//!
//! GAP-027's guard invalidates a run when the association changes mid-phase
//! -- correct for a throughput test, where a roam is contamination. Here the
//! roam is the subject: measuring the handoff itself requires *not*
//! discarding the transition, only the surrounding phases that assumed a
//! stable association. `RoamTransition` is deliberately not a `LoadPhase`
//! result for that reason -- it is evidence about a boundary, not a rate.
//!
//! Privacy: an AP transition is reported purely in terms of the salted
//! labels `ap_identity::label_for_bssid` already produces (before_label,
//! after_label) plus band/channel -- never a BSSID. This module never reads
//! or stores a BSSID itself; it only accepts the caller's already-salted
//! `ApIdentity` values, the same discipline `ap_identity.rs` enforces at its
//! own boundary.

use serde::{Deserialize, Serialize};

use crate::load_guard::ap_identity::{compare as compare_ap_identity, ApComparison, ApIdentity};

/// Whether the handoff moved the client to a genuinely different AP or only
/// changed the radio (band/channel) on the same physical AP -- `ap_identity`
/// already distinguishes these; this module surfaces that distinction
/// rather than collapsing "roamed" into one boolean.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransitionKind {
    SameApSameRadio,
    SameApDifferentRadio,
    DifferentAp,
    /// Either side's identity was unavailable; a transition claim would be
    /// a guess, so this is reported instead of assuming a roam occurred.
    Undetermined,
}

/// Whether the client's Layer-3 identity survived the handoff. A roam that
/// changes the assigned VLAN or public egress looks, from the application's
/// perspective, like an unrelated fault -- this is the sharp clause in the
/// acceptance criteria and gets its own explicit field rather than being
/// inferred from session-reset counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IdentityContinuity {
    Unchanged,
    Changed,
    /// Neither side's identity (e.g. STUN mapped address) was sampled, so
    /// continuity cannot be claimed either way.
    Unavailable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoamTransition {
    pub before_label: Option<String>,
    pub after_label: Option<String>,
    pub before_band: Option<String>,
    pub after_band: Option<String>,
    pub kind: TransitionKind,
    /// `None` when the handoff was never actually observed to complete
    /// (e.g. the association never re-established before the observation
    /// window closed) -- distinct from a genuinely fast (near-zero) handoff.
    /// Collapsing "never measured" into 0ms is exactly the false-zero
    /// pattern this project forbids elsewhere (GAP-009, GAP-043).
    pub handoff_duration_ms: Option<f64>,
    /// Packets lost across the transition window, if a bounded loss sample
    /// was supplied; `None` when no sample was taken, never coerced to 0.
    pub packets_lost_during_handoff: Option<u64>,
    pub session_reset_detected: bool,
    pub identity_continuity: IdentityContinuity,
}

pub fn classify_transition(
    before: &Option<ApIdentity>,
    after: &Option<ApIdentity>,
) -> TransitionKind {
    match compare_ap_identity(before, after) {
        ApComparison::SameApSameRadio => TransitionKind::SameApSameRadio,
        ApComparison::SameApDifferentRadio => TransitionKind::SameApDifferentRadio,
        ApComparison::DifferentAp => TransitionKind::DifferentAp,
        ApComparison::Unavailable => TransitionKind::Undetermined,
    }
}

/// Builds a `RoamTransition` from already-sampled evidence. Every duration
/// or loss figure the caller doesn't have must be passed as `None`, not a
/// placeholder -- there is no fallback-to-zero anywhere in this function.
pub fn build_transition(
    before: Option<ApIdentity>,
    after: Option<ApIdentity>,
    handoff_duration_ms: Option<f64>,
    packets_lost_during_handoff: Option<u64>,
    session_reset_detected: bool,
    identity_before: Option<&str>,
    identity_after: Option<&str>,
) -> RoamTransition {
    let kind = classify_transition(&before, &after);
    let identity_continuity = match (identity_before, identity_after) {
        (Some(b), Some(a)) => {
            if b == a {
                IdentityContinuity::Unchanged
            } else {
                IdentityContinuity::Changed
            }
        }
        _ => IdentityContinuity::Unavailable,
    };
    RoamTransition {
        before_label: before.as_ref().map(|i| i.label.clone()),
        after_label: after.as_ref().map(|i| i.label.clone()),
        before_band: before.as_ref().and_then(|i| i.band.clone()),
        after_band: after.as_ref().and_then(|i| i.band.clone()),
        kind,
        handoff_duration_ms,
        packets_lost_during_handoff,
        session_reset_detected,
        identity_continuity,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(label: &str, band: &str) -> ApIdentity {
        ApIdentity {
            label: label.to_string(),
            band: Some(band.to_string()),
            channel: Some(1),
        }
    }

    #[test]
    fn a_transition_report_never_contains_a_bssid_shaped_value() {
        let t = build_transition(
            Some(identity("ap-aaaa1111", "6GHz")),
            Some(identity("ap-bbbb2222", "6GHz")),
            Some(45.0),
            Some(2),
            false,
            None,
            None,
        );
        let mac_pattern = regex_lite_check(&t.before_label.clone().unwrap_or_default());
        assert!(!mac_pattern);
        assert!(t.before_label.as_deref().unwrap().starts_with("ap-"));
    }

    fn regex_lite_check(s: &str) -> bool {
        // hand-rolled MAC-shape check without pulling in `regex`
        let parts: Vec<&str> = s.split(':').collect();
        parts.len() == 6
            && parts
                .iter()
                .all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()))
    }

    #[test]
    fn same_bssid_same_band_is_same_ap_same_radio() {
        let before = Some(identity("ap-aaaa1111", "6GHz"));
        let after = Some(identity("ap-aaaa1111", "6GHz"));
        assert_eq!(
            classify_transition(&before, &after),
            TransitionKind::SameApSameRadio
        );
    }

    #[test]
    fn same_label_different_band_is_same_ap_different_radio() {
        let before = Some(identity("ap-aaaa1111", "6GHz"));
        let after = Some(identity("ap-aaaa1111", "2GHz"));
        assert_eq!(
            classify_transition(&before, &after),
            TransitionKind::SameApDifferentRadio
        );
    }

    #[test]
    fn different_label_is_different_ap() {
        let before = Some(identity("ap-aaaa1111", "6GHz"));
        let after = Some(identity("ap-bbbb2222", "6GHz"));
        assert_eq!(
            classify_transition(&before, &after),
            TransitionKind::DifferentAp
        );
    }

    #[test]
    fn missing_either_side_is_undetermined_not_guessed() {
        assert_eq!(
            classify_transition(&None, &Some(identity("ap-aaaa1111", "6GHz"))),
            TransitionKind::Undetermined
        );
        assert_eq!(
            classify_transition(&None, &None),
            TransitionKind::Undetermined
        );
    }

    #[test]
    fn an_unobserved_handoff_reports_duration_as_none_never_zero() {
        let t = build_transition(
            Some(identity("ap-aaaa1111", "6GHz")),
            Some(identity("ap-bbbb2222", "6GHz")),
            None,
            None,
            false,
            None,
            None,
        );
        assert_eq!(t.handoff_duration_ms, None);
        assert_eq!(t.packets_lost_during_handoff, None);
    }

    #[test]
    fn a_changed_public_identity_is_reported_distinctly_from_unavailable() {
        let unchanged = build_transition(
            Some(identity("ap-aaaa1111", "6GHz")),
            Some(identity("ap-bbbb2222", "6GHz")),
            Some(30.0),
            Some(0),
            false,
            Some("203.0.113.5:4000"),
            Some("203.0.113.5:4000"),
        );
        assert_eq!(unchanged.identity_continuity, IdentityContinuity::Unchanged);

        let changed = build_transition(
            Some(identity("ap-aaaa1111", "6GHz")),
            Some(identity("ap-bbbb2222", "6GHz")),
            Some(30.0),
            Some(0),
            false,
            Some("203.0.113.5:4000"),
            Some("203.0.113.9:4001"),
        );
        assert_eq!(changed.identity_continuity, IdentityContinuity::Changed);

        let unavailable = build_transition(
            Some(identity("ap-aaaa1111", "6GHz")),
            Some(identity("ap-bbbb2222", "6GHz")),
            Some(30.0),
            Some(0),
            false,
            None,
            None,
        );
        assert_eq!(
            unavailable.identity_continuity,
            IdentityContinuity::Unavailable
        );
    }
}
