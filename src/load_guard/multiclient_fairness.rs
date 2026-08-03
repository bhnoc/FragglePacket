//! GAP-051: coordinated multi-client capacity and fairness.
//!
//! GAP-072's field evidence is the reason this module refuses so much: a
//! coordinated run measured severe degradation on one client, but the
//! written assessment could not reach a verdict because the peer's mode,
//! listener ports, association, and timestamps were never captured -- and
//! the two candidate explanations (peer loaded the same public listener vs.
//! peer was passive and this is background impairment) invert the
//! conclusion from identical numbers. `RoleDescriptor` is the fix: every
//! participating client emits one, and a cross-client verdict is refused
//! until both exist AND their phase windows actually overlap in time.
//! Jain fairness computed from a single side's samples is meaningless by
//! the same logic, so `jain_fairness_index` requires at least two
//! independently-sourced per-client rate series.
//!
//! Ported from `scripts/bhusa-peer-impact-test.zsh`'s method, not its code:
//! a `start_epoch` barrier so independently-launched clients begin their
//! loaded phase at the same wall-clock instant, and UTC phase markers
//! (`PhaseMark`) mirroring the script's `mark_phase` tab-separated log so
//! overlap can be checked after the fact without a live coordinator.

use serde::{Deserialize, Serialize};

/// What a single client was doing during the coordinated window. The
/// GAP-072 fix: every role must state its own listener endpoints so shared
/// public listener contention -- a confound, not a network fault -- is
/// detectable rather than assumed away.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientRole {
    Loading,
    Observing,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleDescriptor {
    pub client_id: String,
    pub role: ClientRole,
    pub interface: String,
    /// Salted AP label (never a BSSID) if available.
    pub association_label: Option<String>,
    pub listener_endpoints: Vec<String>,
    /// Unix epoch seconds this client's clock believes the run started --
    /// used only to compute clock offset between roles, never to change
    /// scheduling.
    pub reported_start_epoch: f64,
    pub phase_marks: Vec<PhaseMark>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseMark {
    pub phase: String,
    pub epoch_secs: f64,
}

impl RoleDescriptor {
    pub fn phase_window(&self) -> Option<(f64, f64)> {
        if self.phase_marks.is_empty() {
            return None;
        }
        let start = self.phase_marks.iter().map(|p| p.epoch_secs).fold(f64::INFINITY, f64::min);
        let end = self.phase_marks.iter().map(|p| p.epoch_secs).fold(f64::NEG_INFINITY, f64::max);
        Some((start, end))
    }
}

/// Whether two roles' phase windows actually overlap in wall-clock time.
/// This is the load-bearing check GAP-072 demands: two descriptors existing
/// is not enough if one ran an hour before the other.
pub fn windows_overlap(a: &RoleDescriptor, b: &RoleDescriptor) -> Option<bool> {
    let (a_start, a_end) = a.phase_window()?;
    let (b_start, b_end) = b.phase_window()?;
    Some(a_start <= b_end && b_start <= a_end)
}

/// Detects a shared-listener confound: both roles targeting the same
/// endpoint means load attributed to "the network" might actually be
/// listener admission contention between the two clients.
pub fn shared_listener_confound(a: &RoleDescriptor, b: &RoleDescriptor) -> Vec<String> {
    a.listener_endpoints.iter().filter(|e| b.listener_endpoints.contains(e)).cloned().collect()
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CrossClientVerdict {
    /// Both descriptors present, windows overlap: a verdict can be computed.
    Comparable { clock_offset_secs: f64, shared_listeners: Vec<String> },
    /// Refuses the verdict and names exactly why, mirroring
    /// `CircuitVerdict::Refused`'s pattern.
    Refused { reason: String },
}

pub fn evaluate_cross_client(a: Option<&RoleDescriptor>, b: Option<&RoleDescriptor>) -> CrossClientVerdict {
    let (Some(a), Some(b)) = (a, b) else {
        let mut missing = Vec::new();
        if a.is_none() {
            missing.push("role descriptor A");
        }
        if b.is_none() {
            missing.push("role descriptor B");
        }
        return CrossClientVerdict::Refused {
            reason: format!("missing: {}", missing.join(", ")),
        };
    };
    match windows_overlap(a, b) {
        None => CrossClientVerdict::Refused {
            reason: "one or both role descriptors have no phase marks; overlap cannot be established".to_string(),
        },
        Some(false) => CrossClientVerdict::Refused {
            reason: "role descriptors' phase windows do not overlap in time; the two clients were not measured concurrently".to_string(),
        },
        Some(true) => CrossClientVerdict::Comparable {
            clock_offset_secs: b.reported_start_epoch - a.reported_start_epoch,
            shared_listeners: shared_listener_confound(a, b),
        },
    }
}

/// Jain's fairness index over a set of per-client achieved rates. Requires
/// at least two rate series (a real second client, not an assumption about
/// one) and a corresponding `CrossClientVerdict::Comparable` -- callers
/// must check that separately; this function only refuses the degenerate
/// single-sample case that is trivially "fair" and therefore meaningless.
pub fn jain_fairness_index(rates: &[f64]) -> Option<f64> {
    if rates.len() < 2 {
        return None;
    }
    let sum: f64 = rates.iter().sum();
    let sum_sq: f64 = rates.iter().map(|r| r * r).sum();
    if sum_sq == 0.0 {
        return None;
    }
    Some((sum * sum) / (rates.len() as f64 * sum_sq))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor(id: &str, marks: &[f64], listeners: &[&str], start: f64) -> RoleDescriptor {
        RoleDescriptor {
            client_id: id.to_string(),
            role: ClientRole::Loading,
            interface: "en0".to_string(),
            association_label: Some("ap-deadbeef".to_string()),
            listener_endpoints: listeners.iter().map(|s| s.to_string()).collect(),
            reported_start_epoch: start,
            phase_marks: marks.iter().map(|t| PhaseMark { phase: "load".to_string(), epoch_secs: *t }).collect(),
        }
    }

    #[test]
    fn cross_client_verdict_is_refused_when_either_descriptor_is_missing() {
        let a = descriptor("a", &[100.0, 110.0], &["s:5201"], 100.0);
        assert!(matches!(evaluate_cross_client(Some(&a), None), CrossClientVerdict::Refused { .. }));
        assert!(matches!(evaluate_cross_client(None, Some(&a)), CrossClientVerdict::Refused { .. }));
        assert!(matches!(evaluate_cross_client(None, None), CrossClientVerdict::Refused { .. }));
    }

    #[test]
    fn cross_client_verdict_is_refused_when_windows_dont_overlap() {
        let a = descriptor("a", &[100.0, 110.0], &["s:5201"], 100.0);
        let b = descriptor("b", &[500.0, 510.0], &["s:5202"], 500.0);
        match evaluate_cross_client(Some(&a), Some(&b)) {
            CrossClientVerdict::Refused { reason } => assert!(reason.contains("do not overlap")),
            other => panic!("expected Refused, got {other:?}"),
        }
    }

    #[test]
    fn cross_client_verdict_is_comparable_when_windows_overlap() {
        let a = descriptor("a", &[100.0, 120.0], &["s:5201"], 100.0);
        let b = descriptor("b", &[110.0, 130.0], &["s:5202"], 110.0);
        match evaluate_cross_client(Some(&a), Some(&b)) {
            CrossClientVerdict::Comparable { .. } => {}
            other => panic!("expected Comparable, got {other:?}"),
        }
    }

    #[test]
    fn shared_listener_endpoints_are_flagged_as_a_confound() {
        let a = descriptor("a", &[100.0, 120.0], &["s:5201", "s:5202"], 100.0);
        let b = descriptor("b", &[110.0, 130.0], &["s:5202"], 110.0);
        match evaluate_cross_client(Some(&a), Some(&b)) {
            CrossClientVerdict::Comparable { shared_listeners, .. } => {
                assert_eq!(shared_listeners, vec!["s:5202".to_string()]);
            }
            other => panic!("expected Comparable, got {other:?}"),
        }
    }

    #[test]
    fn jain_fairness_index_refuses_a_single_sample() {
        assert_eq!(jain_fairness_index(&[100.0]), None);
        assert_eq!(jain_fairness_index(&[]), None);
    }

    #[test]
    fn jain_fairness_index_is_one_for_perfectly_equal_rates() {
        let idx = jain_fairness_index(&[50.0, 50.0, 50.0]).unwrap();
        assert!((idx - 1.0).abs() < 1e-9);
    }

    #[test]
    fn jain_fairness_index_drops_below_one_for_unequal_rates() {
        let idx = jain_fairness_index(&[100.0, 1.0]).unwrap();
        assert!(idx < 1.0);
    }

    #[test]
    fn phase_window_is_none_with_no_marks_not_a_zero_length_window() {
        let a = descriptor("a", &[], &[], 100.0);
        assert_eq!(a.phase_window(), None);
        assert_eq!(windows_overlap(&a, &descriptor("b", &[1.0], &[], 1.0)), None);
    }
}
