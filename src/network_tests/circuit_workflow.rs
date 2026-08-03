//! GAP-029: one-circuit-at-a-time WAN comparison.
//!
//! Client-only tests cannot prove which WAN member or shared edge owns a
//! failure. The decisive test runs the same bundle with WAN A only, WAN B only,
//! and both active, alongside per-member counters.
//!
//! This module observes and labels. It never changes routing: failing over a
//! production circuit at a live event is an operator action inside an approved
//! window, so circuit state is an operator-supplied label and there is
//! deliberately no code path here that could initiate a failover. The types
//! carry no command, socket, or process handle for that reason.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Which circuits the operator states were active for a phase. Supplied, never
/// detected-and-acted-on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CircuitState {
    AOnly,
    BOnly,
    DualActive,
}

impl CircuitState {
    pub fn as_str(&self) -> &'static str {
        match self {
            CircuitState::AOnly => "a-only",
            CircuitState::BOnly => "b-only",
            CircuitState::DualActive => "dual-active",
        }
    }
}

/// Per-member telemetry the operator ingests. Every field is optional because
/// a conclusion must be refused when the evidence is absent rather than
/// inferred from whatever happened to be supplied.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemberTelemetry {
    pub member: String,
    pub utilization_pct: Option<f64>,
    pub drops: Option<u64>,
    pub policer_drops: Option<u64>,
    pub errors: Option<u64>,
    /// Which firewall/NAT node owned the flows during this phase.
    pub nat_owner: Option<String>,
    pub route_changes: Option<u64>,
}

impl MemberTelemetry {
    /// Names the fields a verdict needs but does not have.
    pub fn missing_fields(&self) -> Vec<&'static str> {
        let mut m = Vec::new();
        if self.utilization_pct.is_none() {
            m.push("utilization_pct");
        }
        if self.drops.is_none() {
            m.push("drops");
        }
        if self.policer_drops.is_none() {
            m.push("policer_drops");
        }
        if self.errors.is_none() {
            m.push("errors");
        }
        if self.nat_owner.is_none() {
            m.push("nat_owner");
        }
        if self.route_changes.is_none() {
            m.push("route_changes");
        }
        m
    }
}

/// One phase: a labeled circuit state, the client-side result, and whatever
/// member telemetry the operator supplied for it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitPhase {
    pub circuit_state: CircuitState,
    /// Operator-supplied description of what the client bundle measured.
    pub client_summary: String,
    /// Achieved throughput, if the bundle produced one. Optional so a phase
    /// that failed to run is not scored as zero.
    pub achieved_mbps: Option<f64>,
    pub loss_pct: Option<f64>,
    pub members: Vec<MemberTelemetry>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CircuitVerdict {
    /// A circuit-specific fault is supported: the members differ materially and
    /// the telemetry backs it.
    MemberSpecific { detail: String },
    /// Both members behave alike, so the fault is shared (edge, WLAN, or
    /// policy) rather than owned by one circuit.
    SharedRatherThanMemberSpecific { detail: String },
    /// The comparison cannot be made. Names exactly what is missing so the
    /// operator knows what to collect, rather than implying a finding.
    Refused { missing: Vec<String> },
}

/// A deterministic descriptor of a run, hashable so the same inputs always
/// produce the same identifier. Signing is GAP-065's concern; this only
/// guarantees reproducibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitManifest {
    pub bundle_name: String,
    pub phases: Vec<CircuitPhase>,
}

impl CircuitManifest {
    /// Stable digest over the phase structure. Uses the same std-only hasher
    /// the AP-identity work uses, since this is a reproducibility check rather
    /// than a security primitive.
    pub fn digest(&self) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut h = DefaultHasher::new();
        self.bundle_name.hash(&mut h);
        // Sort by circuit state so ingest order cannot change the digest.
        let mut ordered: Vec<&CircuitPhase> = self.phases.iter().collect();
        ordered.sort_by_key(|p| p.circuit_state);
        for p in ordered {
            p.circuit_state.as_str().hash(&mut h);
            p.client_summary.hash(&mut h);
            format!("{:?}", p.achieved_mbps).hash(&mut h);
            format!("{:?}", p.loss_pct).hash(&mut h);
            let mut members: Vec<&MemberTelemetry> = p.members.iter().collect();
            members.sort_by(|a, b| a.member.cmp(&b.member));
            for m in members {
                m.member.hash(&mut h);
                format!("{:?}", m.utilization_pct).hash(&mut h);
                format!("{:?}", m.drops).hash(&mut h);
                format!("{:?}", m.policer_drops).hash(&mut h);
                format!("{:?}", m.errors).hash(&mut h);
                format!("{:?}", m.nat_owner).hash(&mut h);
                format!("{:?}", m.route_changes).hash(&mut h);
            }
        }
        format!("{:016x}", h.finish())
    }

    pub fn phase(&self, state: CircuitState) -> Option<&CircuitPhase> {
        self.phases.iter().find(|p| p.circuit_state == state)
    }
}

/// Derives the A-vs-B verdict, refusing when the required evidence is absent.
///
/// The refusal path is the important one: an operator who ran only one circuit,
/// or who could not collect member counters, must get a named list of what is
/// missing rather than a verdict extrapolated from half the picture.
pub fn judge_circuits(m: &CircuitManifest) -> CircuitVerdict {
    let mut missing: Vec<String> = Vec::new();

    for required in [CircuitState::AOnly, CircuitState::BOnly, CircuitState::DualActive] {
        match m.phase(required) {
            None => missing.push(format!("phase:{}", required.as_str())),
            Some(p) => {
                if p.achieved_mbps.is_none() {
                    missing.push(format!("{}:achieved_mbps", required.as_str()));
                }
                if p.members.is_empty() {
                    missing.push(format!("{}:member_telemetry", required.as_str()));
                } else {
                    for mem in &p.members {
                        for f in mem.missing_fields() {
                            missing.push(format!("{}:{}:{}", required.as_str(), mem.member, f));
                        }
                    }
                }
            }
        }
    }

    if !missing.is_empty() {
        return CircuitVerdict::Refused { missing };
    }

    let a = m.phase(CircuitState::AOnly).and_then(|p| p.achieved_mbps).unwrap_or(0.0);
    let b = m.phase(CircuitState::BOnly).and_then(|p| p.achieved_mbps).unwrap_or(0.0);
    let a_loss = m.phase(CircuitState::AOnly).and_then(|p| p.loss_pct).unwrap_or(0.0);
    let b_loss = m.phase(CircuitState::BOnly).and_then(|p| p.loss_pct).unwrap_or(0.0);

    let worse = a.max(b);
    let throughput_ratio = if worse > 0.0 { a.min(b) / worse } else { 1.0 };
    let loss_delta = (a_loss - b_loss).abs();

    // One member materially worse on either axis points at that member.
    if throughput_ratio < 0.6 || loss_delta > 5.0 {
        let (slow, fast) = if a <= b { ("A", "B") } else { ("B", "A") };
        CircuitVerdict::MemberSpecific {
            detail: format!(
                "member {} delivered {:.1} Mbps at {:.3}% loss while member {} delivered {:.1} Mbps \
                 at {:.3}% loss; the asymmetry is large enough to implicate the slower member",
                slow,
                a.min(b),
                if a <= b { a_loss } else { b_loss },
                fast,
                worse,
                if a <= b { b_loss } else { a_loss },
            ),
        }
    } else {
        CircuitVerdict::SharedRatherThanMemberSpecific {
            detail: format!(
                "both members performed within {:.0}% of each other ({:.1} and {:.1} Mbps) with a \
                 {:.3} point loss difference, so a single bad member is not supported; the shared \
                 edge, WLAN, or a common policy is the better explanation",
                (1.0 - throughput_ratio) * 100.0,
                a,
                b,
                loss_delta
            ),
        }
    }
}

/// Groups phases by circuit state for reporting.
pub fn by_state(m: &CircuitManifest) -> BTreeMap<&'static str, usize> {
    let mut out = BTreeMap::new();
    for p in &m.phases {
        *out.entry(p.circuit_state.as_str()).or_insert(0) += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_member(name: &str, drops: u64) -> MemberTelemetry {
        MemberTelemetry {
            member: name.to_string(),
            utilization_pct: Some(42.0),
            drops: Some(drops),
            policer_drops: Some(0),
            errors: Some(0),
            nat_owner: Some("fw-node-1".to_string()),
            route_changes: Some(0),
        }
    }

    fn phase(state: CircuitState, mbps: f64, loss: f64) -> CircuitPhase {
        CircuitPhase {
            circuit_state: state,
            client_summary: "bundle".to_string(),
            achieved_mbps: Some(mbps),
            loss_pct: Some(loss),
            members: vec![full_member("wan-a", 0)],
        }
    }

    #[test]
    fn a_missing_phase_refuses_and_names_it() {
        let m = CircuitManifest {
            bundle_name: "b".to_string(),
            phases: vec![phase(CircuitState::AOnly, 900.0, 0.0)],
        };
        match judge_circuits(&m) {
            CircuitVerdict::Refused { missing } => {
                assert!(missing.iter().any(|s| s.contains("b-only")));
                assert!(missing.iter().any(|s| s.contains("dual-active")));
            }
            other => panic!("expected refusal, got {:?}", other),
        }
    }

    #[test]
    fn absent_member_telemetry_refuses_rather_than_guessing() {
        let mut p = phase(CircuitState::AOnly, 900.0, 0.0);
        p.members.clear();
        let m = CircuitManifest {
            bundle_name: "b".to_string(),
            phases: vec![
                p,
                phase(CircuitState::BOnly, 890.0, 0.0),
                phase(CircuitState::DualActive, 880.0, 0.0),
            ],
        };
        match judge_circuits(&m) {
            CircuitVerdict::Refused { missing } => {
                assert!(missing.iter().any(|s| s.contains("member_telemetry")));
            }
            other => panic!("expected refusal, got {:?}", other),
        }
    }

    #[test]
    fn a_partial_member_field_set_refuses_and_names_the_field() {
        let mut p = phase(CircuitState::AOnly, 900.0, 0.0);
        p.members[0].policer_drops = None;
        let m = CircuitManifest {
            bundle_name: "b".to_string(),
            phases: vec![
                p,
                phase(CircuitState::BOnly, 890.0, 0.0),
                phase(CircuitState::DualActive, 880.0, 0.0),
            ],
        };
        match judge_circuits(&m) {
            CircuitVerdict::Refused { missing } => {
                assert!(missing.iter().any(|s| s.contains("policer_drops")));
            }
            other => panic!("expected refusal, got {:?}", other),
        }
    }

    #[test]
    fn symmetric_members_report_shared_not_member_specific() {
        let m = CircuitManifest {
            bundle_name: "b".to_string(),
            phases: vec![
                phase(CircuitState::AOnly, 900.0, 0.1),
                phase(CircuitState::BOnly, 890.0, 0.1),
                phase(CircuitState::DualActive, 880.0, 0.2),
            ],
        };
        // This is the field outcome: the port sweep found no bimodal split, so
        // one bad member was NOT supported and the tool must say so positively.
        assert!(matches!(
            judge_circuits(&m),
            CircuitVerdict::SharedRatherThanMemberSpecific { .. }
        ));
    }

    #[test]
    fn one_slow_member_is_implicated() {
        let m = CircuitManifest {
            bundle_name: "b".to_string(),
            phases: vec![
                phase(CircuitState::AOnly, 900.0, 0.1),
                phase(CircuitState::BOnly, 120.0, 0.1),
                phase(CircuitState::DualActive, 500.0, 0.1),
            ],
        };
        assert!(matches!(
            judge_circuits(&m),
            CircuitVerdict::MemberSpecific { .. }
        ));
    }

    #[test]
    fn a_loss_asymmetry_alone_implicates_a_member() {
        let m = CircuitManifest {
            bundle_name: "b".to_string(),
            phases: vec![
                phase(CircuitState::AOnly, 900.0, 0.1),
                phase(CircuitState::BOnly, 880.0, 20.0),
                phase(CircuitState::DualActive, 870.0, 10.0),
            ],
        };
        assert!(matches!(
            judge_circuits(&m),
            CircuitVerdict::MemberSpecific { .. }
        ));
    }

    #[test]
    fn digest_is_stable_and_order_independent() {
        let p1 = phase(CircuitState::AOnly, 900.0, 0.1);
        let p2 = phase(CircuitState::BOnly, 890.0, 0.1);
        let a = CircuitManifest {
            bundle_name: "b".to_string(),
            phases: vec![p1.clone(), p2.clone()],
        };
        let b = CircuitManifest {
            bundle_name: "b".to_string(),
            phases: vec![p2, p1],
        };
        assert_eq!(a.digest(), b.digest());
        assert_eq!(a.digest(), a.digest());
    }

    #[test]
    fn digest_changes_when_a_measurement_changes() {
        let a = CircuitManifest {
            bundle_name: "b".to_string(),
            phases: vec![phase(CircuitState::AOnly, 900.0, 0.1)],
        };
        let b = CircuitManifest {
            bundle_name: "b".to_string(),
            phases: vec![phase(CircuitState::AOnly, 901.0, 0.1)],
        };
        assert_ne!(a.digest(), b.digest());
    }
}
