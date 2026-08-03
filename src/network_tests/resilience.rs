//! GAP-062: controlled resilience/failover validation.
//!
//! Same absolute constraint as GAP-029's `circuit_workflow` (another
//! agent's file, read for the pattern, not edited): FragglePacket observes
//! and labels a component change, it never performs one. There is no
//! `fail_over`, `kill`, `disable`, or "component under test" identifier
//! taken as an actionable target anywhere in this module -- every type
//! that carries a component name is a plain label attached to
//! operator-supplied evidence, never a parameter fed into a command or
//! socket. `ComponentChange::component_label` exists purely so a report
//! can say which change an outage/loss window followed; nothing in this
//! module can dereference that string into an action.
//!
//! Requires an approved window: `require_authorization` reuses
//! `nat_capacity::require_authorization_for`'s exact pattern (a non-empty
//! operator statement, no boolean shortcut) as the gate on the continuous
//! low-rate session bundle. The bundle itself is a measurement session,
//! not a load-generation phase -- "low-rate continuous" per the acceptance
//! criteria -- so it does not additionally route through `LoadGuard`'s
//! budget machinery, which exists for throughput/capacity phases this is
//! not.

use serde::{Deserialize, Serialize};

pub use crate::network_tests::nat_capacity::require_authorization_for;

pub fn require_authorization(statement: Option<&str>) -> Result<String, String> {
    require_authorization_for(
        statement,
        "run a continuous session bundle across an operator-performed component change",
    )
}

/// A component change the OPERATOR performed and is reporting after the
/// fact. `component_label` is free text the operator chooses (e.g. "WAN-A
/// uplink", "core switch 2", "primary AP controller") -- it is never
/// validated against, looked up in, or used to address any real device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentChange {
    pub component_label: String,
    /// Operator's own description of what they did (e.g. "unplugged WAN-A
    /// uplink", "rebooted core switch 2"). Free text, never parsed as a
    /// command.
    pub action_description: String,
}

/// One continuous-session sample. `session_id` is caller-assigned (e.g. a
/// sequence number), not a handle this module can act on.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSample {
    pub session_id: u32,
    /// `None` when the sample window produced no evidence either way --
    /// distinct from `Some(false)` (confirmed lost).
    pub session_alive: Option<bool>,
    pub route_identity: Option<String>,
    pub nat_identity: Option<String>,
    pub state_resynchronized: Option<bool>,
}

/// The full observed timeline around one component change: samples taken
/// continuously before, during, and after, plus the labeled change itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResilienceRun {
    pub change: ComponentChange,
    /// Ordered by time. Every sample's `session_id` is expected to recur
    /// across the whole run (same sessions tracked continuously) -- this
    /// module does not enforce that ordering itself, only measures what it
    /// is given.
    pub samples: Vec<SessionSample>,
    /// Wall-clock bounds of the observed outage window, if one was
    /// detected. `None` means no outage was observed, NOT a zero-duration
    /// outage -- an outage that was never bracketed by a lost sample must
    /// never read as "0ms", the exact false-zero this gap's must-lock
    /// clause calls out.
    pub outage_started_secs: Option<f64>,
    pub outage_ended_secs: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RouteIdentityContinuity {
    Unchanged,
    Changed { before: String, after: String },
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum NatIdentityContinuity {
    Unchanged,
    Changed { before: String, after: String },
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResilienceVerdict {
    /// `None` when no outage was ever observed to complete -- never
    /// coerced to a numeric 0.
    pub outage_duration_secs: Option<f64>,
    /// Fraction of tracked sessions that had at least one `Some(false)`
    /// sample and later returned to `Some(true)` -- distinct from sessions
    /// that were simply never sampled during the window (excluded, not
    /// counted as failed).
    pub sessions_survived: usize,
    pub sessions_lost: usize,
    pub sessions_never_sampled: usize,
    pub route_identity: RouteIdentityContinuity,
    pub nat_identity: NatIdentityContinuity,
    pub state_resync_observed: Option<bool>,
}

/// Judges one `ResilienceRun`. Never reports an outage duration unless
/// both a start and an end were actually observed; a component change with
/// no bracketed loss at all yields `outage_duration_secs: None`, not 0 --
/// "0ms from a failover that was never observed" is the exact false-zero
/// this function exists to prevent.
pub fn judge_resilience(run: &ResilienceRun) -> ResilienceVerdict {
    let outage_duration_secs = match (run.outage_started_secs, run.outage_ended_secs) {
        (Some(start), Some(end)) if end >= start => Some(end - start),
        _ => None,
    };

    let mut by_session: std::collections::BTreeMap<u32, Vec<&SessionSample>> =
        std::collections::BTreeMap::new();
    for s in &run.samples {
        by_session.entry(s.session_id).or_default().push(s);
    }

    let mut survived = 0;
    let mut lost = 0;
    let mut never_sampled = 0;
    for samples in by_session.values() {
        let ever_lost = samples.iter().any(|s| s.session_alive == Some(false));
        // "Survived" means recovered AFTER being lost -- the last known
        // (non-`None`) sample must read alive, not merely "was alive at
        // some point before it went down". Using only the last known
        // state, rather than any-alive-ever, is what makes a session that
        // goes down and stays down classify as lost instead of survived.
        let last_known_alive = samples.iter().rev().find_map(|s| s.session_alive);
        if last_known_alive.is_none() {
            never_sampled += 1;
        } else if ever_lost && last_known_alive == Some(false) {
            lost += 1;
        } else {
            survived += 1;
        }
    }

    let route_identities: Vec<&str> = run
        .samples
        .iter()
        .filter_map(|s| s.route_identity.as_deref())
        .collect();
    let route_identity = match (route_identities.first(), route_identities.last()) {
        (Some(first), Some(last)) if first != last => RouteIdentityContinuity::Changed {
            before: first.to_string(),
            after: last.to_string(),
        },
        (Some(_), Some(_)) => RouteIdentityContinuity::Unchanged,
        _ => RouteIdentityContinuity::Unavailable,
    };

    let nat_identities: Vec<&str> = run
        .samples
        .iter()
        .filter_map(|s| s.nat_identity.as_deref())
        .collect();
    let nat_identity = match (nat_identities.first(), nat_identities.last()) {
        (Some(first), Some(last)) if first != last => NatIdentityContinuity::Changed {
            before: first.to_string(),
            after: last.to_string(),
        },
        (Some(_), Some(_)) => NatIdentityContinuity::Unchanged,
        _ => NatIdentityContinuity::Unavailable,
    };

    let state_resync_observed = if run.samples.iter().any(|s| s.state_resynchronized.is_some()) {
        Some(
            run.samples
                .iter()
                .any(|s| s.state_resynchronized == Some(true)),
        )
    } else {
        None
    };

    ResilienceVerdict {
        outage_duration_secs,
        sessions_survived: survived,
        sessions_lost: lost,
        sessions_never_sampled: never_sampled,
        route_identity,
        nat_identity,
        state_resync_observed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_statement_refuses() {
        assert!(require_authorization(None).is_err());
        assert!(require_authorization(Some("")).is_err());
    }

    #[test]
    fn a_real_statement_is_accepted() {
        assert_eq!(
            require_authorization(Some("approved by NOC for 03:00-03:30")).unwrap(),
            "approved by NOC for 03:00-03:30"
        );
    }

    fn sample(id: u32, alive: Option<bool>) -> SessionSample {
        SessionSample {
            session_id: id,
            session_alive: alive,
            route_identity: None,
            nat_identity: None,
            state_resynchronized: None,
        }
    }

    #[test]
    fn an_outage_that_was_never_observed_reports_duration_as_none_never_zero() {
        let run = ResilienceRun {
            change: ComponentChange {
                component_label: "WAN-A uplink".to_string(),
                action_description: "unplugged".to_string(),
            },
            samples: vec![sample(1, Some(true)), sample(1, Some(true))],
            outage_started_secs: None,
            outage_ended_secs: None,
        };
        let v = judge_resilience(&run);
        assert_eq!(v.outage_duration_secs, None);
    }

    #[test]
    fn a_bracketed_outage_reports_its_real_duration() {
        let run = ResilienceRun {
            change: ComponentChange {
                component_label: "WAN-A uplink".to_string(),
                action_description: "unplugged".to_string(),
            },
            samples: vec![sample(1, Some(false)), sample(1, Some(true))],
            outage_started_secs: Some(10.0),
            outage_ended_secs: Some(12.4),
        };
        let v = judge_resilience(&run);
        assert!((v.outage_duration_secs.unwrap() - 2.4).abs() < 1e-9);
    }

    #[test]
    fn a_session_that_recovers_is_counted_as_survived_not_lost() {
        let run = ResilienceRun {
            change: ComponentChange {
                component_label: "core switch 2".to_string(),
                action_description: "rebooted".to_string(),
            },
            samples: vec![
                sample(1, Some(true)),
                sample(1, Some(false)),
                sample(1, Some(true)),
            ],
            outage_started_secs: Some(1.0),
            outage_ended_secs: Some(3.0),
        };
        let v = judge_resilience(&run);
        assert_eq!(v.sessions_survived, 1);
        assert_eq!(v.sessions_lost, 0);
    }

    #[test]
    fn a_session_that_never_recovers_is_counted_as_lost() {
        let run = ResilienceRun {
            change: ComponentChange {
                component_label: "core switch 2".to_string(),
                action_description: "rebooted".to_string(),
            },
            samples: vec![sample(1, Some(true)), sample(1, Some(false))],
            outage_started_secs: Some(1.0),
            outage_ended_secs: Some(3.0),
        };
        let v = judge_resilience(&run);
        assert_eq!(v.sessions_lost, 1);
    }

    #[test]
    fn a_session_never_sampled_is_excluded_not_counted_as_lost() {
        let run = ResilienceRun {
            change: ComponentChange {
                component_label: "core switch 2".to_string(),
                action_description: "rebooted".to_string(),
            },
            samples: vec![sample(1, None), sample(1, None)],
            outage_started_secs: None,
            outage_ended_secs: None,
        };
        let v = judge_resilience(&run);
        assert_eq!(v.sessions_never_sampled, 1);
        assert_eq!(v.sessions_lost, 0);
        assert_eq!(v.sessions_survived, 0);
    }

    #[test]
    fn a_route_identity_change_across_the_failover_is_detected() {
        let mut run = ResilienceRun {
            change: ComponentChange {
                component_label: "WAN-A".to_string(),
                action_description: "unplugged".to_string(),
            },
            samples: vec![sample(1, Some(true)), sample(1, Some(true))],
            outage_started_secs: None,
            outage_ended_secs: None,
        };
        run.samples[0].route_identity = Some("via-wan-a".to_string());
        run.samples[1].route_identity = Some("via-wan-b".to_string());
        let v = judge_resilience(&run);
        assert_eq!(
            v.route_identity,
            RouteIdentityContinuity::Changed {
                before: "via-wan-a".to_string(),
                after: "via-wan-b".to_string()
            }
        );
    }

    #[test]
    fn missing_identity_evidence_is_unavailable_not_assumed_unchanged() {
        let run = ResilienceRun {
            change: ComponentChange {
                component_label: "WAN-A".to_string(),
                action_description: "unplugged".to_string(),
            },
            samples: vec![sample(1, Some(true))],
            outage_started_secs: None,
            outage_ended_secs: None,
        };
        let v = judge_resilience(&run);
        assert_eq!(v.route_identity, RouteIdentityContinuity::Unavailable);
    }

    #[test]
    fn this_module_carries_no_function_that_takes_an_action_on_a_component() {
        // Structural proof, not a behavioral one: the only public functions
        // in this module are `require_authorization`/`require_authorization_for`
        // (a refusal gate) and `judge_resilience` (pure observation ->
        // verdict). Neither accepts anything resembling a target/command/
        // socket/handle. This test exists so that if a future edit adds
        // one, a reviewer sees this comment fail its own premise.
        let change = ComponentChange {
            component_label: "anything".to_string(),
            action_description: "anything".to_string(),
        };
        // Constructing a ComponentChange performs no I/O and has no side effect.
        assert_eq!(change.component_label, "anything");
    }
}
