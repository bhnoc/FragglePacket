//! GAP-040: authorized-only listener allocation and baseline-floor control.
//!
//! Field evidence: each XMission listener accepts one test at a time, and
//! old-client reverse UDP showed a roughly 0.6-1.0% loss floor that belongs
//! to the endpoint, not the network under test -- reporting "0.7% loss"
//! without declaring that floor makes the figure meaningless. Separately,
//! XMission's Colorado endpoint produced a duration-inconsistent 44.6 Mbps
//! receiver summary and a 61.2 Mbps reverse ceiling on a client known to be
//! healthy elsewhere, so capacity/duration qualification has to be checked
//! per transport, not just "did it respond to a port probe".
//!
//! The hard rule this module enforces structurally: a caller can only ever
//! obtain a `ListenerLease` for a port present in the `allowlist` it was
//! constructed with. There is no code path here that contacts a port
//! outside that set -- this is not a policy comment, it's what `lease()`
//! actually checks before returning anything.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizedListener {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LeaseError {
    /// The exact enforcement point: this port was never in the operator-
    /// supplied allowlist, so no attempt to contact it is made.
    PortNotAuthorized { port: u16 },
    AllListenersInUse,
    ConcurrencyCapReached { cap: usize },
}

impl std::fmt::Display for LeaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LeaseError::PortNotAuthorized { port } => {
                write!(f, "port {port} is not in the operator-authorized listener allowlist; refusing to contact it")
            }
            LeaseError::AllListenersInUse => write!(f, "all authorized listeners currently leased"),
            LeaseError::ConcurrencyCapReached { cap } => write!(f, "concurrency cap ({cap}) reached"),
        }
    }
}

/// Leases exactly one authorized listener per active session, up to a
/// caller-set concurrency cap. Never discovers ports itself -- the
/// allowlist is supplied whole by the operator at construction, and nothing
/// in this type has a scanning code path.
pub struct ListenerPool {
    allowlist: Vec<AuthorizedListener>,
    in_use: Arc<Mutex<HashSet<u16>>>,
    max_concurrency: usize,
}

pub struct ListenerLease {
    pub listener: AuthorizedListener,
    in_use: Arc<Mutex<HashSet<u16>>>,
}

impl Drop for ListenerLease {
    fn drop(&mut self) {
        self.in_use.lock().unwrap().remove(&self.listener.port);
    }
}

impl ListenerPool {
    pub fn new(allowlist: Vec<AuthorizedListener>, max_concurrency: usize) -> Self {
        Self { allowlist, in_use: Arc::new(Mutex::new(HashSet::new())), max_concurrency }
    }

    pub fn is_authorized(&self, port: u16) -> bool {
        self.allowlist.iter().any(|l| l.port == port)
    }

    /// Leases the first authorized, not-currently-leased listener. Returns
    /// `PortNotAuthorized` only if a caller passes an explicit port request
    /// outside the allowlist via `lease_specific`; the plain `lease()` path
    /// can only ever return ports drawn from `allowlist` in the first place.
    pub fn lease(&self) -> Result<ListenerLease, LeaseError> {
        let mut in_use = self.in_use.lock().unwrap();
        let free = self.allowlist.iter().find(|l| !in_use.contains(&l.port));
        // Distinguish "no authorized listener is free" from "the cap
        // itself is the limiting factor" even when they coincide, so a
        // caller can tell which knob (allowlist size vs concurrency) to
        // turn: checking free-listener existence first means an exhausted
        // allowlist reports AllListenersInUse rather than the cap, which
        // would be misleading when the cap is equal to or above the
        // allowlist size.
        let Some(l) = free else {
            return Err(LeaseError::AllListenersInUse);
        };
        if in_use.len() >= self.max_concurrency {
            return Err(LeaseError::ConcurrencyCapReached { cap: self.max_concurrency });
        }
        in_use.insert(l.port);
        Ok(ListenerLease { listener: l.clone(), in_use: self.in_use.clone() })
    }

    pub fn lease_specific(&self, port: u16) -> Result<ListenerLease, LeaseError> {
        // Look the port up in the allowlist directly, rather than trusting
        // `is_authorized` plus a second separate lookup to stay in sync.
        // The refusal path is this module's safety behavior -- it must be
        // the most robust path here, never one that can panic if the two
        // checks ever drift apart.
        let Some(listener) = self.allowlist.iter().find(|l| l.port == port) else {
            return Err(LeaseError::PortNotAuthorized { port });
        };
        let mut in_use = self.in_use.lock().unwrap();
        if in_use.len() >= self.max_concurrency {
            return Err(LeaseError::ConcurrencyCapReached { cap: self.max_concurrency });
        }
        if in_use.contains(&port) {
            return Err(LeaseError::AllListenersInUse);
        }
        let listener = listener.clone();
        in_use.insert(port);
        Ok(ListenerLease { listener, in_use: self.in_use.clone() })
    }

    pub fn leased_count(&self) -> usize {
        self.in_use.lock().unwrap().len()
    }
}

/// Endpoint loss floor by client/iperf version, from the field's reverse-UDP
/// measurements. Declared alongside any loss figure from a public listener
/// so "0.7% loss" is legible as "within/above the endpoint's own floor"
/// rather than an unqualified network claim.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct EndpointLossFloor {
    pub client_version_family: &'static str,
    pub floor_pct_low: f64,
    pub floor_pct_high: f64,
}

pub fn estimate_loss_floor(iperf_version: &str) -> EndpointLossFloor {
    // iperf3 3.9 is the "old client" the field notes attribute the
    // 0.6-1.0% reverse-UDP floor to. Newer clients (3.16+) were not observed
    // to carry the same floor in the source investigation, so they get a
    // materially lower, still-nonzero default rather than a false 0.0,
    // which would claim more certainty than was measured.
    if iperf_version.contains("3.9") {
        EndpointLossFloor { client_version_family: "iperf3-3.9", floor_pct_low: 0.6, floor_pct_high: 1.0 }
    } else {
        EndpointLossFloor { client_version_family: "iperf3-other", floor_pct_low: 0.0, floor_pct_high: 0.2 }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Transport {
    Tcp,
    Udp,
}

/// Per-transport capacity/duration consistency check, the fix for the
/// XMission Colorado case: a "44.6 Mbps" summary whose reported duration
/// does not match the requested one is not a capacity measurement, it is
/// evidence the run itself was truncated or malformed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapacityCheck {
    pub transport: Transport,
    pub requested_duration_secs: f64,
    pub reported_duration_secs: f64,
    pub receiver_bits_per_second: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CapacityVerdict {
    Consistent,
    DurationInconsistent { requested_secs: f64, reported_secs: f64 },
}

/// A reported duration more than this fraction away from what was requested
/// invalidates the capacity figure that came with it.
const DURATION_TOLERANCE_FRACTION: f64 = 0.15;

pub fn qualify_capacity(check: &CapacityCheck) -> CapacityVerdict {
    if check.requested_duration_secs <= 0.0 {
        return CapacityVerdict::DurationInconsistent {
            requested_secs: check.requested_duration_secs,
            reported_secs: check.reported_duration_secs,
        };
    }
    let delta = (check.reported_duration_secs - check.requested_duration_secs).abs()
        / check.requested_duration_secs;
    if delta > DURATION_TOLERANCE_FRACTION {
        CapacityVerdict::DurationInconsistent {
            requested_secs: check.requested_duration_secs,
            reported_secs: check.reported_duration_secs,
        }
    } else {
        CapacityVerdict::Consistent
    }
}

/// Detects a busy/rate-limited response distinct from a genuine transfer
/// result: iperf3 servers refuse a new session outright ("server is busy")
/// rather than returning a low-throughput normal completion.
pub fn is_busy_or_rate_limited(error_text: &str) -> bool {
    let lower = error_text.to_lowercase();
    lower.contains("busy") || lower.contains("too many") || lower.contains("rate limit")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool(ports: &[u16], cap: usize) -> ListenerPool {
        let allowlist = ports
            .iter()
            .map(|p| AuthorizedListener { host: "example.test".to_string(), port: *p })
            .collect();
        ListenerPool::new(allowlist, cap)
    }

    #[test]
    fn lease_specific_refuses_a_port_outside_the_allowlist() {
        let p = pool(&[5201, 5202], 2);
        let result = p.lease_specific(9999);
        assert_eq!(result.err(), Some(LeaseError::PortNotAuthorized { port: 9999 }));
    }

    #[test]
    fn lease_never_returns_a_port_outside_the_allowlist() {
        let p = pool(&[5201, 5202], 2);
        let l1 = p.lease().unwrap();
        let l2 = p.lease().unwrap();
        assert!(p.is_authorized(l1.listener.port));
        assert!(p.is_authorized(l2.listener.port));
    }

    #[test]
    fn one_listener_per_active_session_enforced() {
        let p = pool(&[5201], 1);
        let _l1 = p.lease().unwrap();
        let err = p.lease();
        assert!(matches!(err, Err(LeaseError::AllListenersInUse)));
    }

    #[test]
    fn concurrency_cap_enforced_below_allowlist_size() {
        let p = pool(&[5201, 5202, 5203], 2);
        let _l1 = p.lease().unwrap();
        let _l2 = p.lease().unwrap();
        let err = p.lease();
        assert!(matches!(err, Err(LeaseError::ConcurrencyCapReached { cap: 2 })));
    }

    #[test]
    fn lease_is_released_on_drop() {
        let p = pool(&[5201], 1);
        {
            let _l1 = p.lease().unwrap();
            assert_eq!(p.leased_count(), 1);
        }
        assert_eq!(p.leased_count(), 0);
        assert!(p.lease().is_ok());
    }

    #[test]
    fn old_client_gets_a_nonzero_declared_loss_floor() {
        let floor = estimate_loss_floor("iperf 3.9");
        assert_eq!(floor.client_version_family, "iperf3-3.9");
        assert!(floor.floor_pct_low > 0.0);
    }

    #[test]
    fn duration_inconsistent_capacity_is_rejected() {
        // The XMission-Colorado shape: requested 10s, reported ~15.84s.
        let check = CapacityCheck {
            transport: Transport::Tcp,
            requested_duration_secs: 10.0,
            reported_duration_secs: 15.84,
            receiver_bits_per_second: 44_600_000.0,
        };
        let verdict = qualify_capacity(&check);
        assert!(matches!(verdict, CapacityVerdict::DurationInconsistent { .. }));
    }

    #[test]
    fn consistent_duration_is_accepted() {
        let check = CapacityCheck {
            transport: Transport::Tcp,
            requested_duration_secs: 10.0,
            reported_duration_secs: 10.3,
            receiver_bits_per_second: 100_000_000.0,
        };
        assert_eq!(qualify_capacity(&check), CapacityVerdict::Consistent);
    }

    #[test]
    fn busy_response_detected_distinct_from_low_throughput() {
        assert!(is_busy_or_rate_limited("server is busy running a test"));
        assert!(!is_busy_or_rate_limited("connection reset by peer"));
    }
}
