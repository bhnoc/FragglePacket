//! GAP-053: managed internal reference-endpoint kit.
//!
//! Public iperf listeners produced admission failures, rate floors, duration
//! errors, and clock drift, all of which contaminated measurements. An internal
//! wired endpoint removes WAN, NAT, and public-server variables from a WLAN
//! question.
//!
//! The inversion that matters: **the server can invalidate the client's
//! result.** If the endpoint was CPU-saturated, dropping on its own NIC, or
//! reported an inconsistent interval, then the client's number describes the
//! endpoint rather than the network. Accepting it would attribute the server's
//! own bottleneck to the WLAN under test.

use serde::{Deserialize, Serialize};

/// Health of the reference endpoint during one client run. Every field is
/// optional so an unread counter is never treated as a healthy zero.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServerHealth {
    pub cpu_utilization_pct: Option<f64>,
    pub nic_drops: Option<u64>,
    pub nic_errors: Option<u64>,
    pub queue_drops: Option<u64>,
    /// Duration the server believes the test ran, versus what was requested.
    pub reported_interval_secs: Option<f64>,
    pub requested_interval_secs: Option<f64>,
    /// Offset against the client's clock, if measured. Required before any
    /// one-way claim; see GAP-064.
    pub clock_offset_ms: Option<f64>,
}

/// Limits the endpoint enforces on itself. A reference endpoint that its own
/// tests can exhaust is not a reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub max_concurrent_sessions: u32,
    pub max_session_secs: u32,
    pub max_rate_mbps: f64,
    /// Retention cap for server-side JSON results.
    pub max_retained_results: u32,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_concurrent_sessions: 4,
            max_session_secs: 60,
            max_rate_mbps: 1000.0,
            max_retained_results: 500,
        }
    }
}

impl ResourceLimits {
    /// Rejects a request that would exceed what this endpoint guarantees it can
    /// serve cleanly. Refusing is better than serving a degraded measurement.
    pub fn admit(&self, active_sessions: u32, secs: u32, rate_mbps: f64) -> Result<(), String> {
        if active_sessions >= self.max_concurrent_sessions {
            return Err(format!(
                "at capacity: {} of {} sessions active; a further session would degrade every \
                 concurrent measurement",
                active_sessions, self.max_concurrent_sessions
            ));
        }
        if secs > self.max_session_secs {
            return Err(format!(
                "requested {}s exceeds the {}s per-session cap",
                secs, self.max_session_secs
            ));
        }
        if rate_mbps > self.max_rate_mbps {
            return Err(format!(
                "requested {:.1} Mbps exceeds the {:.1} Mbps this endpoint guarantees",
                rate_mbps, self.max_rate_mbps
            ));
        }
        Ok(())
    }
}

/// Why a client's result was not accepted. Never a silent downgrade: the client
/// must learn its number was rejected and why.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ResultAcceptance {
    Accepted,
    /// The endpoint itself was the bottleneck or the timing was inconsistent.
    RejectedServerSide { reasons: Vec<String> },
    /// Required health telemetry was absent, so acceptance cannot be decided.
    /// Distinct from rejection: this is unknown, not bad.
    Undetermined { missing: Vec<String> },
}

/// CPU above this during a run means the endpoint, not the path, set the limit.
pub const CPU_SATURATION_PCT: f64 = 85.0;
/// Interval mismatch beyond this fraction invalidates the measurement window.
pub const INTERVAL_TOLERANCE: f64 = 0.10;

/// Decides whether a client result may be accepted, given the endpoint's own
/// health during that run.
///
/// The field evidence for the interval check: a public endpoint returned a
/// duration-inconsistent 44.6 Mbps receiver summary, and a 16-stream trial
/// produced a 15.84-second receiver duration for a shorter requested run. Both
/// are arithmetic nonsense that a naive client would have recorded as data.
pub fn evaluate(h: &ServerHealth) -> ResultAcceptance {
    let mut missing = Vec::new();
    if h.cpu_utilization_pct.is_none() {
        missing.push("cpu_utilization_pct".to_string());
    }
    if h.nic_drops.is_none() {
        missing.push("nic_drops".to_string());
    }
    if h.queue_drops.is_none() {
        missing.push("queue_drops".to_string());
    }
    if h.reported_interval_secs.is_none() || h.requested_interval_secs.is_none() {
        missing.push("interval_validity".to_string());
    }
    if !missing.is_empty() {
        return ResultAcceptance::Undetermined { missing };
    }

    let mut reasons = Vec::new();

    if let Some(cpu) = h.cpu_utilization_pct {
        if cpu >= CPU_SATURATION_PCT {
            reasons.push(format!(
                "endpoint CPU was {:.1}% during the run (>= {:.0}%), so the endpoint rather than \
                 the path set the ceiling",
                cpu, CPU_SATURATION_PCT
            ));
        }
    }
    if let Some(d) = h.nic_drops {
        if d > 0 {
            reasons.push(format!(
                "endpoint NIC dropped {} packets during the run, so observed loss is not \
                 attributable to the network under test",
                d
            ));
        }
    }
    if let Some(d) = h.queue_drops {
        if d > 0 {
            reasons.push(format!("endpoint queue dropped {} packets during the run", d));
        }
    }
    if let Some(e) = h.nic_errors {
        if e > 0 {
            reasons.push(format!("endpoint NIC recorded {} errors during the run", e));
        }
    }
    if let (Some(reported), Some(requested)) = (h.reported_interval_secs, h.requested_interval_secs)
    {
        if requested > 0.0 {
            let deviation = ((reported - requested) / requested).abs();
            if deviation > INTERVAL_TOLERANCE {
                reasons.push(format!(
                    "endpoint reported a {:.2}s interval for a {:.2}s request ({:.0}% off), so the \
                     measurement window is not trustworthy and any rate derived from it is invalid",
                    reported,
                    requested,
                    deviation * 100.0
                ));
            }
        }
    }

    if reasons.is_empty() {
        ResultAcceptance::Accepted
    } else {
        ResultAcceptance::RejectedServerSide { reasons }
    }
}

/// A calibration run proves the endpoint is clean before it is trusted as a
/// reference. Without this, a degraded endpoint silently becomes the baseline
/// every later comparison is measured against.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalibrationReport {
    pub limits: ResourceLimits,
    pub health: ServerHealth,
    pub acceptance: ResultAcceptance,
    pub clock_verified: bool,
    pub notes: Vec<String>,
}

pub fn calibrate(health: ServerHealth, limits: ResourceLimits, max_skew_ms: f64) -> CalibrationReport {
    let acceptance = evaluate(&health);
    let clock_verified = match health.clock_offset_ms {
        Some(o) => o.abs() <= max_skew_ms,
        None => false,
    };

    let mut notes = Vec::new();
    if !clock_verified {
        notes.push(match health.clock_offset_ms {
            Some(o) => format!(
                "clock offset {:.3}ms exceeds the {:.1}ms tolerance; one-way metrics against this \
                 endpoint must be refused (GAP-064)",
                o, max_skew_ms
            ),
            None => "clock offset was not measured, so one-way metrics against this endpoint must \
                     be refused rather than assumed synchronized (GAP-064)"
                .to_string(),
        });
    }
    if matches!(acceptance, ResultAcceptance::Undetermined { .. }) {
        notes.push(
            "endpoint health telemetry is incomplete, so this endpoint is not yet calibrated as a \
             reference; collect the missing fields before accepting client results against it"
                .to_string(),
        );
    }

    CalibrationReport {
        limits,
        health,
        acceptance,
        clock_verified,
        notes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn healthy() -> ServerHealth {
        ServerHealth {
            cpu_utilization_pct: Some(12.0),
            nic_drops: Some(0),
            nic_errors: Some(0),
            queue_drops: Some(0),
            reported_interval_secs: Some(10.0),
            requested_interval_secs: Some(10.0),
            clock_offset_ms: Some(1.2),
        }
    }

    #[test]
    fn a_clean_endpoint_accepts_the_result() {
        assert_eq!(evaluate(&healthy()), ResultAcceptance::Accepted);
    }

    #[test]
    fn a_cpu_saturated_endpoint_rejects_the_client_result() {
        let mut h = healthy();
        h.cpu_utilization_pct = Some(97.0);
        match evaluate(&h) {
            ResultAcceptance::RejectedServerSide { reasons } => {
                assert!(reasons.iter().any(|r| r.contains("CPU")));
            }
            other => panic!("expected server-side rejection, got {:?}", other),
        }
    }

    #[test]
    fn endpoint_nic_drops_reject_the_result() {
        let mut h = healthy();
        h.nic_drops = Some(17);
        assert!(matches!(
            evaluate(&h),
            ResultAcceptance::RejectedServerSide { .. }
        ));
    }

    #[test]
    fn a_duration_inconsistent_interval_rejects_the_result() {
        // The field case: a receiver summary whose duration does not match the
        // request, making any rate derived from it arithmetic nonsense.
        let mut h = healthy();
        h.requested_interval_secs = Some(10.0);
        h.reported_interval_secs = Some(15.84);
        match evaluate(&h) {
            ResultAcceptance::RejectedServerSide { reasons } => {
                assert!(reasons.iter().any(|r| r.contains("interval")));
            }
            other => panic!("expected rejection, got {:?}", other),
        }
    }

    #[test]
    fn missing_telemetry_is_undetermined_not_accepted() {
        let mut h = healthy();
        h.cpu_utilization_pct = None;
        match evaluate(&h) {
            ResultAcceptance::Undetermined { missing } => {
                assert!(missing.contains(&"cpu_utilization_pct".to_string()));
            }
            other => panic!("expected undetermined, got {:?}", other),
        }
    }

    #[test]
    fn missing_telemetry_never_reads_as_a_healthy_zero() {
        // An unread drop counter must not be treated as "zero drops".
        let h = ServerHealth::default();
        assert!(matches!(evaluate(&h), ResultAcceptance::Undetermined { .. }));
    }

    #[test]
    fn limits_refuse_a_session_beyond_capacity() {
        let l = ResourceLimits::default();
        assert!(l.admit(l.max_concurrent_sessions, 10, 100.0).is_err());
        assert!(l.admit(0, l.max_session_secs + 1, 100.0).is_err());
        assert!(l.admit(0, 10, l.max_rate_mbps + 1.0).is_err());
        assert!(l.admit(0, 10, 100.0).is_ok());
    }

    #[test]
    fn an_unmeasured_clock_is_never_treated_as_synchronized() {
        let mut h = healthy();
        h.clock_offset_ms = None;
        let r = calibrate(h, ResourceLimits::default(), 50.0);
        assert!(!r.clock_verified);
        assert!(r.notes.iter().any(|n| n.contains("not measured")));
    }

    #[test]
    fn a_skewed_clock_blocks_one_way_metrics() {
        let mut h = healthy();
        h.clock_offset_ms = Some(400.0);
        let r = calibrate(h, ResourceLimits::default(), 50.0);
        assert!(!r.clock_verified);
    }
}
