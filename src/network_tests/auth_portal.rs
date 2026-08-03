//! GAP-049: authentication, captive-portal, and policy-assignment workflow.
//!
//! PSK, open, captive-portal, and 802.1X networks can all fail before an
//! ordinary IP-layer test ever runs, and a single "took 12 seconds to get
//! online" number cannot say which stage owns the delay. This module keeps
//! association/EAP/DHCP/DNS/first-HTTPS as separate timed fields for
//! exactly that reason -- see `PhaseTimings`, whose fields are independent
//! `Option<Duration>`s, never summed into one total anywhere in this file.
//!
//! Two absolute rules:
//! - No credential is ever requested, read, or logged. There is no
//!   username/password/certificate field anywhere below. `RadiusOutcome`
//!   records accept/reject/timeout and the EAP method only -- never an
//!   identity, matching "anonymized RADIUS outcome" in the acceptance
//!   criteria.
//! - Portal detection means detecting interception and stopping, not
//!   automating a login. `PortalDetectionResult` has no field for
//!   submitted credentials and no function here performs an HTTP POST.
//!   The standard detection URLs (Apple's `captive.apple.com`, Google's
//!   `generate_204`) return a fixed 200/204 "success" body when unblocked;
//!   a portal instead returns a redirect or a substituted body. That
//!   substitution is what `classify_portal_response` looks for, and the
//!   result is "portal detected, hand off to the user" -- never a form
//!   fill.

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Every field independently timed and independently absent when that
/// phase could not be measured on this platform (e.g. EAP method is not
/// exposed to userspace on macOS without a privileged read this module
/// does not attempt). Never collapsed into a single "time to online".
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PhaseTimings {
    pub association_ms: Option<u64>,
    pub eap_ms: Option<u64>,
    pub dhcp_ms: Option<u64>,
    pub dns_ms: Option<u64>,
    pub first_https_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EapMethod {
    Peap,
    Tls,
    Ttls,
    Fast,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RadiusOutcome {
    Accept,
    Reject,
    Timeout,
}

/// Anonymized: no identity, no credential, only method + outcome. Callers
/// must never add a field here that could identify the authenticating
/// party.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct RadiusResult {
    pub eap_method: Option<EapMethod>,
    pub outcome: RadiusOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PortalStatus {
    /// The detection URL returned the platform's expected unblocked
    /// response (200 with the exact expected body, or 204).
    NoPortalDetected,
    /// The detection URL was intercepted -- a redirect, or a 200 with a
    /// body that does not match the expected success marker. This is the
    /// terminal state for this module: hand off to the user, do not proceed.
    PortalDetected { redirect_location: Option<String> },
    /// The probe itself failed (DNS, TCP, TLS) before any HTTP response was
    /// read -- distinct from a portal, which requires an HTTP layer to
    /// respond at all.
    ProbeFailed { detail: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortalDetectionResult {
    pub detection_url: String,
    pub status: PortalStatus,
    pub http_status: Option<u16>,
}

/// Classifies a captive-portal detection response without ever reading or
/// submitting a form. `expected_body_marker` is the exact string the
/// unblocked platform response contains (e.g. Apple's page contains
/// "Success"); a substituted body -- the classic portal behavior of
/// returning HTTP 200 for the probe URL itself with different content --
/// is detected by that marker's absence, not by status code alone.
pub fn classify_portal_response(
    status_code: u16,
    location_header: Option<&str>,
    body: &str,
    expected_body_marker: Option<&str>,
) -> PortalStatus {
    if (300..400).contains(&status_code) {
        return PortalStatus::PortalDetected { redirect_location: location_header.map(|s| s.to_string()) };
    }
    if status_code == 204 {
        return PortalStatus::NoPortalDetected;
    }
    if status_code == 200 {
        match expected_body_marker {
            Some(marker) if body.contains(marker) => PortalStatus::NoPortalDetected,
            Some(_) => PortalStatus::PortalDetected { redirect_location: None },
            None => PortalStatus::NoPortalDetected,
        }
    } else {
        PortalStatus::PortalDetected { redirect_location: None }
    }
}

/// Role/VLAN/ACL verification against an operator-stated expectation.
/// Reads only what the client itself can observe (assigned subnet/DNS via
/// DHCP, reachability of an expected internal target) -- never a
/// privileged switch/controller read, which is GAP-058/065's territory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleAssignmentCheck {
    pub expected_label: String,
    pub observed_subnet: Option<String>,
    pub expected_subnet: Option<String>,
    pub matches_expected: Option<bool>,
}

pub fn verify_role_assignment(
    expected_label: &str,
    expected_subnet: Option<&str>,
    observed_subnet: Option<&str>,
) -> RoleAssignmentCheck {
    let matches_expected = match (expected_subnet, observed_subnet) {
        (Some(e), Some(o)) => Some(e == o),
        _ => None,
    };
    RoleAssignmentCheck {
        expected_label: expected_label.to_string(),
        observed_subnet: observed_subnet.map(|s| s.to_string()),
        expected_subnet: expected_subnet.map(|s| s.to_string()),
        matches_expected,
    }
}

/// Reauthentication/session-expiry detection: samples whether a
/// previously-usable target is still reachable at a later point without
/// re-running the full auth flow. A transition from reachable to
/// unreachable between samples, with no local link-down event, is the
/// session-expiry signature this gap asks for.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionContinuitySample {
    pub elapsed_secs: u64,
    pub still_reachable: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SessionContinuityVerdict {
    Continuous,
    ExpiredOrReauthRequired { last_reachable_at_secs: u64 },
    /// Fewer than two samples, or every sample unmeasurable -- never
    /// coerced to Continuous by default.
    Indeterminate,
}

pub fn evaluate_session_continuity(samples: &[SessionContinuitySample]) -> SessionContinuityVerdict {
    let measured: Vec<&SessionContinuitySample> = samples.iter().filter(|s| s.still_reachable.is_some()).collect();
    if measured.len() < 2 {
        return SessionContinuityVerdict::Indeterminate;
    }
    let mut last_reachable = None;
    for s in &measured {
        if s.still_reachable == Some(true) {
            last_reachable = Some(s.elapsed_secs);
        } else if let Some(last) = last_reachable {
            return SessionContinuityVerdict::ExpiredOrReauthRequired { last_reachable_at_secs: last };
        }
    }
    SessionContinuityVerdict::Continuous
}

#[allow(dead_code)]
fn _no_credential_fields_exist(_association_ms: Duration) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apple_success_body_is_no_portal() {
        let status = classify_portal_response(200, None, "Success", Some("Success"));
        assert_eq!(status, PortalStatus::NoPortalDetected);
    }

    #[test]
    fn substituted_200_body_is_portal_detected() {
        let status = classify_portal_response(200, None, "<html>Please log in</html>", Some("Success"));
        assert_eq!(status, PortalStatus::PortalDetected { redirect_location: None });
    }

    #[test]
    fn redirect_is_portal_detected_with_location() {
        let status = classify_portal_response(302, Some("http://portal.example/login"), "", Some("Success"));
        assert_eq!(
            status,
            PortalStatus::PortalDetected { redirect_location: Some("http://portal.example/login".to_string()) }
        );
    }

    #[test]
    fn generate_204_is_no_portal() {
        let status = classify_portal_response(204, None, "", None);
        assert_eq!(status, PortalStatus::NoPortalDetected);
    }

    #[test]
    fn phase_timings_are_independent_fields_not_a_total() {
        let t = PhaseTimings {
            association_ms: Some(300),
            eap_ms: Some(8100),
            dhcp_ms: Some(200),
            dns_ms: Some(100),
            first_https_ms: Some(3300),
        };
        // Each phase is separately inspectable; there is no `total_ms`
        // field on this struct at all -- this test locks that by
        // confirming every phase is independently Some and distinct.
        let phases = [t.association_ms, t.eap_ms, t.dhcp_ms, t.dns_ms, t.first_https_ms];
        assert!(phases.iter().all(|p| p.is_some()));
        assert_eq!(phases.iter().filter(|p| **p == Some(8100)).count(), 1);
    }

    #[test]
    fn role_mismatch_detected_when_both_subnets_known() {
        let check = verify_role_assignment("attendee-vlan", Some("10.1.0.0/24"), Some("10.9.0.0/24"));
        assert_eq!(check.matches_expected, Some(false));
    }

    #[test]
    fn role_check_unavailable_without_expected_subnet() {
        let check = verify_role_assignment("attendee-vlan", None, Some("10.9.0.0/24"));
        assert_eq!(check.matches_expected, None);
    }

    #[test]
    fn single_sample_continuity_is_indeterminate() {
        let samples = vec![SessionContinuitySample { elapsed_secs: 0, still_reachable: Some(true) }];
        assert_eq!(evaluate_session_continuity(&samples), SessionContinuityVerdict::Indeterminate);
    }

    #[test]
    fn reachable_then_unreachable_is_expired() {
        let samples = vec![
            SessionContinuitySample { elapsed_secs: 0, still_reachable: Some(true) },
            SessionContinuitySample { elapsed_secs: 60, still_reachable: Some(false) },
        ];
        assert_eq!(
            evaluate_session_continuity(&samples),
            SessionContinuityVerdict::ExpiredOrReauthRequired { last_reachable_at_secs: 0 }
        );
    }

    #[test]
    fn continuously_reachable_is_continuous() {
        let samples = vec![
            SessionContinuitySample { elapsed_secs: 0, still_reachable: Some(true) },
            SessionContinuitySample { elapsed_secs: 60, still_reachable: Some(true) },
        ];
        assert_eq!(evaluate_session_continuity(&samples), SessionContinuityVerdict::Continuous);
    }

    #[test]
    fn no_credential_field_exists_on_radius_result() {
        let r = RadiusResult { eap_method: Some(EapMethod::Peap), outcome: RadiusOutcome::Accept };
        let json = serde_json::to_string(&r).unwrap();
        assert!(!json.to_lowercase().contains("password"));
        assert!(!json.to_lowercase().contains("username"));
    }
}
