//! GAP-041: remote probe health and dependency preflight.
//!
//! Field evidence (`precog-ops` skill, 2026-08-02 inventory): one trusted
//! node had a broken iperf binary (missing `libiperf.so.0`), one
//! repeatedly timed out, and three (PV01/PV02/PV13) presented changed SSH
//! host keys. None of those are network results, and averaging a fleet
//! summary over any of them would corrupt every conclusion drawn from the
//! nodes that actually ran -- this module's entire purpose is making sure
//! none of the three ever reach a `Healthy` verdict by accident.
//!
//! The host-key case is the one that must never have an escape hatch. A
//! changed host key is indistinguishable from a machine-in-the-middle
//! without an independent side channel confirming the rotation, and this
//! module contains no code path, flag, or parameter that auto-accepts
//! one. `PreflightOutcome::HostKeyChanged` is terminal: the only way past
//! it is `confirm_host_key_rotation`, which requires the OPERATOR to
//! supply the new fingerprint out of band (matched here against what SSH
//! actually observed) -- there is no "trust it anyway" branch, and no
//! caller of this module can construct one by passing a flag, because no
//! such flag exists on any function signature below.
//!
//! This module never opens an SSH connection itself. `classify_ssh_error`
//! and every check function operate on already-produced text/status (real
//! `ssh` stderr in production, a fixture string in tests), so the
//! preflight logic is fully verifiable offline -- required for this
//! session, since no live fanout was authorized.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PreflightOutcome {
    Healthy,
    /// Terminal until `confirm_host_key_rotation` succeeds. No other path
    /// clears this state.
    HostKeyChanged { observed_fingerprint_hint: Option<String> },
    ConnectionTimedOut,
    ConnectionRefused,
    /// A binary/library dependency is broken on the remote node -- e.g.
    /// `iperf3: error while loading shared libraries: libiperf.so.0`.
    /// Distinct from a network failure: the SSH hop itself succeeded.
    DependencyBroken { detail: String },
    ClockSkewExceeded { skew_secs: f64 },
    RouteUnhealthy { detail: String },
    RadioUnassociated,
    ResourceConstrained { detail: String },
    EndpointUnreachable { detail: String },
}

impl PreflightOutcome {
    pub fn is_healthy(&self) -> bool {
        matches!(self, PreflightOutcome::Healthy)
    }

    pub fn reason(&self) -> String {
        match self {
            PreflightOutcome::Healthy => "healthy".to_string(),
            PreflightOutcome::HostKeyChanged { .. } => {
                "SSH host key changed; quarantined pending independently verified rotation".to_string()
            }
            PreflightOutcome::ConnectionTimedOut => "connection timed out".to_string(),
            PreflightOutcome::ConnectionRefused => "connection refused".to_string(),
            PreflightOutcome::DependencyBroken { detail } => format!("dependency broken: {detail}"),
            PreflightOutcome::ClockSkewExceeded { skew_secs } => format!("clock skew {skew_secs:.1}s exceeds threshold"),
            PreflightOutcome::RouteUnhealthy { detail } => format!("route unhealthy: {detail}"),
            PreflightOutcome::RadioUnassociated => "radio not associated".to_string(),
            PreflightOutcome::ResourceConstrained { detail } => format!("resource constrained: {detail}"),
            PreflightOutcome::EndpointUnreachable { detail } => format!("endpoint unreachable: {detail}"),
        }
    }
}

/// Classifies raw SSH stderr text. Matches OpenSSH's actual wording for a
/// changed host key ("REMOTE HOST IDENTIFICATION HAS CHANGED" /
/// "Host key verification failed"), never a bare exit-code heuristic --
/// an exit code alone cannot distinguish a changed key from a refused
/// connection, and conflating them would either quarantine healthy nodes
/// or, far worse, let a changed-key node slip through as a plain refusal.
pub fn classify_ssh_error(stderr: &str, exit_code: Option<i32>) -> PreflightOutcome {
    let lower = stderr.to_lowercase();
    if lower.contains("remote host identification has changed") || lower.contains("host key verification failed") {
        let hint = stderr
            .lines()
            .find(|l| l.to_lowercase().contains("fingerprint"))
            .map(|l| l.trim().to_string());
        return PreflightOutcome::HostKeyChanged { observed_fingerprint_hint: hint };
    }
    if lower.contains("connection timed out") || lower.contains("operation timed out") {
        return PreflightOutcome::ConnectionTimedOut;
    }
    if lower.contains("connection refused") {
        return PreflightOutcome::ConnectionRefused;
    }
    PreflightOutcome::EndpointUnreachable { detail: format!("ssh exit={exit_code:?}: {}", stderr.trim()) }
}

/// Classifies a remote executable's own failure output (e.g. `iperf3
/// --version` stderr), separate from SSH transport errors -- an
/// executable that fails to start is not the same evidence class as a
/// connection that never happened.
pub fn classify_dependency_check(stderr: &str, exit_code: Option<i32>) -> PreflightOutcome {
    let lower = stderr.to_lowercase();
    if lower.contains("error while loading shared libraries") || lower.contains("cannot open shared object file") {
        return PreflightOutcome::DependencyBroken { detail: stderr.trim().to_string() };
    }
    if exit_code == Some(127) {
        return PreflightOutcome::DependencyBroken { detail: "command not found (exit 127)".to_string() };
    }
    if exit_code == Some(0) {
        PreflightOutcome::Healthy
    } else {
        PreflightOutcome::DependencyBroken { detail: format!("exit={exit_code:?}: {}", stderr.trim()) }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClockCheck {
    pub remote_unix_secs: f64,
    pub local_unix_secs: f64,
}

pub const MAX_CLOCK_SKEW_SECS: f64 = 5.0;

pub fn evaluate_clock_skew(check: &ClockCheck) -> PreflightOutcome {
    let skew = (check.remote_unix_secs - check.local_unix_secs).abs();
    if skew > MAX_CLOCK_SKEW_SECS {
        PreflightOutcome::ClockSkewExceeded { skew_secs: skew }
    } else {
        PreflightOutcome::Healthy
    }
}

/// The ONLY path past `HostKeyChanged`. Requires the operator to supply
/// the new fingerprint from an independent source (e.g. the device's own
/// console, a signed inventory record) -- never from the same SSH session
/// that observed the change, which is exactly what an attacker
/// intercepting that session would also control. Returns an error, never
/// silently succeeds, if the supplied fingerprint does not match what was
/// actually observed.
pub fn confirm_host_key_rotation(
    observed_fingerprint: &str,
    operator_confirmed_fingerprint: &str,
) -> Result<(), String> {
    if observed_fingerprint.trim().is_empty() || operator_confirmed_fingerprint.trim().is_empty() {
        return Err("both observed and operator-confirmed fingerprints must be non-empty".to_string());
    }
    if observed_fingerprint.trim() == operator_confirmed_fingerprint.trim() {
        Ok(())
    } else {
        Err("operator-confirmed fingerprint does not match the observed one; rotation not verified".to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodePreflightResult {
    pub label: String,
    pub outcome: PreflightOutcome,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreflightSummary {
    pub total: usize,
    pub healthy_labels: Vec<String>,
    pub excluded_with_reason: Vec<(String, String)>,
}

pub fn summarize_preflight(results: &[NodePreflightResult]) -> PreflightSummary {
    let mut healthy = Vec::new();
    let mut excluded = Vec::new();
    for r in results {
        if r.outcome.is_healthy() {
            healthy.push(r.label.clone());
        } else {
            excluded.push((r.label.clone(), r.outcome.reason()));
        }
    }
    PreflightSummary { total: results.len(), healthy_labels: healthy, excluded_with_reason: excluded }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn changed_host_key_is_classified_and_never_healthy() {
        let stderr = "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n\
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\n\
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n\
Host key verification failed.";
        let outcome = classify_ssh_error(stderr, Some(255));
        assert!(matches!(outcome, PreflightOutcome::HostKeyChanged { .. }));
        assert!(!outcome.is_healthy());
    }

    #[test]
    fn there_is_no_flag_or_parameter_that_bypasses_host_key_changed() {
        // Structural proof, not a runtime one: classify_ssh_error takes
        // exactly (stderr, exit_code) and confirm_host_key_rotation takes
        // exactly (observed, operator_confirmed) -- neither has a boolean
        // "trust anyway" parameter. This test exists so that if either
        // signature ever grows one, the diff is visible and reviewable.
        let stderr = "Host key verification failed.";
        let outcome = classify_ssh_error(stderr, Some(255));
        assert!(matches!(outcome, PreflightOutcome::HostKeyChanged { .. }));
        // No call form of confirm_host_key_rotation succeeds without a
        // real matching fingerprint.
        assert!(confirm_host_key_rotation("", "").is_err());
        assert!(confirm_host_key_rotation("abc", "").is_err());
        assert!(confirm_host_key_rotation("abc", "xyz").is_err());
    }

    #[test]
    fn matching_operator_confirmed_fingerprint_clears_the_quarantine() {
        assert!(confirm_host_key_rotation("SHA256:abc123", "SHA256:abc123").is_ok());
    }

    #[test]
    fn mismatched_operator_confirmed_fingerprint_still_refuses() {
        assert!(confirm_host_key_rotation("SHA256:abc123", "SHA256:def456").is_err());
    }

    #[test]
    fn broken_shared_library_is_dependency_broken_not_network_failure() {
        let stderr = "iperf3: error while loading shared libraries: libiperf.so.0: cannot open shared object file";
        let outcome = classify_dependency_check(stderr, Some(127));
        assert!(matches!(outcome, PreflightOutcome::DependencyBroken { .. }));
    }

    #[test]
    fn exit_127_alone_is_dependency_broken() {
        let outcome = classify_dependency_check("", Some(127));
        assert!(matches!(outcome, PreflightOutcome::DependencyBroken { .. }));
    }

    #[test]
    fn connection_timeout_is_distinguished_from_refusal() {
        let timeout = classify_ssh_error("ssh: connect to host 10.0.0.1 port 22: Operation timed out", None);
        assert_eq!(timeout, PreflightOutcome::ConnectionTimedOut);
        let refused = classify_ssh_error("ssh: connect to host 10.0.0.1 port 22: Connection refused", None);
        assert_eq!(refused, PreflightOutcome::ConnectionRefused);
    }

    #[test]
    fn clock_skew_within_threshold_is_healthy() {
        let check = ClockCheck { remote_unix_secs: 1000.0, local_unix_secs: 1002.0 };
        assert_eq!(evaluate_clock_skew(&check), PreflightOutcome::Healthy);
    }

    #[test]
    fn clock_skew_beyond_threshold_is_flagged() {
        let check = ClockCheck { remote_unix_secs: 1000.0, local_unix_secs: 1020.0 };
        assert!(matches!(evaluate_clock_skew(&check), PreflightOutcome::ClockSkewExceeded { .. }));
    }

    #[test]
    fn summary_excludes_unhealthy_nodes_with_named_reasons_never_as_zero() {
        let results = vec![
            NodePreflightResult { label: "node-ok000001".to_string(), outcome: PreflightOutcome::Healthy },
            NodePreflightResult {
                label: "node-bad000001".to_string(),
                outcome: PreflightOutcome::HostKeyChanged { observed_fingerprint_hint: None },
            },
            NodePreflightResult {
                label: "node-bad000002".to_string(),
                outcome: PreflightOutcome::DependencyBroken { detail: "missing libiperf.so.0".to_string() },
            },
            NodePreflightResult { label: "node-bad000003".to_string(), outcome: PreflightOutcome::ConnectionTimedOut },
        ];
        let summary = summarize_preflight(&results);
        assert_eq!(summary.total, 4);
        assert_eq!(summary.healthy_labels, vec!["node-ok000001".to_string()]);
        assert_eq!(summary.excluded_with_reason.len(), 3);
        assert!(summary.excluded_with_reason.iter().any(|(_, r)| r.contains("host key changed")));
        assert!(summary.excluded_with_reason.iter().any(|(_, r)| r.contains("missing libiperf.so.0")));
        assert!(summary.excluded_with_reason.iter().any(|(_, r)| r.contains("timed out")));
    }
}
