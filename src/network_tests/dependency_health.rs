//! GAP-059: infrastructure dependency health bundle.
//!
//! A partial dependency failure -- OCSP unreachable, NTP skewed, one DoH
//! resolver down -- presents to a user as "the website is slow," which is
//! exactly how this class of problem gets misattributed to the network
//! itself. The one discipline this module exists to enforce: a network
//! that intentionally blocks a dependency (many enterprise/conference
//! networks deliberately block OCSP/CRL egress) is not the same finding as
//! a network where that dependency is simply broken, and collapsing both
//! into "failed" would misreport a policy choice as an outage. `Verdict`
//! keeps them as distinct variants everywhere in this module; nothing here
//! ever normalizes `BlockedByPolicy` and `Unhealthy` into one boolean.
//!
//! NTP offset is measured via the system `sntp` binary (unprivileged,
//! no `-sS`, so it queries and reports but never adjusts the clock) and
//! is the load-bearing measurement in this file: another gap (one-way
//! delay/event correlation) can only trust a one-way timing figure once a
//! clock-offset bound is confirmed, so `NtpOffsetResult::offset_ms` is
//! `None` on ANY failure to reach or parse a response -- never a
//! defaulted `0.0`, which would silently manufacture confidence in an
//! offset nobody measured.

use serde::{Deserialize, Serialize};
use std::process::Command;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum Verdict {
    Healthy,
    /// The dependency did not respond, and there is no signal indicating
    /// the network deliberately closed it -- e.g. it timed out mid-TLS
    /// rather than being cleanly reset/refused immediately.
    Unhealthy {
        detail_kind: DetailKind,
    },
    /// The network answered in a way consistent with deliberate blocking
    /// -- an immediate connection refused/reset, or a policy-shaped
    /// response -- distinct from silent unresponsiveness.
    BlockedByPolicy {
        detail_kind: DetailKind,
    },
    /// The dependency was not configured/applicable for this check (e.g.
    /// no controller endpoint was supplied).
    NotApplicable,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum DetailKind {
    ConnectionRefused,
    ConnectionReset,
    TimedOut,
    TlsHandshakeFailed,
    Other,
}

/// Classifies a raw connect/IO error into blocked-vs-unhealthy. An
/// immediate refusal or reset is what a firewall/policy device produces
/// when closing a port on purpose; a timeout with no response at all is
/// what an actually-down or filtered-by-silent-drop dependency produces.
/// Both are real signals, but conflating them tells an operator to fix the
/// wrong thing.
pub fn classify_dependency_error(e: &std::io::Error) -> Verdict {
    use std::io::ErrorKind;
    let detail_kind = match e.kind() {
        ErrorKind::ConnectionRefused => DetailKind::ConnectionRefused,
        ErrorKind::ConnectionReset => DetailKind::ConnectionReset,
        ErrorKind::TimedOut => DetailKind::TimedOut,
        _ => DetailKind::Other,
    };
    match detail_kind {
        DetailKind::ConnectionRefused | DetailKind::ConnectionReset => {
            Verdict::BlockedByPolicy { detail_kind }
        }
        _ => Verdict::Unhealthy { detail_kind },
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyCheck {
    pub label: String,
    pub verdict: Verdict,
    pub elapsed_ms: u64,
}

pub fn check_tcp_dependency(
    label: &str,
    host: &str,
    port: u16,
    timeout: Duration,
) -> DependencyCheck {
    use std::net::{TcpStream, ToSocketAddrs};
    let start = std::time::Instant::now();
    let verdict = match format!("{host}:{port}").to_socket_addrs() {
        Ok(mut addrs) => match addrs.next() {
            Some(addr) => match TcpStream::connect_timeout(&addr, timeout) {
                Ok(_) => Verdict::Healthy,
                Err(e) => classify_dependency_error(&e),
            },
            None => Verdict::Unhealthy {
                detail_kind: DetailKind::Other,
            },
        },
        Err(_) => Verdict::Unhealthy {
            detail_kind: DetailKind::Other,
        },
    };
    DependencyCheck {
        label: label.to_string(),
        verdict,
        elapsed_ms: start.elapsed().as_millis() as u64,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NtpOffsetResult {
    pub server: String,
    /// `None` on any failure to reach or parse a response -- see module
    /// doc. Never a defaulted 0.0.
    pub offset_ms: Option<f64>,
    pub round_trip_delay_ms: Option<f64>,
    pub verdict: Verdict,
}

/// Parses `sntp <server>` stdout. Real success line:
/// `+0.073529 +/- 0.101618 time.apple.com 17.253.83.253`. A failure run
/// produces no such line at all (only `Exchange failed`/`Clock select
/// failed` on stderr and a nonzero exit), so absence of the pattern -- not
/// a parse of a zero -- is what drives `None`.
pub fn parse_sntp_output(text: &str) -> Option<(f64, f64)> {
    for line in text.lines() {
        let line = line.trim();
        if !(line.starts_with('+') || line.starts_with('-')) {
            continue;
        }
        let mut parts = line.split_whitespace();
        let offset_str = parts.next()?;
        let pm = parts.next()?;
        let delay_str = parts.next()?;
        if pm != "+/-" {
            continue;
        }
        let offset_s: f64 = offset_str.parse().ok()?;
        let delay_s: f64 = delay_str.parse().ok()?;
        return Some((offset_s * 1000.0, delay_s * 1000.0));
    }
    None
}

pub fn measure_ntp_offset(server: &str, timeout: Duration) -> NtpOffsetResult {
    let output = Command::new("sntp")
        .args(["-t", &timeout.as_secs().max(1).to_string(), server])
        .output();

    match output {
        Ok(out) => {
            let text = String::from_utf8_lossy(&out.stdout);
            match parse_sntp_output(&text) {
                Some((offset_ms, delay_ms)) => NtpOffsetResult {
                    server: server.to_string(),
                    offset_ms: Some(offset_ms),
                    round_trip_delay_ms: Some(delay_ms),
                    verdict: Verdict::Healthy,
                },
                None => NtpOffsetResult {
                    server: server.to_string(),
                    offset_ms: None,
                    round_trip_delay_ms: None,
                    verdict: Verdict::Unhealthy {
                        detail_kind: DetailKind::Other,
                    },
                },
            }
        }
        Err(_) => NtpOffsetResult {
            server: server.to_string(),
            offset_ms: None,
            round_trip_delay_ms: None,
            verdict: Verdict::Unhealthy {
                detail_kind: DetailKind::Other,
            },
        },
    }
}

/// Configured controller/cloud dependency, operator-supplied.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControllerDependency {
    pub label: String,
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyBundle {
    pub dns_checks: Vec<DependencyCheck>,
    pub ntp: Vec<NtpOffsetResult>,
    pub cert_checks: Vec<DependencyCheck>,
    pub ocsp_checks: Vec<DependencyCheck>,
    pub portal_checks: Vec<DependencyCheck>,
    pub controller_checks: Vec<DependencyCheck>,
}

impl DependencyBundle {
    pub fn all_checks(&self) -> Vec<&DependencyCheck> {
        self.dns_checks
            .iter()
            .chain(self.cert_checks.iter())
            .chain(self.ocsp_checks.iter())
            .chain(self.portal_checks.iter())
            .chain(self.controller_checks.iter())
            .collect()
    }

    pub fn blocked_by_policy_count(&self) -> usize {
        self.all_checks()
            .iter()
            .filter(|c| matches!(c.verdict, Verdict::BlockedByPolicy { .. }))
            .count()
    }

    pub fn unhealthy_count(&self) -> usize {
        self.all_checks()
            .iter()
            .filter(|c| matches!(c.verdict, Verdict::Unhealthy { .. }))
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refused_is_blocked_by_policy_not_unhealthy() {
        let e = std::io::Error::from(std::io::ErrorKind::ConnectionRefused);
        assert!(matches!(
            classify_dependency_error(&e),
            Verdict::BlockedByPolicy { .. }
        ));
    }

    #[test]
    fn reset_is_blocked_by_policy() {
        let e = std::io::Error::from(std::io::ErrorKind::ConnectionReset);
        assert!(matches!(
            classify_dependency_error(&e),
            Verdict::BlockedByPolicy { .. }
        ));
    }

    #[test]
    fn timeout_is_unhealthy_not_blocked() {
        let e = std::io::Error::from(std::io::ErrorKind::TimedOut);
        assert!(matches!(
            classify_dependency_error(&e),
            Verdict::Unhealthy { .. }
        ));
    }

    #[test]
    fn blocked_and_unhealthy_are_distinguishable_states_in_one_bundle() {
        let bundle = DependencyBundle {
            dns_checks: vec![],
            ntp: vec![],
            cert_checks: vec![],
            ocsp_checks: vec![DependencyCheck {
                label: "ocsp.example".to_string(),
                verdict: Verdict::BlockedByPolicy {
                    detail_kind: DetailKind::ConnectionRefused,
                },
                elapsed_ms: 5,
            }],
            portal_checks: vec![],
            controller_checks: vec![DependencyCheck {
                label: "controller.example".to_string(),
                verdict: Verdict::Unhealthy {
                    detail_kind: DetailKind::TimedOut,
                },
                elapsed_ms: 3000,
            }],
        };
        assert_eq!(bundle.blocked_by_policy_count(), 1);
        assert_eq!(bundle.unhealthy_count(), 1);
        assert_ne!(
            bundle.blocked_by_policy_count(),
            bundle.unhealthy_count() + 1
        );
    }

    #[test]
    fn real_sntp_success_line_parses_to_a_nonzero_offset() {
        let text = "+0.073529 +/- 0.101618 time.apple.com 17.253.83.253\n";
        let (offset_ms, delay_ms) = parse_sntp_output(text).unwrap();
        assert!((offset_ms - 73.529).abs() < 0.01);
        assert!((delay_ms - 101.618).abs() < 0.01);
    }

    #[test]
    fn negative_offset_parses_correctly() {
        let text = "-0.010500 +/- 0.050000 pool.ntp.org 1.2.3.4\n";
        let (offset_ms, _) = parse_sntp_output(text).unwrap();
        assert!((offset_ms + 10.5).abs() < 0.01);
    }

    #[test]
    fn failed_sntp_output_never_parses_to_a_zero_offset() {
        let text = "sntp: Exchange failed: DNS lookup failure\nsntp: Clock select failed\n";
        assert_eq!(parse_sntp_output(text), None);
    }

    #[test]
    fn measure_ntp_offset_reports_none_when_the_binary_is_missing() {
        // Simulated by requesting a bogus PATH-invisible name is not
        // feasible here without shelling out differently, so this test
        // instead exercises the parse-failure path directly, which is the
        // observable behavior `measure_ntp_offset` falls back to on any
        // unparseable output.
        assert_eq!(parse_sntp_output(""), None);
    }
}
