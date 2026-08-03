//! GAP-065: expected-policy and service-reachability manifest.
//!
//! Conference networks intentionally block some east-west traffic and
//! allow different services by role/SSID/VLAN. A generic reachability
//! sweep with a bare pass/fail either reports correct isolation as an
//! outage, or misses a genuinely wrong authorization policy -- both
//! failures come from not having the operator's INTENDED policy to judge
//! against. `multicast_isolation.rs` (GAP-057) already established this
//! shape for discovery/isolation specifically (`ExpectedPolicy`,
//! `Observation`, `judge()`); this module generalizes it to arbitrary
//! role/zone/destination/protocol/port entries. If GAP-057's structure
//! should converge on this one, that is a follow-up, not done here --
//! this module does not modify `multicast_isolation.rs`.
//!
//! The manifest IS the allowlist: `PolicyManifest::new` takes the whole
//! set of entries at construction, and `probe_entry`/`run_all` only ever
//! contact a `(host, port)` drawn from an entry already in that set.
//! There is no discovery, no range expansion, no code path that builds a
//! destination string from anything other than an existing entry's
//! `destination` field.

use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExpectedOutcome {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyEntry {
    pub role: String,
    pub source_zone: String,
    pub destination_host: String,
    pub destination_port: u16,
    pub protocol: Protocol,
    pub expected: ExpectedOutcome,
    /// If set, an HTTP GET is issued and a 3xx response is reported as
    /// `ObservedOutcome::Redirected` rather than `Reachable` -- a captive
    /// portal answering is a different finding than the real destination
    /// answering, even though both are "the TCP connect succeeded".
    pub http_check_path: Option<String>,
}

/// What was actually observed, kept as three structurally distinct states
/// per the acceptance criteria: a RST/refused is a firewall saying no, a
/// timeout is silence (could be a drop rule OR real unreachability), and a
/// redirect is a captive portal or HTTP-level policy device intercepting
/// the connection rather than the destination answering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObservedOutcome {
    Reachable,
    Rejected,
    TimedOut,
    Redirected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResult {
    pub entry_index: usize,
    pub observed: ObservedOutcome,
    pub elapsed_ms: u64,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DriftVerdict {
    MatchesExpectation,
    /// Expected `Deny` but the destination was reachable -- a policy hole.
    UnexpectedlyAllowed,
    /// Expected `Allow` but the destination was rejected/timed out -- a
    /// service outage or an overly aggressive policy change.
    UnexpectedlyBlocked,
    /// A redirect (captive portal) is neither a clean allow nor deny;
    /// reported as drift only when the entry expected a clean Allow,
    /// since a portal intercepting expected-open traffic is itself a
    /// finding worth surfacing, distinct from a firewall deny.
    InterceptedByPortal,
}

pub fn judge_drift(expected: ExpectedOutcome, observed: ObservedOutcome) -> DriftVerdict {
    match (expected, observed) {
        (ExpectedOutcome::Allow, ObservedOutcome::Reachable) => DriftVerdict::MatchesExpectation,
        (ExpectedOutcome::Deny, ObservedOutcome::Rejected) => DriftVerdict::MatchesExpectation,
        (ExpectedOutcome::Deny, ObservedOutcome::TimedOut) => DriftVerdict::MatchesExpectation,
        (ExpectedOutcome::Deny, ObservedOutcome::Reachable) => DriftVerdict::UnexpectedlyAllowed,
        (ExpectedOutcome::Deny, ObservedOutcome::Redirected) => DriftVerdict::UnexpectedlyAllowed,
        (ExpectedOutcome::Allow, ObservedOutcome::Rejected) => DriftVerdict::UnexpectedlyBlocked,
        (ExpectedOutcome::Allow, ObservedOutcome::TimedOut) => DriftVerdict::UnexpectedlyBlocked,
        (ExpectedOutcome::Allow, ObservedOutcome::Redirected) => DriftVerdict::InterceptedByPortal,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryReport {
    pub entry_index: usize,
    pub role: String,
    pub source_zone: String,
    pub protocol: Protocol,
    pub expected: ExpectedOutcome,
    pub observed: ObservedOutcome,
    pub drift: DriftVerdict,
    pub elapsed_ms: u64,
    /// Present only when producing an operator-facing report; see
    /// `PolicyManifest::report`.
    pub destination_host: Option<String>,
    pub destination_port: Option<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReportMode {
    /// Full detail including internal hostnames/ports -- for the operator
    /// running the diagnostic.
    Operator,
    /// Topology-redacted -- for anything shown to attendees. No hostname,
    /// no port, no source zone name beyond the declared role label.
    AttendeeFacing,
}

pub struct PolicyManifest {
    entries: Vec<PolicyEntry>,
}

impl PolicyManifest {
    /// The manifest IS the allowlist: constructing one from `entries`
    /// fixes the entire set of destinations this manifest will ever
    /// contact. There is no method on this type that adds an entry after
    /// construction or accepts a destination not already present here.
    pub fn new(entries: Vec<PolicyEntry>) -> Self {
        PolicyManifest { entries }
    }

    pub fn entries(&self) -> &[PolicyEntry] {
        &self.entries
    }

    /// Probes exactly the entry at `index` -- never a host/port supplied
    /// by the caller directly. This is the enforcement point: the only
    /// way to get a `(host, port)` into `probe_one` is to have it already
    /// present in `self.entries`.
    pub fn probe_entry(&self, index: usize, timeout: Duration) -> Option<ProbeResult> {
        let entry = self.entries.get(index)?;
        Some(probe_one(index, entry, timeout))
    }

    pub fn run_all(&self, timeout: Duration) -> Vec<ProbeResult> {
        (0..self.entries.len())
            .filter_map(|i| self.probe_entry(i, timeout))
            .collect()
    }

    pub fn report(&self, results: &[ProbeResult], mode: ReportMode) -> Vec<EntryReport> {
        results
            .iter()
            .filter_map(|r| {
                let entry = self.entries.get(r.entry_index)?;
                let drift = judge_drift(entry.expected, r.observed);
                Some(EntryReport {
                    entry_index: r.entry_index,
                    role: entry.role.clone(),
                    source_zone: entry.source_zone.clone(),
                    protocol: entry.protocol,
                    expected: entry.expected,
                    observed: r.observed,
                    drift,
                    elapsed_ms: r.elapsed_ms,
                    destination_host: match mode {
                        ReportMode::Operator => Some(entry.destination_host.clone()),
                        ReportMode::AttendeeFacing => None,
                    },
                    destination_port: match mode {
                        ReportMode::Operator => Some(entry.destination_port),
                        ReportMode::AttendeeFacing => None,
                    },
                })
            })
            .collect()
    }
}

fn probe_one(index: usize, entry: &PolicyEntry, timeout: Duration) -> ProbeResult {
    let start = Instant::now();
    let addr =
        match format!("{}:{}", entry.destination_host, entry.destination_port).to_socket_addrs() {
            Ok(mut addrs) => addrs.next(),
            Err(_) => None,
        };

    let addr = match addr {
        Some(a) => a,
        None => {
            return ProbeResult {
                entry_index: index,
                observed: ObservedOutcome::TimedOut,
                elapsed_ms: start.elapsed().as_millis() as u64,
                detail: "DNS resolution failed for the manifest-declared destination".to_string(),
            }
        }
    };

    let stream = match TcpStream::connect_timeout(&addr, timeout) {
        Ok(s) => s,
        Err(e) => {
            let observed = classify_connect_error(&e);
            return ProbeResult {
                entry_index: index,
                observed,
                elapsed_ms: start.elapsed().as_millis() as u64,
                detail: e.to_string(),
            };
        }
    };

    if let Some(path) = &entry.http_check_path {
        if let Some(status) = http_get_status(stream, &entry.destination_host, path, timeout) {
            if (300..400).contains(&status) {
                return ProbeResult {
                    entry_index: index,
                    observed: ObservedOutcome::Redirected,
                    elapsed_ms: start.elapsed().as_millis() as u64,
                    detail: format!("HTTP {status} redirect"),
                };
            }
        }
    }

    ProbeResult {
        entry_index: index,
        observed: ObservedOutcome::Reachable,
        elapsed_ms: start.elapsed().as_millis() as u64,
        detail: "connect succeeded".to_string(),
    }
}

/// A RST/refused is what a firewall produces closing a port on purpose; a
/// timeout is silence -- both real signals, kept apart. Same
/// classification discipline as `dependency_health::classify_dependency_error`,
/// reproduced locally rather than importing that module's `Verdict` type,
/// since this module's drift semantics (`ObservedOutcome`) are a distinct
/// vocabulary the manifest's own consumers need, not a dependency-health
/// blocked-vs-unhealthy split.
fn classify_connect_error(e: &std::io::Error) -> ObservedOutcome {
    use std::io::ErrorKind;
    match e.kind() {
        ErrorKind::ConnectionRefused | ErrorKind::ConnectionReset => ObservedOutcome::Rejected,
        _ => ObservedOutcome::TimedOut,
    }
}

fn http_get_status(
    mut stream: TcpStream,
    host: &str,
    path: &str,
    timeout: Duration,
) -> Option<u16> {
    use std::io::{Read, Write};
    stream.set_read_timeout(Some(timeout)).ok();
    stream.set_write_timeout(Some(timeout)).ok();
    let request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).ok()?;
    let mut buf = [0u8; 512];
    let n = stream.read(&mut buf).ok()?;
    let text = String::from_utf8_lossy(&buf[..n]);
    let status_line = text.lines().next()?;
    let code_str = status_line.split_whitespace().nth(1)?;
    code_str.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(expected: ExpectedOutcome) -> PolicyEntry {
        PolicyEntry {
            role: "guest".to_string(),
            source_zone: "wlan-guest".to_string(),
            destination_host: "127.0.0.1".to_string(),
            destination_port: 9,
            protocol: Protocol::Tcp,
            expected,
            http_check_path: None,
        }
    }

    #[test]
    fn probing_only_indexes_from_the_manifest_never_an_arbitrary_host() {
        // The manifest is constructed with exactly one entry; probe_entry
        // for any other index must return None, never synthesize a probe.
        let manifest = PolicyManifest::new(vec![entry(ExpectedOutcome::Deny)]);
        assert!(manifest
            .probe_entry(1, Duration::from_millis(100))
            .is_none());
        assert!(manifest
            .probe_entry(0, Duration::from_millis(100))
            .is_some());
    }

    #[test]
    fn expected_deny_reachable_is_unexpectedly_allowed() {
        assert_eq!(
            judge_drift(ExpectedOutcome::Deny, ObservedOutcome::Reachable),
            DriftVerdict::UnexpectedlyAllowed
        );
    }

    #[test]
    fn expected_allow_rejected_is_unexpectedly_blocked() {
        assert_eq!(
            judge_drift(ExpectedOutcome::Allow, ObservedOutcome::Rejected),
            DriftVerdict::UnexpectedlyBlocked
        );
    }

    #[test]
    fn expected_deny_timed_out_matches_expectation() {
        assert_eq!(
            judge_drift(ExpectedOutcome::Deny, ObservedOutcome::TimedOut),
            DriftVerdict::MatchesExpectation
        );
    }

    #[test]
    fn expected_allow_reachable_matches_expectation() {
        assert_eq!(
            judge_drift(ExpectedOutcome::Allow, ObservedOutcome::Reachable),
            DriftVerdict::MatchesExpectation
        );
    }

    #[test]
    fn redirect_on_expected_allow_is_intercepted_not_a_clean_match() {
        assert_eq!(
            judge_drift(ExpectedOutcome::Allow, ObservedOutcome::Redirected),
            DriftVerdict::InterceptedByPortal
        );
    }

    #[test]
    fn timeout_reject_redirect_are_three_distinct_variants() {
        let variants = [
            ObservedOutcome::TimedOut,
            ObservedOutcome::Rejected,
            ObservedOutcome::Redirected,
        ];
        for i in 0..variants.len() {
            for j in 0..variants.len() {
                if i != j {
                    assert_ne!(variants[i], variants[j]);
                }
            }
        }
    }

    #[test]
    fn attendee_facing_report_carries_no_hostname_or_port() {
        let manifest = PolicyManifest::new(vec![entry(ExpectedOutcome::Deny)]);
        let results = vec![ProbeResult {
            entry_index: 0,
            observed: ObservedOutcome::Rejected,
            elapsed_ms: 5,
            detail: "connection refused".to_string(),
        }];
        let report = manifest.report(&results, ReportMode::AttendeeFacing);
        assert_eq!(report.len(), 1);
        assert!(report[0].destination_host.is_none());
        assert!(report[0].destination_port.is_none());
    }

    #[test]
    fn operator_report_carries_hostname_and_port() {
        let manifest = PolicyManifest::new(vec![entry(ExpectedOutcome::Deny)]);
        let results = vec![ProbeResult {
            entry_index: 0,
            observed: ObservedOutcome::Rejected,
            elapsed_ms: 5,
            detail: "connection refused".to_string(),
        }];
        let report = manifest.report(&results, ReportMode::Operator);
        assert_eq!(report[0].destination_host.as_deref(), Some("127.0.0.1"));
        assert_eq!(report[0].destination_port, Some(9));
    }

    #[test]
    fn refused_connection_classifies_as_rejected_not_timed_out() {
        let e = std::io::Error::from(std::io::ErrorKind::ConnectionRefused);
        assert_eq!(classify_connect_error(&e), ObservedOutcome::Rejected);
    }

    #[test]
    fn generic_io_error_classifies_as_timed_out() {
        let e = std::io::Error::from(std::io::ErrorKind::TimedOut);
        assert_eq!(classify_connect_error(&e), ObservedOutcome::TimedOut);
    }
}
