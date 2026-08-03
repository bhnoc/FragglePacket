//! QUIC PMTUD
//!
//! Every tested size must earn its verdict from evidence. A size counts as
//! path-confirmed only when a QUIC handshake completes with all datagrams
//! pinned to that size, which proves the padded datagram crossed the path in
//! both directions. A successful local `send_to()` is explicitly not evidence.

use crate::framework::{
    Diagnosis, DiagnosisSeverity, NetworkTest, TestCategory, TestResult, TestStatus,
};
use crate::probe::pmtu_evidence::{probe_pmtu_evidence, SizeOutcome};
use crate::probe::resolve_hostname;
use std::error::Error;
use std::time::Duration;

pub struct QuicPmtudTest {
    port: u16,
    sizes: Vec<usize>,
    timeout_secs: u64,
}

impl QuicPmtudTest {
    pub fn new() -> Self {
        Self {
            port: 443,
            sizes: vec![1200, 1300, 1400, 1450, 1472, 1492, 1500, 8972],
            timeout_secs: 3,
        }
    }
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }
    pub fn with_sizes(mut self, sizes: Vec<usize>) -> Self {
        self.sizes = sizes;
        self
    }
}

impl Default for QuicPmtudTest {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkTest for QuicPmtudTest {
    fn name(&self) -> &str {
        "QUIC PMTU Probe"
    }
    fn category(&self) -> TestCategory {
        TestCategory::MTU
    }
    fn run(&self, target: &str) -> Result<TestResult, Box<dyn Error>> {
        let mut result =
            TestResult::new(self.name().to_string(), self.category(), target.to_string());
        result.add_metadata(
            "cli_command",
            format!(
                "for s in 1200 1300 1400 1472 1492 8972; do \
                 echo \"size $s needs a protocol response to count; a bare 'nc -u' send proves nothing\"; \
                 done  # see fraggle-packet quic {} -p {}",
                target, self.port
            ),
        );

        let ip = match resolve_hostname(target) {
            Ok(ip) => ip,
            Err(e) => {
                result.set_status(TestStatus::Failed);
                result.add_metadata("error", format!("resolve: {}", e));
                return Ok(result);
            }
        };

        let evidence = probe_pmtu_evidence(
            target,
            ip,
            self.port,
            &self.sizes,
            Duration::from_secs(self.timeout_secs),
        );

        result.add_metadata("resolved_ip", ip.to_string());
        result.add_metadata("df_applied", evidence.df.applied.to_string());
        result.add_metadata("df_detail", evidence.df.detail.clone());
        result.add_metadata("verdict", evidence.verdict.clone());

        for s in &evidence.sizes {
            result.add_metadata(format!("size_{}_outcome", s.size), s.outcome.as_str());
            result.add_metadata(format!("size_{}_detail", s.size), s.detail.clone());
        }

        match evidence.confirmed_pmtu {
            Some(c) => {
                result.add_metric("confirmed_pmtu_bytes", c as f64);
                if let Some(u) = evidence.smallest_unanswered() {
                    if u > c {
                        result.add_metric("first_unconfirmed_size", u as f64);
                        result.set_status(TestStatus::Warning);
                        result.add_diagnosis(
                            Diagnosis::new(
                                DiagnosisSeverity::Warning,
                                "QUIC path MTU ceiling observed".to_string(),
                                format!(
                                    "A QUIC handshake completed with {}-byte datagrams to {} but \
                                     not with {}-byte datagrams. The path carries the smaller size \
                                     and not the larger; the ceiling lies between them.",
                                    c, target, u
                                ),
                            )
                            .with_recommendation(
                                "Clamp the application's QUIC max_udp_payload_size below the ceiling",
                            ),
                        );
                    } else {
                        result.set_status(TestStatus::Success);
                    }
                } else {
                    result.set_status(TestStatus::Success);
                }
            }
            None => {
                // No size earned a response, so there is no path MTU to report.
                // Warning rather than Failed: the endpoint may simply not speak
                // QUIC, which is not a network fault (see GAP-025).
                result.set_status(TestStatus::Warning);
                result.add_diagnosis(
                    Diagnosis::new(
                        DiagnosisSeverity::Warning,
                        "QUIC path MTU undetermined".to_string(),
                        format!(
                            "No tested size produced a protocol-valid response from {}. This is \
                             ambiguous between a path MTU limit, filtered responses, and an \
                             endpoint that does not serve QUIC. No path MTU is reported.",
                            target
                        ),
                    )
                    .with_recommendation(
                        "Run 'fraggle-packet preflight' to check whether this endpoint offers QUIC at all",
                    )
                    .with_recommendation(
                        "Test a known-QUIC-capable endpoint such as cloudflare.com to separate endpoint from network",
                    ),
                );
            }
        }

        if !evidence.df.applied {
            result.add_diagnosis(Diagnosis::new(
                DiagnosisSeverity::Warning,
                "Don't-fragment could not be set".to_string(),
                format!(
                    "DF was requested but not applied ({}). Any confirmed size may describe \
                         fragmented delivery rather than a true path MTU.",
                    evidence.df.detail
                ),
            ));
        }

        let local_refusals: Vec<String> = evidence
            .sizes
            .iter()
            .filter(|s| s.outcome == SizeOutcome::SendFailedLocally)
            .map(|s| s.size.to_string())
            .collect();
        if !local_refusals.is_empty() {
            result.add_metadata("locally_refused_sizes", local_refusals.join(","));
        }

        Ok(result)
    }
}
