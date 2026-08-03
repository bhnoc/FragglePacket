//! GAP-014: DNS steering comparison.
//!
//! `dns_secure.rs` already answers "does UDP/DoT/DoH work" -- all three
//! channels can be perfectly healthy while steering a client to different
//! CDN edges. Field evidence: internal and public resolvers returned
//! different GitHub edge IPs for the same query. A performance comparison
//! that used two different resolvers across its legs measured two
//! different endpoints, not one endpoint under two conditions -- and it
//! would look identical to a real endpoint regression.
//!
//! This module queries the same name against multiple resolvers (via
//! `dig @<resolver>`, matching this crate's existing DNS-testing idiom in
//! `dns.rs`/`dns_secure.rs`) for A/AAAA/HTTPS/SVCB, and reports whether the
//! answer sets diverge -- never which resolver is "right", since a
//! steering difference is not itself a fault.

use std::collections::BTreeSet;
use std::process::Command;
use std::time::Instant;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RecordType {
    A,
    Aaaa,
    Https,
    Svcb,
}

impl RecordType {
    fn dig_arg(&self) -> &'static str {
        match self {
            RecordType::A => "A",
            RecordType::Aaaa => "AAAA",
            RecordType::Https => "HTTPS",
            RecordType::Svcb => "SVCB",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnswerRecord {
    pub record_type: RecordType,
    pub value: String,
    pub ttl_secs: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolverResult {
    pub resolver: String,
    pub query_time_ms: Option<u64>,
    pub answers: Vec<AnswerRecord>,
    /// `None` means the query itself failed to run (dig missing, timeout);
    /// distinct from a successful query with zero answers (record absent).
    pub error: Option<String>,
}

impl ResolverResult {
    pub fn answered(&self) -> bool {
        self.error.is_none()
    }

    /// The endpoint-selection-relevant subset of answers: A/AAAA addresses
    /// this resolver would send a client to. HTTPS/SVCB carry ALPN/hints
    /// that affect protocol selection but are not themselves "the
    /// destination" the way an A/AAAA record is.
    pub fn endpoint_addresses(&self) -> BTreeSet<&str> {
        self.answers
            .iter()
            .filter(|a| matches!(a.record_type, RecordType::A | RecordType::Aaaa))
            .map(|a| a.value.as_str())
            .collect()
    }
}

fn run_dig(resolver: &str, name: &str, record_type: RecordType, timeout_secs: u64) -> ResolverResult {
    let start = Instant::now();
    let output = Command::new("dig")
        .args([
            &format!("@{}", resolver),
            name,
            record_type.dig_arg(),
            "+noall",
            "+answer",
            &format!("+time={}", timeout_secs),
            "+tries=1",
        ])
        .output();

    let elapsed_ms = start.elapsed().as_millis() as u64;

    let output = match output {
        Ok(o) => o,
        Err(e) => {
            return ResolverResult {
                resolver: resolver.to_string(),
                query_time_ms: None,
                answers: vec![],
                error: Some(format!("failed to run dig: {}", e)),
            }
        }
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return ResolverResult {
            resolver: resolver.to_string(),
            query_time_ms: Some(elapsed_ms),
            answers: vec![],
            error: Some(if stderr.is_empty() { "dig exited with an error".to_string() } else { stderr }),
        };
    }

    let text = String::from_utf8_lossy(&output.stdout);
    let answers = parse_dig_answers(&text, record_type);

    ResolverResult { resolver: resolver.to_string(), query_time_ms: Some(elapsed_ms), answers, error: None }
}

/// Parses `dig +noall +answer` output: `name ttl IN TYPE value...`.
/// A record absent is zero lines, not an error -- HTTPS/SVCB in particular
/// are frequently unadvertised, and that must read as "not advertised",
/// never as a query failure.
fn parse_dig_answers(text: &str, requested: RecordType) -> Vec<AnswerRecord> {
    let mut out = Vec::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 5 {
            continue;
        }
        let ttl = fields[1].parse::<u32>().ok();
        let value = fields[4..].join(" ");
        out.push(AnswerRecord { record_type: requested, value, ttl_secs: ttl });
    }
    out
}

/// Runs every record type against one resolver.
pub fn query_resolver(resolver: &str, name: &str, timeout_secs: u64) -> Vec<ResolverResult> {
    [RecordType::A, RecordType::Aaaa, RecordType::Https, RecordType::Svcb]
        .iter()
        .map(|&rt| run_dig(resolver, name, rt, timeout_secs))
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SteeringVerdict {
    /// All resolvers that answered returned the same endpoint address set.
    Consistent,
    /// At least two resolvers that both answered returned different
    /// endpoint address sets -- steering divergence, not an error state.
    Diverges,
    /// Fewer than two resolvers answered, so divergence cannot be assessed.
    Inconclusive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SteeringComparison {
    pub name: String,
    pub per_resolver: Vec<Vec<ResolverResult>>,
    pub verdict: SteeringVerdict,
    pub explanation: String,
}

/// Compares A/AAAA/HTTPS/SVCB answers across resolvers and reports
/// divergence. Never labels one resolver "wrong" -- different answers from
/// healthy resolvers are steering, not a fault in either.
pub fn compare_steering(name: &str, resolvers: &[String], timeout_secs: u64) -> SteeringComparison {
    let per_resolver: Vec<Vec<ResolverResult>> =
        resolvers.iter().map(|r| query_resolver(r, name, timeout_secs)).collect();
    let (verdict, explanation) = decide_verdict(&per_resolver, resolvers.len());
    SteeringComparison { name: name.to_string(), per_resolver, verdict, explanation }
}

/// Pure decision logic, factored out of `compare_steering` so it is
/// testable without shelling out to `dig`.
fn decide_verdict(per_resolver: &[Vec<ResolverResult>], resolver_count: usize) -> (SteeringVerdict, String) {
    let answered: Vec<&Vec<ResolverResult>> = per_resolver
        .iter()
        .filter(|results| results.iter().any(|r| r.answered() && !r.endpoint_addresses().is_empty()))
        .collect();

    if answered.len() < 2 {
        return (
            SteeringVerdict::Inconclusive,
            format!(
                "only {} of {} resolvers returned endpoint addresses; steering divergence requires at least two answering resolvers to compare",
                answered.len(),
                resolver_count
            ),
        );
    }

    let endpoint_sets: Vec<BTreeSet<&str>> = answered
        .iter()
        .map(|results| {
            results.iter().filter(|r| r.answered()).flat_map(|r| r.endpoint_addresses()).collect::<BTreeSet<&str>>()
        })
        .collect();

    let first = &endpoint_sets[0];
    let all_same = endpoint_sets.iter().all(|s| s == first);

    if all_same {
        (SteeringVerdict::Consistent, "all answering resolvers returned the same endpoint address set".to_string())
    } else {
        (
            SteeringVerdict::Diverges,
            "resolvers returned different endpoint address sets for the same name -- this is steering divergence, not a fault in either resolver; any performance comparison spanning these resolvers measured different endpoints".to_string(),
        )
    }
}

/// GAP-014's warning mirror of `protocol-compare`'s endpoint-mismatch
/// check: flags a comparison whose legs used different resolvers.
pub fn resolver_mismatch_warning(leg_resolvers: &[String]) -> Option<String> {
    let unique: BTreeSet<&String> = leg_resolvers.iter().collect();
    if unique.len() > 1 {
        Some(format!(
            "comparison legs used different resolvers ({}); any performance delta may reflect resolver steering, not the condition under test",
            leg_resolvers.join(", ")
        ))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_result(resolver: &str, addr: &str) -> Vec<ResolverResult> {
        vec![ResolverResult {
            resolver: resolver.to_string(),
            query_time_ms: Some(10),
            answers: vec![AnswerRecord { record_type: RecordType::A, value: addr.to_string(), ttl_secs: Some(60) }],
            error: None,
        }]
    }

    #[test]
    fn parses_dig_answer_line_with_ttl() {
        let text = "github.com.\t\t46\tIN\tA\t140.82.112.3\n";
        let answers = parse_dig_answers(text, RecordType::A);
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0].value, "140.82.112.3");
        assert_eq!(answers[0].ttl_secs, Some(46));
    }

    #[test]
    fn empty_answer_is_absent_not_error() {
        let answers = parse_dig_answers("", RecordType::Https);
        assert!(answers.is_empty());
    }

    #[test]
    fn identical_endpoints_report_consistent() {
        let a = synthetic_result("1.1.1.1", "140.82.112.3");
        let b = synthetic_result("8.8.8.8", "140.82.112.3");
        let (verdict, _) = decide_verdict(&[a, b], 2);
        assert_eq!(verdict, SteeringVerdict::Consistent);
    }

    #[test]
    fn different_endpoints_are_divergence_not_a_fault_label() {
        let a = synthetic_result("internal-dns", "10.0.0.5");
        let b = synthetic_result("8.8.8.8", "140.82.112.3");
        let (verdict, explanation) = decide_verdict(&[a, b], 2);
        assert_eq!(verdict, SteeringVerdict::Diverges);
        assert!(!explanation.to_lowercase().contains("wrong"));
        assert!(!explanation.to_lowercase().contains("incorrect"));
    }

    #[test]
    fn mismatch_warning_fires_only_on_different_resolvers() {
        assert!(resolver_mismatch_warning(&["1.1.1.1".to_string(), "8.8.8.8".to_string()]).is_some());
        assert!(resolver_mismatch_warning(&["1.1.1.1".to_string(), "1.1.1.1".to_string()]).is_none());
    }

    #[test]
    fn fewer_than_two_answering_resolvers_is_inconclusive() {
        let comparison =
            compare_steering("nonexistent-host-for-testing.invalid.", &["127.0.0.1".to_string()], 1);
        assert_eq!(comparison.verdict, SteeringVerdict::Inconclusive);
    }
}
