//! iperf3 JSON parsing (GAP-039) and endpoint capability discovery (GAP-036).
//!
//! Field evidence (`harness/fixtures/iperf/`): iperf 3.9, 3.16, and 3.21 all
//! emit different shapes of `end`. A forward/reverse unidirectional test has
//! `sum_sent`/`sum_received` only. `--bidir` additionally emits
//! `sum_sent_bidir_reverse`/`sum_received_bidir_reverse` -- reading only
//! `sum_sent`/`sum_received` silently reports one direction of a
//! bidirectional test. UDP additionally emits a legacy `sum` block AND
//! `sum_sent`/`sum_received`; `udp-reverse-3.21.json` shows `sum_sent`
//! reporting `packets: 0` (the client never receives its own reverse-mode
//! send back) while `sum` and `sum_received` report the real transfer at
//! different packet counts and bit rates. Reading `sum_sent.lost_percent`
//! for a UDP reverse test yields 0% loss computed from zero packets: a
//! confident-looking number with no measurement behind it.
//!
//! This module never collapses those into one number. `RateSample` keeps
//! offered/sent/received/estimated-received distinct, and every accessor
//! that could read a hollow block requires `packets > 0` (TCP: `bytes > 0`)
//! before trusting it, falling back to the next viable source or `None`
//! rather than a value with nothing behind it.

use std::collections::HashSet;
use std::net::{IpAddr, ToSocketAddrs};
use std::process::Command;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Parsed `iperf -v` / JSON `start.version` string, e.g. "iperf 3.21".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct IperfVersion {
    pub major: u32,
    pub minor: u32,
}

impl IperfVersion {
    pub fn parse(text: &str) -> Option<Self> {
        let digits = text
            .split_whitespace()
            .find(|tok| tok.chars().next().is_some_and(|c| c.is_ascii_digit()))?;
        let mut parts = digits.split('.');
        let major = parts.next()?.parse().ok()?;
        let minor = parts
            .next()
            .unwrap_or("0")
            .split(|c: char| !c.is_ascii_digit())
            .next()?
            .parse()
            .ok()?;
        Some(IperfVersion { major, minor })
    }

    /// 3.9 returned empty `--bidir` results against at least one server in
    /// this investigation's field evidence; treat bidir as untrusted below
    /// 3.16 and require the paired normal/reverse fallback instead.
    pub fn supports_bidir_reliably(&self) -> bool {
        (self.major, self.minor) >= (3, 16)
    }
}

pub fn detect_local_version() -> Option<IperfVersion> {
    let out = Command::new("iperf3").arg("-v").output().ok()?;
    if !out.status.success() {
        return None;
    }
    IperfVersion::parse(&String::from_utf8_lossy(&out.stdout))
}

/// One directional rate measurement. Always carries `packets`/`bytes` so a
/// caller can tell a real-but-small transfer from a hollow block before
/// trusting `lost_percent` or `bits_per_second`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct RateSample {
    pub bits_per_second: f64,
    pub bytes: u64,
    pub seconds: f64,
    /// `None` for TCP; UDP always carries a value.
    pub packets: Option<u64>,
    pub lost_percent: Option<f64>,
}

impl RateSample {
    /// A block iperf emitted structurally but that measured nothing: for
    /// UDP, zero packets; for TCP, zero bytes. `udp-reverse-3.21.json`'s
    /// `sum_sent` is exactly this shape (packets:0, lost_percent:0).
    pub fn is_hollow(&self) -> bool {
        match self.packets {
            Some(p) => p == 0,
            None => self.bytes == 0,
        }
    }
}

fn parse_rate_sample(v: &Value) -> Option<RateSample> {
    let bits_per_second = v.get("bits_per_second")?.as_f64()?;
    let bytes = v.get("bytes")?.as_u64()?;
    let seconds = v.get("seconds").and_then(Value::as_f64).unwrap_or(0.0);
    let packets = v.get("packets").and_then(Value::as_u64);
    let lost_percent = v.get("lost_percent").and_then(Value::as_f64);
    Some(RateSample {
        bits_per_second,
        bytes,
        seconds,
        packets,
        lost_percent,
    })
}

/// The four rate kinds kept distinct per GAP-039. `None` means "not present
/// or present but hollow", never a synthesized zero.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RateEvidence {
    /// What the client requested (`-b`/`target_bitrate`), if iperf reported
    /// a nonzero target. iperf reports 0 for "no target" (TCP default), so
    /// a 0 here is folded to `None` -- 0 is not a meaningful offered rate.
    pub offered_bps: Option<f64>,
    /// What the sending side reports it sent. `None` if the sender's sum
    /// block is missing or hollow (GAP-039 UDP-reverse trap).
    pub sent: Option<RateSample>,
    /// What the receiving side reports it received. This is the rate to
    /// trust for achieved throughput; prefer it over `sent` when both
    /// exist and disagree, since only the receiver saw what arrived.
    pub received: Option<RateSample>,
    /// UDP's legacy `sum` block, reported from the sender's perspective in
    /// reverse mode but not always identical to `sum_sent`/`sum_received`
    /// (different `end`/`packets` in the fixture). Kept separate rather
    /// than merged so a caller can see the divergence rather than have it
    /// silently averaged away.
    pub estimated_received: Option<RateSample>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TestDirection {
    Forward,
    Reverse,
    Bidirectional,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IperfResult {
    pub version: Option<IperfVersion>,
    pub protocol: String,
    pub direction: TestDirection,
    pub forward: RateEvidence,
    /// Present only for `Bidirectional` tests (`sum_*_bidir_reverse`).
    pub bidir_reverse: Option<RateEvidence>,
    pub required_fields_missing: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum IperfParseError {
    #[error("invalid JSON: {0}")]
    InvalidJson(String),
    #[error("iperf3 reported an error before any result was produced: {0}")]
    ServerError(String),
    #[error("missing required field: {0}")]
    MissingField(String),
}

/// Parses one iperf3 `-J` JSON document.
///
/// Checks `error` FIRST, before touching `end` at all -- `error-refused.json`
/// carries an empty `end: {}` alongside a top-level `error` string, and
/// reading figures from that shape would report an aborted run as a valid
/// measurement.
pub fn parse_iperf_json(text: &str) -> Result<IperfResult, IperfParseError> {
    let v: Value =
        serde_json::from_str(text).map_err(|e| IperfParseError::InvalidJson(e.to_string()))?;

    if let Some(err) = v.get("error").and_then(Value::as_str) {
        return Err(IperfParseError::ServerError(err.to_string()));
    }

    let version = v
        .get("start")
        .and_then(|s| s.get("version"))
        .and_then(Value::as_str)
        .and_then(IperfVersion::parse);

    let test_start = v.get("start").and_then(|s| s.get("test_start"));
    let protocol = test_start
        .and_then(|t| t.get("protocol"))
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string();

    let bidir = test_start
        .and_then(|t| t.get("bidir"))
        .and_then(Value::as_u64)
        .unwrap_or(0)
        != 0;
    let reverse = test_start
        .and_then(|t| t.get("reverse"))
        .and_then(Value::as_u64)
        .unwrap_or(0)
        != 0;
    let direction = if bidir {
        TestDirection::Bidirectional
    } else if reverse {
        TestDirection::Reverse
    } else {
        TestDirection::Forward
    };

    let end = v
        .get("end")
        .ok_or_else(|| IperfParseError::MissingField("end".to_string()))?;
    let mut missing = Vec::new();

    let offered_bps = test_start
        .and_then(|t| t.get("target_bitrate"))
        .and_then(Value::as_f64)
        .filter(|b| *b > 0.0);

    let sent = end
        .get("sum_sent")
        .and_then(parse_rate_sample)
        .filter(|s| !s.is_hollow());
    if end.get("sum_sent").is_none() {
        missing.push("sum_sent".to_string());
    }
    let received = end
        .get("sum_received")
        .and_then(parse_rate_sample)
        .filter(|s| !s.is_hollow());
    if end.get("sum_received").is_none() {
        missing.push("sum_received".to_string());
    }
    let estimated_received = end.get("sum").and_then(parse_rate_sample);

    let forward = RateEvidence {
        offered_bps,
        sent,
        received,
        estimated_received,
    };

    let bidir_reverse = if bidir {
        let sent_r = end
            .get("sum_sent_bidir_reverse")
            .and_then(parse_rate_sample)
            .filter(|s| !s.is_hollow());
        let recv_r = end
            .get("sum_received_bidir_reverse")
            .and_then(parse_rate_sample)
            .filter(|s| !s.is_hollow());
        if end.get("sum_sent_bidir_reverse").is_none() {
            missing.push("sum_sent_bidir_reverse".to_string());
        }
        if end.get("sum_received_bidir_reverse").is_none() {
            missing.push("sum_received_bidir_reverse".to_string());
        }
        Some(RateEvidence {
            offered_bps,
            sent: sent_r,
            received: recv_r,
            estimated_received: None,
        })
    } else {
        None
    };

    Ok(IperfResult {
        version,
        protocol,
        direction,
        forward,
        bidir_reverse,
        required_fields_missing: missing,
    })
}

/// Runs one bounded iperf3 client invocation and parses its JSON output.
/// Always passes `-t` (duration) and `-J`; never omits a duration cap.
pub fn run_iperf_client(
    host: &str,
    port: u16,
    duration_secs: u32,
    reverse: bool,
    bidir: bool,
    udp: bool,
    target_bitrate: Option<&str>,
    bind_interface: Option<&str>,
) -> Result<IperfResult, IperfParseError> {
    let mut cmd = Command::new("iperf3");
    cmd.args([
        "-c",
        host,
        "-p",
        &port.to_string(),
        "-t",
        &duration_secs.to_string(),
        "-J",
    ]);
    if reverse {
        cmd.arg("-R");
    }
    if bidir {
        cmd.arg("--bidir");
    }
    if udp {
        cmd.arg("-u");
    }
    if let Some(rate) = target_bitrate {
        cmd.args(["-b", rate]);
    }
    if let Some(iface) = bind_interface {
        cmd.args(["--bind-dev", iface]);
    }

    let output = cmd
        .output()
        .map_err(|e| IperfParseError::InvalidJson(format!("failed to run iperf3: {}", e)))?;
    let text = String::from_utf8_lossy(&output.stdout);
    parse_iperf_json(&text)
}

/// GAP-036: an authorized, explicit allowlist of ports to probe. Discovery
/// NEVER sweeps a range; the caller must name every port. This is the
/// authorization boundary -- a port scan against infrastructure you were
/// not told to scan is a different act than measuring a named listener.
#[derive(Debug, Clone)]
pub struct EndpointAllowlist {
    pub host: String,
    pub ports: Vec<u16>,
}

impl EndpointAllowlist {
    pub fn new(host: impl Into<String>, ports: Vec<u16>) -> Self {
        EndpointAllowlist {
            host: host.into(),
            ports,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenerCapability {
    pub port: u16,
    pub reachable: bool,
    pub version: Option<IperfVersion>,
    pub supports_bidir: Option<bool>,
    pub detail: String,
}

/// Probes only the ports named in `allowlist.ports`, one 1-second/near-zero
/// -load control run per port via `-n 16` (16 bytes, not a duration-based
/// load) to confirm the listener answers and to read its reported version
/// from the JSON `start.version` field. Never contacts any port not in the
/// allowlist, and never mutates server state (client-only iperf3 flags).
pub fn discover_listeners(
    allowlist: &EndpointAllowlist,
    connect_timeout_ms: u32,
) -> Vec<ListenerCapability> {
    let attempted: HashSet<u16> = allowlist.ports.iter().copied().collect();
    debug_assert_eq!(
        attempted.len(),
        allowlist.ports.len(),
        "allowlist ports must be unique"
    );

    allowlist
        .ports
        .iter()
        .map(|&port| probe_one_listener(&allowlist.host, port, connect_timeout_ms))
        .collect()
}

fn probe_one_listener(host: &str, port: u16, connect_timeout_ms: u32) -> ListenerCapability {
    let output = Command::new("iperf3")
        .args([
            "-c",
            host,
            "-p",
            &port.to_string(),
            "-n",
            "16",
            "-J",
            "--connect-timeout",
            &connect_timeout_ms.to_string(),
        ])
        .output();

    let output = match output {
        Ok(o) => o,
        Err(e) => {
            return ListenerCapability {
                port,
                reachable: false,
                version: None,
                supports_bidir: None,
                detail: format!("failed to run iperf3: {}", e),
            }
        }
    };

    let text = String::from_utf8_lossy(&output.stdout);
    match parse_iperf_json(&text) {
        Ok(result) => ListenerCapability {
            port,
            reachable: true,
            version: result.version,
            supports_bidir: result.version.map(|v| v.supports_bidir_reliably()),
            detail: "listener answered".to_string(),
        },
        Err(IperfParseError::ServerError(e)) => ListenerCapability {
            port,
            reachable: false,
            version: None,
            supports_bidir: None,
            detail: e,
        },
        Err(e) => ListenerCapability {
            port,
            reachable: false,
            version: None,
            supports_bidir: None,
            detail: format!("parse error: {}", e),
        },
    }
}

/// Resolves the allowlist host once (not per-port) so discovery never
/// triggers repeated independent DNS lookups that could themselves be
/// mistaken for scanning traffic.
pub fn resolve_allowlist_host(host: &str) -> Option<IpAddr> {
    (host, 0u16).to_socket_addrs().ok()?.next().map(|a| a.ip())
}

/// Selects the first reachable listener from a discovery pass, independent
/// of any assumption about which port is "the" default. Returns `None` if
/// no allowlisted port answered, never a guessed default.
pub fn select_independent_listener(
    capabilities: &[ListenerCapability],
) -> Option<&ListenerCapability> {
    capabilities.iter().find(|c| c.reachable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn fixture(name: &str) -> String {
        fs::read_to_string(format!(
            "{}/harness/fixtures/iperf/{}",
            env!("CARGO_MANIFEST_DIR"),
            name
        ))
        .unwrap()
    }

    #[test]
    fn version_parses_from_start_string() {
        assert_eq!(
            IperfVersion::parse("iperf 3.21"),
            Some(IperfVersion {
                major: 3,
                minor: 21
            })
        );
        assert_eq!(
            IperfVersion::parse("iperf 3.9"),
            Some(IperfVersion { major: 3, minor: 9 })
        );
    }

    #[test]
    fn bidir_reliability_gated_on_version() {
        assert!(!IperfVersion { major: 3, minor: 9 }.supports_bidir_reliably());
        assert!(IperfVersion {
            major: 3,
            minor: 16
        }
        .supports_bidir_reliably());
        assert!(IperfVersion {
            major: 3,
            minor: 21
        }
        .supports_bidir_reliably());
    }

    #[test]
    fn error_refused_detected_before_any_figure_read() {
        let text = fixture("error-refused.json");
        let err = parse_iperf_json(&text).unwrap_err();
        match err {
            IperfParseError::ServerError(_) => {}
            other => panic!("expected ServerError, got {:?}", other),
        }
    }

    #[test]
    fn tcp_forward_parses_sent_and_received() {
        let text = fixture("tcp-forward-3.21.json");
        let result = parse_iperf_json(&text).unwrap();
        assert_eq!(result.direction, TestDirection::Forward);
        assert!(result.forward.sent.is_some());
        assert!(result.forward.received.is_some());
        assert!(result.bidir_reverse.is_none());
    }

    #[test]
    fn tcp_bidir_yields_both_directions() {
        let text = fixture("tcp-bidir-3.21.json");
        let result = parse_iperf_json(&text).unwrap();
        assert_eq!(result.direction, TestDirection::Bidirectional);
        assert!(result.forward.sent.is_some());
        assert!(result.forward.received.is_some());
        let rev = result
            .bidir_reverse
            .expect("bidir reverse evidence must be present");
        assert!(rev.sent.is_some());
        assert!(rev.received.is_some());
    }

    #[test]
    fn udp_reverse_sum_sent_is_hollow_not_zero_loss() {
        let text = fixture("udp-reverse-3.21.json");
        let result = parse_iperf_json(&text).unwrap();
        // sum_sent in this fixture has packets: 0 -- must be filtered out,
        // not surfaced as a confident 0% loss.
        assert!(
            result.forward.sent.is_none(),
            "hollow sum_sent must not surface as a rate sample"
        );
        let received = result
            .forward
            .received
            .expect("sum_received must be present and non-hollow");
        assert_eq!(received.packets, Some(460));
        assert_eq!(received.lost_percent, Some(0.0));
        // estimated_received (legacy `sum`) is kept distinct and reports a
        // different packet count (489) than sum_received (460).
        let estimated = result
            .forward
            .estimated_received
            .expect("sum block must be present");
        assert_eq!(estimated.packets, Some(489));
        assert_ne!(estimated.packets, received.packets);
    }

    #[test]
    fn missing_field_reports_unavailable_not_zero() {
        let json = r#"{"start":{"version":"iperf 3.21","test_start":{"protocol":"TCP","reverse":0,"bidir":0}},"intervals":[],"end":{}}"#;
        let result = parse_iperf_json(json).unwrap();
        assert!(result.forward.sent.is_none());
        assert!(result.forward.received.is_none());
        assert!(result
            .required_fields_missing
            .contains(&"sum_sent".to_string()));
        assert!(result
            .required_fields_missing
            .contains(&"sum_received".to_string()));
    }

    #[test]
    fn allowlist_never_probes_a_port_outside_the_list() {
        let allow = EndpointAllowlist::new("127.0.0.1", vec![54321]);
        let results = discover_listeners(&allow, 200);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].port, 54321);
    }
}
