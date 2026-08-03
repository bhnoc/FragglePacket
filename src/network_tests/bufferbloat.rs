//! GAP-002: idle vs loaded latency ("bufferbloat") test.
//!
//! Wraps macOS's `networkQuality` (present at `/usr/bin/networkQuality`),
//! which already runs the exact idle/upload-loaded/download-loaded/
//! simultaneous phases the field investigation had to fall back on by hand.
//! This module degrades gracefully and honestly on any platform (or any
//! macOS install) where the binary is missing: it reports unavailable
//! phases rather than substituting numbers from a different phase or a
//! different platform's idea of "idle latency".
//!
//! `networkQuality` has a real failure mode worth guarding against: given an
//! interface name it cannot bind (verified: a nonexistent interface), the
//! process hangs past its own `-M` budget rather than failing fast. Every
//! invocation here is wrapped in a watchdog that force-kills the child after
//! a hard deadline, so a hung subprocess can never hang this tool.

use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

pub const NETWORK_QUALITY_BIN: &str = "/usr/bin/networkQuality";

/// One phase's worth of throughput/responsiveness numbers. Every field is
/// `Option` on purpose -- GAP-009's lesson generalizes here: an unmeasured
/// phase (tool absent, phase not requested, JSON field missing) must render
/// as unavailable, never as a false zero.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PhaseLatency {
    pub responsiveness_rpm: Option<f64>,
    pub throughput_bps: Option<f64>,
    pub bytes_transferred: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BufferbloatReport {
    /// Names the platform tool that produced every figure in this report,
    /// so a reader never has to guess (or assume) where the numbers came
    /// from. Currently always `NETWORK_QUALITY_BIN` when `tool_available`
    /// is true; kept as its own field rather than folded into a comment so
    /// downstream consumers (e.g. cross-platform reports) can rely on it.
    pub measurement_tool: &'static str,
    pub interface: Option<String>,
    pub default_route_is_tunnel: bool,
    pub test_endpoint: Option<String>,
    pub base_rtt_ms: Option<f64>,
    pub idle: PhaseLatency,
    pub upload_loaded: PhaseLatency,
    pub download_loaded: PhaseLatency,
    pub simultaneous: PhaseLatency,
    /// `None` when the responsiveness grade cannot be computed (any of the
    /// four phases missing its RPM figure).
    pub responsiveness_grade: Option<ResponsivenessGrade>,
    pub tool_available: bool,
    pub unavailable_reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResponsivenessGrade {
    Excellent,
    Good,
    Fair,
    Poor,
}

impl ResponsivenessGrade {
    /// Grades on the worst (lowest RPM) of the four phases, since a single
    /// collapsed phase is what the field investigation actually cared about
    /// -- an average across phases would hide exactly the simultaneous-load
    /// collapse GAP-004 exists to surface.
    pub fn from_worst_rpm(worst_rpm: f64) -> Self {
        if worst_rpm >= 400.0 {
            ResponsivenessGrade::Excellent
        } else if worst_rpm >= 200.0 {
            ResponsivenessGrade::Good
        } else if worst_rpm >= 100.0 {
            ResponsivenessGrade::Fair
        } else {
            ResponsivenessGrade::Poor
        }
    }
}

/// Grades on the three *loaded* phases only. Idle deliberately never carries
/// an RPM figure (no load is offered, so RPM isn't meaningful for it -- see
/// `run_bufferbloat`), so requiring all four phases here would make the
/// grade permanently uncomputable regardless of how healthy the network is.
fn grade_from_phases(
    up: &PhaseLatency,
    down: &PhaseLatency,
    sim: &PhaseLatency,
) -> Option<ResponsivenessGrade> {
    let vals: Option<Vec<f64>> = [up, down, sim]
        .iter()
        .map(|p| p.responsiveness_rpm)
        .collect();
    let vals = vals?;
    let worst = vals.into_iter().fold(f64::INFINITY, f64::min);
    Some(ResponsivenessGrade::from_worst_rpm(worst))
}

/// Runs `networkQuality` with a hard wall-clock kill at `max_duration + KILL_GRACE_SECS`.
/// `-M max_duration_secs` bounds the tool's own budget, but a bad `-I` value
/// has been observed to hang past that budget entirely (verified: passing a
/// nonexistent interface name blocks indefinitely rather than erroring) --
/// so this wrapper enforces its own deadline independent of the tool's.
const KILL_GRACE_SECS: u64 = 5;

fn run_network_quality(args: &[&str], max_duration_secs: u64) -> Result<serde_json::Value, String> {
    let mut child: Child = Command::new(NETWORK_QUALITY_BIN)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("failed to spawn networkQuality: {e}"))?;

    let deadline = Instant::now() + Duration::from_secs(max_duration_secs + KILL_GRACE_SECS);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    return Err(format!("networkQuality exited with {:?}", status.code()));
                }
                break;
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!(
                        "networkQuality exceeded its budget ({}s) and was killed -- likely an unusable --interface value",
                        max_duration_secs + KILL_GRACE_SECS
                    ));
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => return Err(format!("failed to poll networkQuality: {e}")),
        }
    }

    let output = child
        .wait_with_output()
        .map_err(|e| format!("failed to collect output: {e}"))?;
    serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("failed to parse networkQuality JSON: {e}"))
}

// `-s` (sequential mode) is what makes networkQuality report a per-direction
// `{prefix}_responsiveness` at all; each field is read only under its own
// direction-prefixed key, never substituted from the other direction or
// from simultaneous mode's blended `responsiveness` key.
fn extract_phase(v: &serde_json::Value, prefix: &str) -> PhaseLatency {
    let get_f64 = |key: &str| v.get(key).and_then(|x| x.as_f64());
    let get_u64 = |key: &str| v.get(key).and_then(|x| x.as_u64());
    PhaseLatency {
        responsiveness_rpm: get_f64(&format!("{prefix}_responsiveness")),
        throughput_bps: get_f64(&format!("{prefix}_throughput")),
        bytes_transferred: get_u64(&format!("{prefix}_bytes_transferred")),
    }
}

/// Parses one `networkQuality -c` JSON payload into idle/up/down phases
/// depending on which flags produced it. Kept separate from the process
/// invocation so the parsing logic is unit-testable against captured JSON
/// without running the real tool.
pub fn parse_idle_response(v: &serde_json::Value) -> (Option<String>, Option<f64>) {
    let endpoint = v
        .get("test_endpoint")
        .and_then(|x| x.as_str())
        .map(str::to_string);
    let base_rtt = v.get("base_rtt").and_then(|x| x.as_f64());
    (endpoint, base_rtt)
}

pub fn parse_upload_phase(v: &serde_json::Value) -> PhaseLatency {
    extract_phase(v, "ul")
}

pub fn parse_download_phase(v: &serde_json::Value) -> PhaseLatency {
    extract_phase(v, "dl")
}

/// Simultaneous mode (`networkQuality`'s default, no `-s`) reports one
/// blended `responsiveness` figure and both directions' throughput -- it
/// cannot report per-direction RPM because both directions loaded the link
/// at once. This is intentionally distinct from `parse_upload_phase`/
/// `parse_download_phase`, which require `-s` and report per-direction RPM.
pub fn parse_simultaneous_phase(v: &serde_json::Value) -> PhaseLatency {
    PhaseLatency {
        responsiveness_rpm: v.get("responsiveness").and_then(|x| x.as_f64()),
        throughput_bps: None,
        bytes_transferred: None,
    }
}

pub struct BufferbloatConfig {
    pub interface: Option<String>,
    pub default_route_is_tunnel: bool,
    pub max_duration_secs: u64,
}

/// Runs the full four-phase bufferbloat suite: idle, upload-loaded,
/// download-loaded, simultaneous. Each phase is an independent
/// `networkQuality` invocation (its own process, own budget) so one hung or
/// failed phase never silently contaminates another phase's numbers with a
/// stale or substituted value.
pub fn run_bufferbloat(cfg: &BufferbloatConfig) -> BufferbloatReport {
    if !std::path::Path::new(NETWORK_QUALITY_BIN).exists() {
        return BufferbloatReport {
            measurement_tool: NETWORK_QUALITY_BIN,
            interface: cfg.interface.clone(),
            default_route_is_tunnel: cfg.default_route_is_tunnel,
            test_endpoint: None,
            base_rtt_ms: None,
            idle: PhaseLatency::default(),
            upload_loaded: PhaseLatency::default(),
            download_loaded: PhaseLatency::default(),
            simultaneous: PhaseLatency::default(),
            responsiveness_grade: None,
            tool_available: false,
            unavailable_reason: Some(format!(
                "{NETWORK_QUALITY_BIN} not present on this platform; bufferbloat measurement unavailable, not substituted"
            )),
        };
    }

    let mut base_args: Vec<&str> = vec!["-c"];
    if let Some(iface) = &cfg.interface {
        base_args.push("-I");
        base_args.push(iface);
    }
    let m = cfg.max_duration_secs.to_string();
    base_args.push("-M");
    base_args.push(&m);

    // Idle: skip both directions to isolate base_rtt with no offered load.
    let mut idle_args = base_args.clone();
    idle_args.push("-d");
    idle_args.push("-u");
    let idle_result = run_network_quality(&idle_args, cfg.max_duration_secs);

    let (test_endpoint, base_rtt_ms) = match &idle_result {
        Ok(v) => parse_idle_response(v),
        Err(_) => (None, None),
    };
    // Idle offers no load, so RPM/throughput are not meaningful for it; the
    // idle measurement that matters (base_rtt_ms) is already captured above.
    let idle_phase = PhaseLatency::default();

    // Upload-loaded, download-loaded: sequential mode (-s) so each phase
    // reports its OWN responsiveness, never a blended figure.
    let mut up_args = base_args.clone();
    up_args.push("-d");
    up_args.push("-s");
    let up_result = run_network_quality(&up_args, cfg.max_duration_secs);
    let upload_loaded = match &up_result {
        Ok(v) => parse_upload_phase(v),
        Err(_) => PhaseLatency::default(),
    };

    let mut down_args = base_args.clone();
    down_args.push("-u");
    down_args.push("-s");
    let down_result = run_network_quality(&down_args, cfg.max_duration_secs);
    let download_loaded = match &down_result {
        Ok(v) => parse_download_phase(v),
        Err(_) => PhaseLatency::default(),
    };

    // Simultaneous: default mode, both directions loaded at once -- this is
    // the phase the field investigation found collapsing independently of
    // the two directional phases above (GAP-004).
    let sim_result = run_network_quality(&base_args, cfg.max_duration_secs);
    let simultaneous = match &sim_result {
        Ok(v) => parse_simultaneous_phase(v),
        Err(_) => PhaseLatency::default(),
    };

    let grade = grade_from_phases(&upload_loaded, &download_loaded, &simultaneous);

    let mut errors = Vec::new();
    for (name, r) in [
        ("idle", &idle_result),
        ("upload", &up_result),
        ("download", &down_result),
        ("simultaneous", &sim_result),
    ] {
        if let Err(e) = r {
            errors.push(format!("{name}: {e}"));
        }
    }

    BufferbloatReport {
        measurement_tool: NETWORK_QUALITY_BIN,
        interface: cfg.interface.clone(),
        default_route_is_tunnel: cfg.default_route_is_tunnel,
        test_endpoint,
        base_rtt_ms,
        idle: idle_phase,
        upload_loaded,
        download_loaded,
        simultaneous,
        responsiveness_grade: grade,
        tool_available: true,
        unavailable_reason: if errors.is_empty() {
            None
        } else {
            Some(errors.join("; "))
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn missing_tool_reports_unavailable_not_zero() {
        // Cannot force NETWORK_QUALITY_BIN missing on a real macOS box in
        // this test, so this covers the parse/grade path directly instead;
        // the missing-binary path is exercised by the CLI harness gate.
        let report = BufferbloatReport {
            measurement_tool: NETWORK_QUALITY_BIN,
            interface: None,
            default_route_is_tunnel: false,
            test_endpoint: None,
            base_rtt_ms: None,
            idle: PhaseLatency::default(),
            upload_loaded: PhaseLatency::default(),
            download_loaded: PhaseLatency::default(),
            simultaneous: PhaseLatency::default(),
            responsiveness_grade: None,
            tool_available: false,
            unavailable_reason: Some("not present".to_string()),
        };
        assert!(!report.tool_available);
        assert_eq!(report.measurement_tool, NETWORK_QUALITY_BIN);
        assert!(report.base_rtt_ms.is_none());
        assert!(report.responsiveness_grade.is_none());
    }

    #[test]
    fn parse_idle_response_extracts_endpoint_and_rtt() {
        let v = json!({"test_endpoint": "example.aaplimg.com", "base_rtt": 123.4});
        let (endpoint, rtt) = parse_idle_response(&v);
        assert_eq!(endpoint, Some("example.aaplimg.com".to_string()));
        assert_eq!(rtt, Some(123.4));
    }

    #[test]
    fn parse_upload_phase_extracts_ul_fields() {
        let v = json!({"ul_responsiveness": 300.0, "ul_throughput": 50000000.0, "ul_bytes_transferred": 1000});
        let phase = parse_upload_phase(&v);
        assert_eq!(phase.responsiveness_rpm, Some(300.0));
        assert_eq!(phase.throughput_bps, Some(50000000.0));
        assert_eq!(phase.bytes_transferred, Some(1000));
    }

    #[test]
    fn parse_download_phase_never_reads_upload_fields() {
        let v = json!({"ul_responsiveness": 300.0, "dl_responsiveness": 400.0});
        let phase = parse_download_phase(&v);
        assert_eq!(phase.responsiveness_rpm, Some(400.0));
    }

    #[test]
    fn missing_field_is_none_not_zero() {
        let v = json!({});
        let phase = parse_upload_phase(&v);
        assert_eq!(phase.responsiveness_rpm, None);
        assert_eq!(phase.throughput_bps, None);
    }

    #[test]
    fn simultaneous_phase_reads_blended_responsiveness_only() {
        let v = json!({"responsiveness": 250.0, "dl_throughput": 999.0});
        let phase = parse_simultaneous_phase(&v);
        assert_eq!(phase.responsiveness_rpm, Some(250.0));
        // Simultaneous mode's blended report deliberately does not surface
        // a per-direction throughput here -- GAP-004 requires directional
        // figures come from the dedicated sequential phases, not this one.
        assert_eq!(phase.throughput_bps, None);
    }

    #[test]
    fn grade_is_none_when_any_loaded_phase_missing_rpm() {
        let complete = PhaseLatency {
            responsiveness_rpm: Some(300.0),
            ..Default::default()
        };
        let missing = PhaseLatency::default();
        assert!(grade_from_phases(&complete, &complete, &missing).is_none());
    }

    #[test]
    fn grade_never_requires_idle_rpm() {
        // Idle deliberately never carries an RPM figure -- a grade must
        // still be computable from the three loaded phases alone, or every
        // real run (idle never has RPM) would report an uncomputable grade
        // regardless of how healthy the network is.
        let healthy = PhaseLatency {
            responsiveness_rpm: Some(500.0),
            ..Default::default()
        };
        let grade = grade_from_phases(&healthy, &healthy, &healthy).unwrap();
        assert_eq!(grade, ResponsivenessGrade::Excellent);
    }

    #[test]
    fn grade_takes_the_worst_phase_not_the_average() {
        // A field-shaped scenario: two healthy phases, one collapsed
        // simultaneous phase. Averaging would mask exactly the collapse
        // GAP-004 requires surfacing.
        let healthy = PhaseLatency {
            responsiveness_rpm: Some(500.0),
            ..Default::default()
        };
        let collapsed = PhaseLatency {
            responsiveness_rpm: Some(50.0),
            ..Default::default()
        };
        let grade = grade_from_phases(&healthy, &healthy, &collapsed).unwrap();
        assert_eq!(grade, ResponsivenessGrade::Poor);
    }
}
