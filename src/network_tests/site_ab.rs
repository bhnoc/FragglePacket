//! GAP-012: affected-site vs known-good-control A/B workflow.
//!
//! Most of the measurement machinery already exists in `protocol_compare.rs`
//! and `preflight.rs` (both another agent's files this sprint -- called,
//! not edited): forced H1/H2/H3, `--force-ip` pinning, and endpoint-mismatch
//! detection. This module is the workflow that drives `run_comparison`
//! against a named failing site and a known-good control side by side,
//! repeats each for a sample count, and produces one comparative verdict.
//!
//! The field bug this specifically guards against: a 301 redirect was once
//! scored as throughput (a redirect stub's few hundred bytes read as tiny
//! but real "capacity"). `protocol_compare.rs`'s fix made a redirected leg
//! carry `redirected_to_different_host`/`redirect_detail` and reject
//! bodies under `MIN_VALID_TRANSFER_BYTES` as `LossIndicator::BodyTooSmall`
//! rather than `Clean`. This module's job is to make sure that signal
//! actually reaches the operator at the A/B level: `SiteAbVerdict` carries
//! `affected_redirected`/`control_redirected` as their own fields, and the
//! comparison step refuses a throughput-based verdict (never silently
//! substitutes a stub number) whenever either side redirected.

use serde::{Deserialize, Serialize};

use crate::network_tests::protocol_compare::{run_comparison, CompareConfig, ComparisonReport};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteAbConfig {
    pub affected: CompareConfigInput,
    pub control: CompareConfigInput,
    /// Repeated samples per site -- a single sample per leg is at most
    /// Medium confidence (`protocol_compare::confidence_for`); repeating is
    /// how this workflow raises that.
    pub repeat_samples: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompareConfigInput {
    pub host: String,
    pub port: u16,
    pub path: String,
    pub interface: Option<String>,
    pub forced_ip: Option<std::net::IpAddr>,
    pub timeout_secs: u64,
    pub upload_bytes: usize,
    pub protocols: Vec<String>,
    pub run_simultaneous: bool,
}

impl CompareConfigInput {
    fn into_compare_config(&self) -> Result<CompareConfig, String> {
        let protocols = self
            .protocols
            .iter()
            .map(|p| match p.as_str() {
                "http1" => Ok(crate::network_tests::protocol_compare::HttpProtocol::Http1),
                "http2" => Ok(crate::network_tests::protocol_compare::HttpProtocol::Http2),
                "http3" => Ok(crate::network_tests::protocol_compare::HttpProtocol::Http3),
                other => Err(format!("unknown protocol '{other}'")),
            })
            .collect::<Result<Vec<_>, String>>()?;
        Ok(CompareConfig {
            host: self.host.clone(),
            port: self.port,
            path: self.path.clone(),
            interface: self.interface.clone(),
            forced_ip: self.forced_ip,
            timeout_secs: self.timeout_secs,
            upload_bytes: self.upload_bytes,
            protocols,
            run_simultaneous: self.run_simultaneous,
        })
    }
}

/// One site's repeated samples, run through `protocol_compare::run_comparison`
/// unmodified per repeat.
pub fn run_site_samples(
    input: &CompareConfigInput,
    repeat_samples: u32,
) -> Result<Vec<ComparisonReport>, String> {
    let cfg = input.into_compare_config()?;
    let mut reports = Vec::new();
    for _ in 0..repeat_samples.max(1) {
        reports.push(run_comparison(&cfg));
    }
    Ok(reports)
}

/// True when ANY sample for a site redirected to a different hostname --
/// the field bug's trigger condition. Surfaced at the site level so the
/// A/B comparison step can refuse a throughput comparison rather than
/// silently comparing a stub leg against a real one.
fn any_redirected(reports: &[ComparisonReport]) -> (bool, Option<String>) {
    for r in reports {
        if r.redirected_to_different_host {
            return (true, r.redirect_detail.clone());
        }
    }
    (false, None)
}

/// Median download-only throughput across samples for a given protocol,
/// using only legs whose `LossIndicator` is `Clean` -- a leg the redirect
/// fix already marked `BodyTooSmall`/`TransferFailed`/`NonSuccessStatus`
/// never enters this average. `None` when no clean sample exists, never 0.
fn median_clean_download_mbps(reports: &[ComparisonReport], protocol: &str) -> Option<f64> {
    use crate::network_tests::protocol_compare::LossIndicator;
    let mut values: Vec<f64> = reports
        .iter()
        .flat_map(|r| r.protocols.iter())
        .filter(|p| p.protocol == protocol)
        .filter_map(|p| p.download_only.as_ref())
        .filter(|leg| leg.loss_indicator == LossIndicator::Clean)
        .filter_map(|leg| leg.throughput_bps)
        .map(|bps| bps / 1_000_000.0)
        .collect();
    if values.is_empty() {
        return None;
    }
    values.sort_by(|a, b| a.partial_cmp(b).unwrap());
    Some(values[values.len() / 2])
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SiteAbVerdict {
    /// Both sides ran cleanly enough to compare throughput directly.
    Compared {
        affected_mbps: f64,
        control_mbps: f64,
        ratio: f64,
    },
    /// Either side redirected -- comparing throughput would compare a stub
    /// against real capacity, or vice versa. Refused, and which side(s)
    /// redirected is named explicitly.
    RedirectedRatherThanCompared {
        affected_redirected: bool,
        control_redirected: bool,
        detail: String,
    },
    /// Neither side produced a clean sample to compare (e.g. both timed
    /// out, or the protocol was unsupported on both).
    Withheld { reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteAbReport {
    pub protocol: String,
    pub verdict: SiteAbVerdict,
}

/// Produces one side-by-side verdict per requested protocol. Never averages
/// a redirected leg's stub bytes into a throughput figure -- the entire
/// point of this module.
pub fn compare_sites(
    affected: &[ComparisonReport],
    control: &[ComparisonReport],
    protocols: &[String],
) -> Vec<SiteAbReport> {
    let (affected_redirected, affected_detail) = any_redirected(affected);
    let (control_redirected, control_detail) = any_redirected(control);

    protocols
        .iter()
        .map(|protocol| {
            let verdict = if affected_redirected || control_redirected {
                let detail = match (affected_redirected, control_redirected) {
                    (true, true) => format!(
                        "both affected and control redirected to a different hostname; affected: {}; control: {}",
                        affected_detail.clone().unwrap_or_default(),
                        control_detail.clone().unwrap_or_default()
                    ),
                    (true, false) => format!(
                        "affected URL redirected to a different hostname ({}); comparing throughput against the control would compare a stub, not the intended resource",
                        affected_detail.clone().unwrap_or_default()
                    ),
                    (false, true) => format!(
                        "control URL redirected to a different hostname ({}); comparing throughput against the affected site would compare a stub, not the intended resource",
                        control_detail.clone().unwrap_or_default()
                    ),
                    (false, false) => unreachable!(),
                };
                SiteAbVerdict::RedirectedRatherThanCompared { affected_redirected, control_redirected, detail }
            } else {
                match (median_clean_download_mbps(affected, protocol), median_clean_download_mbps(control, protocol)) {
                    (Some(a), Some(c)) if c > 0.0 => SiteAbVerdict::Compared { affected_mbps: a, control_mbps: c, ratio: a / c },
                    _ => SiteAbVerdict::Withheld {
                        reason: format!("no clean {protocol} download sample on both sides to compare"),
                    },
                }
            };
            SiteAbReport { protocol: protocol.clone(), verdict }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network_tests::pcap_report::Confidence;
    use crate::network_tests::protocol_compare::{
        LegResult, LossIndicator, ProtocolComparisonResult,
    };

    fn clean_report(protocol: &str, mbps: f64, redirected: bool) -> ComparisonReport {
        let leg = LegResult {
            protocol: protocol.to_string(),
            direction: "download-only".to_string(),
            host: "example.com".to_string(),
            connected_ip: Some("203.0.113.10".to_string()),
            http_status: Some(200),
            throughput_bps: Some(mbps * 1_000_000.0),
            bytes_transferred: Some(1_000_000),
            time_total_secs: Some(1.0),
            loss_indicator: LossIndicator::Clean,
            error: None,
            final_url: None,
            redirect_count: 0,
        };
        ComparisonReport {
            host: "example.com".to_string(),
            interface: None,
            protocols: vec![ProtocolComparisonResult {
                protocol: protocol.to_string(),
                preflight_verdict: None,
                download_only: Some(leg),
                upload_only: None,
                simultaneous_download: None,
                simultaneous_upload: None,
                confidence: Confidence::Medium,
                confidence_reasons: vec![],
            }],
            endpoint_mismatch: false,
            endpoint_mismatch_detail: None,
            redirected_to_different_host: redirected,
            redirect_detail: if redirected {
                Some("example.com redirected to other.example.com".to_string())
            } else {
                None
            },
        }
    }

    #[test]
    fn a_clean_comparison_computes_a_ratio() {
        let affected = vec![clean_report("http2", 50.0, false)];
        let control = vec![clean_report("http2", 200.0, false)];
        let reports = compare_sites(&affected, &control, &["http2".to_string()]);
        match &reports[0].verdict {
            SiteAbVerdict::Compared {
                affected_mbps,
                control_mbps,
                ratio,
            } => {
                assert_eq!(*affected_mbps, 50.0);
                assert_eq!(*control_mbps, 200.0);
                assert_eq!(*ratio, 0.25);
            }
            other => panic!("expected Compared, got {other:?}"),
        }
    }

    #[test]
    fn an_affected_side_redirect_refuses_throughput_comparison_rather_than_comparing_a_stub() {
        // The exact field bug: a 301 must never let throughput comparison
        // proceed as if the redirected leg's stub bytes were real capacity.
        let affected = vec![clean_report("http2", 0.02, true)];
        let control = vec![clean_report("http2", 200.0, false)];
        let reports = compare_sites(&affected, &control, &["http2".to_string()]);
        match &reports[0].verdict {
            SiteAbVerdict::RedirectedRatherThanCompared {
                affected_redirected,
                control_redirected,
                detail,
            } => {
                assert!(affected_redirected);
                assert!(!control_redirected);
                assert!(detail.contains("affected URL redirected"));
            }
            other => panic!("expected RedirectedRatherThanCompared, got {other:?}"),
        }
    }

    #[test]
    fn a_control_side_redirect_is_also_named_distinctly() {
        let affected = vec![clean_report("http2", 40.0, false)];
        let control = vec![clean_report("http2", 0.02, true)];
        let reports = compare_sites(&affected, &control, &["http2".to_string()]);
        match &reports[0].verdict {
            SiteAbVerdict::RedirectedRatherThanCompared {
                affected_redirected,
                control_redirected,
                ..
            } => {
                assert!(!affected_redirected);
                assert!(*control_redirected);
            }
            other => panic!("expected RedirectedRatherThanCompared, got {other:?}"),
        }
    }

    #[test]
    fn no_clean_sample_on_either_side_withholds_rather_than_dividing_by_zero() {
        let affected: Vec<ComparisonReport> = vec![];
        let control: Vec<ComparisonReport> = vec![];
        let reports = compare_sites(&affected, &control, &["http3".to_string()]);
        match &reports[0].verdict {
            SiteAbVerdict::Withheld { reason } => assert!(reason.contains("http3")),
            other => panic!("expected Withheld, got {other:?}"),
        }
    }

    #[test]
    fn median_uses_only_clean_legs() {
        let dirty = clean_report("http1", 999.0, false);
        let mut dirty = dirty;
        dirty.protocols[0]
            .download_only
            .as_mut()
            .unwrap()
            .loss_indicator = LossIndicator::BodyTooSmall;
        let reports = vec![dirty, clean_report("http1", 40.0, false)];
        assert_eq!(median_clean_download_mbps(&reports, "http1"), Some(40.0));
    }
}
