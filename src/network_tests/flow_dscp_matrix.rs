//! GAP-034: constant-aggregate flow-count and QoS/DSCP classification
//! matrix.
//!
//! Field evidence: Wi-Fi loss varied non-monotonically with 1/2/4/8 flows at
//! a held aggregate rate, and DSCP-marked runs were variable without proof
//! the marking survived the path. That second half is the trap this module
//! exists to close: a DSCP sweep is worthless as QoS evidence unless there
//! is capture proof the mark was still present on arrival -- a middlebox or
//! access-layer switch silently re-marking or zeroing DSCP would otherwise
//! look identical to "the network respected the marking."
//!
//! Two independent claims live here, deliberately not merged into one
//! number: (1) whether the aggregate rate was actually held constant while
//! flow count varied, and (2) whether DSCP marking survival is proven,
//! unproven, or unverifiable for lack of a capture.

use serde::{Deserialize, Serialize};

/// One flow-count point in the matrix. `target_aggregate_bps` is the
/// intended constant; `actual_aggregate_bps` is what was actually measured
/// summed across the flow's members. Holding aggregate constant is a claim
/// that must be checked, not assumed from the per-flow rate arithmetic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowCountPoint {
    pub flow_count: u32,
    pub per_flow_bps: f64,
    pub target_aggregate_bps: f64,
    pub actual_aggregate_bps: Option<f64>,
    pub loss_percent: Option<f64>,
    pub source_ports: Vec<u16>,
    /// True if this point is a repeated control (same flow_count as an
    /// earlier point in the same run), used to detect drift between
    /// repeats of the "same" configuration.
    pub is_repeated_control: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowCountMatrix {
    pub points: Vec<FlowCountPoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregateConstancyCheck {
    /// Max fractional deviation of any point's `actual_aggregate_bps` from
    /// the mean of all measured aggregates. `None` if fewer than two points
    /// had a measured aggregate.
    pub max_deviation_fraction: Option<f64>,
    /// True only when every point's aggregate was measured and stayed
    /// within tolerance of the others. False for anything else, including
    /// "we don't know" -- that ambiguity is what `max_deviation_fraction:
    /// None` communicates instead.
    pub held_constant: bool,
    pub tolerance_fraction: f64,
}

const DEFAULT_AGGREGATE_TOLERANCE: f64 = 0.15;

pub fn check_aggregate_constancy(matrix: &FlowCountMatrix) -> AggregateConstancyCheck {
    let measured: Vec<f64> = matrix.points.iter().filter_map(|p| p.actual_aggregate_bps).collect();
    if measured.len() < 2 {
        return AggregateConstancyCheck {
            max_deviation_fraction: None,
            held_constant: false,
            tolerance_fraction: DEFAULT_AGGREGATE_TOLERANCE,
        };
    }
    let mean = measured.iter().sum::<f64>() / measured.len() as f64;
    let max_deviation_fraction = measured
        .iter()
        .map(|v| if mean > 0.0 { (v - mean).abs() / mean } else { 0.0 })
        .fold(0.0_f64, f64::max);

    // Every point must have contributed a measurement, not just the ones
    // that happened to have one -- an unmeasured point cannot be assumed
    // constant by omission.
    let all_measured = measured.len() == matrix.points.len();

    AggregateConstancyCheck {
        max_deviation_fraction: Some(max_deviation_fraction),
        held_constant: all_measured && max_deviation_fraction <= DEFAULT_AGGREGATE_TOLERANCE,
        tolerance_fraction: DEFAULT_AGGREGATE_TOLERANCE,
    }
}

/// A single DSCP capture-verification attempt: what was sent, and what was
/// observed at send-side and receive-side capture points, if any.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DscpCaptureSample {
    pub sent_dscp: u8,
    /// DSCP value seen in a capture taken at (or near) the sender, proving
    /// what left the host. `None` if no send-side capture was available.
    pub observed_at_source: Option<u8>,
    /// DSCP value seen in a capture taken at (or near) the receiver,
    /// proving what arrived. `None` if no receive-side capture was
    /// available. This is the field the trap is about: without this, DSCP
    /// survival is not provable regardless of what the sender intended.
    pub observed_at_destination: Option<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DscpSurvival {
    /// Both source and destination captures exist, and the value matched.
    Survived,
    /// Both captures exist, and the value did not match -- proof of
    /// re-marking or stripping somewhere on path.
    AlteredOnPath,
    /// One or both captures are missing. Marking survival cannot be
    /// claimed either way; the DSCP sweep's QoS conclusions are qualified
    /// as unverified rather than implied to be meaningful.
    Unverified,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DscpClassResult {
    pub dscp_class: u8,
    pub samples: Vec<DscpCaptureSample>,
    pub survival: DscpSurvival,
    /// Only populated (and only meaningful) when `survival == Survived`.
    /// Correlating loss/WMM-access-category with a DSCP class whose
    /// survival is unverified would misattribute infrastructure behavior
    /// to a marking that might never have reached the infrastructure intact.
    pub loss_percent_if_survived: Option<f64>,
}

pub fn classify_dscp_survival(samples: &[DscpCaptureSample]) -> DscpSurvival {
    if samples.is_empty() {
        return DscpSurvival::Unverified;
    }
    let mut any_pair = false;
    let mut all_matched = true;
    for s in samples {
        match (s.observed_at_source, s.observed_at_destination) {
            (Some(src), Some(dst)) => {
                any_pair = true;
                if src != dst {
                    all_matched = false;
                }
            }
            _ => {
                // Any sample missing a side means the class as a whole
                // cannot claim proven survival -- one gap in coverage is
                // enough to withhold the claim.
                return DscpSurvival::Unverified;
            }
        }
    }
    if !any_pair {
        return DscpSurvival::Unverified;
    }
    if all_matched {
        DscpSurvival::Survived
    } else {
        DscpSurvival::AlteredOnPath
    }
}

pub fn build_dscp_result(dscp_class: u8, samples: Vec<DscpCaptureSample>, loss_percent: Option<f64>) -> DscpClassResult {
    let survival = classify_dscp_survival(&samples);
    let loss_percent_if_survived = if survival == DscpSurvival::Survived { loss_percent } else { None };
    DscpClassResult { dscp_class, samples, survival, loss_percent_if_survived }
}

/// Flags a repeated control whose loss deviates materially from its first
/// occurrence at the same flow_count -- the drift the field notes describe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlDrift {
    pub flow_count: u32,
    pub first_loss_percent: f64,
    pub repeat_loss_percent: f64,
    pub drifted: bool,
}

pub fn detect_control_drift(matrix: &FlowCountMatrix) -> Vec<ControlDrift> {
    use std::collections::HashMap;
    let mut first_seen: HashMap<u32, f64> = HashMap::new();
    let mut drifts = Vec::new();
    for p in &matrix.points {
        let Some(loss) = p.loss_percent else { continue };
        if p.is_repeated_control {
            if let Some(&first) = first_seen.get(&p.flow_count) {
                let drifted = (loss - first).abs() > 10.0;
                drifts.push(ControlDrift {
                    flow_count: p.flow_count,
                    first_loss_percent: first,
                    repeat_loss_percent: loss,
                    drifted,
                });
            }
        } else {
            first_seen.entry(p.flow_count).or_insert(loss);
        }
    }
    drifts
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pt(flow_count: u32, per_flow: f64, target_agg: f64, actual_agg: Option<f64>, loss: Option<f64>, repeat: bool) -> FlowCountPoint {
        FlowCountPoint {
            flow_count,
            per_flow_bps: per_flow,
            target_aggregate_bps: target_agg,
            actual_aggregate_bps: actual_agg,
            loss_percent: loss,
            source_ports: vec![],
            is_repeated_control: repeat,
        }
    }

    #[test]
    fn aggregate_held_constant_across_flow_counts_is_detected() {
        let matrix = FlowCountMatrix {
            points: vec![
                pt(1, 100e6, 100e6, Some(99.5e6), Some(1.0), false),
                pt(2, 50e6, 100e6, Some(101e6), Some(2.0), false),
                pt(4, 25e6, 100e6, Some(98e6), Some(0.5), false),
                pt(8, 12.5e6, 100e6, Some(100.2e6), Some(3.0), false),
            ],
        };
        let check = check_aggregate_constancy(&matrix);
        assert!(check.held_constant, "deviation {:?} should be within tolerance", check.max_deviation_fraction);
    }

    #[test]
    fn aggregate_not_held_constant_is_detected() {
        let matrix = FlowCountMatrix {
            points: vec![
                pt(1, 100e6, 100e6, Some(100e6), Some(1.0), false),
                pt(8, 12.5e6, 100e6, Some(40e6), Some(1.0), false), // way under target
            ],
        };
        let check = check_aggregate_constancy(&matrix);
        assert!(!check.held_constant);
    }

    #[test]
    fn unmeasured_aggregate_point_prevents_held_constant_claim() {
        let matrix = FlowCountMatrix {
            points: vec![
                pt(1, 100e6, 100e6, Some(100e6), Some(1.0), false),
                pt(2, 50e6, 100e6, None, Some(1.0), false), // never measured
            ],
        };
        let check = check_aggregate_constancy(&matrix);
        assert!(!check.held_constant, "an unmeasured point must not be assumed constant");
    }

    #[test]
    fn dscp_survival_requires_both_sides_captured() {
        let both_match = vec![DscpCaptureSample { sent_dscp: 46, observed_at_source: Some(46), observed_at_destination: Some(46) }];
        assert_eq!(classify_dscp_survival(&both_match), DscpSurvival::Survived);

        let mismatched = vec![DscpCaptureSample { sent_dscp: 46, observed_at_source: Some(46), observed_at_destination: Some(0) }];
        assert_eq!(classify_dscp_survival(&mismatched), DscpSurvival::AlteredOnPath);

        let no_dest = vec![DscpCaptureSample { sent_dscp: 46, observed_at_source: Some(46), observed_at_destination: None }];
        assert_eq!(classify_dscp_survival(&no_dest), DscpSurvival::Unverified);

        let no_capture = vec![DscpCaptureSample { sent_dscp: 46, observed_at_source: None, observed_at_destination: None }];
        assert_eq!(classify_dscp_survival(&no_capture), DscpSurvival::Unverified);
    }

    #[test]
    fn unverified_survival_withholds_loss_correlation() {
        let no_dest = vec![DscpCaptureSample { sent_dscp: 46, observed_at_source: Some(46), observed_at_destination: None }];
        let result = build_dscp_result(46, no_dest, Some(5.0));
        assert_eq!(result.survival, DscpSurvival::Unverified);
        assert_eq!(
            result.loss_percent_if_survived, None,
            "loss correlation must not be reported when survival is unverified"
        );
    }

    #[test]
    fn survived_survival_carries_its_loss_figure() {
        let both_match = vec![DscpCaptureSample { sent_dscp: 46, observed_at_source: Some(46), observed_at_destination: Some(46) }];
        let result = build_dscp_result(46, both_match, Some(5.0));
        assert_eq!(result.survival, DscpSurvival::Survived);
        assert_eq!(result.loss_percent_if_survived, Some(5.0));
    }

    #[test]
    fn control_drift_is_detected_between_repeats() {
        let matrix = FlowCountMatrix {
            points: vec![
                pt(1, 100e6, 100e6, Some(100e6), Some(2.0), false),
                pt(1, 100e6, 100e6, Some(100e6), Some(25.0), true), // repeat, drifted
            ],
        };
        let drifts = detect_control_drift(&matrix);
        assert_eq!(drifts.len(), 1);
        assert!(drifts[0].drifted);
    }
}
