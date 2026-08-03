//! GAP-032: independently rate-controlled simultaneous upload/download.
//!
//! Field evidence (`scripts/bhusa-peer-impact-test.zsh`, whose method this
//! ports): a single `iperf3 --bidir` session applies the same target rate in
//! both directions, which hides asymmetric behavior. Independent listeners
//! per direction exposed a sharp cliff: with download fixed at 350 Mbps,
//! upload was nearly clean at 250 Mbps, lost 5.6% at 300, and 13.6% at 350;
//! with upload fixed at 350, download loss jumped from 0.076% at 250 to
//! 19.3% at 300 and 29.7% at 350. The deliverable per the acceptance
//! criteria is "the first lossy rate in each direction" -- a threshold
//! crossing, not an average -- and it must never be extrapolated: reporting
//! it requires having actually measured both a clean rate below it and a
//! lossy rate at it (see `HANDOFF.md`'s "recurring failure mode" -- a rate
//! inferred rather than measured is instance #9 of the same bug).
//!
//! Ported from the zsh script: two independent client sessions against
//! separate listener ports, explicit `-B "$LOCAL_IP%$IFACE"`-style source
//! binding, and a shared start barrier so both sessions' windows overlap
//! rather than merely being launched close together. This module owns the
//! barrier/merge/threshold logic; the actual iperf3 invocation and JSON
//! parsing are the CLI layer's job, using `network_tests::iperf` (GAP-039)
//! -- this module never parses iperf3 output itself.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    Upload,
    Download,
}

/// One rate point measured in one direction. `loss_percent: None` means the
/// point was not actually measured (e.g. skipped, or the session did not
/// connect) -- never a measured zero standing in for "unknown".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RatePoint {
    pub target_mbps: f64,
    pub achieved_mbps: Option<f64>,
    pub loss_percent: Option<f64>,
    pub usable: bool,
}

impl RatePoint {
    pub fn is_lossy(&self, threshold_pct: f64) -> Option<bool> {
        if !self.usable {
            return None;
        }
        self.loss_percent.map(|l| l > threshold_pct)
    }
}

/// A single client session's window on the shared timeline, in seconds
/// relative to the coordinated start epoch both sessions waited for.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionWindow {
    pub direction: Direction,
    pub port: u16,
    pub start_secs: f64,
    pub end_secs: f64,
}

impl SessionWindow {
    pub fn overlaps(&self, other: &SessionWindow) -> bool {
        self.start_secs < other.end_secs && other.start_secs < self.end_secs
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergedTimeline {
    pub upload: SessionWindow,
    pub download: SessionWindow,
    /// `false` when the two sessions' windows did not actually overlap --
    /// e.g. one connected late, or a barrier wait was skipped. A merged
    /// report built from non-overlapping windows would misrepresent
    /// "simultaneous" load as sequential load wearing a shared label.
    pub time_aligned: bool,
}

pub fn merge_timeline(upload: SessionWindow, download: SessionWindow) -> MergedTimeline {
    let time_aligned = upload.overlaps(&download);
    MergedTimeline {
        upload,
        download,
        time_aligned,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectionSweep {
    pub direction: Direction,
    pub points: Vec<RatePoint>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum FirstLossyRate {
    /// A clean rate and a lossy rate immediately above it were both
    /// actually measured; `clean_mbps` is the highest measured clean rate,
    /// `lossy_mbps` the lowest measured rate that crossed the threshold.
    Found { clean_mbps: f64, lossy_mbps: f64 },
    /// Every measured rate stayed under the threshold -- there is no lossy
    /// rate to report, not "the threshold is above the highest tried rate"
    /// (that would be an extrapolation this type does not make).
    NoneObservedWithinTestedRange,
    /// Every measured rate was already lossy, including the lowest tried --
    /// there is no clean baseline to report a threshold against.
    AllTestedRatesLossy,
    /// Fewer than two usable points exist; a threshold cannot be
    /// established from zero or one measurement.
    InsufficientData,
}

/// Finds the first (lowest) rate at which loss exceeds `threshold_pct`,
/// requiring both the crossing point and a clean point below it to have
/// been genuinely measured (`usable`). Points are sorted by `target_mbps`
/// before scanning, since sweep order is not guaranteed by the caller.
pub fn first_lossy_rate(sweep: &DirectionSweep, threshold_pct: f64) -> FirstLossyRate {
    let mut usable_points: Vec<&RatePoint> = sweep.points.iter().filter(|p| p.usable).collect();
    usable_points.sort_by(|a, b| a.target_mbps.partial_cmp(&b.target_mbps).unwrap());

    if usable_points.len() < 2 {
        return FirstLossyRate::InsufficientData;
    }

    let mut last_clean: Option<f64> = None;
    for point in &usable_points {
        match point.is_lossy(threshold_pct) {
            Some(true) => {
                return match last_clean {
                    Some(clean_mbps) => FirstLossyRate::Found {
                        clean_mbps,
                        lossy_mbps: point.target_mbps,
                    },
                    None => FirstLossyRate::AllTestedRatesLossy,
                };
            }
            Some(false) => last_clean = Some(point.target_mbps),
            None => {} // unmeasured loss_percent: skip, do not treat as clean or lossy
        }
    }
    FirstLossyRate::NoneObservedWithinTestedRange
}

#[cfg(test)]
mod tests {
    use super::*;

    fn point(target: f64, achieved: Option<f64>, loss: Option<f64>, usable: bool) -> RatePoint {
        RatePoint {
            target_mbps: target,
            achieved_mbps: achieved,
            loss_percent: loss,
            usable,
        }
    }

    #[test]
    fn first_lossy_rate_requires_a_measured_clean_point_below_it() {
        // Mirrors the field data: 250 clean, 300 lossy (5.6%), 350 lossier.
        let sweep = DirectionSweep {
            direction: Direction::Upload,
            points: vec![
                point(250.0, Some(249.9), Some(0.02), true),
                point(300.0, Some(283.0), Some(5.6), true),
                point(350.0, Some(302.0), Some(13.6), true),
            ],
        };
        let result = first_lossy_rate(&sweep, 2.0);
        assert_eq!(
            result,
            FirstLossyRate::Found {
                clean_mbps: 250.0,
                lossy_mbps: 300.0
            }
        );
    }

    #[test]
    fn never_extrapolates_past_the_tested_range() {
        let sweep = DirectionSweep {
            direction: Direction::Upload,
            points: vec![
                point(100.0, Some(99.9), Some(0.0), true),
                point(150.0, Some(149.8), Some(0.1), true),
            ],
        };
        assert_eq!(
            first_lossy_rate(&sweep, 2.0),
            FirstLossyRate::NoneObservedWithinTestedRange
        );
    }

    #[test]
    fn all_lossy_reports_no_clean_baseline_rather_than_a_fabricated_threshold() {
        let sweep = DirectionSweep {
            direction: Direction::Download,
            points: vec![
                point(300.0, Some(240.0), Some(20.0), true),
                point(350.0, Some(246.0), Some(29.7), true),
            ],
        };
        assert_eq!(
            first_lossy_rate(&sweep, 2.0),
            FirstLossyRate::AllTestedRatesLossy
        );
    }

    #[test]
    fn unusable_points_are_excluded_not_treated_as_clean() {
        // A failed/unconnected session at 300 must not become "clean 300"
        // just because loss_percent could not be read.
        let sweep = DirectionSweep {
            direction: Direction::Upload,
            points: vec![
                point(250.0, Some(249.9), Some(0.02), true),
                point(300.0, None, None, false),
                point(350.0, Some(302.0), Some(13.6), true),
            ],
        };
        let result = first_lossy_rate(&sweep, 2.0);
        assert_eq!(
            result,
            FirstLossyRate::Found {
                clean_mbps: 250.0,
                lossy_mbps: 350.0
            }
        );
    }

    #[test]
    fn insufficient_data_below_two_points() {
        let sweep = DirectionSweep {
            direction: Direction::Upload,
            points: vec![point(250.0, Some(249.9), Some(0.02), true)],
        };
        assert_eq!(
            first_lossy_rate(&sweep, 2.0),
            FirstLossyRate::InsufficientData
        );
    }

    #[test]
    fn overlapping_windows_are_time_aligned() {
        let upload = SessionWindow {
            direction: Direction::Upload,
            port: 5201,
            start_secs: 0.0,
            end_secs: 5.0,
        };
        let download = SessionWindow {
            direction: Direction::Download,
            port: 5202,
            start_secs: 1.0,
            end_secs: 6.0,
        };
        let merged = merge_timeline(upload, download);
        assert!(merged.time_aligned);
    }

    #[test]
    fn sequential_windows_are_not_time_aligned() {
        let upload = SessionWindow {
            direction: Direction::Upload,
            port: 5201,
            start_secs: 0.0,
            end_secs: 5.0,
        };
        let download = SessionWindow {
            direction: Direction::Download,
            port: 5202,
            start_secs: 5.5,
            end_secs: 10.0,
        };
        let merged = merge_timeline(upload, download);
        assert!(!merged.time_aligned);
    }
}
