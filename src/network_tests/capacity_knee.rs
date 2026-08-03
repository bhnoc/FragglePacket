//! GAP-070: native capacity/latency-knee discovery with application
//! cross-validation.
//!
//! Field evidence from PC13. Native bidirectional traffic passed nearly in full
//! through 60 Mbps per direction, then plateaued near 134-142 Mbps combined from
//! 70-100 while loaded gateway latency rose from 8 ms to 17-28 ms. Rate-
//! controlled application traffic independently reproduced the same knee: 60+60
//! stayed balanced, but at 70+70 HTTPS upload fell to 44-47 Mbps while download
//! held near 72 Mbps, with gateway latency averaging 45-68 ms.
//!
//! Two distinctions carry the whole module. A *plateau* (combined throughput
//! flattens while the split stays balanced) is a capacity ceiling; *directional
//! unfairness* (one direction collapses while the other holds) is a different
//! finding with a different owner. And a knee that only one method produces is
//! not credible: GAP-069 showed the paired-process harness manufacturing a
//! directional collapse that looked like a network fault, so an unreproduced
//! knee is reported unconfirmed rather than established.

use serde::{Deserialize, Serialize};

/// Why a measured point cannot be scored. Kept separate from a low result: a
/// rejected point is absent from the analysis, never a zero in it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PointRejection {
    /// Reported duration diverged from the request beyond tolerance, so any
    /// rate derived from the window is arithmetic nonsense.
    DurationInconsistent {
        requested_secs: f64,
        reported_secs: f64,
    },
    /// The runner reported an error before producing a measurement.
    ProcessFailure { detail: String },
    /// A required field was absent from the result schema.
    SchemaIncomplete { missing: Vec<String> },
}

impl PointRejection {
    pub fn reason(&self) -> String {
        match self {
            PointRejection::DurationInconsistent {
                requested_secs,
                reported_secs,
            } => format!(
                "reported a {:.2}s interval for a {:.2}s request, so the measurement window is not \
                 trustworthy",
                reported_secs, requested_secs
            ),
            PointRejection::ProcessFailure { detail } => {
                format!("the runner failed before measuring: {}", detail)
            }
            PointRejection::SchemaIncomplete { missing } => {
                format!(
                    "result schema lacked required field(s): {}",
                    missing.join(", ")
                )
            }
        }
    }
}

/// Reported duration may diverge from the request by at most this fraction.
/// Matches the tolerance `throughput_tuner` already applies.
pub const DURATION_TOLERANCE: f64 = 0.20;

/// One offered rate's outcome. `up_mbps`/`down_mbps` are `Option` so a point
/// that failed to measure is never scored as zero throughput.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SweepPoint {
    /// Offered rate per direction.
    pub offered_mbps: f64,
    pub up_mbps: Option<f64>,
    pub down_mbps: Option<f64>,
    /// Loaded first-hop latency during this point, from an interleaved idle
    /// bracket. `None` when the gateway suppressed ICMP or no probe ran.
    pub loaded_latency_ms: Option<f64>,
    /// Which qualified listener served this point. Distinct per phase so one
    /// listener never serves two concurrent sessions (GAP-040).
    pub listener_label: Option<String>,
    /// Order this point was actually executed in. Randomized ordering is what
    /// keeps a knee from being an artifact of a monotonic ascending pass.
    pub execution_index: usize,
    pub rejected: Option<PointRejection>,
}

impl SweepPoint {
    pub fn usable(&self) -> bool {
        self.rejected.is_none() && self.up_mbps.is_some() && self.down_mbps.is_some()
    }

    pub fn combined_mbps(&self) -> Option<f64> {
        match (self.up_mbps, self.down_mbps) {
            (Some(u), Some(d)) if self.rejected.is_none() => Some(u + d),
            _ => None,
        }
    }

    /// Ratio of the weaker direction to the stronger. 1.0 is perfectly
    /// balanced; near 0 means one direction collapsed.
    pub fn balance(&self) -> Option<f64> {
        match (self.up_mbps, self.down_mbps) {
            (Some(u), Some(d)) if self.rejected.is_none() => {
                let hi = u.max(d);
                if hi <= 0.0 {
                    None
                } else {
                    Some(u.min(d) / hi)
                }
            }
            _ => None,
        }
    }
}

/// Validates a point's timing before it can be scored.
pub fn reject_if_invalid(
    requested_secs: f64,
    reported_secs: Option<f64>,
    error: Option<&str>,
) -> Option<PointRejection> {
    if let Some(e) = error {
        if !e.trim().is_empty() {
            return Some(PointRejection::ProcessFailure {
                detail: e.to_string(),
            });
        }
    }
    match reported_secs {
        None => Some(PointRejection::SchemaIncomplete {
            missing: vec!["reported_interval_secs".to_string()],
        }),
        Some(r) if requested_secs > 0.0 => {
            let dev = ((r - requested_secs) / requested_secs).abs();
            if dev > DURATION_TOLERANCE {
                Some(PointRejection::DurationInconsistent {
                    requested_secs,
                    reported_secs: r,
                })
            } else {
                None
            }
        }
        Some(_) => None,
    }
}

/// A point beyond which combined throughput stops tracking offered load.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum KneeVerdict {
    /// Combined throughput flattened while the split stayed balanced.
    CapacityPlateau {
        knee_offered_mbps: f64,
        plateau_combined_mbps: f64,
        detail: String,
    },
    /// One direction collapsed while the other held. A different finding from a
    /// plateau, with a different owner.
    DirectionalUnfairness {
        knee_offered_mbps: f64,
        weaker_direction: String,
        balance: f64,
        detail: String,
    },
    /// The sweep never stopped tracking offered load, so there is no knee to
    /// report. Never named as the highest tested rate.
    NoKneeWithinTestedRange { highest_tested_mbps: f64 },
    /// Too few usable points to say anything.
    InsufficientPoints { usable: usize, required: usize },
}

/// Balance at or below this counts as one direction collapsing.
///
/// Derived from the PC13 field data rather than picked: the unfair application
/// points sit at 0.61-0.65 (upload 44-47 against download 72) while the
/// balanced native points sit at 0.96-0.99 (69-71 against 68). 0.80 separates
/// them with wide margin on both sides.
pub const UNFAIR_BALANCE: f64 = 0.80;
/// Combined throughput must gain at least this fraction of the offered increase
/// to still be "tracking" the offered load.
pub const TRACKING_EFFICIENCY: f64 = 0.5;
/// Minimum usable points before any verdict.
pub const MIN_POINTS: usize = 3;

/// Detects the knee. Points may arrive in any execution order; they are sorted
/// by offered rate here, so a randomized sweep and an ascending one produce the
/// same verdict. That is what makes the knee robust to ordering and drift.
pub fn detect_knee(points: &[SweepPoint]) -> KneeVerdict {
    let mut usable: Vec<&SweepPoint> = points.iter().filter(|p| p.usable()).collect();
    if usable.len() < MIN_POINTS {
        return KneeVerdict::InsufficientPoints {
            usable: usable.len(),
            required: MIN_POINTS,
        };
    }
    usable.sort_by(|a, b| a.offered_mbps.partial_cmp(&b.offered_mbps).unwrap());

    for w in usable.windows(2) {
        let (lo, hi) = (w[0], w[1]);
        let offered_gain = (hi.offered_mbps - lo.offered_mbps) * 2.0; // both directions
        if offered_gain <= 0.0 {
            continue;
        }
        let lo_c = lo.combined_mbps().unwrap_or(0.0);
        let hi_c = hi.combined_mbps().unwrap_or(0.0);
        let achieved_gain = hi_c - lo_c;
        let tracking = achieved_gain / offered_gain;

        if tracking < TRACKING_EFFICIENCY {
            // Stopped tracking. Which failure is it?
            let bal = hi.balance().unwrap_or(1.0);
            if bal <= UNFAIR_BALANCE {
                let weaker = match (hi.up_mbps, hi.down_mbps) {
                    (Some(u), Some(d)) if u < d => "upload",
                    _ => "download",
                };
                return KneeVerdict::DirectionalUnfairness {
                    knee_offered_mbps: hi.offered_mbps,
                    weaker_direction: weaker.to_string(),
                    balance: bal,
                    detail: format!(
                        "at {:.0} Mbps per direction {} fell to {:.1} Mbps while the other held at \
                         {:.1} Mbps (balance {:.2}); one direction collapsed rather than both \
                         sharing a ceiling",
                        hi.offered_mbps,
                        weaker,
                        hi.up_mbps.unwrap_or(0.0).min(hi.down_mbps.unwrap_or(0.0)),
                        hi.up_mbps.unwrap_or(0.0).max(hi.down_mbps.unwrap_or(0.0)),
                        bal
                    ),
                };
            }
            return KneeVerdict::CapacityPlateau {
                knee_offered_mbps: lo.offered_mbps,
                plateau_combined_mbps: hi_c,
                detail: format!(
                    "combined throughput tracked offered load through {:.0} Mbps per direction then \
                     flattened near {:.1} Mbps combined while the split stayed balanced \
                     (balance {:.2}); this is a shared capacity ceiling, not one direction losing",
                    lo.offered_mbps, hi_c, bal
                ),
            };
        }
    }

    KneeVerdict::NoKneeWithinTestedRange {
        highest_tested_mbps: usable.last().map(|p| p.offered_mbps).unwrap_or(0.0),
    }
}

/// Whether the application method reproduced the native finding.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CrossValidation {
    /// Both methods found a knee at a comparable rate.
    Reproduced {
        native_knee_mbps: f64,
        application_knee_mbps: f64,
    },
    /// The native finding did not reproduce, so it is not established. GAP-069
    /// is the precedent: a single-method result can be harness artifact.
    NotReproduced { detail: String },
    /// The application method was not run or produced nothing usable.
    NotAttempted { reason: String },
}

impl CrossValidation {
    /// Only a reproduced knee may be reported as established.
    pub fn permits_established_claim(&self) -> bool {
        matches!(self, CrossValidation::Reproduced { .. })
    }
}

/// Knees within this fraction of each other count as the same knee.
pub const KNEE_AGREEMENT: f64 = 0.35;

pub fn cross_validate(native: &KneeVerdict, application: Option<&KneeVerdict>) -> CrossValidation {
    let knee_of = |v: &KneeVerdict| -> Option<f64> {
        match v {
            KneeVerdict::CapacityPlateau {
                knee_offered_mbps, ..
            }
            | KneeVerdict::DirectionalUnfairness {
                knee_offered_mbps, ..
            } => Some(*knee_offered_mbps),
            _ => None,
        }
    };

    let app = match application {
        None => {
            return CrossValidation::NotAttempted {
                reason: "no application-method sweep was supplied".to_string(),
            }
        }
        Some(a) => a,
    };

    match (knee_of(native), knee_of(app)) {
        (Some(n), Some(a)) => {
            let hi = n.max(a);
            if hi > 0.0 && ((n - a).abs() / hi) <= KNEE_AGREEMENT {
                CrossValidation::Reproduced {
                    native_knee_mbps: n,
                    application_knee_mbps: a,
                }
            } else {
                CrossValidation::NotReproduced {
                    detail: format!(
                        "native found a knee at {:.0} Mbps but the application method found one at \
                         {:.0} Mbps, too far apart to be the same effect",
                        n, a
                    ),
                }
            }
        }
        (Some(n), None) => CrossValidation::NotReproduced {
            detail: format!(
                "native found a knee at {:.0} Mbps per direction but the application method found \
                 none; a single-method knee may be a load-generator artifact rather than a network \
                 limit (see GAP-069) and is therefore unconfirmed",
                n
            ),
        },
        (None, Some(a)) => CrossValidation::NotReproduced {
            detail: format!(
                "the application method found a knee at {:.0} Mbps that native traffic did not \
                 reproduce",
                a
            ),
        },
        (None, None) => CrossValidation::NotAttempted {
            reason: "neither method found a knee to cross-validate".to_string(),
        },
    }
}

/// Opening and closing controls at the same rate. A public endpoint that drifts
/// between them invalidates comparisons drawn across the sweep.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftBracket {
    pub opening_combined_mbps: Option<f64>,
    pub closing_combined_mbps: Option<f64>,
}

/// Drift beyond this fraction is reported separately from the measurement.
pub const DRIFT_TOLERANCE: f64 = 0.15;

impl DriftBracket {
    /// `None` when either control is missing: drift cannot be computed from one
    /// side, and reporting 0% drift would falsely imply a stable endpoint.
    pub fn drift_fraction(&self) -> Option<f64> {
        match (self.opening_combined_mbps, self.closing_combined_mbps) {
            (Some(o), Some(c)) if o > 0.0 => Some(((c - o) / o).abs()),
            _ => None,
        }
    }

    pub fn exceeds_tolerance(&self) -> Option<bool> {
        self.drift_fraction().map(|d| d > DRIFT_TOLERANCE)
    }

    pub fn statement(&self) -> String {
        match self.drift_fraction() {
            None => "endpoint drift unavailable: both an opening and a closing control are \
                     required, and one is missing"
                .to_string(),
            Some(d) if d > DRIFT_TOLERANCE => format!(
                "endpoint drifted {:.1}% between the opening and closing controls, above the \
                 {:.0}% tolerance; sweep points are not comparable across that drift",
                d * 100.0,
                DRIFT_TOLERANCE * 100.0
            ),
            Some(d) => format!(
                "endpoint drift {:.1}%, within the {:.0}% tolerance",
                d * 100.0,
                DRIFT_TOLERANCE * 100.0
            ),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KneeReport {
    pub interface: String,
    pub native_points: Vec<SweepPoint>,
    pub application_points: Vec<SweepPoint>,
    pub native_verdict: KneeVerdict,
    pub application_verdict: Option<KneeVerdict>,
    pub cross_validation: CrossValidation,
    pub drift: DriftBracket,
    pub idle_latency_ms: Option<f64>,
    pub rejected_points: Vec<(f64, String)>,
    /// The claim an operator may actually make, gated on cross-validation.
    pub established_claim: Option<String>,
}

pub fn build_report(
    interface: &str,
    native_points: Vec<SweepPoint>,
    application_points: Vec<SweepPoint>,
    drift: DriftBracket,
    idle_latency_ms: Option<f64>,
) -> KneeReport {
    let native_verdict = detect_knee(&native_points);
    let application_verdict = if application_points.is_empty() {
        None
    } else {
        Some(detect_knee(&application_points))
    };
    let cross_validation = cross_validate(&native_verdict, application_verdict.as_ref());

    let mut rejected: Vec<(f64, String)> = Vec::new();
    for p in native_points.iter().chain(application_points.iter()) {
        if let Some(r) = &p.rejected {
            rejected.push((p.offered_mbps, r.reason()));
        }
    }

    // A knee is only an established finding when a second method reproduced it
    // AND the endpoint did not drift underneath the sweep.
    let established_claim = if cross_validation.permits_established_claim()
        && drift.exceeds_tolerance() == Some(false)
    {
        match &native_verdict {
            KneeVerdict::CapacityPlateau { detail, .. }
            | KneeVerdict::DirectionalUnfairness { detail, .. } => Some(detail.clone()),
            _ => None,
        }
    } else {
        None
    };

    KneeReport {
        interface: interface.to_string(),
        native_points,
        application_points,
        native_verdict,
        application_verdict,
        cross_validation,
        drift,
        idle_latency_ms,
        rejected_points: rejected,
        established_claim,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pt(offered: f64, up: f64, down: f64, lat: f64, idx: usize) -> SweepPoint {
        SweepPoint {
            offered_mbps: offered,
            up_mbps: Some(up),
            down_mbps: Some(down),
            loaded_latency_ms: Some(lat),
            listener_label: Some(format!("listener-{}", idx)),
            execution_index: idx,
            rejected: None,
        }
    }

    /// PC13's native sweep: full through 60, plateauing 134-142 combined from 70.
    fn pc13_native() -> Vec<SweepPoint> {
        vec![
            pt(40.0, 40.0, 40.0, 8.0, 0),
            pt(60.0, 59.0, 59.0, 9.0, 1),
            pt(70.0, 69.0, 68.0, 17.0, 2),
            pt(85.0, 70.0, 68.0, 22.0, 3),
            pt(100.0, 71.0, 68.0, 28.0, 4),
        ]
    }

    /// PC13's application sweep: 60+60 balanced, 70+70 upload collapses.
    fn pc13_application() -> Vec<SweepPoint> {
        vec![
            pt(40.0, 40.0, 40.0, 10.0, 0),
            pt(60.0, 58.0, 59.0, 12.0, 1),
            pt(70.0, 45.0, 72.0, 56.0, 2),
            pt(85.0, 44.0, 72.0, 68.0, 3),
        ]
    }

    #[test]
    fn pc13_native_sweep_reports_a_capacity_plateau() {
        match detect_knee(&pc13_native()) {
            KneeVerdict::CapacityPlateau {
                knee_offered_mbps,
                plateau_combined_mbps,
                ..
            } => {
                assert!((60.0..=70.0).contains(&knee_offered_mbps));
                assert!((130.0..=145.0).contains(&plateau_combined_mbps));
            }
            other => panic!("expected a plateau, got {:?}", other),
        }
    }

    #[test]
    fn pc13_application_sweep_reports_directional_unfairness() {
        match detect_knee(&pc13_application()) {
            KneeVerdict::DirectionalUnfairness {
                weaker_direction,
                balance,
                ..
            } => {
                assert_eq!(weaker_direction, "upload");
                assert!(balance <= UNFAIR_BALANCE);
            }
            other => panic!("expected directional unfairness, got {:?}", other),
        }
    }

    #[test]
    fn plateau_and_unfairness_are_different_verdicts() {
        // The central GAP-070 distinction: same knee rate, different findings.
        let a = detect_knee(&pc13_native());
        let b = detect_knee(&pc13_application());
        assert_ne!(a, b);
        assert!(matches!(a, KneeVerdict::CapacityPlateau { .. }));
        assert!(matches!(b, KneeVerdict::DirectionalUnfairness { .. }));
    }

    #[test]
    fn a_sweep_that_never_plateaus_reports_no_knee_not_the_highest_rate() {
        let linear = vec![
            pt(10.0, 10.0, 10.0, 5.0, 0),
            pt(20.0, 20.0, 20.0, 5.0, 1),
            pt(30.0, 30.0, 30.0, 6.0, 2),
            pt(40.0, 40.0, 40.0, 6.0, 3),
        ];
        match detect_knee(&linear) {
            KneeVerdict::NoKneeWithinTestedRange {
                highest_tested_mbps,
            } => {
                assert_eq!(highest_tested_mbps, 40.0);
            }
            other => panic!("expected no knee, got {:?}", other),
        }
    }

    #[test]
    fn execution_order_does_not_change_the_verdict() {
        // A knee found only by an ascending pass could be drift or ordering
        // artifact. Shuffled input must reach the same conclusion.
        let mut shuffled = pc13_native();
        shuffled.reverse();
        shuffled.swap(0, 2);
        assert_eq!(detect_knee(&pc13_native()), detect_knee(&shuffled));
    }

    #[test]
    fn too_few_usable_points_is_insufficient_not_a_knee() {
        let two = vec![pt(10.0, 10.0, 10.0, 5.0, 0), pt(20.0, 20.0, 20.0, 5.0, 1)];
        assert!(matches!(
            detect_knee(&two),
            KneeVerdict::InsufficientPoints { .. }
        ));
    }

    #[test]
    fn a_duration_inconsistent_point_is_rejected_not_scored() {
        // The field shape: a 15.84s reported interval for a shorter request.
        let r = reject_if_invalid(10.0, Some(15.84), None);
        assert!(matches!(
            r,
            Some(PointRejection::DurationInconsistent { .. })
        ));

        let mut pts = pc13_native();
        pts[2].rejected = r;
        // The rejected point contributes nothing; it is not a zero.
        assert!(!pts[2].usable());
        assert_eq!(pts[2].combined_mbps(), None);
    }

    #[test]
    fn a_missing_duration_is_schema_incomplete_not_valid() {
        assert!(matches!(
            reject_if_invalid(10.0, None, None),
            Some(PointRejection::SchemaIncomplete { .. })
        ));
    }

    #[test]
    fn a_process_failure_is_rejected_before_any_rate_is_read() {
        assert!(matches!(
            reject_if_invalid(10.0, Some(10.0), Some("unable to connect to server")),
            Some(PointRejection::ProcessFailure { .. })
        ));
    }

    #[test]
    fn a_knee_the_application_method_did_not_reproduce_is_unconfirmed() {
        let native = detect_knee(&pc13_native());
        let flat = vec![
            pt(40.0, 40.0, 40.0, 5.0, 0),
            pt(70.0, 70.0, 70.0, 5.0, 1),
            pt(100.0, 100.0, 100.0, 6.0, 2),
        ];
        let app = detect_knee(&flat);
        let cv = cross_validate(&native, Some(&app));
        assert!(!cv.permits_established_claim());
        match cv {
            CrossValidation::NotReproduced { detail } => {
                assert!(
                    detail.contains("GAP-069"),
                    "should cite the artifact precedent"
                );
            }
            other => panic!("expected NotReproduced, got {:?}", other),
        }
    }

    #[test]
    fn pc13_both_methods_agree_so_the_knee_is_reproduced() {
        let cv = cross_validate(
            &detect_knee(&pc13_native()),
            Some(&detect_knee(&pc13_application())),
        );
        assert!(cv.permits_established_claim(), "got {:?}", cv);
    }

    #[test]
    fn no_application_sweep_means_not_attempted_not_reproduced() {
        let cv = cross_validate(&detect_knee(&pc13_native()), None);
        assert!(!cv.permits_established_claim());
        assert!(matches!(cv, CrossValidation::NotAttempted { .. }));
    }

    #[test]
    fn drift_is_unavailable_from_one_control_never_zero() {
        let d = DriftBracket {
            opening_combined_mbps: Some(140.0),
            closing_combined_mbps: None,
        };
        assert_eq!(d.drift_fraction(), None);
        assert_eq!(d.exceeds_tolerance(), None);
        assert!(d.statement().contains("unavailable"));
    }

    #[test]
    fn severe_drift_is_reported_separately_from_the_measurement() {
        let d = DriftBracket {
            opening_combined_mbps: Some(140.0),
            closing_combined_mbps: Some(90.0),
        };
        assert_eq!(d.exceeds_tolerance(), Some(true));
        assert!(d.statement().contains("not comparable"));
    }

    #[test]
    fn a_drifting_endpoint_blocks_the_established_claim() {
        // Both methods agreed, but the endpoint moved underneath the sweep.
        let r = build_report(
            "en0",
            pc13_native(),
            pc13_application(),
            DriftBracket {
                opening_combined_mbps: Some(140.0),
                closing_combined_mbps: Some(90.0),
            },
            Some(8.0),
        );
        assert!(r.cross_validation.permits_established_claim());
        assert!(
            r.established_claim.is_none(),
            "drift must block the claim even when both methods agreed"
        );
    }

    #[test]
    fn pc13_full_report_establishes_the_knee_and_lists_no_rejections() {
        let r = build_report(
            "en0",
            pc13_native(),
            pc13_application(),
            DriftBracket {
                opening_combined_mbps: Some(140.0),
                closing_combined_mbps: Some(138.0),
            },
            Some(8.0),
        );
        assert!(r.established_claim.is_some());
        assert!(r.rejected_points.is_empty());
        assert!(matches!(
            r.native_verdict,
            KneeVerdict::CapacityPlateau { .. }
        ));
        assert!(matches!(
            r.application_verdict,
            Some(KneeVerdict::DirectionalUnfairness { .. })
        ));
    }

    #[test]
    fn each_point_records_its_own_listener() {
        // GAP-040 leases one listener per active session; a sweep that reused
        // one listener across concurrent phases would be measuring contention.
        let pts = pc13_native();
        let labels: std::collections::BTreeSet<_> = pts
            .iter()
            .filter_map(|p| p.listener_label.clone())
            .collect();
        assert_eq!(
            labels.len(),
            pts.len(),
            "each phase needs a distinct listener"
        );
    }
}
