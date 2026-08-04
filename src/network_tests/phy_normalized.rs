//! GAP-042: PHY-normalized fleet comparison.
//!
//! Field evidence, and the conclusion changed once normalization was
//! applied: a fixed 100 Mbps each way produced eleven VHT probes averaging
//! 27.0% downstream loss against eight HE probes averaging 0.98% -- read
//! naively, a damning legacy-client compatibility defect. PHY-normalized
//! retesting narrowed it sharply (VHT 8.3-18.0% at 150-250 Mbps directional,
//! HE 0.6-0.75% through 250 Mbps; VHT 60+60 simultaneous at 1.67% vs HE
//! 125+125 at 0.578%). Much of the fixed-100 gap was capacity/airtime
//! saturation, not a compatibility defect: a fixed absolute rate against
//! clients with different PHY ceilings conflates "this client is close to
//! its own ceiling" with "this AP mishandles this client's generation".
//!
//! This module never compares absolute offered rates across
//! heterogeneous clients. Every comparison is expressed as a fraction of
//! that client's own PHY capacity, and an attribution to AP backward
//! compatibility is refused unless the caller supplies strong-RF
//! directional control evidence for the comparison.
//!
//! Operates on operator-supplied per-node JSON (GAP-038's live fleet
//! orchestrator is Sprint 8); this module takes already-collected
//! per-node data in, it does not reach out to a fleet itself.

use serde::{Deserialize, Serialize};

use crate::load_guard::radio::RfQuality;
use crate::network_tests::freshness::{check_freshness, horizons, Freshness, InputTiming};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PhyGeneration {
    /// 802.11n
    Ht,
    /// 802.11ac
    Vht,
    /// 802.11ax
    He,
    /// 802.11be
    Eht,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeProfile {
    pub node_id: String,
    pub phy_generation: PhyGeneration,
    pub driver: String,
    pub kernel: String,
    /// The client's own negotiated PHY rate ceiling for this association,
    /// in Mbps (e.g. from `tx_rate_mbps` in a `RadioSnapshot`). This is the
    /// capacity the offered load is normalized against -- never a generic
    /// per-generation table value, since two HE clients on different
    /// chains/widths do not share one ceiling.
    pub phy_capacity_mbps: f64,
    pub rf_quality: RfQuality,
    /// True only when this measurement came from a directional (single-
    /// direction) load phase, as opposed to simultaneous bidirectional --
    /// GAP-042's attribution gate requires directional controls.
    pub directional_control: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseMeasurement {
    pub node: NodeProfile,
    pub offered_mbps: f64,
    pub loss_percent: f64,
    /// GAP-075: when the radio snapshot behind `phy_capacity_mbps` was taken,
    /// and when this phase's throughput was measured, both as seconds from run
    /// start. `None` means the caller did not record timing, in which case
    /// freshness cannot be judged and is reported as unknown rather than
    /// assumed good.
    #[serde(default)]
    pub phy_sampled_at_elapsed_secs: Option<f64>,
    #[serde(default)]
    pub measured_at_elapsed_secs: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedMeasurement {
    pub node_id: String,
    pub phy_generation: PhyGeneration,
    pub driver: String,
    pub kernel: String,
    pub offered_mbps: f64,
    pub phy_capacity_mbps: f64,
    /// offered_mbps / phy_capacity_mbps. This, not the absolute offered
    /// rate, is what makes two different clients' phases comparable.
    ///
    /// GAP-075: `None` when the PHY capacity behind the denominator had aged
    /// out of its validity horizon by the time this phase was measured. A roam
    /// changes PHY capacity without notice, so a fraction computed against a
    /// stale denominator describes a link that no longer exists while looking
    /// perfectly well-formed. See `freshness` for the reason string.
    pub offered_phy_fraction: Option<f64>,
    pub loss_percent: f64,
    pub rf_quality: RfQuality,
    pub directional_control: bool,
    /// Why the fraction was withheld, when it was.
    pub freshness: Freshness,
}

pub fn normalize(m: &PhaseMeasurement) -> NormalizedMeasurement {
    // GAP-075: the PHY capacity is sampled once and reused. Check that it was
    // still inside its horizon when this phase was measured, before dividing by
    // it. Timing is optional, so a caller that records none keeps the previous
    // behaviour rather than silently losing its figures.
    let freshness = match (m.phy_sampled_at_elapsed_secs, m.measured_at_elapsed_secs) {
        (Some(sampled), Some(now)) => check_freshness(
            &[InputTiming::new("phy_capacity_mbps", sampled, horizons::RADIO_SECS)],
            now,
        ),
        _ => Freshness::Fresh,
    };

    let fraction = if !freshness.permits_derived_figure() {
        None
    } else if m.node.phy_capacity_mbps > 0.0 {
        Some(m.offered_mbps / m.node.phy_capacity_mbps)
    } else {
        // A zero or negative PHY capacity cannot normalize anything; withheld
        // rather than reported as NaN, which downstream code would format as a
        // number-shaped nonsense value.
        None
    };

    NormalizedMeasurement {
        node_id: m.node.node_id.clone(),
        phy_generation: m.node.phy_generation,
        driver: m.node.driver.clone(),
        kernel: m.node.kernel.clone(),
        offered_mbps: m.offered_mbps,
        phy_capacity_mbps: m.node.phy_capacity_mbps,
        offered_phy_fraction: fraction,
        loss_percent: m.loss_percent,
        rf_quality: m.node.rf_quality,
        directional_control: m.node.directional_control,
        freshness,
    }
}

/// Two measurements are "comparable" for cohort attribution only when their
/// offered PHY fractions are close -- comparing a client running at 20% of
/// its own ceiling against one running at 90% of its own ceiling is not a
/// fair fixed-target comparison even if their absolute offered Mbps match.
const COMPARABLE_FRACTION_TOLERANCE: f64 = 0.15;

pub fn comparable_targets(a: &NormalizedMeasurement, b: &NormalizedMeasurement) -> bool {
    // A withheld fraction (stale denominator, or no usable PHY capacity) cannot
    // establish comparability. Two unknowns are not "close".
    let (Some(fa), Some(fb)) = (a.offered_phy_fraction, b.offered_phy_fraction) else {
        return false;
    };
    if !fa.is_finite() || !fb.is_finite() {
        return false;
    }
    (fa - fb).abs() <= COMPARABLE_FRACTION_TOLERANCE
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CohortStratum {
    pub phy_generation: PhyGeneration,
    pub driver: String,
    pub kernel: String,
    /// `None` when no member of this stratum had a usable fraction. Previously
    /// this divided a filtered sum by the UNFILTERED count, so one withheld
    /// fraction silently dragged the stratum mean toward zero.
    pub mean_offered_phy_fraction: Option<f64>,
    pub mean_loss_percent: f64,
    pub sample_count: usize,
    /// How many of `sample_count` contributed a usable fraction. A mean over 2
    /// of 8 samples is not the same claim as a mean over 8.
    pub fraction_sample_count: usize,
}

/// Stratifies a set of normalized measurements by (PHY generation, driver,
/// kernel) -- collapsing across those dimensions is exactly how the
/// original fixed-100 comparison hid the capacity confound.
pub fn stratify(measurements: &[NormalizedMeasurement]) -> Vec<CohortStratum> {
    use std::collections::BTreeMap;
    let mut groups: BTreeMap<(String, String, String), Vec<&NormalizedMeasurement>> = BTreeMap::new();
    for m in measurements {
        let key = (format!("{:?}", m.phy_generation), m.driver.clone(), m.kernel.clone());
        groups.entry(key).or_default().push(m);
    }

    groups
        .into_iter()
        .map(|((gen_str, driver, kernel), items)| {
            let n = items.len() as f64;
            // The mean is taken over the samples that actually contributed a
            // fraction, not over every member of the stratum.
            let usable: Vec<f64> = items
                .iter()
                .filter_map(|m| m.offered_phy_fraction)
                .filter(|f| f.is_finite())
                .collect();
            let mean_fraction = if usable.is_empty() {
                None
            } else {
                Some(usable.iter().sum::<f64>() / usable.len() as f64)
            };
            let mean_loss = items.iter().map(|m| m.loss_percent).sum::<f64>() / n;
            let phy_generation = items[0].phy_generation;
            let _ = gen_str;
            CohortStratum {
                phy_generation,
                driver,
                kernel,
                mean_offered_phy_fraction: mean_fraction,
                mean_loss_percent: mean_loss,
                sample_count: items.len(),
                fraction_sample_count: usable.len(),
            }
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttributionVerdict {
    /// Both cohorts have strong-RF, directional-control evidence and
    /// comparable offered PHY fractions -- a difference here is evidence
    /// for or against an AP backward-compatibility explanation.
    Attributable,
    /// Withheld: at least one cohort lacks strong-RF directional control,
    /// so a loss difference could equally be explained by weak RF or
    /// airtime saturation rather than AP behavior.
    WithheldMissingControls,
    /// Withheld: the cohorts were not measured at comparable offered PHY
    /// fractions, so any difference could be a capacity/airtime confound
    /// rather than a generation-specific AP behavior.
    WithheldIncomparableTargets,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CohortAttribution {
    pub cohort_a: CohortStratum,
    pub cohort_b: CohortStratum,
    pub verdict: AttributionVerdict,
    pub explanation: String,
}

/// The acceptance-criterion gate: "require strong-RF directional controls
/// before attributing a cohort difference to AP backward compatibility."
/// `a_all_strong_directional`/`b_all_strong_directional` must be computed
/// by the caller from the underlying measurements (every sample in the
/// cohort strong-RF and directional), since a stratum alone has no
/// per-sample RF/control record.
pub fn attribute_cohort_difference(
    cohort_a: CohortStratum,
    cohort_b: CohortStratum,
    a_all_strong_directional: bool,
    b_all_strong_directional: bool,
) -> CohortAttribution {
    if !a_all_strong_directional || !b_all_strong_directional {
        return CohortAttribution {
            cohort_a,
            cohort_b,
            verdict: AttributionVerdict::WithheldMissingControls,
            explanation: "at least one cohort includes a sample without strong RF or without directional-only load; a compatibility attribution requires both, since weak RF and simultaneous-load airtime pressure produce the same loss symptom as a real AP defect".to_string(),
        };
    }

    // GAP-075: a cohort whose fraction was withheld (stale PHY denominator, or
    // no usable capacity) cannot be shown comparable, so attribution is refused
    // rather than proceeding on an absent number.
    let (Some(frac_a), Some(frac_b)) = (cohort_a.mean_offered_phy_fraction, cohort_b.mean_offered_phy_fraction)
    else {
        let explanation = "at least one cohort has no usable mean offered PHY fraction (the PHY capacity behind it was stale or unavailable), so the cohorts cannot be shown to have been measured at comparable load".to_string();
        return CohortAttribution {
            cohort_a,
            cohort_b,
            verdict: AttributionVerdict::WithheldIncomparableTargets,
            explanation,
        };
    };

    if (frac_a - frac_b).abs() > COMPARABLE_FRACTION_TOLERANCE {
        let explanation = format!(
            "cohorts were measured at different offered PHY fractions ({frac_a:.2} vs {frac_b:.2}); a loss difference at incomparable fractions cannot be attributed to AP generation handling rather than capacity/airtime saturation"
        );
        return CohortAttribution { cohort_a, cohort_b, verdict: AttributionVerdict::WithheldIncomparableTargets, explanation };
    }

    CohortAttribution {
        cohort_a,
        cohort_b,
        verdict: AttributionVerdict::Attributable,
        explanation: "both cohorts have strong-RF directional-control evidence and comparable offered PHY fractions; the residual loss difference is attributable to AP/generation handling rather than capacity or RF confounds".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: &str, gen: PhyGeneration, capacity: f64, rf: RfQuality, directional: bool) -> NodeProfile {
        NodeProfile {
            node_id: id.to_string(),
            phy_generation: gen,
            driver: "ath10k".to_string(),
            kernel: "5.10".to_string(),
            phy_capacity_mbps: capacity,
            rf_quality: rf,
            directional_control: directional,
        }
    }

    #[test]
    fn fixed_absolute_rate_is_not_comparable_across_different_capacity_clients() {
        // The field's fixed-100 case: VHT client near its ceiling, HE
        // client far from its ceiling, same absolute offered rate.
        let vht = normalize(&PhaseMeasurement {
            node: node("PC6", PhyGeneration::Vht, 130.0, RfQuality::Strong, true),
            offered_mbps: 100.0,
            loss_percent: 27.0,
            phy_sampled_at_elapsed_secs: None,
            measured_at_elapsed_secs: None,
        });
        let he = normalize(&PhaseMeasurement {
            node: node("PV03", PhyGeneration::He, 866.0, RfQuality::Strong, true),
            offered_mbps: 100.0,
            loss_percent: 0.98,
            phy_sampled_at_elapsed_secs: None,
            measured_at_elapsed_secs: None,
        });
        assert!(vht.offered_phy_fraction.expect("no timing recorded, so fresh") > 0.5);
        assert!(he.offered_phy_fraction.expect("no timing recorded, so fresh") < 0.2);
        assert!(!comparable_targets(&vht, &he));
    }

    #[test]
    fn comparable_targets_at_matched_phy_fraction() {
        let vht = normalize(&PhaseMeasurement {
            node: node("PC6", PhyGeneration::Vht, 130.0, RfQuality::Strong, true),
            offered_mbps: 60.0,
            loss_percent: 1.67,
            phy_sampled_at_elapsed_secs: None,
            measured_at_elapsed_secs: None,
        });
        let he = normalize(&PhaseMeasurement {
            node: node("PV03", PhyGeneration::He, 866.0, RfQuality::Strong, true),
            offered_mbps: 400.0,
            loss_percent: 0.578,
            phy_sampled_at_elapsed_secs: None,
            measured_at_elapsed_secs: None,
        });
        // Both near ~46% of their own PHY capacity.
        assert!(comparable_targets(&vht, &he));
    }

    #[test]
    fn attribution_withheld_without_strong_rf_directional_controls() {
        let a = CohortStratum {
            phy_generation: PhyGeneration::Vht,
            driver: "ath10k".into(),
            kernel: "5.10".into(),
            mean_offered_phy_fraction: Some(0.5),
            mean_loss_percent: 10.0,
            sample_count: 5, fraction_sample_count: 5,
        };
        let b = CohortStratum {
            phy_generation: PhyGeneration::He,
            driver: "ath11k".into(),
            kernel: "5.15".into(),
            mean_offered_phy_fraction: Some(0.5),
            mean_loss_percent: 1.0,
            sample_count: 5, fraction_sample_count: 5,
        };
        let attribution = attribute_cohort_difference(a, b, true, false);
        assert_eq!(attribution.verdict, AttributionVerdict::WithheldMissingControls);
    }

    #[test]
    fn attribution_withheld_at_incomparable_fractions() {
        let a = CohortStratum {
            phy_generation: PhyGeneration::Vht,
            driver: "ath10k".into(),
            kernel: "5.10".into(),
            mean_offered_phy_fraction: Some(0.8),
            mean_loss_percent: 20.0,
            sample_count: 5, fraction_sample_count: 5,
        };
        let b = CohortStratum {
            phy_generation: PhyGeneration::He,
            driver: "ath11k".into(),
            kernel: "5.15".into(),
            mean_offered_phy_fraction: Some(0.15),
            mean_loss_percent: 1.0,
            sample_count: 5, fraction_sample_count: 5,
        };
        let attribution = attribute_cohort_difference(a, b, true, true);
        assert_eq!(attribution.verdict, AttributionVerdict::WithheldIncomparableTargets);
    }

    #[test]
    fn attribution_issued_with_controls_and_comparable_fractions() {
        let a = CohortStratum {
            phy_generation: PhyGeneration::Vht,
            driver: "ath10k".into(),
            kernel: "5.10".into(),
            mean_offered_phy_fraction: Some(0.45),
            mean_loss_percent: 15.0,
            sample_count: 5, fraction_sample_count: 5,
        };
        let b = CohortStratum {
            phy_generation: PhyGeneration::He,
            driver: "ath11k".into(),
            kernel: "5.15".into(),
            mean_offered_phy_fraction: Some(0.46),
            mean_loss_percent: 1.0,
            sample_count: 5, fraction_sample_count: 5,
        };
        let attribution = attribute_cohort_difference(a, b, true, true);
        assert_eq!(attribution.verdict, AttributionVerdict::Attributable);
    }

    #[test]
    fn stratify_groups_by_generation_driver_kernel() {
        let measurements = vec![
            normalize(&PhaseMeasurement { node: node("a", PhyGeneration::Vht, 130.0, RfQuality::Strong, true), offered_mbps: 50.0, loss_percent: 5.0, phy_sampled_at_elapsed_secs: None, measured_at_elapsed_secs: None }),
            normalize(&PhaseMeasurement { node: node("b", PhyGeneration::Vht, 130.0, RfQuality::Strong, true), offered_mbps: 60.0, loss_percent: 6.0, phy_sampled_at_elapsed_secs: None, measured_at_elapsed_secs: None }),
            normalize(&PhaseMeasurement { node: node("c", PhyGeneration::He, 866.0, RfQuality::Strong, true), offered_mbps: 400.0, loss_percent: 1.0, phy_sampled_at_elapsed_secs: None, measured_at_elapsed_secs: None }),
        ];
        let strata = stratify(&measurements);
        assert_eq!(strata.len(), 2);
    }
    /// GAP-075: the PHY denominator was sampled at t=0 and this phase measured
    /// at t=120. A roam in between changes PHY capacity with no notification, so
    /// the fraction describes a link that may no longer exist.
    #[test]
    fn a_stale_phy_denominator_withholds_the_fraction() {
        let m = normalize(&PhaseMeasurement {
            node: node("PV10", PhyGeneration::He, 866.0, RfQuality::Strong, true),
            offered_mbps: 400.0,
            loss_percent: 1.0,
            phy_sampled_at_elapsed_secs: Some(0.0),
            measured_at_elapsed_secs: Some(120.0),
        });
        assert_eq!(m.offered_phy_fraction, None, "a stale denominator must not produce a fraction");
        assert!(!m.freshness.permits_derived_figure());
        // The absolute inputs are still reported; only the DERIVED figure goes.
        assert!((m.offered_mbps - 400.0).abs() < 1e-9);
        assert!((m.phy_capacity_mbps - 866.0).abs() < 1e-9);
    }

    #[test]
    fn a_fresh_phy_denominator_still_yields_a_fraction() {
        let m = normalize(&PhaseMeasurement {
            node: node("PV10", PhyGeneration::He, 866.0, RfQuality::Strong, true),
            offered_mbps: 400.0,
            loss_percent: 1.0,
            phy_sampled_at_elapsed_secs: Some(100.0),
            measured_at_elapsed_secs: Some(110.0),
        });
        let f = m.offered_phy_fraction.expect("10s old is inside the radio horizon");
        assert!((f - 400.0 / 866.0).abs() < 1e-9);
    }

    /// A zero PHY capacity used to yield NaN, which downstream formatting turns
    /// into a number-shaped nonsense value.
    #[test]
    fn a_zero_phy_capacity_withholds_rather_than_producing_nan() {
        let m = normalize(&PhaseMeasurement {
            node: node("bad", PhyGeneration::Unknown, 0.0, RfQuality::Strong, true),
            offered_mbps: 100.0,
            loss_percent: 0.0,
            phy_sampled_at_elapsed_secs: None,
            measured_at_elapsed_secs: None,
        });
        assert_eq!(m.offered_phy_fraction, None);
    }

    /// The stratum mean previously divided a FILTERED sum by the UNFILTERED
    /// count, so one withheld fraction dragged the mean toward zero.
    #[test]
    fn a_stratum_mean_divides_by_the_usable_sample_count() {
        let fresh = normalize(&PhaseMeasurement {
            node: node("a", PhyGeneration::He, 1000.0, RfQuality::Strong, true),
            offered_mbps: 500.0,
            loss_percent: 1.0,
            phy_sampled_at_elapsed_secs: Some(0.0),
            measured_at_elapsed_secs: Some(1.0),
        });
        let stale = normalize(&PhaseMeasurement {
            node: node("b", PhyGeneration::He, 1000.0, RfQuality::Strong, true),
            offered_mbps: 500.0,
            loss_percent: 1.0,
            phy_sampled_at_elapsed_secs: Some(0.0),
            measured_at_elapsed_secs: Some(500.0),
        });
        let strata = stratify(&[fresh, stale]);
        assert_eq!(strata.len(), 1);
        let s = &strata[0];
        assert_eq!(s.sample_count, 2, "both samples belong to the stratum");
        assert_eq!(s.fraction_sample_count, 1, "only one contributed a fraction");
        let mean = s.mean_offered_phy_fraction.expect("one usable sample yields a mean");
        assert!((mean - 0.5).abs() < 1e-9, "mean must be 0.5, not 0.25; got {mean}");
    }

    #[test]
    fn a_stratum_with_no_usable_fraction_reports_none() {
        let stale = normalize(&PhaseMeasurement {
            node: node("b", PhyGeneration::He, 1000.0, RfQuality::Strong, true),
            offered_mbps: 500.0,
            loss_percent: 1.0,
            phy_sampled_at_elapsed_secs: Some(0.0),
            measured_at_elapsed_secs: Some(500.0),
        });
        let strata = stratify(&[stale]);
        assert_eq!(strata[0].mean_offered_phy_fraction, None);
        assert_eq!(strata[0].fraction_sample_count, 0);
    }

    /// Attribution must refuse when a cohort's fraction was withheld, rather
    /// than proceeding against an absent number.
    #[test]
    fn attribution_is_withheld_when_a_cohort_fraction_is_absent() {
        let a = CohortStratum {
            phy_generation: PhyGeneration::He,
            driver: "d".to_string(),
            kernel: "k".to_string(),
            mean_offered_phy_fraction: None,
            mean_loss_percent: 1.0,
            sample_count: 3,
            fraction_sample_count: 0,
        };
        let b = CohortStratum {
            phy_generation: PhyGeneration::Vht,
            driver: "d".to_string(),
            kernel: "k".to_string(),
            mean_offered_phy_fraction: Some(0.5),
            mean_loss_percent: 9.0,
            sample_count: 3,
            fraction_sample_count: 3,
        };
        let att = attribute_cohort_difference(a, b, true, true);
        assert_eq!(att.verdict, AttributionVerdict::WithheldIncomparableTargets);
        assert!(att.explanation.contains("stale") || att.explanation.contains("unavailable"), "{}", att.explanation);
    }

}
