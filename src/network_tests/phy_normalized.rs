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
    pub offered_phy_fraction: f64,
    pub loss_percent: f64,
    pub rf_quality: RfQuality,
    pub directional_control: bool,
}

pub fn normalize(m: &PhaseMeasurement) -> NormalizedMeasurement {
    let fraction = if m.node.phy_capacity_mbps > 0.0 {
        m.offered_mbps / m.node.phy_capacity_mbps
    } else {
        f64::NAN
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
    }
}

/// Two measurements are "comparable" for cohort attribution only when their
/// offered PHY fractions are close -- comparing a client running at 20% of
/// its own ceiling against one running at 90% of its own ceiling is not a
/// fair fixed-target comparison even if their absolute offered Mbps match.
const COMPARABLE_FRACTION_TOLERANCE: f64 = 0.15;

pub fn comparable_targets(a: &NormalizedMeasurement, b: &NormalizedMeasurement) -> bool {
    if !a.offered_phy_fraction.is_finite() || !b.offered_phy_fraction.is_finite() {
        return false;
    }
    (a.offered_phy_fraction - b.offered_phy_fraction).abs() <= COMPARABLE_FRACTION_TOLERANCE
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CohortStratum {
    pub phy_generation: PhyGeneration,
    pub driver: String,
    pub kernel: String,
    pub mean_offered_phy_fraction: f64,
    pub mean_loss_percent: f64,
    pub sample_count: usize,
}

/// Stratifies a set of normalized measurements by (PHY generation, driver,
/// kernel) -- collapsing across those dimensions is exactly how the
/// original fixed-100 comparison hid the capacity confound.
pub fn stratify(measurements: &[NormalizedMeasurement]) -> Vec<CohortStratum> {
    use std::collections::BTreeMap;
    let mut groups: BTreeMap<(String, String, String), Vec<&NormalizedMeasurement>> =
        BTreeMap::new();
    for m in measurements {
        let key = (
            format!("{:?}", m.phy_generation),
            m.driver.clone(),
            m.kernel.clone(),
        );
        groups.entry(key).or_default().push(m);
    }

    groups
        .into_iter()
        .map(|((gen_str, driver, kernel), items)| {
            let n = items.len() as f64;
            let mean_fraction = items
                .iter()
                .filter(|m| m.offered_phy_fraction.is_finite())
                .map(|m| m.offered_phy_fraction)
                .sum::<f64>()
                / n;
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

    if (cohort_a.mean_offered_phy_fraction - cohort_b.mean_offered_phy_fraction).abs()
        > COMPARABLE_FRACTION_TOLERANCE
    {
        let explanation = format!(
            "cohorts were measured at different offered PHY fractions ({:.2} vs {:.2}); a loss difference at incomparable fractions cannot be attributed to AP generation handling rather than capacity/airtime saturation",
            cohort_a.mean_offered_phy_fraction, cohort_b.mean_offered_phy_fraction
        );
        return CohortAttribution {
            cohort_a,
            cohort_b,
            verdict: AttributionVerdict::WithheldIncomparableTargets,
            explanation,
        };
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

    fn node(
        id: &str,
        gen: PhyGeneration,
        capacity: f64,
        rf: RfQuality,
        directional: bool,
    ) -> NodeProfile {
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
        });
        let he = normalize(&PhaseMeasurement {
            node: node("PV03", PhyGeneration::He, 866.0, RfQuality::Strong, true),
            offered_mbps: 100.0,
            loss_percent: 0.98,
        });
        assert!(vht.offered_phy_fraction > 0.5);
        assert!(he.offered_phy_fraction < 0.2);
        assert!(!comparable_targets(&vht, &he));
    }

    #[test]
    fn comparable_targets_at_matched_phy_fraction() {
        let vht = normalize(&PhaseMeasurement {
            node: node("PC6", PhyGeneration::Vht, 130.0, RfQuality::Strong, true),
            offered_mbps: 60.0,
            loss_percent: 1.67,
        });
        let he = normalize(&PhaseMeasurement {
            node: node("PV03", PhyGeneration::He, 866.0, RfQuality::Strong, true),
            offered_mbps: 400.0,
            loss_percent: 0.578,
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
            mean_offered_phy_fraction: 0.5,
            mean_loss_percent: 10.0,
            sample_count: 5,
        };
        let b = CohortStratum {
            phy_generation: PhyGeneration::He,
            driver: "ath11k".into(),
            kernel: "5.15".into(),
            mean_offered_phy_fraction: 0.5,
            mean_loss_percent: 1.0,
            sample_count: 5,
        };
        let attribution = attribute_cohort_difference(a, b, true, false);
        assert_eq!(
            attribution.verdict,
            AttributionVerdict::WithheldMissingControls
        );
    }

    #[test]
    fn attribution_withheld_at_incomparable_fractions() {
        let a = CohortStratum {
            phy_generation: PhyGeneration::Vht,
            driver: "ath10k".into(),
            kernel: "5.10".into(),
            mean_offered_phy_fraction: 0.8,
            mean_loss_percent: 20.0,
            sample_count: 5,
        };
        let b = CohortStratum {
            phy_generation: PhyGeneration::He,
            driver: "ath11k".into(),
            kernel: "5.15".into(),
            mean_offered_phy_fraction: 0.15,
            mean_loss_percent: 1.0,
            sample_count: 5,
        };
        let attribution = attribute_cohort_difference(a, b, true, true);
        assert_eq!(
            attribution.verdict,
            AttributionVerdict::WithheldIncomparableTargets
        );
    }

    #[test]
    fn attribution_issued_with_controls_and_comparable_fractions() {
        let a = CohortStratum {
            phy_generation: PhyGeneration::Vht,
            driver: "ath10k".into(),
            kernel: "5.10".into(),
            mean_offered_phy_fraction: 0.45,
            mean_loss_percent: 15.0,
            sample_count: 5,
        };
        let b = CohortStratum {
            phy_generation: PhyGeneration::He,
            driver: "ath11k".into(),
            kernel: "5.15".into(),
            mean_offered_phy_fraction: 0.46,
            mean_loss_percent: 1.0,
            sample_count: 5,
        };
        let attribution = attribute_cohort_difference(a, b, true, true);
        assert_eq!(attribution.verdict, AttributionVerdict::Attributable);
    }

    #[test]
    fn stratify_groups_by_generation_driver_kernel() {
        let measurements = vec![
            normalize(&PhaseMeasurement {
                node: node("a", PhyGeneration::Vht, 130.0, RfQuality::Strong, true),
                offered_mbps: 50.0,
                loss_percent: 5.0,
            }),
            normalize(&PhaseMeasurement {
                node: node("b", PhyGeneration::Vht, 130.0, RfQuality::Strong, true),
                offered_mbps: 60.0,
                loss_percent: 6.0,
            }),
            normalize(&PhaseMeasurement {
                node: node("c", PhyGeneration::He, 866.0, RfQuality::Strong, true),
                offered_mbps: 400.0,
                loss_percent: 1.0,
            }),
        ];
        let strata = stratify(&measurements);
        assert_eq!(strata.len(), 2);
    }
}
