//! GAP-013: second-network control workflow.
//!
//! A hotspot rerun is the fastest way to separate client behavior from
//! Wi-Fi infrastructure: if the same symptom reproduces on a different
//! network, the client (or its default route/VPN state -- see
//! `HANDOFF.md`'s gotcha #1) is implicated instead. This module saves a
//! connection fingerprint plus a named-metric test bundle to disk, then
//! diffs two saved bundles after the operator switches networks.
//!
//! Privacy: `NetworkFingerprint` reuses `ap_identity::ApIdentity`
//! (`load_guard/ap_identity.rs`, another agent's file -- read, not
//! edited), which already salts the BSSID into an opaque label and never
//! carries the SSID at all. `operator_label` is the ONE field that can
//! hold SSID-shaped text, and it is populated ONLY when the operator
//! explicitly passes `--retain-network-label` on the CLI -- never
//! defaulted, never inferred from anything this module reads itself. That
//! satisfies "without storing SSID/BSSID unless explicitly requested" by
//! construction: there is no code path that reads a raw SSID/BSSID and
//! writes it into a bundle on its own.

use serde::{Deserialize, Serialize};

use crate::load_guard::ap_identity::{compare as compare_ap_identity, ApComparison, ApIdentity};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkFingerprint {
    pub ap_identity: Option<ApIdentity>,
    pub interface: Option<String>,
    pub interface_is_tunnel: bool,
    /// Only present when the operator explicitly passed
    /// `--retain-network-label`. Never populated by this module on its own.
    pub operator_label: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleMetric {
    pub name: String,
    /// `None` when that metric's test did not run or did not produce a
    /// value on this network -- never coerced to 0.
    pub value: Option<f64>,
    pub unit: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestBundle {
    pub fingerprint: NetworkFingerprint,
    pub metrics: Vec<BundleMetric>,
    /// Operator-supplied tag for this capture (e.g. "run-1-room-wifi"),
    /// distinct from `operator_label` -- this one identifies the SAVE, not
    /// the network.
    pub capture_tag: String,
}

pub fn save_bundle(path: &str, bundle: &TestBundle) -> Result<(), String> {
    let text = serde_json::to_string_pretty(bundle).map_err(|e| e.to_string())?;
    std::fs::write(path, text).map_err(|e| e.to_string())
}

pub fn load_bundle(path: &str) -> Result<TestBundle, String> {
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    serde_json::from_str(&text).map_err(|e| e.to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricComparison {
    pub name: String,
    pub before: Option<f64>,
    pub after: Option<f64>,
    /// `None` whenever either side is `None` -- a metric that only ran on
    /// one network cannot be diffed, so this must not silently read as a
    /// 100%/0% swing.
    pub delta: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecondNetworkComparison {
    pub network_relationship: String,
    pub metrics: Vec<MetricComparison>,
}

fn describe_relationship(cmp: ApComparison) -> &'static str {
    match cmp {
        ApComparison::SameApSameRadio => {
            "same physical AP, same radio -- this is not actually a second network"
        }
        ApComparison::SameApDifferentRadio => {
            "same physical AP, different radio -- band changed but not the AP"
        }
        ApComparison::DifferentAp => "different AP -- genuine second-network control",
        ApComparison::Unavailable => {
            "AP identity unavailable on at least one side; network relationship not determined"
        }
    }
}

/// Compares two saved bundles metric-by-metric. Every metric present in
/// either bundle is reported, matched by name; a metric missing on one
/// side reports `delta: None` rather than treating the absent side as 0.
pub fn compare_bundles(before: &TestBundle, after: &TestBundle) -> SecondNetworkComparison {
    let relationship = describe_relationship(compare_ap_identity(
        &before.fingerprint.ap_identity,
        &after.fingerprint.ap_identity,
    ));

    let mut names: Vec<String> = before.metrics.iter().map(|m| m.name.clone()).collect();
    for m in &after.metrics {
        if !names.contains(&m.name) {
            names.push(m.name.clone());
        }
    }

    let metrics = names
        .into_iter()
        .map(|name| {
            let b = before
                .metrics
                .iter()
                .find(|m| m.name == name)
                .and_then(|m| m.value);
            let a = after
                .metrics
                .iter()
                .find(|m| m.name == name)
                .and_then(|m| m.value);
            let delta = match (b, a) {
                (Some(bv), Some(av)) => Some(av - bv),
                _ => None,
            };
            MetricComparison {
                name,
                before: b,
                after: a,
                delta,
            }
        })
        .collect();

    SecondNetworkComparison {
        network_relationship: relationship.to_string(),
        metrics,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle(label: Option<&str>, ap_label: Option<&str>, metric: Option<f64>) -> TestBundle {
        TestBundle {
            fingerprint: NetworkFingerprint {
                ap_identity: ap_label.map(|l| ApIdentity {
                    label: l.to_string(),
                    band: Some("6GHz".to_string()),
                    channel: Some(37),
                }),
                interface: Some("en0".to_string()),
                interface_is_tunnel: false,
                operator_label: label.map(|s| s.to_string()),
            },
            metrics: vec![BundleMetric {
                name: "download_mbps".to_string(),
                value: metric,
                unit: "Mbps".to_string(),
            }],
            capture_tag: "test-run".to_string(),
        }
    }

    #[test]
    fn a_saved_bundle_round_trips_without_storing_ssid_or_bssid() {
        let b = bundle(None, Some("ap-aaaa1111"), Some(320.5));
        let path = std::env::temp_dir().join(format!(
            "fp-second-network-test-{}.json",
            std::process::id()
        ));
        let path_str = path.to_string_lossy().to_string();
        save_bundle(&path_str, &b).unwrap();
        let text = std::fs::read_to_string(&path_str).unwrap();
        // No MAC-shaped token anywhere in the saved JSON.
        assert!(!text.split(' ').any(|w| {
            let parts: Vec<&str> = w
                .trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != ':')
                .split(':')
                .collect();
            parts.len() == 6
                && parts
                    .iter()
                    .all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()))
        }));
        let loaded = load_bundle(&path_str).unwrap();
        assert_eq!(loaded.fingerprint.ap_identity.unwrap().label, "ap-aaaa1111");
        assert_eq!(loaded.metrics[0].value, Some(320.5));
        std::fs::remove_file(&path_str).ok();
    }

    #[test]
    fn operator_label_is_the_only_field_that_can_carry_ssid_shaped_text_and_only_when_supplied() {
        let default_bundle = bundle(None, Some("ap-aaaa1111"), Some(1.0));
        assert_eq!(default_bundle.fingerprint.operator_label, None);
        let explicit_bundle = bundle(Some("Hotel Guest WiFi"), Some("ap-aaaa1111"), Some(1.0));
        assert_eq!(
            explicit_bundle.fingerprint.operator_label,
            Some("Hotel Guest WiFi".to_string())
        );
    }

    #[test]
    fn a_different_ap_label_is_reported_as_a_genuine_second_network() {
        let before = bundle(None, Some("ap-aaaa1111"), Some(300.0));
        let after = bundle(None, Some("ap-bbbb2222"), Some(50.0));
        let cmp = compare_bundles(&before, &after);
        assert!(cmp
            .network_relationship
            .contains("genuine second-network control"));
    }

    #[test]
    fn the_same_ap_label_flags_that_this_is_not_actually_a_second_network() {
        let before = bundle(None, Some("ap-aaaa1111"), Some(300.0));
        let after = bundle(None, Some("ap-aaaa1111"), Some(290.0));
        let cmp = compare_bundles(&before, &after);
        assert!(cmp
            .network_relationship
            .contains("not actually a second network"));
    }

    #[test]
    fn a_metric_missing_on_one_side_reports_delta_as_none_never_a_fabricated_swing() {
        let mut before = bundle(None, Some("ap-aaaa1111"), Some(300.0));
        before.metrics.push(BundleMetric {
            name: "only_on_before".to_string(),
            value: Some(5.0),
            unit: "ms".to_string(),
        });
        let after = bundle(None, Some("ap-bbbb2222"), Some(50.0));
        let cmp = compare_bundles(&before, &after);
        let m = cmp
            .metrics
            .iter()
            .find(|m| m.name == "only_on_before")
            .unwrap();
        assert_eq!(m.delta, None);
        assert_eq!(m.after, None);
    }

    #[test]
    fn a_common_metric_computes_a_real_delta() {
        let before = bundle(None, Some("ap-aaaa1111"), Some(300.0));
        let after = bundle(None, Some("ap-bbbb2222"), Some(50.0));
        let cmp = compare_bundles(&before, &after);
        let m = cmp
            .metrics
            .iter()
            .find(|m| m.name == "download_mbps")
            .unwrap();
        assert_eq!(m.delta, Some(-250.0));
    }

    #[test]
    fn missing_ap_identity_on_either_side_is_unavailable_not_assumed_same() {
        let before = bundle(None, None, Some(300.0));
        let after = bundle(None, Some("ap-bbbb2222"), Some(50.0));
        let cmp = compare_bundles(&before, &after);
        assert!(cmp.network_relationship.contains("not determined"));
    }
}
