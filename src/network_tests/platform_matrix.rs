//! GAP-063: cross-platform and power-save client matrix.
//!
//! Field evidence: the observed cohorts differed by adapter, driver,
//! kernel, AND iperf version simultaneously (VHT/5.10/iperf3-3.9 versus
//! HE/6.1/iperf3-3.16). With four variables moving together, no result can
//! be attributed to any single one of them -- the module's job is to say
//! that plainly rather than pick a variable to blame.
//!
//! Privacy: this records capability *classes* -- PHY generation, driver
//! family, kernel major version, power-save capability -- never a serial
//! number, hostname, or MAC. TWT/U-APSD power-save state is very likely
//! unobservable from the client side on this platform; that limitation is
//! reported the same `Obtainability`-typed way GAP-055 reports platform
//! limits, not silently omitted.

use serde::{Deserialize, Serialize};

use crate::network_tests::rf_survey::Metric;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PhyGeneration {
    /// 802.11n
    Wifi4,
    /// 802.11ac / VHT
    Wifi5,
    /// 802.11ax / HE
    Wifi6,
    /// 802.11ax 6GHz
    Wifi6E,
    /// 802.11be / EHT
    Wifi7,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PowerSaveState {
    Active,
    PowerSave,
    /// The client's power-save state could not be determined from this
    /// vantage point -- distinct from `Active`, never defaulted to it.
    Unknown,
}

/// Capability class for one client, recorded without any personally or
/// device-identifying value. `kernel_major` and `driver_family` are
/// intentionally coarse (e.g. "6" not "6.1.4-arch1-1", "iwlwifi" not a
/// firmware build string) to stay a class, not an identifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientCapability {
    pub os_family: String,
    pub driver_family: Option<String>,
    pub kernel_major: Option<String>,
    pub phy_generation: PhyGeneration,
    pub power_save: Metric<PowerSaveState>,
    pub iperf_version: Option<String>,
}

/// One test-bundle result for a client capability class at a given power
/// state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatrixResult {
    pub capability: ClientCapability,
    pub power_save_during_test: PowerSaveState,
    pub throughput_mbps: Option<f64>,
    pub loss_percent: Option<f64>,
}

/// The set of capability axes that varied across two results being
/// compared. Confound analysis is built entirely from this: an
/// attribution is only safe when exactly one axis differs.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VaryingAxes {
    pub os_family: bool,
    pub driver_family: bool,
    pub kernel_major: bool,
    pub phy_generation: bool,
    pub iperf_version: bool,
}

impl VaryingAxes {
    pub fn count(&self) -> u32 {
        [
            self.os_family,
            self.driver_family,
            self.kernel_major,
            self.phy_generation,
            self.iperf_version,
        ]
        .iter()
        .filter(|b| **b)
        .count() as u32
    }
}

fn compare_axes(a: &ClientCapability, b: &ClientCapability) -> VaryingAxes {
    VaryingAxes {
        os_family: a.os_family != b.os_family,
        driver_family: a.driver_family != b.driver_family,
        kernel_major: a.kernel_major != b.kernel_major,
        phy_generation: a.phy_generation != b.phy_generation,
        iperf_version: a.iperf_version != b.iperf_version,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Attribution {
    /// Exactly one capability axis differed between the two results, so a
    /// throughput/loss difference can be attributed to that axis.
    SinglePlatformFactor {
        axis: String,
        delta_mbps: Option<f64>,
    },
    /// More than one axis differed -- the field-evidence case. The
    /// difference cannot be assigned to any one variable from this
    /// comparison alone.
    ConfoundedEntangled {
        varying_axes: Vec<String>,
        reason: String,
    },
    /// No axis differed at all; any observed difference is not a platform
    /// effect (it's noise, infrastructure, or something else entirely).
    NoVariation,
}

/// Compares two matrix results and either attributes a difference to a
/// single platform factor, or explicitly withholds attribution when
/// confounds are entangled. This is the GAP-063 deliverable: never guesses
/// which of several simultaneously-varying factors caused a difference.
pub fn attribute_difference(a: &MatrixResult, b: &MatrixResult) -> Attribution {
    let axes = compare_axes(&a.capability, &b.capability);
    let varying: Vec<&str> = [
        (axes.os_family, "os_family"),
        (axes.driver_family, "driver_family"),
        (axes.kernel_major, "kernel_major"),
        (axes.phy_generation, "phy_generation"),
        (axes.iperf_version, "iperf_version"),
    ]
    .iter()
    .filter(|(v, _)| *v)
    .map(|(_, name)| *name)
    .collect();

    match axes.count() {
        0 => Attribution::NoVariation,
        1 => {
            let delta_mbps = match (a.throughput_mbps, b.throughput_mbps) {
                (Some(x), Some(y)) => Some(y - x),
                _ => None,
            };
            Attribution::SinglePlatformFactor { axis: varying[0].to_string(), delta_mbps }
        }
        n => Attribution::ConfoundedEntangled {
            varying_axes: varying.iter().map(|s| s.to_string()).collect(),
            reason: format!(
                "{} capability axes differed simultaneously ({}); a throughput/loss difference cannot be \
                 attributed to any single one of them from this comparison alone",
                n,
                varying.join(", ")
            ),
        },
    }
}

/// Reports the client-side observability of TWT/U-APSD power-save state.
/// Hardcoded to `PlatformLimited` deliberately: there is no macOS
/// unprivileged API used elsewhere in this codebase that exposes a peer's
/// (or even the local radio's) TWT/U-APSD negotiation state, so claiming
/// otherwise here would be exactly the fabricated-observability failure
/// this gap exists to prevent.
pub fn power_save_observability() -> Metric<PowerSaveState> {
    Metric::platform_limited()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cap(
        os: &str,
        driver: Option<&str>,
        kernel: Option<&str>,
        phy: PhyGeneration,
        iperf: Option<&str>,
    ) -> ClientCapability {
        ClientCapability {
            os_family: os.to_string(),
            driver_family: driver.map(|s| s.to_string()),
            kernel_major: kernel.map(|s| s.to_string()),
            phy_generation: phy,
            power_save: Metric::platform_limited(),
            iperf_version: iperf.map(|s| s.to_string()),
        }
    }

    fn result(capability: ClientCapability, throughput: Option<f64>) -> MatrixResult {
        MatrixResult {
            capability,
            power_save_during_test: PowerSaveState::Active,
            throughput_mbps: throughput,
            loss_percent: None,
        }
    }

    #[test]
    fn power_save_state_is_platform_limited_not_defaulted_active() {
        let m = power_save_observability();
        assert_eq!(m.obtainability, Obtainability::PlatformLimited);
        assert_eq!(m.value, None);
    }

    #[test]
    fn single_varying_axis_yields_attribution() {
        let a = result(
            cap(
                "linux",
                Some("iwlwifi"),
                Some("5"),
                PhyGeneration::Wifi5,
                Some("3.9"),
            ),
            Some(300.0),
        );
        let b = result(
            cap(
                "linux",
                Some("iwlwifi"),
                Some("5"),
                PhyGeneration::Wifi6,
                Some("3.9"),
            ),
            Some(450.0),
        );
        let attribution = attribute_difference(&a, &b);
        match attribution {
            Attribution::SinglePlatformFactor { axis, delta_mbps } => {
                assert_eq!(axis, "phy_generation");
                assert_eq!(delta_mbps, Some(150.0));
            }
            other => panic!("expected SinglePlatformFactor, got {:?}", other),
        }
    }

    #[test]
    fn field_evidence_four_entangled_axes_withholds_attribution() {
        // The exact field-evidence cohorts: VHT/5.10/iperf3-3.9 vs HE/6.1/iperf3-3.16,
        // also differing driver family.
        let a = result(
            cap(
                "linux",
                Some("ath10k"),
                Some("5"),
                PhyGeneration::Wifi5,
                Some("3.9"),
            ),
            Some(280.0),
        );
        let b = result(
            cap(
                "linux",
                Some("iwlwifi"),
                Some("6"),
                PhyGeneration::Wifi6,
                Some("3.16"),
            ),
            Some(410.0),
        );
        let attribution = attribute_difference(&a, &b);
        match attribution {
            Attribution::ConfoundedEntangled { varying_axes, .. } => {
                assert!(
                    varying_axes.len() >= 3,
                    "expected multiple entangled axes, got {:?}",
                    varying_axes
                );
            }
            other => panic!("expected ConfoundedEntangled, got {:?}", other),
        }
    }

    #[test]
    fn identical_capability_yields_no_variation() {
        let a = result(
            cap(
                "macos",
                Some("wl"),
                Some("25"),
                PhyGeneration::Wifi6E,
                Some("3.21"),
            ),
            Some(600.0),
        );
        let b = result(
            cap(
                "macos",
                Some("wl"),
                Some("25"),
                PhyGeneration::Wifi6E,
                Some("3.21"),
            ),
            Some(590.0),
        );
        assert!(matches!(
            attribute_difference(&a, &b),
            Attribution::NoVariation
        ));
    }
}
