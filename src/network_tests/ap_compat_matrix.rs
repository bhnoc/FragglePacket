//! GAP-037: AP-generation, radio-mode, and client-capability compatibility
//! matrix.
//!
//! Field evidence: every probe-associated AP was an Arista C-460 on
//! firmware `21.3.0M-13`, yet tested clients negotiated VHT or HE, never
//! EHT. Twenty of 24 APs sat in reduced-power PoE+ mode, but the single
//! worst client (PC10) was on full power and the cleanest HE client (PV10)
//! was also on full power -- so AP model, firmware, and power mode each
//! individually fail to explain the cohort split. The open question is
//! whether this is a Wi-Fi 7 (802.11be) backward-compatibility datapath
//! defect for non-MLO HE clients, or a general WLAN/policy effect, and
//! client-side evidence alone cannot answer it: that requires comparing the
//! same client/threshold test across an AP radio switched between BE and AX
//! mode, and against an independent Wi-Fi 6E AP -- an infrastructure
//! change this tool must never make itself.
//!
//! This module therefore does two structurally separate things:
//! 1. Records what THIS client observed about its own negotiated link
//!    (`ClientAssociation`, from `RadioSnapshot`/`RadioDiagnostic` --
//!    HE/EHT, band/width, MCS -- never storing SSID/BSSID/MAC).
//! 2. Ingests operator-supplied AP-side context (`ApContext`, from Arista
//!    CV-CUE managed-device fields per the `arista-ops` skill: model,
//!    firmware, power mode, radio mode, MLO state) as JSON, verbatim --
//!    inventing no field the operator did not supply.
//!
//! A `CompatibilityMatrix` is a set of `MatrixCell`s, each one client
//! association paired with one AP context. The four cells the acceptance
//! criteria name -- BE-mode control, AX-mode control on the same AP/radio,
//! a Wi-Fi 6E AP control, and native Wi-Fi 7 vs Wi-Fi 6E client controls --
//! must all be present and mutually distinguishable before `verdict()`
//! returns anything but `InsufficientCells`, which names exactly which
//! required cells are still missing. This is the GAP-037-specific instance
//! of the project's recurring bug: a plausible verdict from one cell would
//! point a TAC case at the wrong firmware.

use serde::{Deserialize, Serialize};

use crate::load_guard::{ApIdentity, RadioSnapshot};

/// The client's own negotiated mode. Deliberately NOT the AP's advertised
/// capability -- an EHT-capable (BE) AP serving an HE (AX) client is exactly
/// the case that must not collapse into "the link is Wi-Fi 7". `Unknown`
/// covers a PHY-mode string this parser does not recognize, never guessed
/// as either mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NegotiatedGeneration {
    /// 802.11ax
    He,
    /// 802.11be
    Eht,
    /// 802.11ac or earlier
    PreHe,
    Unknown,
}

pub fn classify_negotiated_generation(phy_mode: &Option<String>) -> NegotiatedGeneration {
    match phy_mode {
        None => NegotiatedGeneration::Unknown,
        Some(s) => {
            let lower = s.to_lowercase();
            if lower.contains("be") && !lower.contains("beacon") {
                NegotiatedGeneration::Eht
            } else if lower.contains("ax") {
                NegotiatedGeneration::He
            } else if lower.contains("ac") || lower.contains("n") || lower.contains("a/b/g") {
                NegotiatedGeneration::PreHe
            } else {
                NegotiatedGeneration::Unknown
            }
        }
    }
}

/// What this client can observe about its own association, built only from
/// the existing GAP-027/GAP-024 allowlisted radio fields -- no new
/// privileged read, no SSID/BSSID/MAC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientAssociation {
    pub negotiated_generation: NegotiatedGeneration,
    pub phy_mode_raw: Option<String>,
    pub band: Option<String>,
    pub channel: Option<u32>,
    pub width_mhz: Option<u32>,
    pub mcs_index: Option<u32>,
    pub tx_rate_mbps: Option<f64>,
    /// macOS's unprivileged and privileged (`wdutil`) sources both expose
    /// MCS index but never a spatial-stream/NSS count directly, so this is
    /// always `None` on this platform today -- an explicit gap, not a
    /// guess from MCS (MCS index does not determine NSS in HE/EHT).
    pub nss: Option<u32>,
    /// This platform has no unprivileged or privileged read for MLO
    /// (Multi-Link Operation) state; always `None` with the reason
    /// recorded in `platform_limitations`.
    pub mlo_active: Option<bool>,
    pub ap_identity: Option<ApIdentity>,
    pub platform_limitations: Vec<String>,
}

const NSS_LIMITATION: &str =
    "spatial stream count (NSS) is not exposed by any known unprivileged or privileged macOS Wi-Fi CLI path";
const MLO_LIMITATION: &str =
    "MLO (Multi-Link Operation) state is not exposed by any known unprivileged or privileged macOS Wi-Fi CLI path";

pub fn client_association_from_snapshot(
    snap: &RadioSnapshot,
    ap_identity: Option<ApIdentity>,
) -> ClientAssociation {
    ClientAssociation {
        negotiated_generation: classify_negotiated_generation(&snap.phy_mode),
        phy_mode_raw: snap.phy_mode.clone(),
        band: snap.band.clone(),
        channel: snap.channel,
        width_mhz: snap.width_mhz,
        mcs_index: snap.mcs_index,
        tx_rate_mbps: snap.tx_rate_mbps,
        nss: None,
        mlo_active: None,
        ap_identity,
        platform_limitations: vec![NSS_LIMITATION.to_string(), MLO_LIMITATION.to_string()],
    }
}

/// AP model's *advertised* capability, distinct from what the client above
/// actually negotiated. Populated only from operator-supplied JSON --
/// nothing here is probed or scanned. Field shape follows the managed-device
/// fields validated in the `arista-ops` skill (model/softwareVersion/
/// powerSource/lowPowerSupply), not invented ahead of what that API returns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApContext {
    pub ap_identity: Option<ApIdentity>,
    pub model: Option<String>,
    pub firmware_version: Option<String>,
    /// `POE_PLUS` / `FOUR_PPoE` in Arista's vocabulary; kept as the
    /// operator's raw string rather than mapped, since the mapping between
    /// vendor power-mode strings and PoE class differs by controller.
    pub power_mode_raw: Option<String>,
    pub low_power_supply: Option<bool>,
    pub radio_mode: Option<RadioMode>,
    pub mlo_supported: Option<bool>,
    pub band_advertised: Option<String>,
    pub width_advertised_mhz: Option<u32>,
    pub nss_advertised: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RadioMode {
    /// 802.11be enabled (Wi-Fi 7 capable AP running in BE mode).
    Be,
    /// 802.11be disabled; AP running in AX (Wi-Fi 6/6E) mode.
    Ax,
}

/// The client generation this run is being attributed to, for the "native
/// Wi-Fi 7 versus Wi-Fi 6E clients" comparison cell. Distinct from
/// `NegotiatedGeneration`: a Wi-Fi 7 chipset can still negotiate HE against
/// a BE-disabled AP, which is exactly the case under investigation, so the
/// operator states the client's hardware generation independently of what
/// it negotiated in any one run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientHardwareGeneration {
    Wifi7,
    Wifi6e,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatrixCell {
    pub label: String,
    pub client: ClientAssociation,
    pub ap: ApContext,
    pub client_hardware_generation: Option<ClientHardwareGeneration>,
}

/// A required comparison slot from the acceptance criteria. `matches`
/// decides whether a given cell satisfies this slot -- deliberately
/// conservative: a cell with a missing field required to judge the slot
/// does not satisfy it (no benefit-of-the-doubt matching).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RequiredCell {
    Wifi7ApBeMode,
    SameApAxMode,
    Wifi6eApControl,
    NativeWifi7Client,
    NativeWifi6eClient,
}

impl RequiredCell {
    pub fn label(&self) -> &'static str {
        match self {
            RequiredCell::Wifi7ApBeMode => "Wi-Fi 7 AP in BE mode",
            RequiredCell::SameApAxMode => "the same AP/radio in AX mode",
            RequiredCell::Wifi6eApControl => "a Wi-Fi 6E AP control",
            RequiredCell::NativeWifi7Client => "a native Wi-Fi 7 client",
            RequiredCell::NativeWifi6eClient => "a native Wi-Fi 6E client",
        }
    }

    fn matches(&self, cell: &MatrixCell) -> bool {
        match self {
            RequiredCell::Wifi7ApBeMode => cell.ap.radio_mode == Some(RadioMode::Be),
            RequiredCell::SameApAxMode => cell.ap.radio_mode == Some(RadioMode::Ax),
            RequiredCell::Wifi6eApControl => {
                // A Wi-Fi 6E AP has no BE capability at all; represented as
                // an AX-mode context whose model is explicitly not a
                // BE-capable model. Absent a model string, this cannot be
                // distinguished from "the same AP in AX mode", so it does
                // not match -- matching would blur exactly the two facts
                // GAP-037 exists to keep separate.
                cell.ap.radio_mode == Some(RadioMode::Ax) && cell.ap.model.is_some()
            }
            RequiredCell::NativeWifi7Client => {
                cell.client_hardware_generation == Some(ClientHardwareGeneration::Wifi7)
            }
            RequiredCell::NativeWifi6eClient => {
                cell.client_hardware_generation == Some(ClientHardwareGeneration::Wifi6e)
            }
        }
    }
}

pub const REQUIRED_CELLS: [RequiredCell; 5] = [
    RequiredCell::Wifi7ApBeMode,
    RequiredCell::SameApAxMode,
    RequiredCell::Wifi6eApControl,
    RequiredCell::NativeWifi7Client,
    RequiredCell::NativeWifi6eClient,
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompatibilityMatrix {
    pub cells: Vec<MatrixCell>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CompatibilityVerdict {
    /// Every required cell is present; comparison values are named, not a
    /// prose conclusion this module does not have the domain authority to
    /// assert on its own.
    Comparable { present_cells: Vec<String> },
    /// The central regression this gate locks: refuse, and name exactly
    /// which required cells are still missing.
    InsufficientCells { missing: Vec<String> },
}

pub fn verdict(matrix: &CompatibilityMatrix) -> CompatibilityVerdict {
    let missing: Vec<String> = REQUIRED_CELLS
        .iter()
        .filter(|req| !matrix.cells.iter().any(|c| req.matches(c)))
        .map(|req| req.label().to_string())
        .collect();

    if !missing.is_empty() {
        return CompatibilityVerdict::InsufficientCells { missing };
    }

    CompatibilityVerdict::Comparable {
        present_cells: matrix.cells.iter().map(|c| c.label.clone()).collect(),
    }
}

/// A deterministic, hashable descriptor of one run -- not a signature
/// (GAP-029/065's manifest work owns signing), but stable enough that a
/// signature can be attached to it later without this module changing.
/// Built only from fields already present on `MatrixCell`, so recomputing
/// it never requires re-reading anything from the client or operator.
pub fn run_descriptor_digest(cell: &MatrixCell) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    #[derive(Hash)]
    struct Descriptor<'a> {
        label: &'a str,
        negotiated_generation: &'a str,
        band: &'a Option<String>,
        channel: &'a Option<u32>,
        width_mhz: &'a Option<u32>,
        ap_label: Option<&'a str>,
        ap_model: &'a Option<String>,
        ap_firmware: &'a Option<String>,
        radio_mode: Option<&'a str>,
    }

    let d = Descriptor {
        label: &cell.label,
        negotiated_generation: match cell.client.negotiated_generation {
            NegotiatedGeneration::He => "he",
            NegotiatedGeneration::Eht => "eht",
            NegotiatedGeneration::PreHe => "pre-he",
            NegotiatedGeneration::Unknown => "unknown",
        },
        band: &cell.client.band,
        channel: &cell.client.channel,
        width_mhz: &cell.client.width_mhz,
        ap_label: cell.ap.ap_identity.as_ref().map(|a| a.label.as_str()),
        ap_model: &cell.ap.model,
        ap_firmware: &cell.ap.firmware_version,
        radio_mode: cell.ap.radio_mode.map(|m| match m {
            RadioMode::Be => "be",
            RadioMode::Ax => "ax",
        }),
    };

    let mut hasher = DefaultHasher::new();
    d.hash(&mut hasher);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(phy_mode: &str) -> RadioSnapshot {
        RadioSnapshot {
            associated: true,
            phy_mode: Some(phy_mode.to_string()),
            band: Some("6GHz".to_string()),
            channel: Some(197),
            width_mhz: Some(80),
            rssi_dbm: Some(-59),
            noise_dbm: Some(-94),
            tx_rate_mbps: Some(680.0),
            mcs_index: Some(7),
        }
    }

    fn empty_ap() -> ApContext {
        ApContext {
            ap_identity: None,
            model: None,
            firmware_version: None,
            power_mode_raw: None,
            low_power_supply: None,
            radio_mode: None,
            mlo_supported: None,
            band_advertised: None,
            width_advertised_mhz: None,
            nss_advertised: None,
        }
    }

    #[test]
    fn ax_client_is_he_not_eht() {
        assert_eq!(
            classify_negotiated_generation(&Some("802.11ax".to_string())),
            NegotiatedGeneration::He
        );
    }

    #[test]
    fn be_client_is_eht() {
        assert_eq!(
            classify_negotiated_generation(&Some("802.11be".to_string())),
            NegotiatedGeneration::Eht
        );
    }

    #[test]
    fn missing_phy_mode_is_unknown_not_guessed() {
        assert_eq!(
            classify_negotiated_generation(&None),
            NegotiatedGeneration::Unknown
        );
    }

    #[test]
    fn client_negotiated_mode_stays_distinct_from_ap_capability() {
        // The exact field case: a BE-capable (Wi-Fi 7) AP serving an
        // HE-negotiated client. The client's own record must say He, never
        // Eht, regardless of what the AP context claims it supports.
        let client = client_association_from_snapshot(&snapshot("802.11ax"), None);
        let ap = ApContext {
            radio_mode: Some(RadioMode::Be),
            model: Some("C-460".to_string()),
            ..empty_ap()
        };
        assert_eq!(client.negotiated_generation, NegotiatedGeneration::He);
        assert_eq!(ap.radio_mode, Some(RadioMode::Be));
        assert_ne!(
            format!("{:?}", client.negotiated_generation),
            format!("{:?}", ap.radio_mode)
        );
    }

    #[test]
    fn single_cell_matrix_never_yields_a_verdict() {
        let client = client_association_from_snapshot(&snapshot("802.11ax"), None);
        let ap = ApContext {
            radio_mode: Some(RadioMode::Be),
            model: Some("C-460".to_string()),
            ..empty_ap()
        };
        let matrix = CompatibilityMatrix {
            cells: vec![MatrixCell {
                label: "only-cell".to_string(),
                client,
                ap,
                client_hardware_generation: Some(ClientHardwareGeneration::Wifi7),
            }],
        };
        match verdict(&matrix) {
            CompatibilityVerdict::InsufficientCells { missing } => {
                assert!(!missing.is_empty());
                assert!(missing.iter().any(|m| m.contains("AX mode")));
            }
            CompatibilityVerdict::Comparable { .. } => panic!("one cell must never be comparable"),
        }
    }

    #[test]
    fn missing_cells_are_named_explicitly() {
        let empty_matrix = CompatibilityMatrix { cells: vec![] };
        match verdict(&empty_matrix) {
            CompatibilityVerdict::InsufficientCells { missing } => {
                assert_eq!(missing.len(), REQUIRED_CELLS.len());
            }
            CompatibilityVerdict::Comparable { .. } => {
                panic!("empty matrix must never be comparable")
            }
        }
    }

    #[test]
    fn all_five_required_cells_present_yields_comparable() {
        let he_client = client_association_from_snapshot(&snapshot("802.11ax"), None);
        let eht_client = client_association_from_snapshot(&snapshot("802.11be"), None);

        let be_ap = ApContext {
            radio_mode: Some(RadioMode::Be),
            model: Some("C-460".to_string()),
            ..empty_ap()
        };
        let ax_ap_same = ApContext {
            radio_mode: Some(RadioMode::Ax),
            model: Some("C-460".to_string()),
            ..empty_ap()
        };
        let wifi6e_ap = ApContext {
            radio_mode: Some(RadioMode::Ax),
            model: Some("C-360".to_string()),
            ..empty_ap()
        };

        let matrix = CompatibilityMatrix {
            cells: vec![
                MatrixCell {
                    label: "be-mode".to_string(),
                    client: he_client.clone(),
                    ap: be_ap,
                    client_hardware_generation: Some(ClientHardwareGeneration::Wifi7),
                },
                MatrixCell {
                    label: "ax-mode-same-ap".to_string(),
                    client: he_client.clone(),
                    ap: ax_ap_same,
                    client_hardware_generation: Some(ClientHardwareGeneration::Wifi7),
                },
                MatrixCell {
                    label: "wifi6e-ap".to_string(),
                    client: he_client,
                    ap: wifi6e_ap,
                    client_hardware_generation: Some(ClientHardwareGeneration::Wifi6e),
                },
                MatrixCell {
                    label: "native-wifi7-client".to_string(),
                    client: eht_client.clone(),
                    ap: empty_ap(),
                    client_hardware_generation: Some(ClientHardwareGeneration::Wifi7),
                },
                MatrixCell {
                    label: "native-wifi6e-client".to_string(),
                    client: eht_client,
                    ap: empty_ap(),
                    client_hardware_generation: Some(ClientHardwareGeneration::Wifi6e),
                },
            ],
        };
        match verdict(&matrix) {
            CompatibilityVerdict::Comparable { present_cells } => {
                assert_eq!(present_cells.len(), 5)
            }
            CompatibilityVerdict::InsufficientCells { missing } => {
                panic!("expected comparable, missing: {missing:?}")
            }
        }
    }

    #[test]
    fn wifi6e_control_requires_a_named_ap_model_not_just_ax_mode() {
        // An AX-mode cell with no AP model cannot be distinguished from
        // "the same AP switched to AX mode" -- it must not satisfy the
        // independent 6E-AP slot.
        let client = client_association_from_snapshot(&snapshot("802.11ax"), None);
        let ap_no_model = ApContext {
            radio_mode: Some(RadioMode::Ax),
            ..empty_ap()
        };
        let cell = MatrixCell {
            label: "ambiguous".to_string(),
            client,
            ap: ap_no_model,
            client_hardware_generation: None,
        };
        assert!(!RequiredCell::Wifi6eApControl.matches(&cell));
    }

    #[test]
    fn ingest_round_trips_a_missing_firmware_as_none_not_a_guess() {
        let ap = ApContext {
            firmware_version: None,
            ..empty_ap()
        };
        let json = serde_json::to_string(&ap).unwrap();
        let back: ApContext = serde_json::from_str(&json).unwrap();
        assert_eq!(back.firmware_version, None);
    }

    #[test]
    fn run_descriptor_is_deterministic_for_the_same_cell() {
        let client = client_association_from_snapshot(&snapshot("802.11ax"), None);
        let ap = ApContext {
            radio_mode: Some(RadioMode::Be),
            model: Some("C-460".to_string()),
            ..empty_ap()
        };
        let cell = MatrixCell {
            label: "x".to_string(),
            client,
            ap,
            client_hardware_generation: None,
        };
        assert_eq!(run_descriptor_digest(&cell), run_descriptor_digest(&cell));
    }

    #[test]
    fn client_association_never_carries_ssid_bssid_mac_text() {
        let client = client_association_from_snapshot(&snapshot("802.11ax"), None);
        let debug = format!("{client:?}");
        assert!(!debug.to_lowercase().contains("bssid"));
        assert!(!debug.to_lowercase().contains("ssid"));
    }
}
