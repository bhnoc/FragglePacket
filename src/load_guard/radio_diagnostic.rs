//! GAP-011: Wi-Fi radio/retry diagnostic with safe elevation and explicit
//! platform-limitation reporting.
//!
//! Field evidence: manual inspection found strong 6 GHz RF, but retry
//! counters, WMM state, and channel utilization required elevated tools --
//! and even the elevated `wdutil info` output never carried retry or WMM
//! counters (the 2026-08-01 field investigation note). This module's
//! `platform_limitations` field is not a courtesy footnote; it is the
//! deliverable GAP-011 explicitly asks for, and it is populated whenever a
//! counter genuinely cannot be obtained on this platform rather than left
//! to read as an implicit zero (the GAP-043 frozen-counter trap: a 0 must
//! never stand in for "not measured").

use crate::load_guard::radio::{classify_rf, RadioSnapshot, RfQuality};
use crate::load_guard::wdutil::{self, WdutilError, WdutilFields};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RadioDiagnostic {
    pub associated: bool,
    pub band: Option<String>,
    pub channel: Option<u32>,
    pub width_mhz: Option<u32>,
    pub rssi_dbm: Option<i32>,
    pub noise_dbm: Option<i32>,
    pub snr_db: Option<i32>,
    pub mcs_index: Option<u32>,
    pub tx_rate_mbps: Option<f64>,
    pub rf_quality: RfQuality,
    /// Channel utilization via CCA%, from the privileged source only --
    /// `system_profiler`/`ioreg` do not expose it. `None` when the
    /// privileged read was unavailable, never a fabricated 0%.
    pub channel_utilization_pct: Option<f64>,
    /// Retries and WMM access-category state: this platform provides no
    /// unprivileged or privileged CLI path to either figure (confirmed
    /// against real elevated `wdutil info` output during the investigation
    /// this gap traces to). Always `None` here; kept as explicit fields
    /// rather than omitted so a JSON consumer sees the absence structurally,
    /// not by a missing key it might mistake for an oversight.
    pub retries: Option<u64>,
    pub wmm_access_category: Option<String>,
    /// Every reason a figure above is `None` because the *platform* cannot
    /// provide it, as opposed to a transient sampling failure. Always
    /// non-empty for `retries`/`wmm_access_category`/(when privileged read
    /// failed) `channel_utilization_pct`.
    pub platform_limitations: Vec<String>,
    /// Set when the privileged (`wdutil`) source could not be read, naming
    /// the exact elevation command -- never invoked automatically.
    pub privilege_note: Option<String>,
}

const RETRY_LIMITATION: &str = "retry counters are not exposed by any known unprivileged or privileged macOS CLI path (system_profiler, ioreg, or wdutil info); this platform genuinely cannot report them, not a zero measurement";
const WMM_LIMITATION: &str = "WMM access-category state is not exposed by any known unprivileged or privileged macOS CLI path on this platform";

pub fn build_diagnostic(base: RadioSnapshot, privileged: Result<WdutilFields, WdutilError>) -> RadioDiagnostic {
    let rf_quality = classify_rf(&base);
    let mut platform_limitations = vec![RETRY_LIMITATION.to_string(), WMM_LIMITATION.to_string()];

    let (channel_utilization_pct, privilege_note) = match &privileged {
        Ok(f) => {
            if f.cca_percent.is_none() {
                platform_limitations.push("channel utilization (CCA%) was not present in this wdutil info output".to_string());
            }
            (f.cca_percent, None)
        }
        Err(e) => {
            platform_limitations.push(format!("channel utilization (CCA%) requires elevated wdutil access: {e}"));
            let note = match e {
                WdutilError::PrivilegeRequired { command } => Some(format!("re-run as: {command}")),
                _ => Some(e.to_string()),
            };
            (None, note)
        }
    };

    // Prefer the privileged source's RSSI/noise/PHY fields when available
    // (wdutil reports a live, single-sample view matching the unprivileged
    // one) but never overwrite with a privileged None -- the unprivileged
    // base snapshot is the floor, not replaced by a failed privileged read.
    let (rssi_dbm, noise_dbm, mcs_index, tx_rate_mbps) = match &privileged {
        Ok(f) => (
            f.rssi_dbm.or(base.rssi_dbm),
            f.noise_dbm.or(base.noise_dbm),
            f.mcs_index.or(base.mcs_index),
            f.tx_rate_mbps.or(base.tx_rate_mbps),
        ),
        Err(_) => (base.rssi_dbm, base.noise_dbm, base.mcs_index, base.tx_rate_mbps),
    };

    let snr_db = match (rssi_dbm, noise_dbm) {
        (Some(r), Some(n)) => Some(r - n),
        _ => None,
    };

    RadioDiagnostic {
        associated: base.associated,
        band: base.band,
        channel: base.channel,
        width_mhz: base.width_mhz,
        rssi_dbm,
        noise_dbm,
        snr_db,
        mcs_index,
        tx_rate_mbps,
        rf_quality,
        channel_utilization_pct,
        retries: None,
        wmm_access_category: None,
        platform_limitations,
        privilege_note,
    }
}

/// Live composition: unprivileged `system_profiler` base plus a best-effort
/// privileged `wdutil` read. Never fails outright if the privileged read is
/// unavailable -- the unprivileged data still stands, with the gap noted.
pub fn diagnose_live() -> RadioDiagnostic {
    let base = crate::load_guard::radio::snapshot_live().unwrap_or_else(|_| RadioSnapshot::unavailable());
    let privileged = wdutil::snapshot_live();
    build_diagnostic(base, privileged)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strong_snapshot() -> RadioSnapshot {
        RadioSnapshot {
            associated: true,
            phy_mode: Some("802.11ax".to_string()),
            band: Some("6GHz".to_string()),
            channel: Some(37),
            width_mhz: Some(80),
            rssi_dbm: Some(-53),
            noise_dbm: Some(-93),
            tx_rate_mbps: Some(900.0),
            mcs_index: Some(9),
        }
    }

    #[test]
    fn retries_and_wmm_are_always_none_with_platform_limitation_stated() {
        let diag = build_diagnostic(strong_snapshot(), Err(WdutilError::ToolMissing));
        assert_eq!(diag.retries, None);
        assert_eq!(diag.wmm_access_category, None);
        assert!(diag.platform_limitations.iter().any(|l| l.contains("retry")));
        assert!(diag.platform_limitations.iter().any(|l| l.contains("WMM")));
    }

    #[test]
    fn missing_privileged_source_notes_privilege_requirement_not_a_silent_gap() {
        let diag = build_diagnostic(
            strong_snapshot(),
            Err(WdutilError::PrivilegeRequired { command: "sudo wdutil info".to_string() }),
        );
        assert!(diag.privilege_note.is_some());
        assert!(diag.privilege_note.unwrap().contains("sudo wdutil info"));
        assert_eq!(diag.channel_utilization_pct, None);
    }

    #[test]
    fn channel_utilization_present_when_privileged_source_available() {
        let fields = WdutilFields {
            bssid: Some("02:00:00:00:00:01".to_string()),
            rssi_dbm: Some(-53),
            noise_dbm: Some(-93),
            cca_percent: Some(3.5),
            tx_rate_mbps: Some(1200.0),
            phy_mode: Some("802.11ax".to_string()),
            mcs_index: Some(11),
            band: Some("6GHz".to_string()),
            channel: Some(5),
            width_mhz: Some(80),
        };
        let diag = build_diagnostic(strong_snapshot(), Ok(fields));
        assert_eq!(diag.channel_utilization_pct, Some(3.5));
        assert!(diag.privilege_note.is_none());
    }

    #[test]
    fn unprivileged_floor_survives_a_failed_privileged_read() {
        let diag = build_diagnostic(strong_snapshot(), Err(WdutilError::ToolMissing));
        assert_eq!(diag.rssi_dbm, Some(-53));
        assert_eq!(diag.noise_dbm, Some(-93));
        assert_eq!(diag.snr_db, Some(40));
    }

    #[test]
    fn rf_quality_is_computed_from_the_resulting_snapshot() {
        let mut weak = strong_snapshot();
        weak.rssi_dbm = Some(-80);
        let diag = build_diagnostic(weak, Err(WdutilError::ToolMissing));
        assert_eq!(diag.rf_quality, RfQuality::Weak);
    }
}
