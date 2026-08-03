//! GAP-011/GAP-024: privileged `wdutil info` extraction, allowlisted only.
//!
//! `wdutil info` requires root on this platform and, per GAP-020, its raw
//! output additionally dumps a `BLUETOOTH` section with paired-device names
//! -- unrelated to any Wi-Fi test and a privacy leak on its own. This module
//! extracts only the allowlisted Wi-Fi fields (plus BSSID, immediately
//! hashed by the caller and never returned) directly from the process
//! output; the Bluetooth section, SSID, and every field not in the allowlist
//! below are never read into any struct that could be printed or persisted.
//!
//! Never escalates privilege itself -- same GAP-016 pattern as
//! `network_tests::capture`: if `wdutil info` fails because this process
//! lacks root, that is detected and reported as a named required command,
//! never silently retried with sudo.

use serde::{Deserialize, Serialize};
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WdutilFields {
    /// Read once, in memory, only long enough for the caller to hash it via
    /// `ap_identity::label_for_bssid` immediately. No `Display`/`Debug`
    /// derive path in this crate should ever print this field; treat it as
    /// write-once, read-never after construction.
    pub bssid: Option<String>,
    pub rssi_dbm: Option<i32>,
    pub noise_dbm: Option<i32>,
    /// CCA (Clear Channel Assessment) percentage -- the channel-utilization
    /// figure this platform's unprivileged and privileged tools both
    /// expose; see `docs/GAP_LIST.md`'s 2026-08-01 note that even elevated
    /// diagnostics did not carry retry or WMM counters.
    pub cca_percent: Option<f64>,
    pub tx_rate_mbps: Option<f64>,
    pub phy_mode: Option<String>,
    pub mcs_index: Option<u32>,
    pub band: Option<String>,
    pub channel: Option<u32>,
    pub width_mhz: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WdutilError {
    ToolMissing,
    PrivilegeRequired { command: String },
    ParseFailed(String),
}

impl std::fmt::Display for WdutilError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WdutilError::ToolMissing => write!(f, "wdutil not found on this system"),
            WdutilError::PrivilegeRequired { command } => {
                write!(f, "wdutil info requires elevated privilege; re-run as: {command}")
            }
            WdutilError::ParseFailed(detail) => write!(f, "failed to parse wdutil info output: {detail}"),
        }
    }
}

pub fn suggested_privileged_command() -> String {
    "sudo wdutil info".to_string()
}

fn is_privilege_error(stderr_or_stdout: &str) -> bool {
    let lower = stderr_or_stdout.to_lowercase();
    lower.contains("sudo") || lower.contains("permission") || lower.contains("not permitted") || lower.contains("root")
}

/// Runs `wdutil info` and extracts the allowlisted Wi-Fi fields. Never
/// invokes sudo; a permission failure is reported as `PrivilegeRequired`
/// naming the exact command to re-run, per the GAP-016 pattern.
pub fn snapshot_live() -> Result<WdutilFields, WdutilError> {
    let output = Command::new("wdutil").arg("info").output().map_err(|_| WdutilError::ToolMissing)?;

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    if !output.status.success() && is_privilege_error(&combined) {
        return Err(WdutilError::PrivilegeRequired { command: suggested_privileged_command() });
    }
    if !output.status.success() {
        return Err(WdutilError::ParseFailed(format!("wdutil exited with {:?}", output.status.code())));
    }

    Ok(parse_wdutil_info(&String::from_utf8_lossy(&output.stdout)))
}

/// Parses `wdutil info` text. Only reads lines inside the `WIFI` section,
/// stopping at the next all-caps section header (e.g. `BLUETOOTH`) -- this
/// is the structural enforcement of GAP-020's allowlist, not a per-field
/// afterthought: the Bluetooth section is never entered as a parse state at
/// all, so there is no code path that could read a paired-device name.
pub fn parse_wdutil_info(text: &str) -> WdutilFields {
    let mut fields = WdutilFields {
        bssid: None,
        rssi_dbm: None,
        noise_dbm: None,
        cca_percent: None,
        tx_rate_mbps: None,
        phy_mode: None,
        mcs_index: None,
        band: None,
        channel: None,
        width_mhz: None,
    };

    let mut in_wifi_section = false;
    for raw_line in text.lines() {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() {
            continue;
        }
        // A section header is a bare all-caps word at zero indentation
        // (e.g. "WIFI", "BLUETOOTH", "NETWORK"), distinct from indented
        // "Key : Value" field lines.
        let is_header = !raw_line.starts_with(' ') && !trimmed.contains(':');
        if is_header {
            in_wifi_section = trimmed == "WIFI";
            continue;
        }
        if !in_wifi_section {
            continue;
        }

        let Some((key, value)) = trimmed.split_once(':') else { continue };
        let key = key.trim();
        let value = value.trim();

        match key {
            "BSSID" => {
                if value != "<redacted>" && !value.is_empty() {
                    fields.bssid = Some(value.to_string());
                }
            }
            "RSSI" => fields.rssi_dbm = parse_dbm(value),
            "Noise" => fields.noise_dbm = parse_dbm(value),
            "CCA" => fields.cca_percent = value.trim_end_matches('%').trim().parse::<f64>().ok(),
            "Tx Rate" => fields.tx_rate_mbps = value.trim_end_matches("Mbps").trim().parse::<f64>().ok(),
            "PHY Mode" => fields.phy_mode = Some(value.to_string()),
            "MCS Index" => fields.mcs_index = value.parse::<u32>().ok(),
            "Channel" => parse_wdutil_channel(value, &mut fields),
            // SSID, MAC Address, NetworkServiceID, and every other field not
            // matched above is intentionally dropped here.
            _ => {}
        }
    }

    fields
}

fn parse_dbm(value: &str) -> Option<i32> {
    value.trim_end_matches("dBm").trim().parse::<i32>().ok()
}

// "6 GHz channel 5 / 80 MHz" -> band="6GHz" channel=5 width_mhz=80
fn parse_wdutil_channel(value: &str, fields: &mut WdutilFields) {
    let parts: Vec<&str> = value.split('/').collect();
    if let Some(first) = parts.first() {
        let tokens: Vec<&str> = first.split_whitespace().collect();
        if tokens.len() >= 4 && tokens[1].eq_ignore_ascii_case("ghz") && tokens[2].eq_ignore_ascii_case("channel") {
            fields.band = Some(format!("{}GHz", tokens[0]));
            fields.channel = tokens[3].parse::<u32>().ok();
        }
    }
    if let Some(second) = parts.get(1) {
        let cleaned = second.trim().trim_end_matches("MHz").trim();
        fields.width_mhz = cleaned.parse::<u32>().ok();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = include_str!("../../harness/fixtures/wifi/wdutil-info.txt");

    #[test]
    fn parses_allowlisted_fields_from_fixture() {
        let fields = parse_wdutil_info(FIXTURE);
        assert_eq!(fields.rssi_dbm, Some(-53));
        assert_eq!(fields.noise_dbm, Some(-93));
        assert_eq!(fields.cca_percent, Some(0.0));
        assert_eq!(fields.tx_rate_mbps, Some(1200.0));
        assert_eq!(fields.phy_mode, Some("802.11ax".to_string()));
        assert_eq!(fields.mcs_index, Some(11));
        assert_eq!(fields.band, Some("6GHz".to_string()));
        assert_eq!(fields.channel, Some(5));
        assert_eq!(fields.width_mhz, Some(80));
    }

    #[test]
    fn bssid_is_extracted_only_for_immediate_hashing_use() {
        // The fixture's BSSID line uses the same placeholder gate 001
        // permits; confirm the parser reads it (proving the field exists to
        // be hashed) without this test itself printing it anywhere.
        let fields = parse_wdutil_info(FIXTURE);
        assert!(fields.bssid.is_some());
    }

    #[test]
    fn bluetooth_section_is_never_entered_as_a_parse_state() {
        // The fixture's BLUETOOTH section contains device names; confirm no
        // parsed field carries that text, proving the section is structurally
        // unreachable rather than filtered after the fact.
        assert!(FIXTURE.contains("AirPods") && FIXTURE.contains("Magic Keyboard"));
        let fields = parse_wdutil_info(FIXTURE);
        let debug = format!("{fields:?}");
        assert!(!debug.contains("AirPods"));
        assert!(!debug.contains("Magic Keyboard"));
        assert!(!debug.contains("Paired"));
    }

    #[test]
    fn ssid_and_mac_address_fields_are_never_captured() {
        let fields = parse_wdutil_info(FIXTURE);
        let debug = format!("{fields:?}");
        // The fixture's SSID line is "<redacted>" already; the stronger
        // proof is that no field in WdutilFields corresponds to SSID or MAC
        // Address at all -- there is no member to leak through. Checked as
        // "SSID" (not the "ssid" substring inside "bssid", which is the one
        // BSSID field this module intentionally does carry for hashing).
        assert!(!debug.contains("SSID"));
        assert!(!debug.contains("MAC Address"));
        assert!(!debug.to_lowercase().contains("mac_address"));
    }

    #[test]
    fn is_privilege_error_detects_sudo_wording() {
        assert!(is_privilege_error("wdutil: this command requires root privileges, use sudo"));
        assert!(is_privilege_error("Operation not permitted"));
        assert!(!is_privilege_error("wdutil: unknown command foo"));
    }
}
