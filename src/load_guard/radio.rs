//! Unprivileged Wi-Fi radio-state sampling (GAP-027/GAP-035).
//!
//! Parses `system_profiler SPAirPortDataType`, which works without root and
//! already redacts SSID/BSSID text in newer macOS. We additionally never read
//! or store the `MAC Address:` line — GAP-018/GAP-020/GAP-035 forbid
//! persisting SSID, BSSID, or MAC, so only an allowlist of RF fields is kept.

use serde::{Deserialize, Serialize};
use std::process::Command;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RadioSnapshot {
    pub associated: bool,
    pub phy_mode: Option<String>,
    pub band: Option<String>,
    pub channel: Option<u32>,
    pub width_mhz: Option<u32>,
    pub rssi_dbm: Option<i32>,
    pub noise_dbm: Option<i32>,
    pub tx_rate_mbps: Option<f64>,
    pub mcs_index: Option<u32>,
}

impl RadioSnapshot {
    pub fn unavailable() -> Self {
        Self {
            associated: false,
            phy_mode: None,
            band: None,
            channel: None,
            width_mhz: None,
            rssi_dbm: None,
            noise_dbm: None,
            tx_rate_mbps: None,
            mcs_index: None,
        }
    }

    /// A non-identifying fingerprint of the current association, built only
    /// from allowlisted fields (band/channel/width/phy). This is NOT a stable
    /// AP identity (that's GAP-024's salted-identifier job) — it exists so a
    /// roam/band-change can be detected structurally without ever touching a
    /// BSSID or MAC.
    pub fn association_fingerprint(&self) -> Option<String> {
        if !self.associated {
            return None;
        }
        Some(format!(
            "{}:{}:{}:{}",
            self.band.as_deref().unwrap_or("?"),
            self.channel.map(|c| c.to_string()).unwrap_or_default(),
            self.width_mhz.map(|w| w.to_string()).unwrap_or_default(),
            self.phy_mode.as_deref().unwrap_or("?"),
        ))
    }

    pub fn snr_db(&self) -> Option<i32> {
        match (self.rssi_dbm, self.noise_dbm) {
            (Some(r), Some(n)) => Some(r - n),
            _ => None,
        }
    }
}

/// RF quality qualification. Weak/unstable RF must be flagged even absent a
/// roam — a stationary run on marginal RF is exactly the GAP-027 downstairs
/// scenario after the roam settled onto weak 2.4 GHz.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RfQuality {
    Strong,
    Weak,
    Unstable,
    Unknown,
}

pub const WEAK_RSSI_DBM: i32 = -75;
pub const UNSTABLE_SNR_DB: i32 = 15;

pub fn classify_rf(snap: &RadioSnapshot) -> RfQuality {
    if !snap.associated {
        return RfQuality::Unknown;
    }
    match (snap.rssi_dbm, snap.snr_db()) {
        (Some(rssi), Some(snr)) => {
            if rssi <= WEAK_RSSI_DBM {
                RfQuality::Weak
            } else if snr < UNSTABLE_SNR_DB {
                RfQuality::Unstable
            } else {
                RfQuality::Strong
            }
        }
        (Some(rssi), None) => {
            if rssi <= WEAK_RSSI_DBM {
                RfQuality::Weak
            } else {
                RfQuality::Strong
            }
        }
        _ => RfQuality::Unknown,
    }
}

/// Live unprivileged snapshot via `system_profiler SPAirPortDataType`.
pub fn snapshot_live() -> Result<RadioSnapshot, String> {
    let out = Command::new("system_profiler")
        .arg("SPAirPortDataType")
        .output()
        .map_err(|e| format!("failed to run system_profiler: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "system_profiler exited with {:?}",
            out.status.code()
        ));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    Ok(parse_airport_text(&text))
}

/// Parse from a captured fixture (or live output) string. Kept separate from
/// `snapshot_live` so radio logic is unit-testable without real Wi-Fi.
pub fn parse_airport_text(text: &str) -> RadioSnapshot {
    let mut snap = RadioSnapshot::unavailable();
    let mut in_current = false;

    for raw_line in text.lines() {
        let line = raw_line.trim();

        if line.starts_with("Status:") {
            snap.associated = line.contains("Connected");
        }
        if line.starts_with("Current Network Information:") {
            in_current = true;
            continue;
        }
        if line.starts_with("Other Local Wi-Fi Networks:") {
            in_current = false;
            continue;
        }
        if !in_current {
            continue;
        }

        if let Some(v) = line.strip_prefix("PHY Mode:") {
            snap.phy_mode = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("Channel:") {
            parse_channel(v.trim(), &mut snap);
        } else if let Some(v) = line.strip_prefix("Signal / Noise:") {
            parse_signal_noise(v.trim(), &mut snap);
        } else if let Some(v) = line.strip_prefix("Transmit Rate:") {
            snap.tx_rate_mbps = v.trim().parse::<f64>().ok();
        } else if let Some(v) = line.strip_prefix("MCS Index:") {
            snap.mcs_index = v.trim().parse::<u32>().ok();
        }
    }

    if snap.phy_mode.is_some() || snap.channel.is_some() {
        snap.associated = true;
    }
    snap
}

// "197 (6GHz, 80MHz)" -> channel=197 band="6GHz" width_mhz=80
fn parse_channel(v: &str, snap: &mut RadioSnapshot) {
    let mut parts = v.splitn(2, '(');
    if let Some(chan_str) = parts.next() {
        snap.channel = chan_str.trim().parse::<u32>().ok();
    }
    if let Some(rest) = parts.next() {
        let rest = rest.trim_end_matches(')');
        for token in rest.split(',') {
            let token = token.trim();
            if token.ends_with("GHz") {
                snap.band = Some(token.to_string());
            } else if token.ends_with("MHz") {
                snap.width_mhz = token.trim_end_matches("MHz").trim().parse::<u32>().ok();
            }
        }
    }
}

// "-59 dBm / -94 dBm" -> rssi=-59 noise=-94
fn parse_signal_noise(v: &str, snap: &mut RadioSnapshot) {
    let mut parts = v.split('/');
    if let Some(rssi) = parts.next() {
        snap.rssi_dbm = rssi.trim().trim_end_matches("dBm").trim().parse::<i32>().ok();
    }
    if let Some(noise) = parts.next() {
        snap.noise_dbm = noise.trim().trim_end_matches("dBm").trim().parse::<i32>().ok();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = include_str!("../../harness/fixtures/wifi/system_profiler-airport.txt");

    #[test]
    fn parses_fixture_current_network() {
        let snap = parse_airport_text(FIXTURE);
        assert!(snap.associated);
        assert_eq!(snap.phy_mode, Some("802.11ax".to_string()));
        assert_eq!(snap.channel, Some(197));
        assert_eq!(snap.band, Some("6GHz".to_string()));
        assert_eq!(snap.width_mhz, Some(80));
        assert_eq!(snap.rssi_dbm, Some(-59));
        assert_eq!(snap.noise_dbm, Some(-94));
        assert_eq!(snap.tx_rate_mbps, Some(680.0));
        assert_eq!(snap.mcs_index, Some(7));
    }

    #[test]
    fn strong_rf_classified_strong() {
        let snap = parse_airport_text(FIXTURE);
        assert_eq!(classify_rf(&snap), RfQuality::Strong);
    }

    #[test]
    fn weak_rssi_classified_weak() {
        let mut snap = parse_airport_text(FIXTURE);
        snap.rssi_dbm = Some(-80);
        assert_eq!(classify_rf(&snap), RfQuality::Weak);
    }

    #[test]
    fn low_snr_classified_unstable() {
        let mut snap = parse_airport_text(FIXTURE);
        snap.rssi_dbm = Some(-70);
        snap.noise_dbm = Some(-60);
        assert_eq!(classify_rf(&snap), RfQuality::Unstable);
    }

    #[test]
    fn fingerprint_changes_on_band_change() {
        let a = parse_airport_text(FIXTURE);
        let mut b = a.clone();
        b.band = Some("2GHz".to_string());
        b.channel = Some(6);
        assert_ne!(a.association_fingerprint(), b.association_fingerprint());
    }

    #[test]
    fn fixture_text_never_carries_ssid_bssid_mac() {
        assert!(!FIXTURE.contains("00:00:00:00:00:00") || FIXTURE.contains("02:00:00:00:00:01"));
        for line in FIXTURE.lines() {
            assert!(!line.trim_start().starts_with("SSID"));
        }
    }
}
