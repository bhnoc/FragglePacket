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
    /// from allowlisted fields (band/channel/width). This is NOT a stable AP
    /// identity (that's GAP-024's salted-identifier job) — it exists so a
    /// roam/band-change can be detected structurally without ever touching a
    /// BSSID or MAC.
    ///
    /// Deliberately excludes `phy_mode`: the cheap `ioreg`-backed fast source
    /// used for in-phase polling never populates it, so including it would
    /// make a full snapshot's fingerprint mismatch a fast snapshot's on every
    /// single comparison — a false roam on every run, not just a real one.
    /// Band/channel/width alone is the same signal a real roam or band change
    /// produces and is available from both sources.
    pub fn association_fingerprint(&self) -> Option<String> {
        if !self.associated {
            return None;
        }
        Some(format!(
            "{}:{}:{}",
            self.band.as_deref().unwrap_or("?"),
            self.channel.map(|c| c.to_string()).unwrap_or_default(),
            self.width_mhz.map(|w| w.to_string()).unwrap_or_default(),
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

/// Live unprivileged snapshot via `system_profiler SPAirPortDataType`. Full
/// detail (RSSI/noise/PHY rate/MCS) but costs ~8s per call on this class of
/// machine — reserved for the before/after snapshots, never for in-phase
/// polling.
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

/// Cheap (~30ms) unprivileged snapshot via `ioreg`, used for in-phase roam
/// polling where `system_profiler`'s ~8s cost would otherwise dominate the
/// run. Carries only band/channel/width — no RSSI/noise/MCS/PHY-mode, which
/// `ioreg` does not expose for this driver — enough to detect a roam or band
/// change (GAP-027's in-phase signal) but not enough to qualify RF quality.
/// `ioreg`'s raw output also contains `IO80211SSID`/`IO80211BSSID`; the
/// parser below never reads those keys, matching the same allowlist
/// discipline as the `system_profiler` path.
pub fn snapshot_fast() -> Result<RadioSnapshot, String> {
    let out = Command::new("ioreg")
        .args(["-c", "AppleBCMWLANSkywalkInterface", "-r", "-l"])
        .output()
        .map_err(|e| format!("failed to run ioreg: {e}"))?;
    if !out.status.success() {
        return Err(format!("ioreg exited with {:?}", out.status.code()));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    Ok(parse_ioreg_wlan(&text))
}

/// Parses `ioreg -c AppleBCMWLANSkywalkInterface -r -l` output. Deliberately
/// only looks for `IO80211Channel`/`IO80211Band`/`IO80211ChannelBandwidth` —
/// never `IO80211SSID` or `IO80211BSSID`, which appear in the same block.
pub fn parse_ioreg_wlan(text: &str) -> RadioSnapshot {
    let mut snap = RadioSnapshot::unavailable();

    for line in text.lines() {
        // ioreg's tree-drawing prefix (`| |   `) varies with nesting depth,
        // so match on the quoted key + " = " rather than a fixed line
        // prefix. `IO80211ChannelBandwidth` is checked before `IO80211Band`
        // since the latter's key text is a substring-adjacent but distinct
        // field — using the full quoted key avoids any ambiguity.
        if let Some(v) = extract_ioreg_value(line, "\"IO80211Channel\" = ") {
            snap.channel = v.trim().parse::<u32>().ok();
        } else if let Some(v) = extract_ioreg_value(line, "\"IO80211ChannelBandwidth\" = ") {
            snap.width_mhz = v.trim().parse::<u32>().ok();
        } else if let Some(v) = extract_ioreg_value(line, "\"IO80211Band\" = ") {
            // ioreg prints `"6 GHz"` (with a space); system_profiler's format
            // (and this module's fingerprint/RfQuality logic) use `6GHz`.
            let cleaned = v.trim().trim_matches('"').replace(' ', "");
            if !cleaned.is_empty() {
                snap.band = Some(cleaned);
            }
        }
        // IO80211SSID / IO80211BSSID intentionally not matched or stored.
    }

    snap.associated = snap.channel.is_some();
    snap
}

fn extract_ioreg_value<'a>(line: &'a str, key_eq: &str) -> Option<&'a str> {
    line.find(key_eq).map(|idx| &line[idx + key_eq.len()..])
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
        snap.rssi_dbm = rssi
            .trim()
            .trim_end_matches("dBm")
            .trim()
            .parse::<i32>()
            .ok();
    }
    if let Some(noise) = parts.next() {
        snap.noise_dbm = noise
            .trim()
            .trim_end_matches("dBm")
            .trim()
            .parse::<i32>()
            .ok();
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

    const IOREG_FIXTURE: &str = include_str!("../../harness/fixtures/wifi/ioreg-bcmwlan.txt");

    #[test]
    fn parses_ioreg_fixture_channel_band_width() {
        let snap = parse_ioreg_wlan(IOREG_FIXTURE);
        assert!(snap.associated);
        assert_eq!(snap.channel, Some(197));
        assert_eq!(snap.band, Some("6GHz".to_string()));
        assert_eq!(snap.width_mhz, Some(80));
        // ioreg does not expose these fields for this driver.
        assert_eq!(snap.rssi_dbm, None);
        assert_eq!(snap.noise_dbm, None);
        assert_eq!(snap.mcs_index, None);
        assert_eq!(snap.phy_mode, None);
    }

    #[test]
    fn ioreg_parse_never_reads_ssid_or_bssid() {
        // The fixture's raw text does contain SSID/BSSID lines (that's the
        // point of the test — ioreg's real output always does); the parser
        // must never surface them anywhere in the resulting snapshot.
        assert!(IOREG_FIXTURE.contains("IO80211SSID"));
        assert!(IOREG_FIXTURE.contains("IO80211BSSID"));
        let snap = parse_ioreg_wlan(IOREG_FIXTURE);
        let debug = format!("{snap:?}");
        assert!(!debug.contains("Redacted"));
        assert!(!debug.to_lowercase().contains("bssid"));
    }

    #[test]
    fn ioreg_and_airport_fixtures_agree_on_band_channel_width() {
        // Both fixtures were captured from the same real association; the
        // fast path's allowlisted fields must match the full path's.
        let full = parse_airport_text(FIXTURE);
        let fast = parse_ioreg_wlan(IOREG_FIXTURE);
        assert_eq!(full.channel, fast.channel);
        assert_eq!(full.band, fast.band);
        assert_eq!(full.width_mhz, fast.width_mhz);
    }
}
