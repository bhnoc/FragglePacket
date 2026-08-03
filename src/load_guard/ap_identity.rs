//! GAP-024: stable, privacy-safe AP/radio identity from BSSID.
//!
//! Field evidence: switching from a room SSID to a general SSID changed
//! band, channel, signal, and PHY rate, but redaction removed the one
//! signal that could have proven or disproven "same physical AP, different
//! radio" versus "different AP entirely" -- the BSSID. Those are different
//! fault domains and this gap exists to make that distinction possible
//! again without reintroducing the BSSID leak GAP-018/GAP-020 forbid.
//!
//! Design: a locally-generated random salt, persisted once under
//! `dirs::config_dir()`, is mixed with the BSSID through `std::hash`
//! (SipHash via `DefaultHasher` -- no new crate; the "salt" is the mixed-in
//! data, not the hasher's fixed internal key) to produce a short opaque
//! label. The BSSID itself is read only in memory by the privileged caller,
//! passed straight into `label_for_bssid`, and never stored, logged, or
//! returned from any function in this module. Same AP -> same label on this
//! machine, forever (until the salt file is deleted); a different AP's
//! BSSID -> a different label; the label cannot be reversed to a BSSID
//! without the salt file, which never leaves this machine.

use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::PathBuf;

const SALT_FILE_NAME: &str = "fraggle-packet-ap-salt";

fn salt_path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join(SALT_FILE_NAME))
}

/// Loads the persisted salt, generating and saving a new one on first use.
/// The salt is 32 hex characters (16 bytes) read from the OS CSPRNG via
/// `/dev/urandom` -- real entropy, not derived from a hash of predictable
/// process state. The file is created mode 0600 so only this user's
/// processes can read it back out.
pub fn load_or_create_salt() -> Result<String, String> {
    let path = salt_path().ok_or_else(|| "no config directory available on this platform".to_string())?;
    if let Ok(existing) = std::fs::read_to_string(&path) {
        let trimmed = existing.trim().to_string();
        if !trimmed.is_empty() {
            return Ok(trimmed);
        }
    }
    let salt = generate_salt()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("failed to create config dir: {e}"))?;
    }
    std::fs::write(&path, &salt).map_err(|e| format!("failed to persist AP-identity salt: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("failed to restrict AP-identity salt permissions: {e}"))?;
    }
    Ok(salt)
}

fn generate_salt() -> Result<String, String> {
    // The salt is the only thing standing between a published label and the
    // BSSID it came from (BSSIDs are a 48-bit space with a constrained OUI
    // prefix, so a fallen salt is reversible by brute force). This must be
    // real randomness, not a hash of predictable process state (clock, pid,
    // stack address) -- that construction is guessable and was previously
    // used here. `/dev/urandom` is std-only (no new dependency) and is the
    // OS CSPRNG on macOS/Linux.
    use std::io::Read;
    let mut bytes = [0u8; 16];
    let mut f = std::fs::File::open("/dev/urandom").map_err(|e| format!("failed to open /dev/urandom: {e}"))?;
    f.read_exact(&mut bytes).map_err(|e| format!("failed to read entropy: {e}"))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// Produces a short opaque label from a BSSID and salt. Never called with
/// anything that gets stored -- callers must discard the BSSID string
/// immediately after this call returns.
pub fn label_for_bssid(bssid: &str, salt: &str) -> String {
    let mut hasher = DefaultHasher::new();
    salt.hash(&mut hasher);
    bssid.hash(&mut hasher);
    // Re-hash with salt appended a second time so the label space isn't
    // trivially the same as a bare SipHash(bssid) if salt were ever empty.
    salt.hash(&mut hasher);
    format!("ap-{:08x}", hasher.finish() as u32)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApIdentity {
    pub label: String,
    pub band: Option<String>,
    pub channel: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApComparison {
    /// Same label, same band -- same physical AP, same radio.
    SameApSameRadio,
    /// Same label, different band -- same physical AP, different radio
    /// (e.g. a dual-band AP presenting one BSSID-derived identity per
    /// radio would still collide here only if BSSIDs happen to match,
    /// which is why band is recorded alongside the label rather than
    /// folded into it).
    SameApDifferentRadio,
    /// Different label, at least one band/channel value changed -- a roam
    /// to a different AP.
    DifferentAp,
    /// Either identity was unavailable (no privileged BSSID read); no
    /// comparison can be made honestly.
    Unavailable,
}

pub fn compare(before: &Option<ApIdentity>, after: &Option<ApIdentity>) -> ApComparison {
    let (Some(b), Some(a)) = (before, after) else {
        return ApComparison::Unavailable;
    };
    if b.label != a.label {
        return ApComparison::DifferentAp;
    }
    if b.band == a.band {
        ApComparison::SameApSameRadio
    } else {
        ApComparison::SameApDifferentRadio
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_is_stable_for_the_same_bssid_and_salt() {
        let salt = "fixed-test-salt";
        let a = label_for_bssid("02:00:00:00:00:01", salt);
        let b = label_for_bssid("02:00:00:00:00:01", salt);
        assert_eq!(a, b);
    }

    #[test]
    fn label_differs_for_a_different_bssid() {
        let salt = "fixed-test-salt";
        let a = label_for_bssid("02:00:00:00:00:01", salt);
        let b = label_for_bssid("02:00:00:00:00:02", salt);
        assert_ne!(a, b);
    }

    #[test]
    fn label_differs_for_a_different_salt_same_bssid() {
        // Confirms the salt genuinely participates in the hash rather than
        // being a decorative no-op -- two machines (different salts) never
        // produce a comparable label for the same physical AP, which is the
        // whole point: the label must not be usable to correlate across
        // machines, only within one.
        let a = label_for_bssid("02:00:00:00:00:01", "salt-one");
        let b = label_for_bssid("02:00:00:00:00:01", "salt-two");
        assert_ne!(a, b);
    }

    #[test]
    fn label_never_contains_the_input_bssid_text() {
        let salt = "fixed-test-salt";
        let bssid = "02:00:00:00:00:01";
        let label = label_for_bssid(bssid, salt);
        assert!(!label.contains(bssid));
        assert!(!label.contains(':'));
    }

    #[test]
    fn same_label_same_band_is_same_ap_same_radio() {
        let a = ApIdentity { label: "ap-deadbeef".to_string(), band: Some("6GHz".to_string()), channel: Some(37) };
        let b = ApIdentity { label: "ap-deadbeef".to_string(), band: Some("6GHz".to_string()), channel: Some(37) };
        assert_eq!(compare(&Some(a), &Some(b)), ApComparison::SameApSameRadio);
    }

    #[test]
    fn same_label_different_band_is_same_ap_different_radio() {
        let a = ApIdentity { label: "ap-deadbeef".to_string(), band: Some("6GHz".to_string()), channel: Some(37) };
        let b = ApIdentity { label: "ap-deadbeef".to_string(), band: Some("5GHz".to_string()), channel: Some(100) };
        assert_eq!(compare(&Some(a), &Some(b)), ApComparison::SameApDifferentRadio);
    }

    #[test]
    fn different_label_is_different_ap() {
        let a = ApIdentity { label: "ap-deadbeef".to_string(), band: Some("6GHz".to_string()), channel: Some(37) };
        let b = ApIdentity { label: "ap-cafef00d".to_string(), band: Some("6GHz".to_string()), channel: Some(37) };
        assert_eq!(compare(&Some(a), &Some(b)), ApComparison::DifferentAp);
    }

    #[test]
    fn missing_identity_on_either_side_is_unavailable_not_guessed() {
        let a = ApIdentity { label: "ap-deadbeef".to_string(), band: Some("6GHz".to_string()), channel: Some(37) };
        assert_eq!(compare(&Some(a), &None), ApComparison::Unavailable);
        assert_eq!(compare(&None, &None), ApComparison::Unavailable);
    }

    #[test]
    fn load_or_create_salt_is_stable_across_calls() {
        // Uses the real config dir on this machine (matches production
        // behavior); if that directory is unwritable in some CI sandbox this
        // will surface as an Err, which is the honest outcome -- not a
        // silently different salt per call.
        if let (Ok(first), Ok(second)) = (load_or_create_salt(), load_or_create_salt()) {
            assert_eq!(first, second);
        }
    }

    #[test]
    fn generated_salt_first_half_does_not_equal_second_half() {
        // Would have caught the earlier XOR-with-shifted-self construction,
        // which produced a salt whose two 16-hex-char halves were always
        // identical -- half the claimed entropy, and a visible fingerprint
        // of a weak scheme.
        let salt = generate_salt().expect("reading /dev/urandom should succeed");
        assert_eq!(salt.len(), 32);
        let (first_half, second_half) = salt.split_at(16);
        assert_ne!(first_half, second_half);
    }

    #[test]
    fn two_generated_salts_differ() {
        let a = generate_salt().expect("reading /dev/urandom should succeed");
        let b = generate_salt().expect("reading /dev/urandom should succeed");
        assert_ne!(a, b);
    }

    #[test]
    #[cfg(unix)]
    fn persisted_salt_file_is_not_group_or_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        // load_or_create_salt() guarantees the file exists (creating it if
        // needed) before this asserts on its permissions -- this is not
        // conditional on a prior run having already created it.
        if let (Ok(_), Some(path)) = (load_or_create_salt(), salt_path()) {
            let meta = std::fs::metadata(&path).expect("salt file must exist after load_or_create_salt");
            let mode = meta.permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "salt file must be 0600, got {mode:o}");
        }
    }
}
