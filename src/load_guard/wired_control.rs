//! GAP-030: matched wired-versus-Wi-Fi fault-domain control.
//!
//! Field evidence: wired was lossless at 350 Mbps each way while matched
//! Wi-Fi lost 8.3-30.1% downstream on every bucket -- but the two paths
//! used *different public egress IPs*, which only localizes the fault to
//! "WLAN/controller path OR VLAN-specific NAT/egress", not cleanly to the
//! WLAN. `attribute` refuses a WLAN-specific conclusion whenever the
//! supplied egress identities differ, mirroring the refusal pattern in
//! `circuit_workflow::CircuitVerdict::Refused` (GAP-029, this repo, another
//! agent's file -- read, not edited).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathResult {
    pub label: &'static str,
    pub achieved_mbps: Option<f64>,
    pub loss_pct: Option<f64>,
    /// e.g. a STUN mapped address or salted equivalent -- whatever the
    /// caller used to observe public egress identity for this path. `None`
    /// when it was never sampled, distinct from a value that happened to
    /// match.
    pub egress_identity: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum FaultAttribution {
    Wlan {
        detail: String,
    },
    SharedEdgeOrWan {
        detail: String,
    },
    /// The matched control does not support attribution. Names the reason
    /// explicitly rather than defaulting to the WLAN explanation, which
    /// field evidence shows is often the wrong one to assume.
    Withheld {
        reason: String,
    },
}

const LOSS_MATERIAL_THRESHOLD_PCT: f64 = 1.0;

/// Compares a wired control run against a matched Wi-Fi run and attributes
/// a difference only when the control genuinely supports it: both sides
/// must have measured loss, and (the sharp clause) their egress identities
/// must match -- otherwise a WLAN-specific finding cannot be distinguished
/// from a VLAN-specific NAT/egress difference.
pub fn attribute(wired: &PathResult, wifi: &PathResult) -> FaultAttribution {
    let (Some(wired_loss), Some(wifi_loss)) = (wired.loss_pct, wifi.loss_pct) else {
        return FaultAttribution::Withheld {
            reason: "loss_pct missing on at least one path; the matched control needs both sides measured".to_string(),
        };
    };

    match (&wired.egress_identity, &wifi.egress_identity) {
        (Some(w), Some(f)) if w != f => {
            return FaultAttribution::Withheld {
                reason: format!(
                    "wired and Wi-Fi used different public egress identities ({w} vs {f}); this control localizes to WLAN/controller path OR VLAN-specific NAT/egress, not cleanly to the WLAN"
                ),
            };
        }
        (None, _) | (_, None) => {
            return FaultAttribution::Withheld {
                reason: "egress identity was not sampled on at least one path; a WLAN-specific attribution cannot rule out a NAT/egress difference".to_string(),
            };
        }
        _ => {}
    }

    let delta = wifi_loss - wired_loss;
    if wired_loss <= LOSS_MATERIAL_THRESHOLD_PCT && delta >= LOSS_MATERIAL_THRESHOLD_PCT {
        FaultAttribution::Wlan {
            detail: format!(
                "wired control was clean (loss={wired_loss:.2}%) while matched Wi-Fi lost {wifi_loss:.2}% under the same egress identity; the difference localizes to the WLAN"
            ),
        }
    } else {
        FaultAttribution::SharedEdgeOrWan {
            detail: format!(
                "wired control also showed material loss (loss={wired_loss:.2}%), so the shared edge/WAN cannot be ruled out as the cause of the Wi-Fi loss ({wifi_loss:.2}%)"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(
        label: &'static str,
        mbps: Option<f64>,
        loss: Option<f64>,
        egress: Option<&str>,
    ) -> PathResult {
        PathResult {
            label,
            achieved_mbps: mbps,
            loss_pct: loss,
            egress_identity: egress.map(str::to_string),
        }
    }

    #[test]
    fn attribution_is_withheld_when_egress_identities_differ() {
        // Reproduces the exact field-evidence shape: wired clean, wifi
        // lossy, but different public IPs -- must not conclude WLAN.
        let wired = path("wired", Some(350.0), Some(0.0), Some("203.0.113.5"));
        let wifi = path("wifi", Some(300.0), Some(20.0), Some("198.51.100.9"));
        match attribute(&wired, &wifi) {
            FaultAttribution::Withheld { reason } => {
                assert!(reason.contains("different public egress identities"))
            }
            other => panic!("expected Withheld, got {other:?}"),
        }
    }

    #[test]
    fn attribution_names_wlan_when_control_is_clean_and_egress_matches() {
        let wired = path("wired", Some(350.0), Some(0.0), Some("203.0.113.5"));
        let wifi = path("wifi", Some(300.0), Some(20.0), Some("203.0.113.5"));
        match attribute(&wired, &wifi) {
            FaultAttribution::Wlan { .. } => {}
            other => panic!("expected Wlan, got {other:?}"),
        }
    }

    #[test]
    fn attribution_is_shared_when_the_wired_control_itself_shows_loss() {
        let wired = path("wired", Some(350.0), Some(5.0), Some("203.0.113.5"));
        let wifi = path("wifi", Some(300.0), Some(20.0), Some("203.0.113.5"));
        match attribute(&wired, &wifi) {
            FaultAttribution::SharedEdgeOrWan { .. } => {}
            other => panic!("expected SharedEdgeOrWan, got {other:?}"),
        }
    }

    #[test]
    fn attribution_is_withheld_when_loss_is_missing_on_either_side() {
        let wired = path("wired", Some(350.0), None, Some("203.0.113.5"));
        let wifi = path("wifi", Some(300.0), Some(20.0), Some("203.0.113.5"));
        match attribute(&wired, &wifi) {
            FaultAttribution::Withheld { reason } => assert!(reason.contains("loss_pct missing")),
            other => panic!("expected Withheld, got {other:?}"),
        }
    }

    #[test]
    fn attribution_is_withheld_when_egress_identity_was_never_sampled() {
        let wired = path("wired", Some(350.0), Some(0.0), None);
        let wifi = path("wifi", Some(300.0), Some(20.0), Some("203.0.113.5"));
        match attribute(&wired, &wifi) {
            FaultAttribution::Withheld { reason } => assert!(reason.contains("not sampled")),
            other => panic!("expected Withheld, got {other:?}"),
        }
    }
}
