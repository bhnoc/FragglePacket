//! GAP-058: wired edge, AP uplink, LLDP, and PoE health bundle.
//!
//! A client cannot read a switch/AP's own counters, PoE draw, or LLDP
//! identity -- this is pure ingest, structurally identical to
//! `nat_capacity::FirewallTelemetry` and `circuit_workflow::MemberTelemetry`
//! (other agent's files, read for the pattern, not edited): every field is
//! `Option` and a conclusion is refused, naming what's missing, rather than
//! inferred from whatever happened to arrive.
//!
//! PoE is the field-flagged risk, not a checkbox: `PoeClass` distinguishes
//! `PoePlus` (802.3at, ~25.5W) from `PoePlusPlus` (802.3bt, full budget).
//! `arista-ops` documents that a C-460 AP on PoE+ instead of PoE++ enters a
//! reduced-functionality mode -- fewer spatial streams, lower TX power, or a
//! throttled radio, depending on firmware -- which could itself explain a
//! throughput symptom being investigated as a WLAN fault. `reduced_power`
//! is carried as its own field (not inferred from `PoeClass` alone) because
//! the AP's actual negotiated state, not just its wiring class, is the
//! fact that matters.
//!
//! Never modifies switch or AP configuration -- there is no code path here
//! that writes anything back to managed infrastructure, matching the
//! GAP-029/038/054 read-only discipline this sprint reuses everywhere.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PoeClass {
    /// 802.3af, ~12.95W delivered.
    Poe,
    /// 802.3at, ~25.5W delivered.
    PoePlus,
    /// 802.3bt, up to ~90-100W delivered depending on type.
    PoePlusPlus,
    NotPoweredByPoe,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LinkDuplex {
    Full,
    Half,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LacpMemberState {
    Active,
    Standby,
    Down,
}

/// One wired-edge port/AP-uplink snapshot. Every field optional -- absence
/// means "not retrieved from this telemetry source", never zero.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WiredEdgeSnapshot {
    /// Hashed chassis/AP identity -- never a raw switch/AP name or MAC.
    /// Callers hash upstream the same way `ap_identity::label_for_bssid`
    /// does; this module never receives the raw identifier at all.
    pub hashed_chassis_label: Option<String>,
    pub switch_port_id: Option<String>,
    pub lldp_identity_verified: Option<bool>,
    pub poe_class: Option<PoeClass>,
    pub poe_requested_watts: Option<f64>,
    pub poe_negotiated_watts: Option<f64>,
    /// The AP's own reported reduced-functionality state, distinct from
    /// `poe_class` -- a class alone does not prove the AP actually entered
    /// reduced mode on this link.
    pub reduced_power_state: Option<bool>,
    pub link_speed_mbps: Option<u64>,
    pub link_duplex: Option<LinkDuplex>,
    pub lacp_member_state: Option<LacpMemberState>,
    pub vlan_id: Option<u16>,
    pub native_vlan_tag_consistent: Option<bool>,
    pub crc_errors: Option<u64>,
    pub input_discards: Option<u64>,
    pub output_discards: Option<u64>,
    pub pause_frames_rx: Option<u64>,
    pub pause_frames_tx: Option<u64>,
    pub queue_drops: Option<u64>,
    pub link_flap_count: Option<u32>,
}

impl WiredEdgeSnapshot {
    /// Names the fields a wired-edge conclusion needs but does not have.
    /// Mirrors `MemberTelemetry::missing_fields` (`circuit_workflow.rs`,
    /// another agent's file) exactly in shape, not shared code, because
    /// the two structs' required-field sets differ and a shared list would
    /// either over- or under-constrain one of them.
    pub fn missing_fields(&self) -> Vec<&'static str> {
        let mut m = Vec::new();
        if self.hashed_chassis_label.is_none() {
            m.push("hashed_chassis_label");
        }
        if self.poe_class.is_none() {
            m.push("poe_class");
        }
        if self.poe_negotiated_watts.is_none() {
            m.push("poe_negotiated_watts");
        }
        if self.reduced_power_state.is_none() {
            m.push("reduced_power_state");
        }
        if self.link_speed_mbps.is_none() {
            m.push("link_speed_mbps");
        }
        if self.link_duplex.is_none() {
            m.push("link_duplex");
        }
        if self.crc_errors.is_none() {
            m.push("crc_errors");
        }
        if self.input_discards.is_none() {
            m.push("input_discards");
        }
        if self.output_discards.is_none() {
            m.push("output_discards");
        }
        if self.queue_drops.is_none() {
            m.push("queue_drops");
        }
        if self.link_flap_count.is_none() {
            m.push("link_flap_count");
        }
        m
    }
}

/// A before/after pair bracketing the client test timeline -- the
/// acceptance criteria's "bracket counters around the client test
/// timeline" clause. Deltas are computed only from present values; any
/// counter absent on either side withholds that specific delta rather than
/// treating it as zero.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WiredEdgeBracket {
    pub before: WiredEdgeSnapshot,
    pub after: WiredEdgeSnapshot,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CounterDelta {
    pub crc_errors: Option<u64>,
    pub input_discards: Option<u64>,
    pub output_discards: Option<u64>,
    pub pause_frames_rx: Option<u64>,
    pub pause_frames_tx: Option<u64>,
    pub queue_drops: Option<u64>,
    pub link_flap_count: Option<u32>,
}

fn delta_u64(before: Option<u64>, after: Option<u64>) -> Option<u64> {
    match (before, after) {
        (Some(b), Some(a)) if a >= b => Some(a - b),
        // A backwards counter is a reset/wrap, not real evidence of zero
        // traffic -- withheld rather than reported as a negative or as 0,
        // the same discipline `InterfaceCounters::usable_delta_from` uses
        // (`load_guard/counters.rs`).
        _ => None,
    }
}

fn delta_u32(before: Option<u32>, after: Option<u32>) -> Option<u32> {
    match (before, after) {
        (Some(b), Some(a)) if a >= b => Some(a - b),
        _ => None,
    }
}

pub fn compute_delta(bracket: &WiredEdgeBracket) -> CounterDelta {
    CounterDelta {
        crc_errors: delta_u64(bracket.before.crc_errors, bracket.after.crc_errors),
        input_discards: delta_u64(bracket.before.input_discards, bracket.after.input_discards),
        output_discards: delta_u64(bracket.before.output_discards, bracket.after.output_discards),
        pause_frames_rx: delta_u64(bracket.before.pause_frames_rx, bracket.after.pause_frames_rx),
        pause_frames_tx: delta_u64(bracket.before.pause_frames_tx, bracket.after.pause_frames_tx),
        queue_drops: delta_u64(bracket.before.queue_drops, bracket.after.queue_drops),
        link_flap_count: delta_u32(bracket.before.link_flap_count, bracket.after.link_flap_count),
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PoeRiskVerdict {
    /// Negotiated power is below what the AP requested AND the AP itself
    /// reports reduced-power state -- the field-flagged risk this module
    /// exists to catch, named explicitly rather than left as two
    /// unconnected numbers the operator has to notice themselves.
    ReducedFunctionalityFromPoe { requested_watts: f64, negotiated_watts: f64 },
    FullPowerNegotiated,
    /// The evidence needed to rule PoE in or out is absent.
    Withheld { missing: Vec<String> },
}

pub fn assess_poe_risk(snapshot: &WiredEdgeSnapshot) -> PoeRiskVerdict {
    let missing = snapshot.missing_fields();
    let required_present = snapshot.poe_requested_watts.is_some()
        && snapshot.poe_negotiated_watts.is_some()
        && snapshot.reduced_power_state.is_some();
    if !required_present {
        let mut m: Vec<&'static str> = vec![];
        if snapshot.poe_requested_watts.is_none() {
            m.push("poe_requested_watts");
        }
        if snapshot.poe_negotiated_watts.is_none() {
            m.push("poe_negotiated_watts");
        }
        if snapshot.reduced_power_state.is_none() {
            m.push("reduced_power_state");
        }
        let chosen: Vec<&'static str> = if m.is_empty() { missing } else { m };
        return PoeRiskVerdict::Withheld { missing: chosen.into_iter().map(str::to_string).collect() };
    }
    let requested = snapshot.poe_requested_watts.unwrap();
    let negotiated = snapshot.poe_negotiated_watts.unwrap();
    let reduced = snapshot.reduced_power_state.unwrap();
    if reduced && negotiated < requested {
        PoeRiskVerdict::ReducedFunctionalityFromPoe { requested_watts: requested, negotiated_watts: negotiated }
    } else {
        PoeRiskVerdict::FullPowerNegotiated
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum WiredEdgeVerdict {
    Healthy,
    Degraded { detail: String },
    /// The bundle refuses a conclusion when required telemetry is absent --
    /// mirrors `CircuitVerdict::Refused` (`circuit_workflow.rs`).
    Refused { missing: Vec<String> },
}

/// Judges a bracketed wired-edge snapshot. Refuses when required fields are
/// missing on either side; otherwise reports degradation only from counters
/// that actually moved, never from a delta that was withheld.
pub fn judge_wired_edge(bracket: &WiredEdgeBracket) -> WiredEdgeVerdict {
    let mut missing: Vec<String> = Vec::new();
    for (label, snap) in [("before", &bracket.before), ("after", &bracket.after)] {
        for f in snap.missing_fields() {
            missing.push(format!("{label}:{f}"));
        }
    }
    if !missing.is_empty() {
        return WiredEdgeVerdict::Refused { missing };
    }

    let delta = compute_delta(bracket);
    let mut problems = Vec::new();
    if let Some(crc) = delta.crc_errors {
        if crc > 0 {
            problems.push(format!("{crc} new CRC errors"));
        }
    }
    if let Some(d) = delta.input_discards {
        if d > 0 {
            problems.push(format!("{d} new input discards"));
        }
    }
    if let Some(d) = delta.output_discards {
        if d > 0 {
            problems.push(format!("{d} new output discards"));
        }
    }
    if let Some(d) = delta.queue_drops {
        if d > 0 {
            problems.push(format!("{d} new queue drops"));
        }
    }
    if let Some(f) = delta.link_flap_count {
        if f > 0 {
            problems.push(format!("{f} link flap(s)"));
        }
    }
    if let PoeRiskVerdict::ReducedFunctionalityFromPoe { requested_watts, negotiated_watts } = assess_poe_risk(&bracket.after) {
        problems.push(format!(
            "AP negotiated only {negotiated_watts:.1}W of {requested_watts:.1}W requested and reports reduced-power state"
        ));
    }

    if problems.is_empty() {
        WiredEdgeVerdict::Healthy
    } else {
        WiredEdgeVerdict::Degraded { detail: problems.join("; ") }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_snapshot() -> WiredEdgeSnapshot {
        WiredEdgeSnapshot {
            hashed_chassis_label: Some("AP-8b464c93".to_string()),
            switch_port_id: Some("Ethernet46".to_string()),
            lldp_identity_verified: Some(true),
            poe_class: Some(PoeClass::PoePlus),
            poe_requested_watts: Some(40.0),
            poe_negotiated_watts: Some(40.0),
            reduced_power_state: Some(false),
            link_speed_mbps: Some(5000),
            link_duplex: Some(LinkDuplex::Full),
            lacp_member_state: None,
            vlan_id: Some(100),
            native_vlan_tag_consistent: Some(true),
            crc_errors: Some(0),
            input_discards: Some(0),
            output_discards: Some(0),
            pause_frames_rx: Some(0),
            pause_frames_tx: Some(0),
            queue_drops: Some(0),
            link_flap_count: Some(0),
        }
    }

    #[test]
    fn a_missing_snapshot_field_refuses_and_names_it() {
        let mut before = full_snapshot();
        before.crc_errors = None;
        let bracket = WiredEdgeBracket { before, after: full_snapshot() };
        match judge_wired_edge(&bracket) {
            WiredEdgeVerdict::Refused { missing } => {
                assert!(missing.iter().any(|m| m == "before:crc_errors"));
            }
            other => panic!("expected Refused, got {other:?}"),
        }
    }

    #[test]
    fn no_movement_is_healthy() {
        let bracket = WiredEdgeBracket { before: full_snapshot(), after: full_snapshot() };
        assert_eq!(judge_wired_edge(&bracket), WiredEdgeVerdict::Healthy);
    }

    #[test]
    fn new_crc_errors_are_reported_as_degraded() {
        let mut after = full_snapshot();
        after.crc_errors = Some(12);
        let bracket = WiredEdgeBracket { before: full_snapshot(), after };
        match judge_wired_edge(&bracket) {
            WiredEdgeVerdict::Degraded { detail } => assert!(detail.contains("12 new CRC errors")),
            other => panic!("expected Degraded, got {other:?}"),
        }
    }

    #[test]
    fn a_backwards_counter_never_reports_a_fabricated_delta() {
        // Reset/wrap, not real evidence -- must withhold, not report a
        // negative delta or coerce to 0.
        let mut before = full_snapshot();
        before.crc_errors = Some(500);
        let mut after = full_snapshot();
        after.crc_errors = Some(3);
        let bracket = WiredEdgeBracket { before, after };
        let delta = compute_delta(&bracket);
        assert_eq!(delta.crc_errors, None);
    }

    #[test]
    fn reduced_power_state_with_a_wattage_shortfall_is_flagged_as_a_risk() {
        // This is the field-flagged case: PoE+ (25.5W) instead of PoE++ on
        // a C-460 that requested 40W and itself reports reduced-power.
        let mut snap = full_snapshot();
        snap.poe_requested_watts = Some(40.0);
        snap.poe_negotiated_watts = Some(25.5);
        snap.reduced_power_state = Some(true);
        match assess_poe_risk(&snap) {
            PoeRiskVerdict::ReducedFunctionalityFromPoe { requested_watts, negotiated_watts } => {
                assert_eq!(requested_watts, 40.0);
                assert_eq!(negotiated_watts, 25.5);
            }
            other => panic!("expected ReducedFunctionalityFromPoe, got {other:?}"),
        }
    }

    #[test]
    fn full_power_is_not_flagged_as_a_risk() {
        assert_eq!(assess_poe_risk(&full_snapshot()), PoeRiskVerdict::FullPowerNegotiated);
    }

    #[test]
    fn missing_poe_fields_withhold_the_risk_verdict_rather_than_assuming_full_power() {
        let mut snap = full_snapshot();
        snap.reduced_power_state = None;
        match assess_poe_risk(&snap) {
            PoeRiskVerdict::Withheld { missing } => assert!(missing.iter().any(|m| m == "reduced_power_state")),
            other => panic!("expected Withheld, got {other:?}"),
        }
    }

    #[test]
    fn a_reduced_power_ap_surfaces_in_the_overall_wired_edge_verdict() {
        let mut after = full_snapshot();
        after.poe_negotiated_watts = Some(25.5);
        after.reduced_power_state = Some(true);
        let bracket = WiredEdgeBracket { before: full_snapshot(), after };
        match judge_wired_edge(&bracket) {
            WiredEdgeVerdict::Degraded { detail } => assert!(detail.contains("reduced-power")),
            other => panic!("expected Degraded, got {other:?}"),
        }
    }

    #[test]
    fn an_empty_bundle_never_reports_zero_watts_as_a_measurement() {
        // "a PoE draw of 0W from a switch that never answered" -- the
        // exact false-zero shape the assignment calls out.
        let snap = WiredEdgeSnapshot::default();
        assert_eq!(snap.poe_negotiated_watts, None);
        match assess_poe_risk(&snap) {
            PoeRiskVerdict::Withheld { .. } => {}
            other => panic!("expected Withheld, got {other:?}"),
        }
    }
}
