//! GAP-023: ECN/AQM protocol A/B control.
//!
//! Field evidence, explicitly a correlation and not yet causation: in the
//! same-room control, HTTP/3 reported Accurate ECN with L4S disabled while
//! HTTP/2 on the same radio reported ECN disabled; H3 kept full upload but
//! lost ~85% of directional download under simultaneous load. The external
//! MGM control reported ECN unavailable for H3 and the collapse did not
//! reproduce there. The Black Hat capture held 514,587 outbound and 26,017
//! inbound UDP/443 packets marked ECT(0), six outbound ECT(1), and ZERO
//! CE-marked packets: ECN capability was present with no observed
//! congestion marking. That is the crux this module exists to state
//! plainly: capability present, marking absent, therefore CE handling is
//! not implicated by this evidence -- dropping, policing, or directional
//! scheduling remain more likely. A negative finding stated positively,
//! not silence.
//!
//! ECT(0) vs ECT(1) vs CE is read from the two low bits of the IP
//! TOS/traffic-class byte (`libc::IPTOS_ECN_*`). ECT(1) is the L4S marking;
//! ECT(0) is classic ECN. Distinguishing them is the whole ask of "classic
//! ECN vs L4S" in the acceptance criteria -- this module counts the three
//! non-zero codepoints separately rather than folding them into one
//! "ECN seen" boolean.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EcnCodepoint {
    NotEct,
    Ect1,
    Ect0,
    Ce,
}

impl EcnCodepoint {
    pub fn from_tos_byte(tos: u8) -> Self {
        match tos & 0x03 {
            0x00 => EcnCodepoint::NotEct,
            0x01 => EcnCodepoint::Ect1,
            0x02 => EcnCodepoint::Ect0,
            0x03 => EcnCodepoint::Ce,
            _ => unreachable!("mask 0x03 only yields 0..=3"),
        }
    }

    /// L4S (RFC 9331) uses ECT(1); classic ECN (RFC 3168) uses ECT(0). CE
    /// can appear under either scheme once actually congestion-marked, so
    /// it alone cannot say which -- see `EcnCounts::scheme()`.
    pub fn is_l4s_marking(&self) -> bool {
        matches!(self, EcnCodepoint::Ect1)
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct EcnCounts {
    pub not_ect: u64,
    pub ect1: u64,
    pub ect0: u64,
    pub ce: u64,
}

impl EcnCounts {
    pub fn total(&self) -> u64 {
        self.not_ect + self.ect1 + self.ect0 + self.ce
    }

    pub fn record(&mut self, cp: EcnCodepoint) {
        match cp {
            EcnCodepoint::NotEct => self.not_ect += 1,
            EcnCodepoint::Ect1 => self.ect1 += 1,
            EcnCodepoint::Ect0 => self.ect0 += 1,
            EcnCodepoint::Ce => self.ce += 1,
        }
    }

    /// ECN capability requires at least one ECT(0) or ECT(1) marking
    /// observed -- NotEct-only traffic never negotiated/used ECN at all.
    pub fn ecn_capable_observed(&self) -> bool {
        self.ect0 > 0 || self.ect1 > 0
    }

    /// Classifies which ECN scheme the ECT markings indicate. `Mixed` is a
    /// real, reportable state (both ECT(0) and ECT(1) seen in the same
    /// sample) -- not an error to collapse into one bucket.
    pub fn scheme(&self) -> EcnScheme {
        match (self.ect0 > 0, self.ect1 > 0) {
            (true, true) => EcnScheme::Mixed,
            (true, false) => EcnScheme::Classic,
            (false, true) => EcnScheme::L4s,
            (false, false) => EcnScheme::NoneObserved,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EcnScheme {
    Classic,
    L4s,
    Mixed,
    NoneObserved,
}

/// The specific GAP-023 finding: ECN capability was observed (ECT marks
/// present) but no CE mark was ever seen. This is deliberately a distinct,
/// positive statement -- "CE handling is not implicated by this evidence" --
/// rather than an absence that could be misread as "we don't know" or
/// silently omitted from a report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityWithoutMarkingFinding {
    pub ecn_capable: bool,
    pub ce_marks_observed: u64,
    pub statement: String,
}

pub fn evaluate_capability_without_marking(counts: &EcnCounts) -> CapabilityWithoutMarkingFinding {
    let ecn_capable = counts.ecn_capable_observed();
    let statement = if ecn_capable && counts.ce == 0 {
        format!(
            "ECN capability observed ({} ECT-marked packet(s) of {} total) with zero CE marks -- \
             congestion-mark (CE) handling is NOT implicated by this evidence; a drop, policer, or \
             directional scheduling policy remains a more likely explanation for any observed loss/asymmetry",
            counts.ect0 + counts.ect1,
            counts.total()
        )
    } else if ecn_capable {
        format!("ECN capability observed with {} CE mark(s) present -- congestion marking did occur", counts.ce)
    } else {
        "no ECN capability observed (no ECT-marked packets); ECN negotiation state on this path is unknown from packet marks alone".to_string()
    };
    CapabilityWithoutMarkingFinding { ecn_capable, ce_marks_observed: counts.ce, statement }
}

/// Whether this process could actually set the ECN codepoint bits on an
/// outgoing socket, and what happened when it tried. Distinguishes a real
/// platform refusal from a silent no-op -- macOS/BSD sockets do not always
/// permit userspace ECN bit manipulation via a documented sockopt the way
/// Linux's `IP_TOS`/`IPV6_TCLASS` does.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcnSetAttempt {
    pub requested: EcnCodepoint,
    pub applied: bool,
    pub detail: String,
}

/// One side (direction) of a queue-delay correlation sample: a burst's
/// observed CE-mark rate alongside the delay measurement that direction
/// carried at the same time. Reuses the burst-structure discipline from
/// GAP-066/GAP-052: a delay figure with no valid burst context is `None`,
/// never a fabricated zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    Upload,
    Download,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueDelayCeSample {
    pub direction: Direction,
    pub ce_marks: u64,
    pub total_packets: u64,
    pub mean_queue_delay_ms: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueDelayCorrelation {
    pub direction: Direction,
    pub ce_rate_pct: f64,
    pub mean_queue_delay_ms: Option<f64>,
    /// True only when both a non-zero CE rate AND a delay measurement are
    /// present for this direction -- a correlation claim needs both sides
    /// of the pair, not just one.
    pub correlated: bool,
}

pub fn correlate_ce_with_queue_delay(samples: &[QueueDelayCeSample]) -> Vec<QueueDelayCorrelation> {
    samples
        .iter()
        .map(|s| {
            let ce_rate_pct = if s.total_packets == 0 { 0.0 } else { (s.ce_marks as f64 / s.total_packets as f64) * 100.0 };
            let correlated = s.ce_marks > 0 && s.mean_queue_delay_ms.is_some();
            QueueDelayCorrelation { direction: s.direction, ce_rate_pct, mean_queue_delay_ms: s.mean_queue_delay_ms, correlated }
        })
        .collect()
}

/// Whether the interface a measurement ran over is a tunnel. A tunnel
/// strips or rewrites ECN bits on many implementations, so ECN results
/// gathered through one are not meaningful path evidence -- this is a
/// caller-supplied fact (from `load_guard::route`, which this module does
/// not import to stay out of the off-limits `src/load_guard/` tree) rather
/// than something this module detects itself.
pub fn tunnel_warning(interface_is_tunnel: bool, interface: &str) -> Option<String> {
    if interface_is_tunnel {
        Some(format!(
            "interface '{}' is a tunnel; tunnels commonly strip or rewrite ECN bits, so ECN/CE results measured through it are not meaningful path evidence",
            interface
        ))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ect0_and_ect1_and_ce_are_counted_separately() {
        let mut counts = EcnCounts::default();
        for _ in 0..514_587 {
            counts.record(EcnCodepoint::Ect0);
        }
        for _ in 0..6 {
            counts.record(EcnCodepoint::Ect1);
        }
        assert_eq!(counts.ect0, 514_587);
        assert_eq!(counts.ect1, 6);
        assert_eq!(counts.ce, 0);
    }

    #[test]
    fn l4s_distinguished_from_classic_ecn_by_ect1_vs_ect0() {
        let mut classic = EcnCounts::default();
        classic.record(EcnCodepoint::Ect0);
        assert_eq!(classic.scheme(), EcnScheme::Classic);

        let mut l4s = EcnCounts::default();
        l4s.record(EcnCodepoint::Ect1);
        assert_eq!(l4s.scheme(), EcnScheme::L4s);

        let mut mixed = EcnCounts::default();
        mixed.record(EcnCodepoint::Ect0);
        mixed.record(EcnCodepoint::Ect1);
        assert_eq!(mixed.scheme(), EcnScheme::Mixed);
    }

    #[test]
    fn field_evidence_capability_present_marking_absent_is_stated_positively() {
        // The exact Black Hat capture counts from the field evidence.
        let mut counts = EcnCounts::default();
        for _ in 0..514_587 {
            counts.record(EcnCodepoint::Ect0);
        }
        for _ in 0..26_017 {
            counts.record(EcnCodepoint::Ect0);
        }
        for _ in 0..6 {
            counts.record(EcnCodepoint::Ect1);
        }
        // no CE recorded at all.

        let finding = evaluate_capability_without_marking(&counts);
        assert!(finding.ecn_capable);
        assert_eq!(finding.ce_marks_observed, 0);
        assert!(finding.statement.contains("NOT implicated"));
        assert!(!finding.statement.to_lowercase().contains("unknown"));
    }

    #[test]
    fn ce_marks_present_yields_a_different_statement() {
        let mut counts = EcnCounts::default();
        counts.record(EcnCodepoint::Ect0);
        counts.record(EcnCodepoint::Ce);
        let finding = evaluate_capability_without_marking(&counts);
        assert!(finding.ecn_capable);
        assert_eq!(finding.ce_marks_observed, 1);
        assert!(finding.statement.contains("did occur"));
    }

    #[test]
    fn no_ecn_capability_observed_is_a_third_distinct_state() {
        let mut counts = EcnCounts::default();
        counts.record(EcnCodepoint::NotEct);
        let finding = evaluate_capability_without_marking(&counts);
        assert!(!finding.ecn_capable);
        assert!(finding.statement.to_lowercase().contains("unknown"));
    }

    #[test]
    fn correlation_requires_both_a_nonzero_ce_rate_and_a_delay_measurement() {
        let samples = vec![
            QueueDelayCeSample { direction: Direction::Download, ce_marks: 5, total_packets: 100, mean_queue_delay_ms: Some(40.0) },
            QueueDelayCeSample { direction: Direction::Upload, ce_marks: 0, total_packets: 100, mean_queue_delay_ms: Some(5.0) },
            QueueDelayCeSample { direction: Direction::Download, ce_marks: 3, total_packets: 50, mean_queue_delay_ms: None },
        ];
        let correlations = correlate_ce_with_queue_delay(&samples);
        assert!(correlations[0].correlated);
        assert!(!correlations[1].correlated, "zero CE marks must not be reported as correlated");
        assert!(!correlations[2].correlated, "missing delay measurement must not be reported as correlated");
    }

    #[test]
    fn tunnel_interface_produces_a_warning_and_non_tunnel_does_not() {
        assert!(tunnel_warning(true, "utun6").is_some());
        assert!(tunnel_warning(false, "en0").is_none());
    }

    #[test]
    fn tos_byte_masking_matches_libc_ecn_constants() {
        // Not-ECT has no portable libc name: the BSDs (and macOS) export
        // IPTOS_ECN_NOTECT, glibc exports nothing, and hurd/l4re spell it
        // IPTOS_ECN_NOT_ECT. The value is 0x00 in RFC 3168 everywhere, so
        // asserting the literal keeps this test compiling on every target
        // instead of only the one it was written on.
        const NOT_ECT: u8 = 0x00;
        assert_eq!(EcnCodepoint::from_tos_byte(NOT_ECT), EcnCodepoint::NotEct);
        assert_eq!(EcnCodepoint::from_tos_byte(libc::IPTOS_ECN_ECT1), EcnCodepoint::Ect1);
        assert_eq!(EcnCodepoint::from_tos_byte(libc::IPTOS_ECN_ECT0), EcnCodepoint::Ect0);
        assert_eq!(EcnCodepoint::from_tos_byte(libc::IPTOS_ECN_CE), EcnCodepoint::Ce);
        // High DSCP bits must not affect the ECN read.
        assert_eq!(EcnCodepoint::from_tos_byte(0xB8 | libc::IPTOS_ECN_CE), EcnCodepoint::Ce);
    }
}
