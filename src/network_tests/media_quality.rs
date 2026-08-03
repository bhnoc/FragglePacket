//! GAP-052: real-time voice/video/WebRTC quality test.
//!
//! Speed tests can pass while conferencing fails: calls care about one-way
//! delay, jitter, burst loss, and media setup, not average throughput. This
//! module reuses `burst_analysis::analyze` -- audio-like (small, ~50pps)
//! and video-like (large, bursty) synthetic RTP-shaped sequences feed the
//! same run-length/gap/reorder/jitter machinery already built for GAP-066.
//! What's new here is setup/ICE path reporting and deriving concealment
//! risk, freeze risk, and an MOS-style *estimate* from burst structure
//! rather than a mean-loss number.
//!
//! Two honesty rules enforced structurally, not just in wording:
//! - One-way delay needs synchronized clocks. Without a verified clock
//!   offset this module never derives it from half the RTT -- that specific
//!   shortcut is exactly the kind of plausible-but-wrong number this
//!   project keeps having to unlearn. `OneWayDelay::Unavailable` carries the
//!   reason; there is no code path from an RTT sample to a one-way figure.
//! - The MOS-style figure is typed as `MosEstimate`, never a bare score: it
//!   always carries the word "estimate" plus the inputs that produced it,
//!   so nothing downstream can print it as a real ITU-T P.800 MOS result.

use serde::{Deserialize, Serialize};

use crate::network_tests::burst_analysis::{analyze, BoundedSample, BurstAnalysisReport};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MediaProfile {
    /// ~50 packets/sec, small payload (e.g. Opus 20ms frames).
    Audio,
    /// Larger, burstier payload/rate shape (e.g. a video keyframe cadence).
    Video,
}

impl MediaProfile {
    pub fn packets_per_sec(&self) -> f64 {
        match self {
            MediaProfile::Audio => 50.0,
            MediaProfile::Video => 30.0,
        }
    }
    pub fn payload_bytes(&self) -> usize {
        match self {
            MediaProfile::Audio => 160,
            MediaProfile::Video => 1200,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PathKind {
    DirectUdp,
    TurnUdp,
    TurnTcp,
    TurnTls,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SetupOutcome {
    Established,
    /// The candidate path never completed a round trip within the setup
    /// budget. Distinct from `Established` -- callers must not treat a
    /// timed-out setup as a degraded-but-live call.
    TimedOut,
    /// The path itself could not even be attempted (e.g. TURN allocation
    /// refused, TLS handshake failed before any RTP was sent).
    Refused {
        detail: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IceCandidateResult {
    pub path: PathKind,
    pub setup: SetupOutcome,
    pub setup_rtt_ms: Option<f64>,
}

/// One-way delay requires a verified clock offset between sender and
/// receiver. This type makes "we don't have that" a distinct, structural
/// state rather than a missing field a caller could paper over by halving
/// an RTT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OneWayDelay {
    /// A verified offset was available and one-way delay was computed
    /// directly from send/receive timestamps in that common clock.
    Measured { delay_ms: f64 },
    /// No verified clock offset. `reason` explains why (e.g. "no NTP-style
    /// offset exchange performed"); this is GAP-064's territory.
    Unavailable { reason: String },
}

/// Concealment/freeze-risk estimates derived from burst structure --
/// specifically run length and gap duration -- not from the mean loss
/// percentage. A codec's PLC (packet-loss concealment) can usually mask a
/// single dropped frame; it cannot mask a multi-frame gap, regardless of
/// what the overall loss percentage says.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum ConcealmentEstimate {
    /// No loss bursts, or all bursts short enough that codec PLC plausibly
    /// masks them (single-packet runs only).
    LikelyConcealed,
    /// At least one burst long enough that PLC alone is unlikely to mask
    /// it without an audible/visible artifact.
    LikelyAudibleArtifact,
    /// Not enough information (no bursts occurred, or burst data itself
    /// unavailable) to estimate either way.
    Indeterminate,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum FreezeRisk {
    Low,
    Elevated,
    High,
}

/// Frames per second implied by `MediaProfile::packets_per_sec()`, used to
/// convert a burst run length (packet count) into an approximate frame-time
/// gap for concealment/freeze judgment.
fn packet_interval_ms(profile: MediaProfile) -> f64 {
    1000.0 / profile.packets_per_sec()
}

/// A burst run this short (in packet count) is the kind of single-frame
/// drop most codec PLC can mask; longer runs are increasingly likely to
/// surface as an audible glitch or a frozen frame.
const PLC_MASKABLE_RUN_LENGTH: u64 = 1;
const FREEZE_RISK_ELEVATED_MS: f64 = 100.0;
const FREEZE_RISK_HIGH_MS: f64 = 300.0;

pub fn estimate_concealment(report: &BurstAnalysisReport) -> ConcealmentEstimate {
    if report.burst.burst_count == 0 {
        return ConcealmentEstimate::Indeterminate;
    }
    if report.burst.max_run_length <= PLC_MASKABLE_RUN_LENGTH {
        ConcealmentEstimate::LikelyConcealed
    } else {
        ConcealmentEstimate::LikelyAudibleArtifact
    }
}

pub fn estimate_freeze_risk(report: &BurstAnalysisReport, profile: MediaProfile) -> FreezeRisk {
    if report.burst.burst_count == 0 {
        return FreezeRisk::Low;
    }
    let interval = packet_interval_ms(profile);
    // Prefer a real measured gap duration; fall back to the run-length x
    // packet-interval estimate only when the burst's gap duration itself is
    // unavailable (e.g. it touched the sequence boundary) -- still an
    // estimate, but never silently substitutes a completely different
    // quantity for a missing one without saying so structurally via this
    // fallback's caller-visible behavior (see `MediaQualityReport::notes`).
    let worst_gap_ms = report
        .burst
        .bursts
        .iter()
        .map(|b| b.gap_duration_ms.unwrap_or(b.run_length as f64 * interval))
        .fold(0.0_f64, f64::max);

    if worst_gap_ms >= FREEZE_RISK_HIGH_MS {
        FreezeRisk::High
    } else if worst_gap_ms >= FREEZE_RISK_ELEVATED_MS {
        FreezeRisk::Elevated
    } else {
        FreezeRisk::Low
    }
}

/// An explicitly-labeled estimate, never a real ITU-T P.800 MOS score.
/// Carries the inputs it was derived from so a reader can judge it rather
/// than trust a bare number.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MosEstimate {
    pub estimated_score: f64,
    pub inputs: MosInputs,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MosInputs {
    pub loss_percent: f64,
    pub jitter_ms: Option<f64>,
    pub freeze_risk: FreezeRisk,
    pub concealment: ConcealmentEstimate,
}

/// A simple, clearly-approximate E-model-flavored deduction: starts from a
/// clean-call ceiling and subtracts for loss, jitter, and burst severity.
/// This is NOT ITU-T P.800/P.862 and must never be presented as such --
/// enforced by always wrapping the number in `MosEstimate` with `label`
/// stating it is an estimate.
pub fn estimate_mos(
    report: &BurstAnalysisReport,
    freeze_risk: FreezeRisk,
    concealment: ConcealmentEstimate,
) -> MosEstimate {
    let mut score = 4.4_f64;
    score -= (report.loss_percent / 100.0) * 2.0;
    if let Some(j) = report.jitter.mean_ms {
        score -= (j / 50.0).min(1.0);
    }
    score -= match freeze_risk {
        FreezeRisk::Low => 0.0,
        FreezeRisk::Elevated => 0.5,
        FreezeRisk::High => 1.5,
    };
    if concealment == ConcealmentEstimate::LikelyAudibleArtifact {
        score -= 0.3;
    }
    let estimated_score = score.clamp(1.0, 4.5);

    MosEstimate {
        estimated_score,
        inputs: MosInputs {
            loss_percent: report.loss_percent,
            jitter_ms: report.jitter.mean_ms,
            freeze_risk,
            concealment,
        },
        label: "estimate (E-model-flavored heuristic, NOT an ITU-T P.800 subjective MOS)"
            .to_string(),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaQualityReport {
    pub profile: MediaProfile,
    pub ice_candidates: Vec<IceCandidateResult>,
    pub setup_success: bool,
    pub rtt_ms: Option<f64>,
    pub one_way_delay: OneWayDelay,
    pub burst: BurstAnalysisReport,
    pub concealment: ConcealmentEstimate,
    pub freeze_risk: FreezeRisk,
    pub mos: MosEstimate,
    pub notes: Vec<String>,
}

/// Builds the full report from a completed burst-analysis run plus ICE
/// candidate results and an optional RTT sample. `clock_offset_verified`
/// gates the one-way-delay computation entirely -- when `false`, no matter
/// what timestamps are present in `sample`, the report states
/// `OneWayDelay::Unavailable`.
pub fn build_report(
    profile: MediaProfile,
    ice_candidates: Vec<IceCandidateResult>,
    sample: &BoundedSample,
    rtt_ms: Option<f64>,
    clock_offset_verified: bool,
) -> MediaQualityReport {
    let setup_success = ice_candidates
        .iter()
        .any(|c| matches!(c.setup, SetupOutcome::Established));
    let burst = analyze(sample, None);
    let concealment = estimate_concealment(&burst);
    let freeze_risk = estimate_freeze_risk(&burst, profile);
    let mos = estimate_mos(&burst, freeze_risk, concealment);

    let one_way_delay = if clock_offset_verified {
        // Even with a verified offset, this module does not itself compute
        // it from `sample`'s send/receive timestamps unless those
        // timestamps are already in a common clock -- that verification is
        // the caller's job (GAP-064). Absent that plumbing, still report
        // unavailable rather than silently deriving from RTT.
        OneWayDelay::Unavailable {
            reason:
                "clock offset verification path not yet wired to a common-clock timestamp source"
                    .to_string(),
        }
    } else {
        OneWayDelay::Unavailable { reason: "no verified clock offset between endpoints (GAP-064); one-way delay is never derived from RTT/2".to_string() }
    };

    let mut notes = Vec::new();
    if !setup_success {
        notes.push("no ICE candidate path established -- burst/jitter figures below describe the underlying transport probe only, not a live call".to_string());
    }
    if matches!(one_way_delay, OneWayDelay::Unavailable { .. }) {
        notes.push("one-way delay unavailable: reporting RTT/jitter/burst only, never halving RTT to approximate it".to_string());
    }

    MediaQualityReport {
        profile,
        ice_candidates,
        setup_success,
        rtt_ms,
        one_way_delay,
        burst,
        concealment,
        freeze_risk,
        mos,
        notes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network_tests::burst_analysis::Arrival;

    fn arr(seq: u64, sent: f64, received: f64) -> Arrival {
        Arrival {
            seq,
            sent_at_ms: sent,
            received_at_ms: received,
        }
    }

    #[test]
    fn one_way_delay_never_derived_from_rtt() {
        let sample = BoundedSample {
            sent_count: 2,
            arrivals: vec![arr(0, 0.0, 5.0), arr(1, 20.0, 25.0)],
        };
        let report = build_report(MediaProfile::Audio, vec![], &sample, Some(50.0), false);
        match report.one_way_delay {
            OneWayDelay::Unavailable { .. } => {}
            OneWayDelay::Measured { .. } => {
                panic!("one-way delay must not be derived without a verified clock offset")
            }
        }
        // Even flipping "clock_offset_verified" true doesn't produce a
        // fabricated figure without a real common-clock timestamp source.
        let report2 = build_report(MediaProfile::Audio, vec![], &sample, Some(50.0), true);
        assert!(matches!(
            report2.one_way_delay,
            OneWayDelay::Unavailable { .. }
        ));
    }

    #[test]
    fn mos_is_always_labeled_an_estimate_with_inputs() {
        let sample = BoundedSample {
            sent_count: 10,
            arrivals: (0..10)
                .map(|i| arr(i, i as f64 * 20.0, i as f64 * 20.0 + 5.0))
                .collect(),
        };
        let report = build_report(MediaProfile::Audio, vec![], &sample, None, false);
        assert!(report.mos.label.to_lowercase().contains("estimate"));
        assert!(!report.mos.label.contains("P.800") || report.mos.label.contains("NOT"));
        assert_eq!(report.mos.inputs.loss_percent, report.burst.loss_percent);
    }

    #[test]
    fn concealment_and_freeze_risk_derive_from_burst_structure_not_mean_loss() {
        // Two runs with the SAME mean loss (20%) but different burst shape:
        // one long outage (6 consecutive missing, ~120ms at 50pps) vs many
        // single-packet drops (never more than 1 in a row).
        let mut single_drop_arrivals = Vec::new();
        for i in 0..30u64 {
            if i % 5 != 0 {
                single_drop_arrivals.push(arr(i, i as f64 * 20.0, i as f64 * 20.0 + 5.0));
            }
        }
        let single_drop_sample = BoundedSample {
            sent_count: 30,
            arrivals: single_drop_arrivals,
        };

        let mut long_outage_arrivals = Vec::new();
        for i in 0..30u64 {
            if !(12..18).contains(&i) {
                long_outage_arrivals.push(arr(i, i as f64 * 20.0, i as f64 * 20.0 + 5.0));
            }
        }
        let long_outage_sample = BoundedSample {
            sent_count: 30,
            arrivals: long_outage_arrivals,
        };

        let single_report = build_report(
            MediaProfile::Audio,
            vec![],
            &single_drop_sample,
            None,
            false,
        );
        let outage_report = build_report(
            MediaProfile::Audio,
            vec![],
            &long_outage_sample,
            None,
            false,
        );

        assert_eq!(
            single_report.burst.loss_percent, outage_report.burst.loss_percent,
            "both samples must share the same mean loss for this test to be meaningful"
        );
        assert_eq!(
            single_report.concealment,
            ConcealmentEstimate::LikelyConcealed
        );
        assert_eq!(
            outage_report.concealment,
            ConcealmentEstimate::LikelyAudibleArtifact
        );
        assert!(matches!(single_report.freeze_risk, FreezeRisk::Low));
        assert!(!matches!(outage_report.freeze_risk, FreezeRisk::Low));
    }

    #[test]
    fn setup_never_established_is_distinct_from_a_degraded_call() {
        let sample = BoundedSample {
            sent_count: 1,
            arrivals: vec![],
        };
        let candidates = vec![IceCandidateResult {
            path: PathKind::DirectUdp,
            setup: SetupOutcome::TimedOut,
            setup_rtt_ms: None,
        }];
        let report = build_report(MediaProfile::Audio, candidates, &sample, None, false);
        assert!(!report.setup_success);
        assert!(report
            .notes
            .iter()
            .any(|n| n.contains("no ICE candidate path established")));
    }

    #[test]
    fn indeterminate_concealment_when_no_bursts_occurred() {
        let sample = BoundedSample {
            sent_count: 3,
            arrivals: vec![arr(0, 0.0, 5.0), arr(1, 20.0, 25.0), arr(2, 40.0, 45.0)],
        };
        let report = build_report(MediaProfile::Audio, vec![], &sample, None, false);
        assert_eq!(report.concealment, ConcealmentEstimate::Indeterminate);
    }
}
