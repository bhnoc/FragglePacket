//! GAP-046: version-aware maximum-throughput tuner.
//!
//! Field evidence: iperf3 3.9 and 3.16 reacted differently to parallel
//! streams and zero-copy -- PC3/3.9 peaked at 4 streams/128 KiB while
//! PV03/3.16 reached 454 Mbps at 8 streams/512 KiB/zero-copy. Sixteen
//! streams produced an invalid 15.84-second receiver duration for a run
//! that should have been materially shorter, and per-node throughput was
//! not monotonic across 64/128/512 KiB blocks -- so a single fixed-order
//! sweep cannot find a real maximum; it can only find whatever the current
//! endpoint/drift state happened to favor at that moment. Opening/final
//! baseline drift was severe, so any profile from one pass is provisional.
//!
//! This module scores randomized-order candidate trials, rejects any trial
//! whose reported duration doesn't match what was requested, brackets
//! endpoint drift via repeated baseline probes, and -- the acceptance
//! criterion most likely to get flattened by accident -- keeps a synthetic
//! best-case number and a representative-application number in genuinely
//! separate fields, never one computed by relabeling the other.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::network_tests::iperf::{IperfParseError, IperfResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Candidate {
    pub streams: u32,
    pub block_size_kib: u32,
    pub zero_copy: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrialResult {
    pub candidate: Candidate,
    pub requested_duration_secs: f64,
    pub reported_duration_secs: Option<f64>,
    pub receiver_bits_per_second: Option<f64>,
    pub rejected_reason: Option<String>,
}

/// A trial is rejected -- not scored, not averaged in -- if its reported
/// duration deviates from the requested one by more than this fraction.
/// This is what catches the 15.84s-for-a-shorter-run case.
const DURATION_TOLERANCE_FRACTION: f64 = 0.20;

pub fn evaluate_trial(
    candidate: Candidate,
    requested_duration_secs: f64,
    parsed: &Result<IperfResult, IperfParseError>,
) -> TrialResult {
    let result = match parsed {
        Err(e) => {
            return TrialResult {
                candidate,
                requested_duration_secs,
                reported_duration_secs: None,
                receiver_bits_per_second: None,
                rejected_reason: Some(e.to_string()),
            }
        }
        Ok(r) => r,
    };

    let received = match &result.forward.received {
        None => {
            return TrialResult {
                candidate,
                requested_duration_secs,
                reported_duration_secs: None,
                receiver_bits_per_second: None,
                rejected_reason: Some("session admitted but no receiver rate evidence".to_string()),
            }
        }
        Some(r) => r,
    };

    let duration_ok = requested_duration_secs > 0.0
        && (received.seconds - requested_duration_secs).abs() / requested_duration_secs
            <= DURATION_TOLERANCE_FRACTION;
    if !duration_ok {
        return TrialResult {
            candidate,
            requested_duration_secs,
            reported_duration_secs: Some(received.seconds),
            receiver_bits_per_second: None,
            rejected_reason: Some(format!(
                "receiver duration {:.2}s inconsistent with requested {}s",
                received.seconds, requested_duration_secs
            )),
        };
    }
    TrialResult {
        candidate,
        requested_duration_secs,
        reported_duration_secs: Some(received.seconds),
        receiver_bits_per_second: Some(received.bits_per_second),
        rejected_reason: None,
    }
}

/// CPU/socket-limit preflight: refuses to even attempt a candidate whose
/// stream count would plausibly exceed available parallelism or the
/// process's open-file-descriptor limit, rather than letting the OS reject
/// sockets mid-trial and produce a confusing partial result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreflightLimits {
    pub cpu_cores: usize,
    pub max_open_files: Option<u64>,
}

pub fn detect_preflight_limits() -> PreflightLimits {
    let cpu_cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let max_open_files = read_rlimit_nofile();
    PreflightLimits {
        cpu_cores,
        max_open_files,
    }
}

#[cfg(unix)]
fn read_rlimit_nofile() -> Option<u64> {
    let mut rl = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let rc = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) };
    if rc == 0 {
        Some(rl.rlim_cur as u64)
    } else {
        None
    }
}

#[cfg(not(unix))]
fn read_rlimit_nofile() -> Option<u64> {
    None
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PreflightVerdict {
    Ok,
    /// Streams requested would need more file descriptors than currently
    /// allowed. Each TCP stream is roughly one socket/fd.
    SocketLimitRisk {
        requested_streams: u32,
        fd_limit: u64,
    },
    CpuOversubscriptionRisk {
        requested_streams: u32,
        cpu_cores: usize,
    },
}

pub fn preflight_candidate(candidate: &Candidate, limits: &PreflightLimits) -> PreflightVerdict {
    if let Some(fd_limit) = limits.max_open_files {
        // Leave headroom for the process's own fds (stdio, sockets already
        // open, etc); a candidate must not consume the whole budget.
        if (candidate.streams as u64) * 2 > fd_limit.saturating_sub(16) {
            return PreflightVerdict::SocketLimitRisk {
                requested_streams: candidate.streams,
                fd_limit,
            };
        }
    }
    if candidate.streams as usize > limits.cpu_cores * 4 {
        return PreflightVerdict::CpuOversubscriptionRisk {
            requested_streams: candidate.streams,
            cpu_cores: limits.cpu_cores,
        };
    }
    PreflightVerdict::Ok
}

/// One repeated baseline probe against the same candidate, used to bracket
/// endpoint drift: if the *same* configuration produces materially
/// different throughput across repeats with no local change, the endpoint
/// itself (not the candidate search) is the source of variance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftBracket {
    pub samples_bps: Vec<f64>,
}

impl DriftBracket {
    pub fn spread_fraction(&self) -> Option<f64> {
        if self.samples_bps.len() < 2 {
            return None;
        }
        let max = self.samples_bps.iter().cloned().fold(f64::MIN, f64::max);
        let min = self.samples_bps.iter().cloned().fold(f64::MAX, f64::min);
        if max <= 0.0 {
            return None;
        }
        Some((max - min) / max)
    }

    /// Drift above this fraction means any single-pass "best" candidate
    /// from this endpoint is provisional -- matches the field notes calling
    /// the XMission profiles provisional due to severe opening/final drift.
    pub fn is_severe(&self) -> bool {
        self.spread_fraction().map(|f| f > 0.25).unwrap_or(false)
    }
}

/// Cohort profile keyed by client generation / iperf version, since the
/// field data shows different iperf versions peaking at different
/// stream/block-size combinations on the same physical client hardware.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CohortProfile {
    pub cohort_label: String,
    pub best_candidate: Option<Candidate>,
    pub best_receiver_bps: Option<f64>,
    pub drift: Option<DriftBracket>,
}

/// The core separation this gap requires: an unbounded best-case number is
/// not the same claim as a diagnostic measurement at a representative rate,
/// and printing only one invites exactly the conflation the field notes
/// warn about.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunerVerdict {
    pub cohort: CohortProfile,
    /// Best validated (duration-consistent, preflight-passed) trial across
    /// all randomized candidates -- an unbounded saturation number.
    pub synthetic_maximum_bps: Option<f64>,
    pub synthetic_maximum_candidate: Option<Candidate>,
    /// Throughput at a caller-chosen representative candidate (e.g. the
    /// application's actual configured stream count/block size), never
    /// derived from `synthetic_maximum_bps`.
    pub representative_application_bps: Option<f64>,
    pub representative_candidate: Option<Candidate>,
    pub rejected_trials: Vec<TrialResult>,
    pub drift_provisional: bool,
}

pub fn build_verdict(
    cohort_label: &str,
    trials: Vec<TrialResult>,
    representative: Candidate,
    drift: Option<DriftBracket>,
) -> TunerVerdict {
    let mut accepted: Vec<&TrialResult> = trials
        .iter()
        .filter(|t| t.rejected_reason.is_none())
        .collect();
    accepted.sort_by(|a, b| {
        b.receiver_bits_per_second
            .unwrap_or(0.0)
            .partial_cmp(&a.receiver_bits_per_second.unwrap_or(0.0))
            .unwrap()
    });

    let best = accepted.first();
    let representative_trial = accepted.iter().find(|t| t.candidate == representative);

    let drift_provisional = drift.as_ref().map(|d| d.is_severe()).unwrap_or(false);

    let mut by_candidate: HashMap<Candidate, f64> = HashMap::new();
    for t in &accepted {
        if let Some(bps) = t.receiver_bits_per_second {
            by_candidate.insert(t.candidate, bps);
        }
    }

    TunerVerdict {
        cohort: CohortProfile {
            cohort_label: cohort_label.to_string(),
            best_candidate: best.map(|t| t.candidate),
            best_receiver_bps: best.and_then(|t| t.receiver_bits_per_second),
            drift: drift.clone(),
        },
        synthetic_maximum_bps: best.and_then(|t| t.receiver_bits_per_second),
        synthetic_maximum_candidate: best.map(|t| t.candidate),
        representative_application_bps: representative_trial
            .and_then(|t| t.receiver_bits_per_second),
        representative_candidate: Some(representative),
        rejected_trials: trials
            .into_iter()
            .filter(|t| t.rejected_reason.is_some())
            .collect(),
        drift_provisional,
    }
}

/// Randomized candidate order so a fixed sweep can't repeatedly favor
/// whatever configuration happens to run first (and thus catch the
/// endpoint in its best moment) or last (its most-drifted moment).
pub fn randomize_candidates(mut candidates: Vec<Candidate>, seed: u64) -> Vec<Candidate> {
    use rand::seq::SliceRandom;
    use rand::SeedableRng;
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
    candidates.shuffle(&mut rng);
    candidates
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network_tests::iperf::{RateEvidence, RateSample, TestDirection};

    fn usable_result(seconds: f64, bps: f64) -> Result<IperfResult, IperfParseError> {
        Ok(IperfResult {
            version: None,
            protocol: "TCP".to_string(),
            direction: TestDirection::Forward,
            forward: RateEvidence {
                offered_bps: None,
                sent: None,
                received: Some(RateSample {
                    bits_per_second: bps,
                    bytes: 1000,
                    seconds,
                    packets: None,
                    lost_percent: None,
                }),
                estimated_received: None,
            },
            bidir_reverse: None,
            required_fields_missing: Vec::new(),
        })
    }

    fn refused_result() -> Result<IperfResult, IperfParseError> {
        Err(IperfParseError::ServerError(
            "connection refused".to_string(),
        ))
    }

    #[test]
    fn duration_inconsistent_trial_is_rejected_not_scored() {
        // The field's 16-stream/15.84s-for-a-shorter-run case.
        let candidate = Candidate {
            streams: 16,
            block_size_kib: 512,
            zero_copy: true,
        };
        let result = usable_result(15.84, 900_000_000.0);
        let trial = evaluate_trial(candidate, 8.0, &result);
        assert!(trial.rejected_reason.is_some());
        assert!(trial.receiver_bits_per_second.is_none());
    }

    #[test]
    fn duration_consistent_trial_is_scored() {
        let candidate = Candidate {
            streams: 8,
            block_size_kib: 512,
            zero_copy: true,
        };
        let result = usable_result(10.1, 454_000_000.0);
        let trial = evaluate_trial(candidate, 10.0, &result);
        assert!(trial.rejected_reason.is_none());
        assert_eq!(trial.receiver_bits_per_second, Some(454_000_000.0));
    }

    #[test]
    fn unusable_summary_is_rejected_never_scored() {
        let candidate = Candidate {
            streams: 4,
            block_size_kib: 128,
            zero_copy: false,
        };
        let result = refused_result();
        let trial = evaluate_trial(candidate, 10.0, &result);
        assert!(trial.rejected_reason.is_some());
        assert!(trial.receiver_bits_per_second.is_none());
    }

    #[test]
    fn preflight_flags_socket_limit_risk() {
        let limits = PreflightLimits {
            cpu_cores: 8,
            max_open_files: Some(64),
        };
        let candidate = Candidate {
            streams: 100,
            block_size_kib: 128,
            zero_copy: false,
        };
        assert_eq!(
            preflight_candidate(&candidate, &limits),
            PreflightVerdict::SocketLimitRisk {
                requested_streams: 100,
                fd_limit: 64
            }
        );
    }

    #[test]
    fn preflight_flags_cpu_oversubscription() {
        let limits = PreflightLimits {
            cpu_cores: 2,
            max_open_files: Some(100_000),
        };
        let candidate = Candidate {
            streams: 64,
            block_size_kib: 128,
            zero_copy: false,
        };
        assert!(matches!(
            preflight_candidate(&candidate, &limits),
            PreflightVerdict::CpuOversubscriptionRisk { .. }
        ));
    }

    #[test]
    fn preflight_passes_a_reasonable_candidate() {
        let limits = detect_preflight_limits();
        let candidate = Candidate {
            streams: 2,
            block_size_kib: 128,
            zero_copy: false,
        };
        assert_eq!(
            preflight_candidate(&candidate, &limits),
            PreflightVerdict::Ok
        );
    }

    #[test]
    fn severe_drift_is_detected_from_repeated_baseline() {
        let drift = DriftBracket {
            samples_bps: vec![100_000_000.0, 40_000_000.0],
        };
        assert!(drift.is_severe());
    }

    #[test]
    fn low_drift_is_not_severe() {
        let drift = DriftBracket {
            samples_bps: vec![100_000_000.0, 98_000_000.0],
        };
        assert!(!drift.is_severe());
    }

    #[test]
    fn synthetic_maximum_and_representative_are_independent_fields() {
        let candidate_best = Candidate {
            streams: 8,
            block_size_kib: 512,
            zero_copy: true,
        };
        let candidate_rep = Candidate {
            streams: 4,
            block_size_kib: 128,
            zero_copy: false,
        };
        let trials = vec![
            evaluate_trial(candidate_best, 10.0, &usable_result(10.0, 454_000_000.0)),
            evaluate_trial(candidate_rep, 10.0, &usable_result(10.0, 200_000_000.0)),
        ];
        let verdict = build_verdict("PV03/iperf3-3.16", trials, candidate_rep, None);
        assert_eq!(verdict.synthetic_maximum_bps, Some(454_000_000.0));
        assert_eq!(verdict.representative_application_bps, Some(200_000_000.0));
        assert_ne!(
            verdict.synthetic_maximum_bps,
            verdict.representative_application_bps
        );
    }

    #[test]
    fn rejected_trials_never_influence_synthetic_maximum() {
        let bad = Candidate {
            streams: 16,
            block_size_kib: 512,
            zero_copy: true,
        };
        let good = Candidate {
            streams: 4,
            block_size_kib: 128,
            zero_copy: false,
        };
        let trials = vec![
            evaluate_trial(bad, 8.0, &usable_result(15.84, 900_000_000.0)),
            evaluate_trial(good, 8.0, &usable_result(8.1, 100_000_000.0)),
        ];
        let verdict = build_verdict("PC3/iperf3-3.9", trials, good, None);
        assert_eq!(verdict.synthetic_maximum_bps, Some(100_000_000.0));
        assert_eq!(verdict.rejected_trials.len(), 1);
    }

    #[test]
    fn randomization_is_deterministic_given_a_seed_and_covers_all_candidates() {
        let candidates = vec![
            Candidate {
                streams: 1,
                block_size_kib: 64,
                zero_copy: false,
            },
            Candidate {
                streams: 4,
                block_size_kib: 128,
                zero_copy: false,
            },
            Candidate {
                streams: 8,
                block_size_kib: 512,
                zero_copy: true,
            },
        ];
        let a = randomize_candidates(candidates.clone(), 42);
        let b = randomize_candidates(candidates.clone(), 42);
        assert_eq!(a, b);
        assert_eq!(a.len(), candidates.len());
    }
}
