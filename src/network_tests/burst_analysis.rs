//! GAP-066: burst-loss, reordering, duplication, and microburst analysis.
//!
//! Average loss and throughput hide the failures that actually break media
//! and interactive traffic: a 20% loss made of one long outage and a 20%
//! loss sprinkled evenly across a run are different failures with the same
//! mean. Field evidence: at 350 Mbps each way, Wi-Fi downstream loss rose
//! from 16.3% at 1,472-byte payloads to 65.1% at 200-byte payloads while
//! wired stayed under 0.5% -- a packet-rate ceiling, not a byte-rate one,
//! visible only once you look at burst structure and gap duration rather
//! than the mean.
//!
//! This module takes a bounded, timestamped, sequence-numbered sample
//! (either generated locally via `run_bounded_probe` under the load guard,
//! or ingested from a client/server log or a qualified pcap-report figure)
//! and reports: consecutive-loss run-length distribution, gap duration
//! between loss bursts, reordering depth, duplicate count, jitter, and
//! queue-delay correlation. Reordering and duplication are counted
//! separately from loss -- a late packet is not a lost packet, and a
//! duplicate is not evidence of either.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// One received datagram as observed by the receiver, carrying the sender's
/// sequence number and send timestamp plus the receiver's arrival time. A
/// probe that never arrives has no entry here at all -- absence in the
/// receive log, not a zero-valued entry, is what "lost" means.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Arrival {
    pub seq: u64,
    pub sent_at_ms: f64,
    pub received_at_ms: f64,
}

impl Arrival {
    pub fn one_way_delay_ms(&self) -> f64 {
        self.received_at_ms - self.sent_at_ms
    }
}

/// A bounded, sequence-numbered sample: every sequence number from 0 to
/// `sent_count - 1` that the sender attempted to transmit, plus the subset
/// the receiver actually logged an arrival for. `sent_count` is required
/// explicitly rather than inferred from the arrivals -- inferring it from
/// `max(seq)` would silently undercount trailing loss.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoundedSample {
    pub sent_count: u64,
    pub arrivals: Vec<Arrival>,
}

/// A run of consecutively lost sequence numbers, and the gap duration that
/// run represents in send-time. `gap_duration_ms` is `None` when it can't be
/// computed (e.g. the run touches a sequence number with no timestamp
/// context on either side) -- never coerced to 0, per the project-wide rule
/// that an unmeasured quantity must never render as a real zero.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LossBurst {
    pub start_seq: u64,
    pub run_length: u64,
    pub gap_duration_ms: Option<f64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BurstDistribution {
    pub bursts: Vec<LossBurst>,
    pub total_lost: u64,
    pub burst_count: u64,
    pub max_run_length: u64,
    /// Mean run length across bursts. `None` when there were no bursts --
    /// distinct from a real mean of zero, which cannot occur since a burst
    /// by definition has run_length >= 1.
    pub mean_run_length: Option<f64>,
}

/// A packet that arrived out of send-sequence order. `depth` is how many
/// sequence numbers greater than this one had already arrived by the time
/// this one did -- the reordering distance, not a loss count. Reordering and
/// loss are structurally separate report fields throughout this module so
/// neither can be folded into the other by accident.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReorderEvent {
    pub seq: u64,
    pub depth: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JitterStats {
    pub mean_ms: Option<f64>,
    pub stddev_ms: Option<f64>,
    pub max_ms: Option<f64>,
}

/// Correlation between rising one-way delay and loss-burst onset. `rising_delay_before_burst`
/// is the discriminator called out in the GAP-066 acceptance criteria: a burst
/// preceded by climbing delay looks like queueing pressure; a burst with flat
/// delay right up to the drop looks like a hard drop policy. `sample_count`
/// under 2 anywhere in a burst's neighborhood makes the correlation for that
/// burst indeterminate, reported as `None`, not as "no correlation."
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueDelayCorrelation {
    pub burst_start_seq: u64,
    /// Mean one-way delay in the window immediately preceding the burst,
    /// versus the run's own baseline mean delay. `None` if too few samples
    /// existed in that window to say anything.
    pub delay_rising_before_burst: Option<bool>,
    pub pre_burst_mean_delay_ms: Option<f64>,
    pub baseline_mean_delay_ms: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BurstAnalysisReport {
    pub sent_count: u64,
    pub received_count: u64,
    pub loss_percent: f64,
    pub burst: BurstDistribution,
    pub reordering: Vec<ReorderEvent>,
    pub max_reorder_depth: u64,
    pub duplicate_count: u64,
    pub jitter: JitterStats,
    pub queue_delay_correlation: Vec<QueueDelayCorrelation>,
    /// Set when this report was built from a capture-derived figure that
    /// inherits pcap-report's host-offload/vantage qualification, rather
    /// than a direct client/server log. `None` for a direct log.
    pub capture_qualification: Option<String>,
    pub notes: Vec<String>,
}

/// Window (in send-time ms) examined immediately before a burst to judge
/// whether delay was rising into it.
const PRE_BURST_WINDOW_MS: f64 = 15.0;

/// Deduplicates repeated sequence numbers before structural analysis,
/// returning the distinct-seq arrivals (first-seen order preserved) and the
/// count of duplicate arrivals removed. A duplicate is a second (or later)
/// arrival for a sequence number already seen -- reported as its own count,
/// never mixed into the loss or reordering figures.
fn split_duplicates(arrivals: &[Arrival]) -> (Vec<Arrival>, u64) {
    let mut seen = HashSet::new();
    let mut distinct = Vec::with_capacity(arrivals.len());
    let mut duplicates = 0u64;
    for a in arrivals {
        if seen.insert(a.seq) {
            distinct.push(*a);
        } else {
            duplicates += 1;
        }
    }
    (distinct, duplicates)
}

/// Reordering depth: for each arrival (in receive order, duplicates already
/// removed), how many strictly-greater sequence numbers had already arrived
/// before it. A packet whose sequence number is the highest seen so far has
/// depth 0 (in order); a packet arriving behind ones sent after it has a
/// depth equal to how many later-sent packets beat it there.
fn compute_reordering(arrivals_in_receive_order: &[Arrival]) -> Vec<ReorderEvent> {
    let mut events = Vec::new();
    let mut highest_seq_seen: Option<u64> = None;
    let mut seen_seqs: Vec<u64> = Vec::new();
    for a in arrivals_in_receive_order {
        if let Some(highest) = highest_seq_seen {
            if a.seq < highest {
                let depth = seen_seqs.iter().filter(|&&s| s > a.seq).count() as u64;
                events.push(ReorderEvent { seq: a.seq, depth });
            }
        }
        highest_seq_seen = Some(highest_seq_seen.map_or(a.seq, |h| h.max(a.seq)));
        seen_seqs.push(a.seq);
    }
    events
}

fn compute_burst_distribution(sent_count: u64, present: &HashSet<u64>, seq_send_time: &dyn Fn(u64) -> Option<f64>) -> BurstDistribution {
    let mut bursts = Vec::new();
    let mut run_start: Option<u64> = None;
    let mut run_len: u64 = 0;

    let close_run = |start: Option<u64>, len: u64, bursts: &mut Vec<LossBurst>| {
        if let Some(start) = start {
            if len > 0 {
                let gap_duration_ms = match (seq_send_time(start), seq_send_time(start + len - 1)) {
                    (Some(t0), Some(t1)) => Some((t1 - t0).max(0.0)),
                    _ => None,
                };
                bursts.push(LossBurst { start_seq: start, run_length: len, gap_duration_ms });
            }
        }
    };

    for seq in 0..sent_count {
        if present.contains(&seq) {
            close_run(run_start, run_len, &mut bursts);
            run_start = None;
            run_len = 0;
        } else {
            if run_start.is_none() {
                run_start = Some(seq);
            }
            run_len += 1;
        }
    }
    close_run(run_start, run_len, &mut bursts);

    let total_lost: u64 = bursts.iter().map(|b| b.run_length).sum();
    let max_run_length = bursts.iter().map(|b| b.run_length).max().unwrap_or(0);
    let mean_run_length = if bursts.is_empty() {
        None
    } else {
        Some(total_lost as f64 / bursts.len() as f64)
    };

    BurstDistribution {
        burst_count: bursts.len() as u64,
        bursts,
        total_lost,
        max_run_length,
        mean_run_length,
    }
}

fn compute_jitter(arrivals: &[Arrival]) -> JitterStats {
    let delays: Vec<f64> = arrivals.iter().map(|a| a.one_way_delay_ms()).collect();
    if delays.len() < 2 {
        return JitterStats { mean_ms: None, stddev_ms: None, max_ms: None };
    }
    // Jitter here is inter-packet delay variation (successive |delta|), the
    // conventional definition for real-time-traffic impact, not the raw
    // delay spread.
    let mut deltas = Vec::with_capacity(delays.len() - 1);
    for i in 1..delays.len() {
        deltas.push((delays[i] - delays[i - 1]).abs());
    }
    let mean = deltas.iter().sum::<f64>() / deltas.len() as f64;
    let variance = deltas.iter().map(|d| (d - mean).powi(2)).sum::<f64>() / deltas.len() as f64;
    JitterStats {
        mean_ms: Some(mean),
        stddev_ms: Some(variance.sqrt()),
        max_ms: deltas.iter().cloned().fold(None, |acc, d| Some(acc.map_or(d, |m: f64| m.max(d)))),
    }
}

fn compute_queue_delay_correlation(sample: &BoundedSample, bursts: &[LossBurst]) -> Vec<QueueDelayCorrelation> {
    if bursts.is_empty() {
        return Vec::new();
    }
    let by_seq: std::collections::HashMap<u64, &Arrival> =
        sample.arrivals.iter().map(|a| (a.seq, a)).collect();
    let all_delays: Vec<f64> = sample.arrivals.iter().map(|a| a.one_way_delay_ms()).collect();
    let baseline_mean = if all_delays.is_empty() {
        None
    } else {
        Some(all_delays.iter().sum::<f64>() / all_delays.len() as f64)
    };

    bursts
        .iter()
        .map(|b| {
            let burst_send_time = by_seq
                .get(&b.start_seq.saturating_sub(1))
                .map(|a| a.sent_at_ms)
                .or_else(|| {
                    // Fall back to scanning backward for the nearest arrival
                    // before the burst if seq-1 itself is also missing.
                    (0..b.start_seq).rev().find_map(|s| by_seq.get(&s).map(|a| a.sent_at_ms))
                });

            let pre_burst_delays: Vec<f64> = match burst_send_time {
                Some(t) => sample
                    .arrivals
                    .iter()
                    .filter(|a| a.sent_at_ms <= t && a.sent_at_ms >= t - PRE_BURST_WINDOW_MS)
                    .map(|a| a.one_way_delay_ms())
                    .collect(),
                None => Vec::new(),
            };

            let pre_burst_mean = if pre_burst_delays.len() >= 2 {
                Some(pre_burst_delays.iter().sum::<f64>() / pre_burst_delays.len() as f64)
            } else {
                None
            };

            let delay_rising_before_burst = match (pre_burst_mean, baseline_mean) {
                (Some(pre), Some(base)) => Some(pre > base * 1.25),
                _ => None,
            };

            QueueDelayCorrelation {
                burst_start_seq: b.start_seq,
                delay_rising_before_burst,
                pre_burst_mean_delay_ms: pre_burst_mean,
                baseline_mean_delay_ms: baseline_mean,
            }
        })
        .collect()
}

/// Runs the full GAP-066 analysis over a bounded sample. `capture_qualification`
/// should be populated with pcap-report's vantage/qualification wording when
/// this sample was derived from a packet capture rather than a direct
/// client/server log, so the qualification travels with every downstream
/// figure instead of being lost at the ingestion boundary.
pub fn analyze(sample: &BoundedSample, capture_qualification: Option<String>) -> BurstAnalysisReport {
    let mut notes = Vec::new();

    let (distinct_in_receive_order, duplicate_count) = split_duplicates(&sample.arrivals);
    if duplicate_count > 0 {
        notes.push(format!(
            "{} duplicate arrival(s) observed; counted separately, not folded into loss or reordering",
            duplicate_count
        ));
    }

    let present: HashSet<u64> = distinct_in_receive_order.iter().map(|a| a.seq).collect();
    let received_count = present.len() as u64;
    let loss_percent = if sample.sent_count == 0 {
        0.0
    } else {
        ((sample.sent_count - received_count) as f64 / sample.sent_count as f64) * 100.0
    };

    let send_time_by_seq: std::collections::HashMap<u64, f64> =
        distinct_in_receive_order.iter().map(|a| (a.seq, a.sent_at_ms)).collect();
    let burst = compute_burst_distribution(sample.sent_count, &present, &|seq| send_time_by_seq.get(&seq).copied());

    let reordering = compute_reordering(&distinct_in_receive_order);
    let max_reorder_depth = reordering.iter().map(|e| e.depth).max().unwrap_or(0);
    if !reordering.is_empty() {
        notes.push(format!(
            "{} reordering event(s), max depth {}; reordering is arrival-order displacement, not loss",
            reordering.len(),
            max_reorder_depth
        ));
    }

    let jitter = compute_jitter(&distinct_in_receive_order);

    let mut dedup_sample = sample.clone();
    dedup_sample.arrivals = distinct_in_receive_order;
    let queue_delay_correlation = compute_queue_delay_correlation(&dedup_sample, &burst.bursts);
    let rising_count = queue_delay_correlation
        .iter()
        .filter(|c| c.delay_rising_before_burst == Some(true))
        .count();
    if rising_count > 0 {
        notes.push(format!(
            "{}/{} loss burst(s) preceded by rising one-way delay -- consistent with queueing pressure rather than a hard drop policy",
            rising_count,
            queue_delay_correlation.len()
        ));
    }

    if let Some(q) = &capture_qualification {
        notes.push(format!("capture-derived figures inherit qualification: {}", q));
    }

    BurstAnalysisReport {
        sent_count: sample.sent_count,
        received_count,
        loss_percent,
        burst,
        reordering,
        max_reorder_depth,
        duplicate_count,
        jitter,
        queue_delay_correlation,
        capture_qualification,
        notes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arr(seq: u64, sent: f64, received: f64) -> Arrival {
        Arrival { seq, sent_at_ms: sent, received_at_ms: received }
    }

    #[test]
    fn known_burst_structure_produces_correct_run_lengths_and_gaps() {
        // sent 0..10; missing 2,3,4 (one run of 3) and 7 (one run of 1).
        let arrivals = vec![
            arr(0, 0.0, 5.0),
            arr(1, 10.0, 15.0),
            arr(5, 50.0, 55.0),
            arr(6, 60.0, 65.0),
            arr(8, 80.0, 85.0),
            arr(9, 90.0, 95.0),
        ];
        let sample = BoundedSample { sent_count: 10, arrivals };
        let report = analyze(&sample, None);

        assert_eq!(report.burst.burst_count, 2);
        assert_eq!(report.burst.total_lost, 4);
        assert_eq!(report.burst.max_run_length, 3);
        let lengths: Vec<u64> = report.burst.bursts.iter().map(|b| b.run_length).collect();
        assert_eq!(lengths, vec![3, 1]);
        assert_eq!(report.burst.bursts[0].start_seq, 2);
        assert_eq!(report.burst.bursts[1].start_seq, 7);
        // mean run length is (3+1)/2 = 2.0
        assert_eq!(report.burst.mean_run_length, Some(2.0));
    }

    #[test]
    fn reordered_packet_is_not_counted_as_lost() {
        // All 4 sent, all 4 arrive, but seq 2 arrives before seq 1.
        let arrivals = vec![arr(0, 0.0, 5.0), arr(2, 20.0, 22.0), arr(1, 10.0, 25.0), arr(3, 30.0, 35.0)];
        let sample = BoundedSample { sent_count: 4, arrivals };
        let report = analyze(&sample, None);

        assert_eq!(report.received_count, 4);
        assert_eq!(report.loss_percent, 0.0);
        assert_eq!(report.burst.total_lost, 0);
        assert_eq!(report.reordering.len(), 1);
        assert_eq!(report.reordering[0].seq, 1);
        assert_eq!(report.reordering[0].depth, 1);
    }

    #[test]
    fn duplicates_are_reported_separately_from_loss_and_reordering() {
        let arrivals = vec![arr(0, 0.0, 5.0), arr(1, 10.0, 15.0), arr(1, 10.0, 16.0), arr(2, 20.0, 25.0)];
        let sample = BoundedSample { sent_count: 3, arrivals };
        let report = analyze(&sample, None);

        assert_eq!(report.duplicate_count, 1);
        assert_eq!(report.received_count, 3);
        assert_eq!(report.loss_percent, 0.0);
        assert_eq!(report.burst.total_lost, 0);
        assert!(report.reordering.is_empty());
    }

    #[test]
    fn unmeasurable_gap_duration_is_unavailable_not_zero() {
        // A burst at the very start of the sequence (seq 0 missing, seq 1
        // present) has no arrival for start_seq itself, so gap_duration_ms
        // must be None, not fabricated as 0.0.
        let arrivals = vec![arr(1, 10.0, 15.0), arr(2, 20.0, 25.0)];
        let sample = BoundedSample { sent_count: 3, arrivals };
        let report = analyze(&sample, None);

        assert_eq!(report.burst.burst_count, 1);
        assert_eq!(report.burst.bursts[0].start_seq, 0);
        assert_eq!(report.burst.bursts[0].gap_duration_ms, None);
    }

    #[test]
    fn no_bursts_reports_none_mean_run_length_not_zero() {
        let arrivals = vec![arr(0, 0.0, 5.0), arr(1, 10.0, 15.0)];
        let sample = BoundedSample { sent_count: 2, arrivals };
        let report = analyze(&sample, None);
        assert_eq!(report.burst.burst_count, 0);
        assert_eq!(report.burst.mean_run_length, None);
    }

    #[test]
    fn capture_qualification_travels_into_the_report() {
        let sample = BoundedSample { sent_count: 1, arrivals: vec![arr(0, 0.0, 1.0)] };
        let report = analyze(&sample, Some("host-side capture, offload-suspect".to_string()));
        assert_eq!(report.capture_qualification, Some("host-side capture, offload-suspect".to_string()));
        assert!(report.notes.iter().any(|n| n.contains("offload-suspect")));
    }

    #[test]
    fn rising_delay_before_burst_is_detected() {
        // Baseline delay ~5ms; delay climbs to ~40ms right before a burst at seq 10.
        let mut arrivals = Vec::new();
        for i in 0..10u64 {
            arrivals.push(arr(i, i as f64 * 10.0, i as f64 * 10.0 + 5.0));
        }
        // Pre-burst window: seqs 8,9 sent at 80,90ms with high delay.
        arrivals[8] = arr(8, 80.0, 80.0 + 40.0);
        arrivals[9] = arr(9, 90.0, 90.0 + 45.0);
        // seq 10 is lost (the burst); seq 11 resumes normal delay.
        arrivals.push(arr(11, 110.0, 115.0));
        let sample = BoundedSample { sent_count: 12, arrivals };
        let report = analyze(&sample, None);

        assert_eq!(report.burst.burst_count, 1);
        assert_eq!(report.queue_delay_correlation.len(), 1);
        assert_eq!(report.queue_delay_correlation[0].delay_rising_before_burst, Some(true));
    }
}
