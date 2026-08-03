//! GAP-044: local-gateway latency-under-load bracket.
//!
//! Field evidence: concurrent gateway ping localized PC6's downstream-loss
//! incident to a path already containing the WLAN downlink — idle RTT
//! 1.646ms rose to 7.146ms average / 22.738ms max during a simultaneous
//! 100+100 phase with 23.550% downstream loss, while a healthy control node
//! (PV03) stayed near its 2.340ms idle baseline under matching load. That
//! near-side co-movement is evidence the queueing already exists on the
//! WLAN-facing leg; it does not by itself identify which queue is dropping,
//! and every gateway in that investigation suppressed ICMP entirely while
//! still passing transit traffic (21 of 21 Precog probes got zero replies
//! idle AND loaded). Both limits are load-bearing and must survive into any
//! caller's output, not just this module's internals.
//!
//! This module builds four phases (idle, upload, download, simultaneous),
//! runs each through `load_guard::LoadGuard` for budget/ramp/abort discipline,
//! and pairs it with an interface-bound first-hop probe sampled throughout
//! the phase. It reuses `firsthop`'s suppression-vs-loss classification and
//! TCP SYN fallback rather than reimplementing ICMP handling.

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::load_guard::{
    guard::{CounterSource, LoadGuard, LoadPhase, PhaseTick, RadioSource},
    LoadBudget,
};
use crate::network_tests::firsthop::{
    classify, probe_icmp_n, tcp_syn_timing, FallbackResult, IcmpProbeResult, IcmpState,
};

/// One RTT sample taken during a phase, paired with when it was taken
/// relative to phase start so it can be laid against the throughput timeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewaySample {
    pub elapsed_secs: f64,
    /// `None` means the probe was lost/suppressed at this instant, never a
    /// zero-latency measurement — same discipline as GAP-009/GAP-021.
    pub rtt_ms: Option<f64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PhaseKind {
    Idle,
    Upload,
    Download,
    Simultaneous,
}

impl PhaseKind {
    pub fn label(&self) -> &'static str {
        match self {
            PhaseKind::Idle => "idle",
            PhaseKind::Upload => "upload",
            PhaseKind::Download => "download",
            PhaseKind::Simultaneous => "simultaneous",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayPhaseResult {
    pub phase: PhaseKind,
    pub icmp_state: IcmpState,
    pub icmp_sent: usize,
    pub icmp_received: usize,
    /// `None` when every sample in this phase was suppressed/lost — an
    /// unmeasurable average must read as unavailable, never 0ms.
    pub avg_rtt_ms: Option<f64>,
    pub max_rtt_ms: Option<f64>,
    pub samples: Vec<GatewaySample>,
    /// Fallback (e.g. TCP SYN timing) used when ICMP produced nothing at all
    /// for this phase. `None` when ICMP itself returned samples.
    pub fallback: Option<FallbackResult>,
    /// Bytes the paired load phase moved during this window. `Some(0)` for
    /// idle (deliberately no load), `None` only if the phase itself could not
    /// report it.
    pub bytes_transferred: Option<u64>,
    pub throughput_loss_pct: Option<f64>,
    /// `"synthetic-demo-generator"` when `bytes_transferred`/`throughput_loss_pct`
    /// came from the fixed-size `SyntheticPhase` byte generator rather than
    /// real traffic (true for every non-idle phase today, since a real
    /// iperf3-backed phase is later sprints' job), `"live"` once a real
    /// phase is wired in, `"n/a"` for idle (no load is presented at all).
    /// ICMP/RTT provenance is tracked separately by `icmp_state` and the
    /// gateway probe itself, which really is live even when the paired
    /// throughput number is not -- a single report-level marker cannot
    /// describe both, so each signal states its own.
    pub throughput_source: &'static str,
}

impl GatewayPhaseResult {
    /// RTT delta versus a baseline (normally the idle phase's average).
    /// `None` when either side is unmeasurable — a delta computed against a
    /// missing baseline would silently fabricate a number.
    pub fn rtt_delta_ms(&self, baseline_avg_ms: Option<f64>) -> Option<f64> {
        match (self.avg_rtt_ms, baseline_avg_ms) {
            (Some(a), Some(b)) => Some(a - b),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayBracketReport {
    pub interface: Option<String>,
    pub interface_is_tunnel: bool,
    pub gateway: String,
    pub phases: Vec<GatewayPhaseResult>,
    /// Present on every phase report; repeated here at the top level so a
    /// caller reading only the top-level JSON still sees it and cannot miss
    /// it by only reading one phase.
    pub small_icmp_packet_caveat: String,
    pub queue_localization_caveat: String,
    /// `"synthetic"` when built from `--inject-synthetic`, `"live"` for a
    /// real probed run. A saved artifact must declare this on its own --
    /// see `harness/checks/020-synthetic-provenance.sh`.
    pub data_source: &'static str,
}

pub const SMALL_ICMP_PACKET_CAVEAT: &str =
    "gateway ICMP probes are small packets and may receive different queue treatment than the bulk load traffic; a clean ICMP result does not by itself prove the queue is healthy";

pub const QUEUE_LOCALIZATION_CAVEAT: &str =
    "rising gateway RTT under load localizes queueing to a path that includes this interface's link; it does not identify which queue or device is dropping without AP/controller counters or an internal wired endpoint";

/// A phase the gateway bracket drives: idle just samples RTT, the load
/// phases additionally track bytes moved so the throughput timeline can be
/// correlated against the RTT timeline.
pub trait BracketPhase: LoadPhase {
    fn bytes_transferred(&self) -> u64;
    fn target_bytes(&self) -> u64;
}

/// A `LoadPhase` that produces a fixed-size tick of synthetic bytes per call.
/// Real upload/download/simultaneous wiring (iperf3, a real socket) is a
/// later sprint's job per GAP-031-034; this type is what `LoadGuard::run`
/// needs today and is exactly what GAP-047's "don't generate real load while
/// building the guard" constraint calls for.
pub struct SyntheticPhase {
    bytes_per_tick: u64,
    transferred: Arc<AtomicU64>,
}

impl SyntheticPhase {
    pub fn new(bytes_per_tick: u64) -> Self {
        Self {
            bytes_per_tick,
            transferred: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn idle() -> Self {
        Self::new(0)
    }
}

impl LoadPhase for SyntheticPhase {
    fn tick(&mut self, _ramp_rate_mbps: f64, _elapsed: Duration) -> PhaseTick {
        self.transferred
            .fetch_add(self.bytes_per_tick, Ordering::SeqCst);
        PhaseTick {
            bytes_sent_delta: self.bytes_per_tick,
            ..Default::default()
        }
    }
}

impl BracketPhase for SyntheticPhase {
    fn bytes_transferred(&self) -> u64 {
        self.transferred.load(Ordering::SeqCst)
    }
    fn target_bytes(&self) -> u64 {
        u64::MAX // caller supplies the real target via the budget; unused here
    }
}

/// Samples the gateway at a fixed cadence for `duration`, recording
/// elapsed-since-start alongside each RTT so the timeline can be laid against
/// throughput. Falls back to TCP SYN timing (via `firsthop::classify`) only
/// if ICMP produced zero replies across the whole phase — matching GAP-022's
/// suppression-vs-loss discipline rather than re-deriving it here.
pub fn sample_gateway_during(
    gateway: IpAddr,
    duration: Duration,
    cadence_hz: f64,
    icmp_timeout_ms: u64,
    tcp_fallback_port: u16,
) -> (IcmpProbeResult, Option<FallbackResult>, Vec<GatewaySample>) {
    let interval = Duration::from_secs_f64(1.0 / cadence_hz.max(0.01));
    let start = Instant::now();
    let mut samples = Vec::new();
    let mut sent = 0usize;
    let mut received = 0usize;

    while start.elapsed() < duration {
        let tick_start = Instant::now();
        let (s, r) = probe_icmp_n(gateway, 1, icmp_timeout_ms);
        sent += s;
        received += r;
        let rtt_ms = if r > 0 {
            Some(tick_start.elapsed().as_secs_f64() * 1000.0)
        } else {
            None
        };
        samples.push(GatewaySample {
            elapsed_secs: start.elapsed().as_secs_f64(),
            rtt_ms,
        });
        let spent = tick_start.elapsed();
        if spent < interval {
            std::thread::sleep(interval - spent);
        }
    }

    let fallback = if received == 0 {
        Some(tcp_syn_timing(gateway, tcp_fallback_port, icmp_timeout_ms))
    } else {
        None
    };
    let (icmp, fallback) = classify((sent, received), fallback);
    (icmp, fallback, samples)
}

fn avg_max_rtt(samples: &[GatewaySample]) -> (Option<f64>, Option<f64>) {
    let rtts: Vec<f64> = samples.iter().filter_map(|s| s.rtt_ms).collect();
    if rtts.is_empty() {
        return (None, None);
    }
    let avg = rtts.iter().sum::<f64>() / rtts.len() as f64;
    let max = rtts.iter().cloned().fold(f64::MIN, f64::max);
    (Some(avg), Some(max))
}

/// Runs one phase: drives `phase` through a guard-controlled budget while
/// concurrently sampling the gateway, then correlates the two timelines.
/// `budget` is `None` for the idle phase (no load is presented at all).
pub fn run_phase(
    kind: PhaseKind,
    gateway: IpAddr,
    budget: Option<LoadBudget>,
    phase_duration: Duration,
    cadence_hz: f64,
    icmp_timeout_ms: u64,
    tcp_fallback_port: u16,
    bytes_per_tick: u64,
) -> GatewayPhaseResult {
    let bytes_transferred = Arc::new(AtomicU64::new(0));
    let target_bytes = Arc::new(AtomicU64::new(0));

    let gateway_result: Arc<
        Mutex<Option<(IcmpProbeResult, Option<FallbackResult>, Vec<GatewaySample>)>>,
    > = Arc::new(Mutex::new(None));
    let gateway_result_writer = gateway_result.clone();
    let sampler_stop = Arc::new(AtomicBool::new(false));
    let sampler_stop_reader = sampler_stop.clone();

    let sampler = std::thread::spawn(move || {
        let out = sample_gateway_during(
            gateway,
            phase_duration,
            cadence_hz,
            icmp_timeout_ms,
            tcp_fallback_port,
        );
        *gateway_result_writer.lock().unwrap() = Some(out);
        sampler_stop_reader.store(true, Ordering::SeqCst);
    });

    match budget {
        None => {
            // Idle: no LoadGuard phase at all -- deliberately presents zero
            // load rather than a synthetic zero-byte "phase" that would imply
            // a guard ran and produced a validity verdict for nothing.
            let _ = sampler.join();
        }
        Some(budget) => {
            let radio =
                RadioSource::new(|| Err("gateway bracket phase: radio not sampled".to_string()));
            let counters = CounterSource::new(|| {
                Err("gateway bracket phase: counters not sampled".to_string())
            });
            if let Ok(guard) = LoadGuard::new(budget, "gateway-bracket", false, radio, counters) {
                let bt = bytes_transferred.clone();
                let cancel = Arc::new(AtomicBool::new(false));
                let report = guard.run(
                    move |_rate: f64, _elapsed: Duration| {
                        bt.fetch_add(bytes_per_tick, Ordering::SeqCst);
                        PhaseTick {
                            bytes_sent_delta: bytes_per_tick,
                            ..Default::default()
                        }
                    },
                    cancel,
                );
                target_bytes.store(report.raw.target_bytes, Ordering::SeqCst);
            }
            let _ = sampler.join();
        }
    }

    let (icmp, fallback, samples) = gateway_result.lock().unwrap().take().unwrap_or_else(|| {
        (
            IcmpProbeResult {
                sent: 0,
                received: 0,
                state: IcmpState::Lost,
            },
            None,
            Vec::new(),
        )
    });
    let (avg_rtt_ms, max_rtt_ms) = avg_max_rtt(&samples);

    let bt = bytes_transferred.load(Ordering::SeqCst);
    let tb = target_bytes.load(Ordering::SeqCst);
    let throughput_loss_pct = if tb > 0 {
        Some((1.0 - (bt as f64 / tb as f64)).clamp(0.0, 1.0) * 100.0)
    } else {
        None
    };

    GatewayPhaseResult {
        phase: kind,
        icmp_state: icmp.state,
        icmp_sent: icmp.sent,
        icmp_received: icmp.received,
        avg_rtt_ms,
        max_rtt_ms,
        throughput_source: if kind == PhaseKind::Idle {
            "n/a"
        } else {
            // The paired load phase is always the synthetic demo byte
            // generator today (see `SyntheticPhase` docs) -- a real
            // iperf3-backed phase is GAP-031-034's job. Marking this
            // "synthetic-demo-generator" here, not "live", is what keeps a
            // fabricated loss percentage from being read as a real network
            // measurement even though the ICMP/RTT samples in this same
            // record genuinely are live.
            "synthetic-demo-generator"
        },
        samples,
        fallback,
        bytes_transferred: Some(bt),
        throughput_loss_pct,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(elapsed: f64, rtt: Option<f64>) -> GatewaySample {
        GatewaySample {
            elapsed_secs: elapsed,
            rtt_ms: rtt,
        }
    }

    #[test]
    fn avg_max_rtt_ignores_lost_samples() {
        let samples = vec![
            sample(0.0, Some(2.0)),
            sample(1.0, None),
            sample(2.0, Some(4.0)),
        ];
        let (avg, max) = avg_max_rtt(&samples);
        assert_eq!(avg, Some(3.0));
        assert_eq!(max, Some(4.0));
    }

    #[test]
    fn avg_max_rtt_all_lost_is_none_not_zero() {
        let samples = vec![sample(0.0, None), sample(1.0, None)];
        let (avg, max) = avg_max_rtt(&samples);
        assert_eq!(avg, None);
        assert_eq!(max, None);
    }

    #[test]
    fn rtt_delta_requires_both_sides_measurable() {
        let result = GatewayPhaseResult {
            phase: PhaseKind::Download,
            icmp_state: IcmpState::Responding,
            icmp_sent: 10,
            icmp_received: 10,
            avg_rtt_ms: Some(7.0),
            max_rtt_ms: Some(20.0),
            samples: vec![],
            fallback: None,
            bytes_transferred: Some(100),
            throughput_loss_pct: Some(5.0),
            throughput_source: "synthetic-demo-generator",
        };
        assert_eq!(result.rtt_delta_ms(Some(2.0)), Some(5.0));
        assert_eq!(result.rtt_delta_ms(None), None);

        let unmeasurable = GatewayPhaseResult {
            avg_rtt_ms: None,
            ..result
        };
        assert_eq!(unmeasurable.rtt_delta_ms(Some(2.0)), None);
    }

    #[test]
    fn caveats_are_non_empty_constants() {
        assert!(SMALL_ICMP_PACKET_CAVEAT.contains("queue"));
        assert!(QUEUE_LOCALIZATION_CAVEAT.contains("does not identify"));
    }
}
