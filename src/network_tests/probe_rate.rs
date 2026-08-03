//! GAP-021: probe-rate artifact detection.
//!
//! Field evidence: at 1 probe/sec, gateway ICMP (4.28ms avg / 0.33ms stddev)
//! and Internet ICMP (19.36ms avg / 1.47ms stddev) were both stable. At 5
//! probes/sec, BOTH targets showed correlated spikes approaching 100ms. That
//! pattern -- simultaneous spikes at two otherwise-unrelated hops, appearing
//! only when cadence changed -- is the signature of ICMP rate-limiting or
//! control-plane batching in a router, not path jitter. A single-cadence
//! test cannot see this: it would just report elevated jitter and send
//! someone hunting for a congested link that doesn't exist.
//!
//! This module samples the same two targets (a near hop and a remote host)
//! at two or more cadences and looks for spikes that appear only at the
//! higher cadence and correlate across both targets. It also refuses to
//! promote an ICMP-only spike into an application-latency claim without
//! corroboration from a non-ICMP probe (TCP connect timing).

use std::net::IpAddr;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::probe::probe_icmp;

/// A single probe outcome. `rtt_ms: None` means the packet was lost, never
/// a zero-latency measurement (same unavailable-vs-zero discipline as
/// GAP-009's ping parser).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RttSample {
    pub seq: usize,
    pub rtt_ms: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CadenceRun {
    pub rate_hz: f64,
    pub samples: Vec<RttSample>,
}

impl CadenceRun {
    fn received(&self) -> Vec<f64> {
        self.samples.iter().filter_map(|s| s.rtt_ms).collect()
    }

    pub fn avg_ms(&self) -> Option<f64> {
        let v = self.received();
        if v.is_empty() {
            None
        } else {
            Some(v.iter().sum::<f64>() / v.len() as f64)
        }
    }

    pub fn stddev_ms(&self) -> Option<f64> {
        let v = self.received();
        if v.len() < 2 {
            return None;
        }
        let avg = self.avg_ms()?;
        let var = v.iter().map(|x| (x - avg).powi(2)).sum::<f64>() / v.len() as f64;
        Some(var.sqrt())
    }

    pub fn loss_percent(&self) -> f64 {
        if self.samples.is_empty() {
            return 0.0;
        }
        let lost = self.samples.iter().filter(|s| s.rtt_ms.is_none()).count();
        (lost as f64 / self.samples.len() as f64) * 100.0
    }
}

/// Samples ICMP RTT at a fixed cadence. Uses `probe_icmp`'s own retry-free
/// probe and times it locally, so the RTT reflects exactly what was sent at
/// this rate (retries would blur cadence with retry backoff).
pub fn sample_icmp_cadence(
    target: IpAddr,
    rate_hz: f64,
    count: usize,
    timeout_ms: u64,
) -> CadenceRun {
    let interval = Duration::from_secs_f64(1.0 / rate_hz.max(0.01));
    let mut samples = Vec::with_capacity(count);
    for seq in 0..count {
        let start = Instant::now();
        let ok = probe_icmp(target, 32, timeout_ms, 0);
        let elapsed = start.elapsed();
        samples.push(RttSample {
            seq,
            rtt_ms: if ok {
                Some(elapsed.as_secs_f64() * 1000.0)
            } else {
                None
            },
        });
        let spent = start.elapsed();
        if spent < interval {
            std::thread::sleep(interval - spent);
        }
    }
    CadenceRun { rate_hz, samples }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetCadenceComparison {
    pub label: String,
    pub normal: CadenceRun,
    pub elevated: CadenceRun,
}

impl TargetCadenceComparison {
    /// A target "spiked" if elevated-cadence avg latency more than doubled
    /// AND rose by a materially significant absolute amount -- both
    /// thresholds guard against noise on an already-fast, already-jittery
    /// path producing a false positive.
    pub fn spiked(&self) -> bool {
        match (self.normal.avg_ms(), self.elevated.avg_ms()) {
            (Some(n), Some(e)) => e > n * 2.0 && (e - n) > 10.0,
            _ => false,
        }
    }
}

/// A non-ICMP probe run at the elevated cadence, used to corroborate (or
/// refute) an ICMP-only latency spike before it is allowed to become an
/// application-latency claim.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorroborationProbe {
    pub protocol: String,
    pub port: u16,
    pub rate_hz: f64,
    pub avg_ms: Option<f64>,
    pub samples: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeRateReport {
    pub gateway: TargetCadenceComparison,
    pub remote: TargetCadenceComparison,
    pub tcp_corroboration_elevated: CorroborationProbe,
    /// True only when BOTH gateway and remote ICMP spiked at the elevated
    /// cadence -- the specific correlated-across-hops signature of ICMP
    /// policing/batching, not a single congested path.
    pub probable_icmp_policing: bool,
    /// True only when the remote ICMP spike is corroborated by a
    /// comparable rise in the non-ICMP (TCP) probe. This is the gate that
    /// prevents an ICMP-only observation from being reported as an
    /// application-latency finding.
    pub application_latency_confirmed: bool,
    pub notes: Vec<String>,
}

pub fn analyze(
    gateway: TargetCadenceComparison,
    remote: TargetCadenceComparison,
    tcp: CorroborationProbe,
) -> ProbeRateReport {
    let mut notes = Vec::new();
    let gw_spiked = gateway.spiked();
    let remote_spiked = remote.spiked();
    let correlated = gw_spiked && remote_spiked;

    if correlated {
        notes.push(format!(
            "gateway avg {:.2}->{:.2}ms and remote avg {:.2}->{:.2}ms both rose when cadence went from {:.0} to {:.0} probes/sec; \
             simultaneous ICMP-only spikes at two otherwise-unrelated hops is the signature of ICMP rate-limiting/control-plane \
             batching, not path jitter",
            gateway.normal.avg_ms().unwrap_or(0.0), gateway.elevated.avg_ms().unwrap_or(0.0),
            remote.normal.avg_ms().unwrap_or(0.0), remote.elevated.avg_ms().unwrap_or(0.0),
            remote.normal.rate_hz, remote.elevated.rate_hz,
        ));
    } else if gw_spiked || remote_spiked {
        notes.push(
            "only one target's ICMP latency rose with cadence; this looks like a real per-path effect, \
             not router-level ICMP policing (which would hit both hops together)"
                .to_string(),
        );
    } else {
        notes.push("no material ICMP latency change between cadences".to_string());
    }

    let tcp_confirms = match (tcp.avg_ms, remote.elevated.avg_ms(), remote.normal.avg_ms()) {
        (Some(tcp_ms), Some(icmp_elevated), Some(icmp_normal)) => {
            let icmp_spike = icmp_elevated - icmp_normal;
            // The TCP-observed latency must itself sit meaningfully above
            // the ICMP baseline, not just above zero, to count as
            // corroboration of the same spike.
            tcp_ms - icmp_normal > icmp_spike * 0.5
        }
        _ => false,
    };

    let application_latency_confirmed = remote_spiked && tcp_confirms;
    if remote_spiked && !tcp_confirms {
        notes.push(
            "remote ICMP latency spiked at the elevated cadence but the TCP-connect corroboration probe did not \
             show a comparable rise -- NOT reporting this as an application-latency finding; ICMP-only evidence \
             is insufficient to make that claim"
                .to_string(),
        );
    }

    ProbeRateReport {
        gateway,
        remote,
        tcp_corroboration_elevated: tcp,
        probable_icmp_policing: correlated,
        application_latency_confirmed,
        notes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(rate_hz: f64, rtts: &[Option<f64>]) -> CadenceRun {
        CadenceRun {
            rate_hz,
            samples: rtts
                .iter()
                .enumerate()
                .map(|(seq, rtt)| RttSample { seq, rtt_ms: *rtt })
                .collect(),
        }
    }

    #[test]
    fn correlated_spike_flags_probable_icmp_policing_without_corroboration() {
        let gateway = TargetCadenceComparison {
            label: "gateway".into(),
            normal: run(1.0, &[Some(4.0), Some(4.2), Some(4.5)]),
            elevated: run(5.0, &[Some(95.0), Some(98.0), Some(92.0)]),
        };
        let remote = TargetCadenceComparison {
            label: "remote".into(),
            normal: run(1.0, &[Some(19.0), Some(19.5), Some(19.2)]),
            elevated: run(5.0, &[Some(96.0), Some(99.0), Some(94.0)]),
        };
        // Non-ICMP corroboration stays near the normal-cadence ICMP baseline:
        // the spike is ICMP-only.
        let tcp = CorroborationProbe {
            protocol: "tcp_connect".to_string(),
            port: 443,
            rate_hz: 5.0,
            avg_ms: Some(20.0),
            samples: 3,
        };

        let report = analyze(gateway, remote, tcp);
        assert!(
            report.probable_icmp_policing,
            "both hops spiked together -> probable policing"
        );
        assert!(
            !report.application_latency_confirmed,
            "ICMP-only spike must not be promoted to an application-latency claim without TCP corroboration"
        );
    }

    #[test]
    fn tcp_corroborated_spike_confirms_application_latency() {
        let gateway = TargetCadenceComparison {
            label: "gateway".into(),
            normal: run(1.0, &[Some(4.0), Some(4.1)]),
            elevated: run(5.0, &[Some(4.3), Some(4.4)]), // gateway did NOT spike
        };
        let remote = TargetCadenceComparison {
            label: "remote".into(),
            normal: run(1.0, &[Some(19.0), Some(19.2)]),
            elevated: run(5.0, &[Some(90.0), Some(92.0)]),
        };
        let tcp = CorroborationProbe {
            protocol: "tcp_connect".to_string(),
            port: 443,
            rate_hz: 5.0,
            avg_ms: Some(85.0), // TCP also rose sharply: real app-level effect
            samples: 2,
        };

        let report = analyze(gateway, remote, tcp);
        assert!(
            !report.probable_icmp_policing,
            "gateway did not spike, so this is not the correlated-hop signature"
        );
        assert!(
            report.application_latency_confirmed,
            "TCP corroborated the remote spike"
        );
    }

    #[test]
    fn no_spike_reports_neither_claim() {
        let gateway = TargetCadenceComparison {
            label: "gateway".into(),
            normal: run(1.0, &[Some(4.0)]),
            elevated: run(5.0, &[Some(4.1)]),
        };
        let remote = TargetCadenceComparison {
            label: "remote".into(),
            normal: run(1.0, &[Some(19.0)]),
            elevated: run(5.0, &[Some(19.3)]),
        };
        let tcp = CorroborationProbe {
            protocol: "tcp_connect".to_string(),
            port: 443,
            rate_hz: 5.0,
            avg_ms: Some(19.5),
            samples: 1,
        };
        let report = analyze(gateway, remote, tcp);
        assert!(!report.probable_icmp_policing);
        assert!(!report.application_latency_confirmed);
    }
}
