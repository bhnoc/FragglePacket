//! GAP-033: datagram-size and packet-rate pressure matrix.
//!
//! Field evidence: at 350 Mbps each way, Wi-Fi downstream loss rose from
//! 16.3% at 1,472-byte payloads to 65.1% at 200-byte payloads -- the same
//! byte rate, four times the packet rate, four times the loss. Byte rate
//! alone hides this: a report that only prints Mbps would show two numbers
//! that look like "the same load" while the receiver-side reality is a
//! packet-processing/airtime ceiling being hit far below any byte-rate cap.
//!
//! This module holds a "verdict" apart from a single sweep: distinguishing a
//! packet-rate ceiling from byte-rate policing needs two complementary
//! sweeps, not one. A sweep that holds byte rate constant while shrinking
//! payload size (raising packet rate) shows a packet-rate ceiling if loss
//! rises as size shrinks. A sweep that holds packet rate constant while
//! growing payload size (raising byte rate) shows byte-rate policing if
//! loss rises as size grows. Only when one signature appears without the
//! other is the discrimination clean; both or neither means inconclusive.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IpFamily {
    V4,
    V6,
}

/// One measured point in a sweep. `offered_pps`/`offered_bps` describe what
/// was sent; `received_pps`/`received_bps` are `None` when nothing came
/// back at all (not zero -- a genuinely unmeasurable rate is not the same
/// claim as a measured rate of zero). `loss_percent` is likewise `None`
/// when `offered_count` was zero, since a percentage of nothing sent is not
/// a real measurement of anything.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SizePoint {
    pub payload_size: usize,
    pub offered_count: u64,
    pub offered_pps: f64,
    pub offered_bps: f64,
    pub received_count: u64,
    pub received_pps: Option<f64>,
    pub received_bps: Option<f64>,
    pub loss_percent: Option<f64>,
    /// The IP family actually used for this point, verified from the
    /// resolved/bound address rather than assumed from what was requested.
    pub ip_family: Option<IpFamily>,
    /// True only if `payload_size` plus IP+UDP headers fits within the
    /// interface's actual measured MTU without fragmenting. A caller
    /// sweeping sizes must never claim "non-fragmenting" for a size this
    /// is false for.
    pub mtu_safe: bool,
}

impl SizePoint {
    pub fn from_counts(
        payload_size: usize,
        offered_count: u64,
        elapsed_secs: f64,
        received_count: u64,
        ip_family: Option<IpFamily>,
        mtu_safe: bool,
    ) -> Self {
        let offered_pps = if elapsed_secs > 0.0 { offered_count as f64 / elapsed_secs } else { 0.0 };
        let offered_bps = offered_pps * payload_size as f64 * 8.0;
        let (received_pps, received_bps) = if elapsed_secs > 0.0 && offered_count > 0 {
            let pps = received_count as f64 / elapsed_secs;
            (Some(pps), Some(pps * payload_size as f64 * 8.0))
        } else {
            (None, None)
        };
        let loss_percent = if offered_count > 0 {
            Some(((offered_count - received_count.min(offered_count)) as f64 / offered_count as f64) * 100.0)
        } else {
            None
        };
        Self {
            payload_size,
            offered_count,
            offered_pps,
            offered_bps,
            received_count,
            received_pps,
            received_bps,
            loss_percent,
            ip_family,
            mtu_safe,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DirectionMode {
    Directional,
    Bidirectional,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SizeRateMatrix {
    pub mode: DirectionMode,
    /// Payload size varies; byte rate is held approximately constant across
    /// points by scaling packet count/pacing inversely with size, so packet
    /// rate rises as size shrinks. This is the sweep shape the field
    /// evidence used.
    pub constant_byte_rate: Vec<SizePoint>,
    /// Payload size varies; packet rate is held approximately constant, so
    /// byte rate rises with size. The complementary control needed to rule
    /// byte-rate policing in or out.
    pub constant_packet_rate: Vec<SizePoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PressureVerdict {
    PacketRateCeiling { evidence: String },
    ByteRatePolicing { evidence: String },
    Inconclusive { reason: String },
}

/// A sweep endpoint pair (smallest and largest payload size with usable
/// loss figures) used to judge whether loss trends with size in a given
/// sweep. Returns `None` if fewer than two points have a measured loss.
fn endpoints(points: &[SizePoint]) -> Option<(&SizePoint, &SizePoint)> {
    let mut usable: Vec<&SizePoint> = points.iter().filter(|p| p.loss_percent.is_some()).collect();
    if usable.len() < 2 {
        return None;
    }
    usable.sort_by_key(|p| p.payload_size);
    let smallest = *usable.first().unwrap();
    let largest = *usable.last().unwrap();
    Some((smallest, largest))
}

/// A rise is material if it is both a large relative jump and a large
/// absolute one -- guards against a noisy 1-2pp wobble reading as a real
/// trend on an already-lossy path.
fn material_rise(from: f64, to: f64) -> bool {
    to > from * 1.5 && (to - from) > 10.0
}

pub fn classify_pressure(matrix: &SizeRateMatrix) -> PressureVerdict {
    let byte_rate_endpoints = endpoints(&matrix.constant_byte_rate);
    let packet_rate_endpoints = endpoints(&matrix.constant_packet_rate);

    let packet_ceiling_signature = byte_rate_endpoints.map(|(smallest, largest)| {
        // Held byte rate constant, size shrank (packet rate rose): loss
        // rising at the smallest size is the packet-rate-ceiling signature.
        material_rise(largest.loss_percent.unwrap(), smallest.loss_percent.unwrap())
    });

    let byte_policing_signature = packet_rate_endpoints.map(|(smallest, largest)| {
        // Held packet rate constant, size grew (byte rate rose): loss
        // rising at the largest size is the byte-rate-policing signature.
        material_rise(smallest.loss_percent.unwrap(), largest.loss_percent.unwrap())
    });

    match (packet_ceiling_signature, byte_policing_signature) {
        (Some(true), Some(false)) => PressureVerdict::PacketRateCeiling {
            evidence: format!(
                "loss rose from {:.1}% to {:.1}% as payload shrank at constant byte rate, \
                 with no comparable rise when packet rate was instead held constant",
                byte_rate_endpoints.unwrap().1.loss_percent.unwrap(),
                byte_rate_endpoints.unwrap().0.loss_percent.unwrap(),
            ),
        },
        (Some(false), Some(true)) => PressureVerdict::ByteRatePolicing {
            evidence: format!(
                "loss rose from {:.1}% to {:.1}% as payload grew at constant packet rate, \
                 with no comparable rise when byte rate was instead held constant",
                packet_rate_endpoints.unwrap().0.loss_percent.unwrap(),
                packet_rate_endpoints.unwrap().1.loss_percent.unwrap(),
            ),
        },
        (Some(true), Some(true)) => PressureVerdict::Inconclusive {
            reason: "both sweeps show a material loss rise; packet-rate and byte-rate pressure cannot be \
                     separated from this data alone"
                .to_string(),
        },
        (Some(false), Some(false)) => PressureVerdict::Inconclusive {
            reason: "neither sweep shows a material loss rise; no pressure signature detected at the tested sizes/rates"
                .to_string(),
        },
        _ => PressureVerdict::Inconclusive {
            reason: "insufficient measured points (need at least two sized points with a known loss percent \
                     in each sweep) to classify pressure"
                .to_string(),
        },
    }
}

/// Computes the largest non-fragmenting UDP payload for a given path MTU.
/// `path_mtu` must be the interface's actually-measured MTU, never a bare
/// 1500 assumption -- this host's default route is commonly a VPN tunnel at
/// MTU 1412, and a naive 1472-byte payload (1500 - 28) would fragment on it.
pub fn max_safe_payload(path_mtu: usize, ip_header_len: usize, udp_header_len: usize) -> usize {
    path_mtu.saturating_sub(ip_header_len + udp_header_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn point(size: usize, offered: u64, received: u64, elapsed: f64) -> SizePoint {
        SizePoint::from_counts(size, offered, elapsed, received, Some(IpFamily::V4), true)
    }

    #[test]
    fn offered_and_received_pps_are_separate_fields() {
        let p = point(1000, 100, 90, 1.0);
        assert_eq!(p.offered_pps, 100.0);
        assert_eq!(p.received_pps, Some(90.0));
        assert_ne!(p.offered_pps, p.received_pps.unwrap());
    }

    #[test]
    fn zero_offered_yields_unavailable_loss_not_zero() {
        let p = point(1000, 0, 0, 1.0);
        assert_eq!(p.loss_percent, None);
        assert_eq!(p.received_pps, None);
    }

    #[test]
    fn packet_rate_ceiling_and_byte_rate_policing_produce_distinguishable_verdicts() {
        // Ground truth from the field investigation (the field investigation /        // duplex-threshold characterization): at a fixed ~350 Mbps each way,
        // Wi-Fi downstream loss went from 16.3% at 1,472-byte payloads to
        // 65.1% at 200-byte payloads -- same byte rate, ~7.4x the packet
        // rate (7360 vs 1000 offered at the smaller size), ~4x the loss.
        // Wired stayed under 0.5% and was lossless at 1,200 bytes over the
        // same packet-rate matrix -- the flat control this classifier must
        // NOT flag as a byte-rate-policing signature.
        let ceiling_matrix = SizeRateMatrix {
            mode: DirectionMode::Directional,
            constant_byte_rate: vec![point(1472, 1000, 837, 1.0), point(200, 7360, 2569, 1.0)],
            constant_packet_rate: vec![point(1472, 1000, 995, 1.0), point(200, 1000, 998, 1.0)],
        };
        // Byte-rate-policing shaped matrix: constant-packet-rate sweep shows
        // loss rising as size (and thus byte rate) grows; constant-byte-rate
        // sweep stays flat.
        let policing_matrix = SizeRateMatrix {
            mode: DirectionMode::Directional,
            constant_byte_rate: vec![point(1472, 1000, 990, 1.0), point(200, 7300, 7250, 1.0)],
            constant_packet_rate: vec![point(1472, 1000, 700, 1.0), point(200, 1000, 990, 1.0)],
        };

        let ceiling_verdict = classify_pressure(&ceiling_matrix);
        let policing_verdict = classify_pressure(&policing_matrix);

        assert!(
            matches!(ceiling_verdict, PressureVerdict::PacketRateCeiling { .. }),
            "expected PacketRateCeiling for the field-evidence Wi-Fi matrix, got {:?}",
            ceiling_verdict
        );
        assert!(
            matches!(policing_verdict, PressureVerdict::ByteRatePolicing { .. }),
            "expected ByteRatePolicing, got {:?}",
            policing_verdict
        );
    }

    #[test]
    fn insufficient_points_is_inconclusive_not_a_guess() {
        let matrix = SizeRateMatrix {
            mode: DirectionMode::Directional,
            constant_byte_rate: vec![point(1000, 100, 95, 1.0)],
            constant_packet_rate: vec![point(1000, 100, 95, 1.0)],
        };
        assert!(matches!(classify_pressure(&matrix), PressureVerdict::Inconclusive { .. }));
    }

    #[test]
    fn max_safe_payload_never_assumes_bare_1500() {
        // The tunnel MTU from field notes: 1412, not 1500.
        assert_eq!(max_safe_payload(1412, 20, 8), 1384);
        assert_ne!(max_safe_payload(1412, 20, 8), max_safe_payload(1500, 20, 8));
    }
}
