//! GAP-043: telemetry-counter liveness validation.
//!
//! Field evidence: privileged `iw` station counters were readable on
//! Precog nodes PC6/PV03 but did not advance during known 100+100 Mbps
//! traffic. A counter that answers a read call is not the same thing as a
//! counter that is live -- a frozen driver counter reporting 0 retries and
//! 0 drops looks identical, byte for byte, to a healthy radio that
//! genuinely dropped nothing. The only way to tell them apart is to
//! bracket a KNOWN stimulus and check the counter actually moved by
//! roughly that amount.
//!
//! Three distinct unusable states, deliberately kept apart because each
//! implies something different about what happened to the source:
//! - Frozen: the delta is exactly zero despite a nonzero stimulus. The
//!   counter register itself is not incrementing.
//! - Reset: the delta is negative and small relative to the observed
//!   range -- consistent with the source having been zeroed mid-window
//!   (e.g. interface down/up, driver reload).
//! - Wrapped: the delta is negative but the magnitude is enormous relative
//!   to the stimulus -- consistent with the counter register overflowing
//!   past a 32- or 64-bit boundary rather than being reset to zero.
//! A genuine zero delta (no stimulus sent, or a counter that isn't the one
//! being exercised) is never confused with Frozen: liveness is only ever
//! evaluated against a *known, bracketed* stimulus size.

use serde::{Deserialize, Serialize};
use std::net::UdpSocket;
use std::process::Command;
use std::time::{Duration, Instant};

/// Reads an interface's `Ipkts` (rx packet) counter via `netstat -I <iface>
/// -b`, indexing columns from the RIGHT rather than by header-name lookup
/// from the left. `load_guard::counters::parse_netstat_ib` indexes from the
/// left and misparses interfaces like `lo0` whose `<Link#N>` row has no
/// hardware-address field -- every column after `Network` shifts left by
/// one, so `Ipkts` gets read out of the `Ierrs`/`Ibytes` slot. This is a
/// read-only alternate implementation kept local to this module rather than
/// a fix to `load_guard/counters.rs`, which is another agent's file.
pub fn read_rx_packets(interface: &str) -> Result<u64, String> {
    let out = Command::new("netstat")
        .args(["-I", interface, "-b"])
        .output()
        .map_err(|e| format!("failed to run netstat: {e}"))?;
    if !out.status.success() {
        return Err(format!("netstat exited with {:?}", out.status.code()));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    parse_rx_packets_right_anchored(&text, interface)
        .ok_or_else(|| format!("no netstat row for interface {interface}"))
}

/// `netstat -I <iface> -b` header is always, right-to-left:
/// ... Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll -- 7 trailing numeric
/// columns regardless of how many descriptive columns precede them (an
/// address-bearing row has one more column than a bare `<Link#N>` row).
/// Anchoring from the end sidesteps that shift entirely.
fn parse_rx_packets_right_anchored(text: &str, interface: &str) -> Option<u64> {
    for line in text.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.is_empty() || fields[0] != interface {
            continue;
        }
        if fields.len() < 7 {
            continue;
        }
        let ipkts = fields[fields.len() - 7];
        if let Ok(v) = ipkts.parse::<u64>() {
            return Some(v);
        }
    }
    None
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LivenessVerdict {
    /// Delta is consistent with the known stimulus within tolerance.
    Live,
    /// Delta is exactly zero (or within noise-floor tolerance of zero)
    /// despite a nonzero stimulus having been sent.
    Frozen,
    /// Delta went backwards by a small amount relative to the stimulus --
    /// consistent with a counter reset mid-window.
    Reset,
    /// Delta went backwards by an amount consistent with wraparound near a
    /// 32-bit (4,294,967,296) or 64-bit boundary.
    Wrapped,
    /// Advanced, but by far more or less than the stimulus predicts -- the
    /// source is live but not attributable to this stimulus alone (e.g.
    /// unrelated background traffic sharing the counter).
    Unattributable,
}

impl LivenessVerdict {
    pub fn is_usable(&self) -> bool {
        matches!(self, LivenessVerdict::Live)
    }
}

/// A bracket result: what stimulus was sent, what the counter read before
/// and after, and the resulting classification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LivenessBracket {
    pub source_name: String,
    pub stimulus_packets_sent: u64,
    pub counter_before: u64,
    pub counter_after: u64,
    pub verdict: LivenessVerdict,
    pub detail: String,
}

/// 32-bit wrap boundary. A negative delta whose magnitude, modulo this
/// boundary, lands close to the expected stimulus is treated as wrapped
/// rather than reset.
const U32_BOUNDARY: i128 = 1i128 << 32;
const U64_BOUNDARY: i128 = 1i128 << 64;

/// Fraction of the stimulus a delta must reach to count as attributable
/// "Live" advance. Real counters can lag a stimulus slightly (retries,
/// coalescing) so this is deliberately generous, not exact-match.
const LIVE_MIN_FRACTION: f64 = 0.5;
/// Upper bound past which an advance is "real but not attributable to this
/// stimulus alone" rather than simply "live" -- guards against silently
/// crediting unrelated background traffic as proof of this bracket.
const LIVE_MAX_FRACTION: f64 = 20.0;
/// A reset is distinguished from a wrap by how large the backwards jump is
/// relative to the stimulus: small backwards jumps look like a counter
/// that was zeroed, not one that overflowed.
const RESET_MAX_MAGNITUDE_VS_STIMULUS: f64 = 50.0;
/// How close (in packets) a wrapped delta's reconstructed value must land
/// to the stimulus to be classified as a wrap rather than an
/// unattributable anomaly.
const WRAP_TOLERANCE_PACKETS: i128 = 10_000;

pub fn classify_delta(
    source_name: &str,
    stimulus_packets_sent: u64,
    before: u64,
    after: u64,
) -> LivenessBracket {
    let delta: i128 = after as i128 - before as i128;
    let stimulus = stimulus_packets_sent as i128;

    let verdict = if stimulus == 0 {
        LivenessVerdict::Unattributable
    } else if delta == 0 {
        LivenessVerdict::Frozen
    } else if delta > 0 {
        let frac = delta as f64 / stimulus_packets_sent as f64;
        if (LIVE_MIN_FRACTION..=LIVE_MAX_FRACTION).contains(&frac) {
            LivenessVerdict::Live
        } else {
            LivenessVerdict::Unattributable
        }
    } else {
        // delta < 0: could be reset (zeroed) or wrapped (overflowed).
        let magnitude = -delta;
        if (magnitude as f64) <= (stimulus as f64) * RESET_MAX_MAGNITUDE_VS_STIMULUS {
            LivenessVerdict::Reset
        } else {
            // If the register actually wrapped past a 32- or 64-bit
            // boundary, the true advance is boundary - magnitude (the
            // counter climbed from `before` to the boundary, then from
            // zero up to `after`). A real wrap reconstructs to something
            // close to the known stimulus; anything else is unexplained.
            let reconstructed_32 = U32_BOUNDARY - magnitude;
            let reconstructed_64 = U64_BOUNDARY - magnitude;
            let matches_stimulus = |reconstructed: i128| {
                reconstructed > 0 && (reconstructed - stimulus).abs() <= WRAP_TOLERANCE_PACKETS
            };
            if matches_stimulus(reconstructed_32) || matches_stimulus(reconstructed_64) {
                LivenessVerdict::Wrapped
            } else {
                LivenessVerdict::Unattributable
            }
        }
    };

    let detail = match verdict {
        LivenessVerdict::Live => format!(
            "counter advanced by {} against a stimulus of {} packets -- within the {:.0}x-{:.0}x expected range",
            delta, stimulus_packets_sent, LIVE_MIN_FRACTION, LIVE_MAX_FRACTION
        ),
        LivenessVerdict::Frozen => format!(
            "counter did not move at all ({} -> {}) despite a {}-packet stimulus -- this source is not usable as evidence",
            before, after, stimulus_packets_sent
        ),
        LivenessVerdict::Reset => format!(
            "counter went backwards by {} ({} -> {}), a small jump relative to the stimulus -- consistent with a counter reset, not real traffic",
            magnitude_or_zero(delta), before, after
        ),
        LivenessVerdict::Wrapped => format!(
            "counter went backwards by {} ({} -> {}), consistent with wraparound past a register boundary",
            magnitude_or_zero(delta), before, after
        ),
        LivenessVerdict::Unattributable => format!(
            "counter changed by {} against a stimulus of {}, outside the range attributable to this bracket alone",
            delta, stimulus_packets_sent
        ),
    };

    LivenessBracket {
        source_name: source_name.to_string(),
        stimulus_packets_sent,
        counter_before: before,
        counter_after: after,
        verdict,
        detail,
    }
}

fn magnitude_or_zero(delta: i128) -> i128 {
    if delta < 0 {
        -delta
    } else {
        delta
    }
}

/// Sends a known quantity of small UDP datagrams over loopback and returns
/// how many were actually handed to the socket layer (send_to succeeding).
/// This is the stimulus generator for bracketing a *local* counter (e.g.
/// `lo0`'s packet counters via `load_guard::counters::snapshot_live`).
/// Deliberately small and local -- GAP-047 forbids default heavy load, and
/// proving a counter advances needs nothing more than a few thousand tiny
/// packets.
pub fn send_loopback_stimulus(packet_count: u64, payload_len: usize) -> Result<u64, String> {
    let receiver = UdpSocket::bind("127.0.0.1:0").map_err(|e| format!("bind receiver: {e}"))?;
    let receiver_addr = receiver
        .local_addr()
        .map_err(|e| format!("receiver addr: {e}"))?;
    receiver.set_nonblocking(true).ok();

    let sender = UdpSocket::bind("127.0.0.1:0").map_err(|e| format!("bind sender: {e}"))?;
    let payload = vec![0xABu8; payload_len.max(1)];

    let mut sent = 0u64;
    for _ in 0..packet_count {
        if sender.send_to(&payload, receiver_addr).is_ok() {
            sent += 1;
        }
    }

    // Drain briefly so the datagrams are actually consumed rather than
    // left queued, which keeps the bracket's counter read close to the
    // send completion rather than racing an OS-buffered backlog.
    let deadline = Instant::now() + Duration::from_millis(200);
    let mut buf = [0u8; 2048];
    let mut drained = 0u64;
    while Instant::now() < deadline && drained < sent {
        match receiver.recv(&mut buf) {
            Ok(_) => drained += 1,
            Err(_) => std::thread::sleep(Duration::from_millis(2)),
        }
    }

    Ok(sent)
}

/// A single counter source's classification plus whatever corroborating
/// sources were checked. GAP-043's hard requirement: a zero-drop verdict
/// may never rest on one source that has only been proven *readable* --
/// it must also be proven *live*, and even then a second, independent
/// source must corroborate before "zero drops" is reported.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZeroDropVerdict {
    pub primary_source: String,
    pub primary_live: bool,
    pub corroborating_sources: Vec<String>,
    /// `None` unless both the primary source is live AND at least one
    /// corroborating source was supplied and agrees. This is the gate the
    /// acceptance criterion describes as "require an alternate source...
    /// before issuing a zero-drop verdict".
    pub verdict: Option<bool>,
    pub explanation: String,
}

pub fn qualify_zero_drop_claim(
    primary_source: &str,
    primary_bracket: &LivenessBracket,
    primary_drops_observed: u64,
    corroborating_sources: &[(String, u64)],
) -> ZeroDropVerdict {
    let primary_live = primary_bracket.verdict.is_usable();

    if !primary_live {
        return ZeroDropVerdict {
            primary_source: primary_source.to_string(),
            primary_live: false,
            corroborating_sources: corroborating_sources.iter().map(|(n, _)| n.clone()).collect(),
            verdict: None,
            explanation: format!(
                "primary source '{}' failed liveness bracketing ({:?}); a zero-drop reading from an unproven-live counter is withheld, not reported",
                primary_source, primary_bracket.verdict
            ),
        };
    }

    if corroborating_sources.is_empty() {
        return ZeroDropVerdict {
            primary_source: primary_source.to_string(),
            primary_live: true,
            corroborating_sources: vec![],
            verdict: None,
            explanation: "primary source is live, but no corroborating source was supplied; a zero-drop verdict requires at least one independent corroborating source (AP/controller telemetry or capture)".to_string(),
        };
    }

    let all_agree_zero =
        primary_drops_observed == 0 && corroborating_sources.iter().all(|(_, d)| *d == 0);

    ZeroDropVerdict {
        primary_source: primary_source.to_string(),
        primary_live: true,
        corroborating_sources: corroborating_sources
            .iter()
            .map(|(n, _)| n.clone())
            .collect(),
        verdict: Some(all_agree_zero),
        explanation: if all_agree_zero {
            format!(
                "primary source live and reports 0 drops, corroborated by {} independent source(s) also reporting 0",
                corroborating_sources.len()
            )
        } else {
            "primary and corroborating sources disagree, or a nonzero drop count was observed by at least one source".to_string()
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn right_anchored_parse_handles_link_row_with_no_address_column() {
        let sample = "Name       Mtu   Network       Address            Ipkts Ierrs     Ibytes    Opkts Oerrs     Obytes  Coll\nlo0        16384 <Link#1>                      198863802     0 2278739684880 198863802     0 2278739684880     0\n";
        assert_eq!(
            parse_rx_packets_right_anchored(sample, "lo0"),
            Some(198863802)
        );
    }

    #[test]
    fn right_anchored_parse_handles_link_row_with_address_column() {
        let sample = "Name       Mtu   Network       Address            Ipkts Ierrs     Ibytes    Opkts Oerrs     Obytes  Coll\nen0        1500  <Link#14>   ca:86:b7:85:e2:33 32826500     0 42035483011 36105402     0 46481108372     0\n";
        assert_eq!(
            parse_rx_packets_right_anchored(sample, "en0"),
            Some(32826500)
        );
    }

    #[test]
    fn frozen_counter_never_yields_live() {
        let b = classify_delta("iw-station", 5000, 100, 100);
        assert_eq!(b.verdict, LivenessVerdict::Frozen);
        assert!(!b.verdict.is_usable());
    }

    #[test]
    fn live_counter_advances_within_tolerance() {
        let b = classify_delta("lo0", 2000, 100_000, 102_000);
        assert_eq!(b.verdict, LivenessVerdict::Live);
        assert!(b.verdict.is_usable());
    }

    #[test]
    fn small_backwards_jump_is_reset_not_wrapped() {
        let b = classify_delta("iw-station", 2000, 5_000, 4_950);
        assert_eq!(b.verdict, LivenessVerdict::Reset);
    }

    #[test]
    fn large_backwards_jump_near_u32_boundary_is_wrapped() {
        // Reconstructed advance = (u32::MAX + 1 - before) + after = 1000 +
        // 1000 = 2000, matching the known stimulus -- a real wrap, not an
        // unexplained anomaly.
        let before: u64 = 4_294_966_296;
        let after: u64 = 1_000;
        let b = classify_delta("iw-station", 2000, before, after);
        assert_eq!(b.verdict, LivenessVerdict::Wrapped);
    }

    #[test]
    fn genuine_zero_stimulus_is_never_frozen() {
        let b = classify_delta("iw-station", 0, 100, 100);
        assert_ne!(b.verdict, LivenessVerdict::Frozen);
        assert_eq!(b.verdict, LivenessVerdict::Unattributable);
    }

    #[test]
    fn zero_drop_verdict_withheld_without_corroboration() {
        let bracket = classify_delta("iw-station", 2000, 100, 2100);
        let v = qualify_zero_drop_claim("iw-station", &bracket, 0, &[]);
        assert!(v.verdict.is_none());
    }

    #[test]
    fn zero_drop_verdict_withheld_when_primary_frozen() {
        let bracket = classify_delta("iw-station", 2000, 100, 100);
        let v = qualify_zero_drop_claim("iw-station", &bracket, 0, &[("capture".to_string(), 0)]);
        assert!(v.verdict.is_none());
        assert!(!v.primary_live);
    }

    #[test]
    fn zero_drop_verdict_issued_with_live_primary_and_corroboration() {
        let bracket = classify_delta("iw-station", 2000, 100, 2100);
        let v = qualify_zero_drop_claim("iw-station", &bracket, 0, &[("capture".to_string(), 0)]);
        assert_eq!(v.verdict, Some(true));
    }

    #[test]
    fn disagreeing_corroboration_refuses_zero_drop() {
        let bracket = classify_delta("iw-station", 2000, 100, 2100);
        let v = qualify_zero_drop_claim("iw-station", &bracket, 0, &[("capture".to_string(), 3)]);
        assert_eq!(v.verdict, Some(false));
    }

    #[test]
    fn loopback_stimulus_sends_the_requested_count() {
        let sent = send_loopback_stimulus(500, 32).unwrap();
        assert_eq!(sent, 500);
    }
}
