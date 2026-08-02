//! GAP-031: normalized, qualified per-phase interface-counter deltas.
//!
//! Field evidence: a wired interface accumulated 17,517 cumulative drops
//! across a near-gigabit suite while a separately bracketed 350 Mbps
//! bidirectional UDP phase, timed with its own before/after snapshot, added
//! zero. The cumulative total attributed nothing to anything; the per-phase
//! bracket (already the shape `load_guard::counters` snapshots in) attributed
//! everything. This module is the normalization/qualification layer that
//! turns a raw before/after `InterfaceCounters` pair into a reportable delta:
//! per-packet and per-byte rates rather than a bare count, host/driver drops
//! kept structurally distinct from remote loss (this interface never sees
//! remote loss directly -- only its own local errors/drops), and an explicit
//! qualification whenever the counters cannot be trusted as-is.

use crate::load_guard::counters::InterfaceCounters;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeltaQualification {
    /// The delta is usable as-is.
    Clean,
    /// `after` regressed below `before` on at least one field -- a wrap or
    /// an interface reset, not a real negative count. See
    /// `InterfaceCounters::usable_delta_from`, which this reuses.
    CounterWrappedOrReset,
    /// The interface carries traffic this phase did not generate (e.g. `en0`
    /// with background OS/app traffic on a shared machine). A drop delta on
    /// such an interface cannot be attributed to the phase alone -- it is
    /// evidence about the interface during the window, not about the phase.
    SharedInterfaceUnrelatedTraffic,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CounterDelta {
    pub interface: String,
    pub elapsed_secs: f64,
    pub qualification: DeltaQualification,
    /// Raw before/after retained regardless of qualification -- evidence is
    /// never discarded just because a derived rate is withheld.
    pub before: InterfaceCounters,
    pub after: InterfaceCounters,
    /// `None` whenever `qualification != Clean`: a normalized rate computed
    /// from an untrustworthy delta would be exactly the "number with no
    /// referent" failure mode this project keeps re-finding (GAP-009,
    /// GAP-019, GAP-027, `--fake-radio`, `gateway-bracket`). Withhold, don't
    /// caveat-and-print.
    pub normalized: Option<NormalizedDelta>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedDelta {
    /// Host/driver-visible errors and drops on this interface during the
    /// window -- NOT remote loss. A local NIC/driver error counter can never
    /// observe a packet dropped somewhere else on the path; conflating the
    /// two is how a driver-side stat gets misread as network loss.
    pub host_driver_rx_errors: u64,
    pub host_driver_tx_errors: u64,
    pub rx_packets_delta: u64,
    pub tx_packets_delta: u64,
    pub rx_bytes_delta: u64,
    pub tx_bytes_delta: u64,
    pub rx_errors_per_1k_packets: f64,
    pub tx_errors_per_1k_packets: f64,
    pub rx_bytes_per_sec: f64,
    pub tx_bytes_per_sec: f64,
}

/// Interfaces known to carry non-test background traffic on a typical
/// developer machine. `en0`/`en1` are physical adapters that also serve the
/// OS, iCloud sync, background app traffic, etc.; a drop delta there during
/// a phase is not attributable to the phase alone unless the caller has
/// independently isolated the interface (e.g. a dedicated test VLAN).
pub fn interface_likely_shares_traffic(interface: &str) -> bool {
    interface.starts_with("en") || interface.starts_with("eth") || interface.starts_with("wlan")
}

/// Builds a qualified, normalized delta from a before/after snapshot pair.
/// `assume_isolated` lets a caller who has verified the interface carries
/// only this phase's traffic (e.g. a dedicated test link) opt out of the
/// shared-traffic qualification; default callers should pass `false`.
pub fn compute_delta(
    interface: &str,
    before: InterfaceCounters,
    after: InterfaceCounters,
    elapsed_secs: f64,
    assume_isolated: bool,
) -> CounterDelta {
    let qualification = if !after.usable_delta_from(&before) {
        DeltaQualification::CounterWrappedOrReset
    } else if !assume_isolated && interface_likely_shares_traffic(interface) {
        DeltaQualification::SharedInterfaceUnrelatedTraffic
    } else {
        DeltaQualification::Clean
    };

    let normalized = if qualification == DeltaQualification::Clean {
        let rx_packets_delta = after.rx_packets - before.rx_packets;
        let tx_packets_delta = after.tx_packets - before.tx_packets;
        let rx_bytes_delta = after.rx_bytes - before.rx_bytes;
        let tx_bytes_delta = after.tx_bytes - before.tx_bytes;
        let host_driver_rx_errors = after.rx_errors.saturating_sub(before.rx_errors);
        let host_driver_tx_errors = after.tx_errors.saturating_sub(before.tx_errors);

        let per_1k = |errors: u64, packets: u64| {
            if packets == 0 {
                0.0
            } else {
                (errors as f64 / packets as f64) * 1000.0
            }
        };
        let per_sec = |bytes: u64| {
            if elapsed_secs <= 0.0 {
                0.0
            } else {
                bytes as f64 / elapsed_secs
            }
        };

        Some(NormalizedDelta {
            host_driver_rx_errors,
            host_driver_tx_errors,
            rx_packets_delta,
            tx_packets_delta,
            rx_bytes_delta,
            tx_bytes_delta,
            rx_errors_per_1k_packets: per_1k(host_driver_rx_errors, rx_packets_delta),
            tx_errors_per_1k_packets: per_1k(host_driver_tx_errors, tx_packets_delta),
            rx_bytes_per_sec: per_sec(rx_bytes_delta),
            tx_bytes_per_sec: per_sec(tx_bytes_delta),
        })
    } else {
        None
    };

    CounterDelta {
        interface: interface.to_string(),
        elapsed_secs,
        qualification,
        before,
        after,
        normalized,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn counters(rx_packets: u64, tx_packets: u64, rx_bytes: u64, tx_bytes: u64, rx_errors: u64, tx_errors: u64) -> InterfaceCounters {
        InterfaceCounters { rx_packets, tx_packets, rx_bytes, tx_bytes, rx_errors, tx_errors }
    }

    #[test]
    fn clean_isolated_delta_is_normalized() {
        let before = counters(1000, 1000, 100_000, 100_000, 0, 0);
        let after = counters(2000, 2000, 200_000, 200_000, 1, 0);
        let delta = compute_delta("lo0", before, after, 1.0, true);
        assert_eq!(delta.qualification, DeltaQualification::Clean);
        let n = delta.normalized.expect("clean delta must normalize");
        assert_eq!(n.rx_packets_delta, 1000);
        assert_eq!(n.rx_bytes_per_sec, 100_000.0);
        assert_eq!(n.host_driver_rx_errors, 1);
        assert!((n.rx_errors_per_1k_packets - 1.0).abs() < 1e-9);
    }

    #[test]
    fn wrapped_counters_withhold_normalized_delta() {
        let before = counters(2000, 1000, 100_000, 100_000, 0, 0);
        let after = counters(1000, 1000, 100_000, 100_000, 0, 0); // rx_packets went backwards
        let delta = compute_delta("lo0", before, after, 1.0, true);
        assert_eq!(delta.qualification, DeltaQualification::CounterWrappedOrReset);
        assert!(delta.normalized.is_none());
        // Raw evidence is retained even though the derived rate is withheld.
        assert_eq!(delta.before.rx_packets, 2000);
        assert_eq!(delta.after.rx_packets, 1000);
    }

    #[test]
    fn shared_interface_without_isolation_flag_withholds_normalized_delta() {
        let before = counters(1000, 1000, 100_000, 100_000, 0, 0);
        let after = counters(2000, 2000, 200_000, 200_000, 0, 0);
        let delta = compute_delta("en0", before, after, 1.0, false);
        assert_eq!(delta.qualification, DeltaQualification::SharedInterfaceUnrelatedTraffic);
        assert!(delta.normalized.is_none());
    }

    #[test]
    fn shared_interface_with_explicit_isolation_override_normalizes() {
        let before = counters(1000, 1000, 100_000, 100_000, 0, 0);
        let after = counters(2000, 2000, 200_000, 200_000, 0, 0);
        let delta = compute_delta("en0", before, after, 1.0, true);
        assert_eq!(delta.qualification, DeltaQualification::Clean);
        assert!(delta.normalized.is_some());
    }

    #[test]
    fn host_driver_errors_are_distinct_field_from_any_remote_concept() {
        // Structural check: NormalizedDelta has no field named anything like
        // "remote_loss" -- host/driver errors are the only loss-adjacent
        // figure this local-interface delta can honestly produce.
        let before = counters(1000, 1000, 100_000, 100_000, 5, 2);
        let after = counters(2000, 2000, 200_000, 200_000, 9, 2);
        let delta = compute_delta("lo0", before, after, 2.0, true);
        let n = delta.normalized.unwrap();
        assert_eq!(n.host_driver_rx_errors, 4);
        assert_eq!(n.host_driver_tx_errors, 0);
    }
}
