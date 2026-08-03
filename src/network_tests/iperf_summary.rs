//! Flat iperf3 JSON summary consumed directly by GAP-006/031/032/040/046
//! (`IperfSummary`). `iperf.rs` (GAP-039/036) is the richer typed parser
//! that keeps offered/sent/received/estimated-received and forward/bidir
//! evidence fully separate; this module is a flatter, field-level summary
//! several load-matrix commands parse iperf3 output into directly.
//!
//! Same non-negotiable rule as `iperf.rs`: an `error` key, or a `connected`
//! list that's empty, means the run produced no usable measurement, and
//! `usable()` must be checked (or `from_json` must have already zeroed the
//! rate fields to `None`) before any figure derived from this struct is
//! trusted. `udp_lost_percent` and `receiver_bits_per_second` are read from
//! `sum`/`sum_received`, never `sum_sent` -- see GAP-039's fixture trap.

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IperfSummary {
    pub version: Option<String>,
    pub error: Option<String>,
    /// `false` if `error` is present, or `start.connected` is an empty
    /// list, or the JSON couldn't be parsed at all.
    pub connected: bool,
    pub streams_established: u64,
    pub num_streams_requested: Option<u64>,
    pub requested_duration_secs: Option<f64>,
    pub sender_bytes: Option<u64>,
    pub sender_seconds: Option<f64>,
    pub sender_bits_per_second: Option<f64>,
    pub receiver_bytes: Option<u64>,
    pub receiver_seconds: Option<f64>,
    pub receiver_bits_per_second: Option<f64>,
    pub udp_lost_packets: Option<u64>,
    pub udp_packets: Option<u64>,
    pub udp_lost_percent: Option<f64>,
}

impl IperfSummary {
    /// A summary is usable only when the run actually connected and
    /// produced no top-level error. Callers must gate every derived figure
    /// on this rather than trusting `Option::is_some()` alone, since a
    /// hollow-but-present block (GAP-039's `sum_sent` trap) is filtered out
    /// before it ever reaches these fields, but a summary built from
    /// completely absent `end` data would otherwise look identical to one
    /// with nothing measured yet.
    pub fn usable(&self) -> bool {
        self.connected && self.error.is_none()
    }

    /// Parses a raw iperf3 `-J` JSON value into a flat summary. Never
    /// panics on a malformed document; missing/unexpected fields become
    /// `None`/defaults and `connected` becomes `false`.
    pub fn from_json(v: &Value) -> Self {
        let error = v.get("error").and_then(Value::as_str).map(|s| s.to_string());

        let start = v.get("start");
        let version = start.and_then(|s| s.get("version")).and_then(Value::as_str).map(|s| s.to_string());
        let connected_list_len =
            start.and_then(|s| s.get("connected")).and_then(Value::as_array).map(|a| a.len()).unwrap_or(0);

        let test_start = start.and_then(|s| s.get("test_start"));
        let num_streams_requested = test_start.and_then(|t| t.get("num_streams")).and_then(Value::as_u64);
        let requested_duration_secs = test_start.and_then(|t| t.get("duration")).and_then(Value::as_f64);

        let connected = error.is_none() && connected_list_len > 0;

        if !connected {
            return IperfSummary {
                version,
                error,
                connected: false,
                streams_established: 0,
                num_streams_requested,
                requested_duration_secs,
                sender_bytes: None,
                sender_seconds: None,
                sender_bits_per_second: None,
                receiver_bytes: None,
                receiver_seconds: None,
                receiver_bits_per_second: None,
                udp_lost_packets: None,
                udp_packets: None,
                udp_lost_percent: None,
            };
        }

        let end = v.get("end");
        let sum_sent = end.and_then(|e| e.get("sum_sent"));
        // For UDP, `sum_received` is the receiver's own account and is what
        // "achieved" means; `sum` is a legacy/estimated block. Prefer
        // `sum_received`, falling back to `sum` only when `sum_received`
        // is absent or hollow (packets: 0), never averaging the two.
        let sum_received_raw = end.and_then(|e| e.get("sum_received"));
        let sum_legacy = end.and_then(|e| e.get("sum"));

        let is_hollow = |block: &Value| -> bool {
            match block.get("packets").and_then(Value::as_u64) {
                Some(p) => p == 0,
                None => block.get("bytes").and_then(Value::as_u64).unwrap_or(0) == 0,
            }
        };

        let receiver_block = sum_received_raw
            .filter(|b| !is_hollow(b))
            .or_else(|| sum_legacy.filter(|b| !is_hollow(b)));

        let sender_block = sum_sent.filter(|b| !is_hollow(b));

        let sender_bytes = sender_block.and_then(|b| b.get("bytes")).and_then(Value::as_u64);
        let sender_seconds = sender_block.and_then(|b| b.get("seconds")).and_then(Value::as_f64);
        let sender_bits_per_second = sender_block.and_then(|b| b.get("bits_per_second")).and_then(Value::as_f64);

        let receiver_bytes = receiver_block.and_then(|b| b.get("bytes")).and_then(Value::as_u64);
        let receiver_seconds = receiver_block.and_then(|b| b.get("seconds")).and_then(Value::as_f64);
        let receiver_bits_per_second = receiver_block.and_then(|b| b.get("bits_per_second")).and_then(Value::as_f64);

        let udp_lost_packets = receiver_block.and_then(|b| b.get("lost_packets")).and_then(Value::as_u64);
        let udp_packets = receiver_block.and_then(|b| b.get("packets")).and_then(Value::as_u64);
        let udp_lost_percent = receiver_block.and_then(|b| b.get("lost_percent")).and_then(Value::as_f64);

        let streams_established =
            end.and_then(|e| e.get("streams")).and_then(Value::as_array).map(|a| a.len() as u64).unwrap_or(0);

        IperfSummary {
            version,
            error,
            connected,
            streams_established,
            num_streams_requested,
            requested_duration_secs,
            sender_bytes,
            sender_seconds,
            sender_bits_per_second,
            receiver_bytes,
            receiver_seconds,
            receiver_bits_per_second,
            udp_lost_packets,
            udp_packets,
            udp_lost_percent,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn fixture_json(name: &str) -> Value {
        let path = format!("{}/harness/fixtures/iperf/{}", env!("CARGO_MANIFEST_DIR"), name);
        let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {}", path, e));
        serde_json::from_str(&text).unwrap()
    }

    #[test]
    fn error_refused_is_not_usable() {
        let s = IperfSummary::from_json(&fixture_json("error-refused.json"));
        assert!(!s.usable());
        assert!(s.error.is_some());
        assert!(s.receiver_bits_per_second.is_none());
    }

    #[test]
    fn tcp_forward_is_usable_with_receiver_rate() {
        let s = IperfSummary::from_json(&fixture_json("tcp-forward-3.21.json"));
        assert!(s.usable());
        assert!(s.receiver_bits_per_second.unwrap() > 0.0);
    }

    #[test]
    fn udp_reverse_reads_loss_from_sum_received_not_sum_sent() {
        let s = IperfSummary::from_json(&fixture_json("udp-reverse-3.21.json"));
        assert!(s.usable());
        assert_eq!(s.udp_packets, Some(460));
        assert_eq!(s.udp_lost_percent, Some(0.0));
    }

    #[test]
    fn malformed_json_value_never_panics() {
        let v = serde_json::json!({"nonsense": true});
        let s = IperfSummary::from_json(&v);
        assert!(!s.connected);
        assert!(s.receiver_bits_per_second.is_none());
    }
}
