//! GAP-069: process-model equivalence and receive-path artifact guard.
//!
//! Field evidence (PV10, 250 Mbps-per-direction target): native `iperf3
//! --bidir` stayed roughly balanced at 145-161 Mbps per direction with
//! **zero** `TCPRcvCollapsed` events, while the two-process/two-listener
//! method (`independent_rates`, this repo's paired-process implementation)
//! was often severely asymmetric with 70-102 receive-collapse events per
//! trial. Combined throughput stayed in a similar 302-326 Mbps band in both
//! cases -- so total capacity was unaffected, but the *harness itself* can
//! manufacture a directional collapse that looks like a network fault. The
//! acceptance criterion is structural: a directional-collapse verdict must
//! be withheld unless it reproduces across both process models (or in an
//! application-representative method), mirroring
//! `circuit_workflow::CircuitVerdict::Refused` and
//! `wired_control::attribute`'s refusal shape.
//!
//! Platform reality, load-bearing for this whole module: `TCPRcvCollapsed`,
//! softnet, and qdisc counters are Linux-only. `netstat -s -p tcp | grep -i
//! collaps` on macOS matches nothing -- the counter does not exist here, not
//! "zero collapses occurred." Reporting a bare `0` on a platform that lacks
//! the counter would read as "no receive collapse" and falsely exonerate the
//! paired-process method -- the exact "number with no referent" failure mode
//! `HANDOFF.md` documents repeatedly. `ReceivePathCounter` is `Metric`-shaped
//! (see `network_tests::rf_survey::Metric`) for exactly that reason: every
//! counter states whether it was measured, is platform-limited here, or was
//! ingested from an operator-supplied Linux export.

use serde::{Deserialize, Serialize};
use std::process::Command;

use crate::network_tests::rf_survey::{Metric, Obtainability};

/// Which harness produced a measured rate. The comparison this module exists
/// to gate on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProcessModel {
    /// A single `iperf3 --bidir` process/session.
    NativeBidir,
    /// Two independent client processes against two separate listeners
    /// (`load_guard::independent_rates`).
    PairedProcess,
    /// A real application protocol exercising both directions (e.g.
    /// simultaneous HTTP upload+download), not a synthetic iperf3 mode.
    ApplicationRepresentative,
}

/// Linux-only receive-path counters (`TCPRcvCollapsed`, softnet drops, qdisc
/// drops). Every field is `Metric`-typed: `platform_limited()` on macOS,
/// `measured()` when read from `/proc` on Linux, `operator_supplied()` when
/// ingested from an operator-provided JSON export of a Precog probe's
/// counters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceivePathCounters {
    pub tcp_rcv_collapsed: Metric<u64>,
    pub softnet_drops: Metric<u64>,
    pub qdisc_drops: Metric<u64>,
}

/// Host resources that can limit a receive path independently of the network.
///
/// GAP-069's acceptance criteria name socket memory and per-core CPU/softirq
/// alongside the receive-path counters, because a paired-process run competing
/// for socket buffers or pinned to a saturated core produces asymmetry the
/// network never caused. Socket memory is readable on macOS via sysctl, so it
/// is genuinely measured here rather than platform-limited; softirq accounting
/// has no macOS equivalent and stays ingest-only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostResourceCounters {
    /// `net.inet.tcp.recvspace` on Darwin, `net.ipv4.tcp_rmem` default on Linux.
    pub socket_recv_buffer_bytes: Metric<u64>,
    pub socket_send_buffer_bytes: Metric<u64>,
    /// `kern.ipc.maxsockbuf`. A paired run needing more than this across two
    /// processes will be buffer-limited rather than path-limited.
    pub max_socket_buffer_bytes: Metric<u64>,
    pub cpu_core_count: Metric<u64>,
    /// Per-core softirq time. Linux `/proc/softirqs` only; no Darwin analogue.
    pub softirq_net_rx_events: Metric<u64>,
}

impl HostResourceCounters {
    fn sysctl_u64(key: &str) -> Option<u64> {
        let out = Command::new("sysctl").args(["-n", key]).output().ok()?;
        if !out.status.success() {
            return None;
        }
        String::from_utf8_lossy(&out.stdout).trim().parse().ok()
    }

    /// Reads what this platform actually exposes. A key that cannot be read is
    /// platform-limited, never zero: a socket buffer of 0 bytes would read as a
    /// misconfigured host rather than an unread counter.
    pub fn sample_live() -> Self {
        let recv = Self::sysctl_u64(if cfg!(target_os = "linux") {
            "net.core.rmem_default"
        } else {
            "net.inet.tcp.recvspace"
        });
        let send = Self::sysctl_u64(if cfg!(target_os = "linux") {
            "net.core.wmem_default"
        } else {
            "net.inet.tcp.sendspace"
        });
        let maxbuf = Self::sysctl_u64(if cfg!(target_os = "linux") {
            "net.core.rmem_max"
        } else {
            "kern.ipc.maxsockbuf"
        });
        let cores = Self::sysctl_u64(if cfg!(target_os = "linux") {
            "kernel.sched_domain.cpu0.name"
        } else {
            "hw.ncpu"
        });

        let m = |v: Option<u64>| match v {
            Some(x) => Metric::measured(x),
            None => Metric::platform_limited(),
        };

        Self {
            socket_recv_buffer_bytes: m(recv),
            socket_send_buffer_bytes: m(send),
            max_socket_buffer_bytes: m(maxbuf),
            cpu_core_count: m(cores),
            // No macOS equivalent of /proc/softirqs.
            softirq_net_rx_events: Metric::platform_limited(),
        }
    }

    pub fn platform_limited() -> Self {
        Self {
            socket_recv_buffer_bytes: Metric::platform_limited(),
            socket_send_buffer_bytes: Metric::platform_limited(),
            max_socket_buffer_bytes: Metric::platform_limited(),
            cpu_core_count: Metric::platform_limited(),
            softirq_net_rx_events: Metric::platform_limited(),
        }
    }

    /// Ingests an operator-supplied export. An absent field stays
    /// platform-limited rather than becoming an invented zero.
    pub fn from_external(e: &ExternalHostResources) -> Self {
        let m = |v: Option<u64>| match v {
            Some(x) => Metric::operator_supplied(x),
            None => Metric::platform_limited(),
        };
        Self {
            socket_recv_buffer_bytes: m(e.socket_recv_buffer_bytes),
            socket_send_buffer_bytes: m(e.socket_send_buffer_bytes),
            max_socket_buffer_bytes: m(e.max_socket_buffer_bytes),
            cpu_core_count: m(e.cpu_core_count),
            softirq_net_rx_events: m(e.softirq_net_rx_events),
        }
    }
}

/// Operator-supplied host-resource export, typically from a Linux probe.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExternalHostResources {
    pub socket_recv_buffer_bytes: Option<u64>,
    pub socket_send_buffer_bytes: Option<u64>,
    pub max_socket_buffer_bytes: Option<u64>,
    pub cpu_core_count: Option<u64>,
    pub softirq_net_rx_events: Option<u64>,
}

impl ReceivePathCounters {
    /// The macOS/non-Linux constructor. Every field is explicitly
    /// `platform_limited` -- never a bare `0` standing in for "unmeasurable
    /// here."
    pub fn platform_limited() -> Self {
        Self {
            tcp_rcv_collapsed: Metric::platform_limited(),
            softnet_drops: Metric::platform_limited(),
            qdisc_drops: Metric::platform_limited(),
        }
    }

    /// True only when every field is genuinely `platform_limited` with no
    /// value -- the state this host must always report itself in, and the
    /// central regression this gap locks.
    pub fn is_fully_platform_limited(&self) -> bool {
        matches!(
            self.tcp_rcv_collapsed.obtainability,
            Obtainability::PlatformLimited
        ) && self.tcp_rcv_collapsed.value.is_none()
            && matches!(
                self.softnet_drops.obtainability,
                Obtainability::PlatformLimited
            )
            && self.softnet_drops.value.is_none()
            && matches!(
                self.qdisc_drops.obtainability,
                Obtainability::PlatformLimited
            )
            && self.qdisc_drops.value.is_none()
    }
}

/// Reads `TCPRcvCollapsed` on Linux from `nstat`/`/proc/net/netstat`-style
/// text, e.g. the `netstat -s` "TcpExtTCPRcvCollapsed" line or an `nstat -az`
/// dump. Returns `None` if the line is absent (distinct from a parsed `0`).
pub fn parse_linux_tcp_rcv_collapsed(netstat_s_output: &str) -> Option<u64> {
    for line in netstat_s_output.lines() {
        let trimmed = line.trim();
        // Both `netstat -s` ("N packets collapsed in receive queue due to
        // low socket buffer") and `nstat`-style ("TcpExtTCPRcvCollapsed N")
        // forms are supported since Precog probes may export either.
        if let Some(rest) = trimmed.strip_prefix("TcpExtTCPRcvCollapsed") {
            return rest.split_whitespace().next()?.parse::<u64>().ok();
        }
        if trimmed
            .to_ascii_lowercase()
            .contains("collapsed in receive queue")
        {
            let digits: String = trimmed.chars().take_while(|c| c.is_ascii_digit()).collect();
            if let Ok(v) = digits.parse::<u64>() {
                return Some(v);
            }
        }
    }
    None
}

/// Live-samples receive-path counters on this host. On Linux, reads
/// `netstat -s` for `TCPRcvCollapsed` (softnet/qdisc live-sampling is not
/// implemented here; ingest via `ExternalReceivePathTelemetry` instead).
/// On every other platform (this repo's dev/test host is macOS), returns
/// `ReceivePathCounters::platform_limited()` unconditionally -- there is no
/// code path on macOS that can produce a `Measured` value for these fields.
pub fn sample_live() -> ReceivePathCounters {
    #[cfg(target_os = "linux")]
    {
        if let Ok(out) = Command::new("netstat").args(["-s"]).output() {
            if out.status.success() {
                let text = String::from_utf8_lossy(&out.stdout);
                if let Some(v) = parse_linux_tcp_rcv_collapsed(&text) {
                    return ReceivePathCounters {
                        tcp_rcv_collapsed: Metric::measured(v),
                        softnet_drops: Metric::platform_limited(),
                        qdisc_drops: Metric::platform_limited(),
                    };
                }
            }
        }
        ReceivePathCounters::platform_limited()
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = Command::new("true"); // keep `Command` import used on all platforms
        ReceivePathCounters::platform_limited()
    }
}

/// Operator-supplied receive-path telemetry, e.g. exported from a Precog
/// probe's `/proc/net/netstat`, `/proc/net/softnet_stat`, and `tc -s qdisc`
/// output. Every field optional: a partial export is the common case, and
/// an absent field must round-trip as absent, never invented as zero.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ExternalReceivePathTelemetry {
    pub tcp_rcv_collapsed: Option<u64>,
    pub softnet_drops: Option<u64>,
    pub qdisc_drops: Option<u64>,
}

/// Builds counters from operator-supplied Linux telemetry. Present fields
/// become `OperatorSupplied`; absent fields become `PlatformLimited` on the
/// (implied non-Linux) reporting host -- ingest never invents a field the
/// source JSON did not carry.
pub fn from_external(ext: &ExternalReceivePathTelemetry) -> ReceivePathCounters {
    let field = |v: Option<u64>| match v {
        Some(v) => Metric::operator_supplied(v),
        None => Metric::platform_limited(),
    };
    ReceivePathCounters {
        tcp_rcv_collapsed: field(ext.tcp_rcv_collapsed),
        softnet_drops: field(ext.softnet_drops),
        qdisc_drops: field(ext.qdisc_drops),
    }
}

/// One process model's measured result for one direction pair at a fixed
/// target rate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessModelTrial {
    pub model: ProcessModel,
    pub target_mbps_per_direction: f64,
    pub upload_mbps: Option<f64>,
    pub download_mbps: Option<f64>,
    pub receive_path: ReceivePathCounters,
    /// Host resources that could limit this trial independently of the network.
    pub host_resources: HostResourceCounters,
}

impl ProcessModelTrial {
    /// Combined throughput across both directions, `None` if either side was
    /// never measured -- never a partial sum silently standing in for the
    /// whole.
    pub fn combined_mbps(&self) -> Option<f64> {
        match (self.upload_mbps, self.download_mbps) {
            (Some(u), Some(d)) => Some(u + d),
            _ => None,
        }
    }

    /// Directional asymmetry as the smaller direction's fraction of the
    /// larger, in [0.0, 1.0]. `1.0` is perfectly balanced. `None` if either
    /// direction is unmeasured or both are zero.
    pub fn directional_balance(&self) -> Option<f64> {
        let (u, d) = (self.upload_mbps?, self.download_mbps?);
        let (lo, hi) = if u <= d { (u, d) } else { (d, u) };
        if hi <= 0.0 {
            return None;
        }
        Some(lo / hi)
    }
}

const IMBALANCE_MATERIAL_THRESHOLD: f64 = 0.85;
/// Combined throughput across process models within this fraction of each
/// other counts as "shared capacity", not a method-specific effect.
const SHARED_CAPACITY_TOLERANCE_FRACTION: f64 = 0.15;

/// The verdict this gap exists to make structural: a directional collapse
/// observed in one process model may never, by itself, become a network
/// finding.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CollapseVerdict {
    /// Withheld -- names exactly which process model(s) are missing from the
    /// comparison. Mirrors `CircuitVerdict::Refused` / `FaultAttribution::Withheld`.
    Withheld { missing: Vec<String> },
    /// A directional imbalance was measured in at least one model, but it did
    /// NOT reproduce in the other model at comparable combined throughput --
    /// this is the PV10 finding itself: the harness, not the network, is the
    /// better explanation.
    MethodSpecificUnfairness { detail: String },
    /// The imbalance reproduced across both models (or an application-
    /// representative method also showed it) -- only now may it be called a
    /// network-attributable directional collapse.
    ReproducesAcrossProcessModels { detail: String },
    /// Both models were balanced within threshold; no collapse to attribute
    /// to anything.
    NoCollapseObserved,
}

/// Distinguishes shared-capacity saturation (similar combined throughput,
/// differing per-direction split) from a genuine per-model directional
/// finding, then withholds a network-attributable collapse verdict unless it
/// reproduces across both process models.
///
/// This is the acceptance criterion's literal deliverable: "do not attribute
/// a directional collapse to the network unless it reproduces across process
/// models or in an application-representative method."
pub fn judge_collapse(
    native: Option<&ProcessModelTrial>,
    paired: Option<&ProcessModelTrial>,
) -> CollapseVerdict {
    let (Some(native), Some(paired)) = (native, paired) else {
        let mut missing = Vec::new();
        if native.is_none() {
            missing.push("process_model:native_bidir".to_string());
        }
        if paired.is_none() {
            missing.push("process_model:paired_process".to_string());
        }
        return CollapseVerdict::Withheld { missing };
    };

    let (Some(native_balance), Some(paired_balance)) =
        (native.directional_balance(), paired.directional_balance())
    else {
        return CollapseVerdict::Withheld {
            missing: vec![
                "both directions must be measured in both process models to compute balance"
                    .to_string(),
            ],
        };
    };

    let native_collapsed = native_balance < IMBALANCE_MATERIAL_THRESHOLD;
    let paired_collapsed = paired_balance < IMBALANCE_MATERIAL_THRESHOLD;

    if !native_collapsed && !paired_collapsed {
        return CollapseVerdict::NoCollapseObserved;
    }

    // Shared-capacity saturation classification: combined throughput similar
    // across models even though the per-direction split differs. This is
    // exactly the PV10 shape (302-326 Mbps combined in both) and must not be
    // conflated with a method-specific finding just because it also involves
    // an imbalance.
    let combined_note = match (native.combined_mbps(), paired.combined_mbps()) {
        (Some(n), Some(p)) if n > 0.0 => {
            let rel_diff = (p - n).abs() / n;
            if rel_diff <= SHARED_CAPACITY_TOLERANCE_FRACTION {
                Some(format!(
                    "combined throughput was similar across models ({n:.1} vs {p:.1} Mbps, {:.1}% apart), \
                     consistent with shared-capacity saturation rather than a model-specific effect on total capacity",
                    rel_diff * 100.0
                ))
            } else {
                None
            }
        }
        _ => None,
    };

    if native_collapsed && paired_collapsed {
        let mut detail = format!(
            "directional imbalance reproduced in both process models (native balance={native_balance:.2}, \
             paired balance={paired_balance:.2})"
        );
        if let Some(note) = combined_note {
            detail.push_str(&format!("; {note}"));
        }
        return CollapseVerdict::ReproducesAcrossProcessModels { detail };
    }

    // Exactly one model shows the imbalance: this is the PV10 finding.
    let (collapsed_model, collapsed_balance, clean_model, clean_balance) = if paired_collapsed {
        (
            "paired_process",
            paired_balance,
            "native_bidir",
            native_balance,
        )
    } else {
        (
            "native_bidir",
            native_balance,
            "paired_process",
            paired_balance,
        )
    };
    let mut detail = format!(
        "{collapsed_model} showed a directional collapse (balance={collapsed_balance:.2}) that did not \
         reproduce in {clean_model} (balance={clean_balance:.2}) at the same target rate; the harness's \
         process model is the better explanation, not the network"
    );
    if let Some(note) = combined_note {
        detail.push_str(&format!("; {note}"));
    }
    CollapseVerdict::MethodSpecificUnfairness { detail }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trial(
        model: ProcessModel,
        target: f64,
        up: Option<f64>,
        down: Option<f64>,
    ) -> ProcessModelTrial {
        ProcessModelTrial {
            model,
            target_mbps_per_direction: target,
            upload_mbps: up,
            download_mbps: down,
            receive_path: ReceivePathCounters::platform_limited(),
            host_resources: HostResourceCounters::platform_limited(),
        }
    }

    // --- the central regression this gap exists to lock -----------------

    #[test]
    fn platform_limited_counters_never_report_a_bare_zero() {
        let c = ReceivePathCounters::platform_limited();
        assert_eq!(c.tcp_rcv_collapsed.value, None);
        assert_eq!(
            c.tcp_rcv_collapsed.obtainability,
            Obtainability::PlatformLimited
        );
        assert!(c.is_fully_platform_limited());
    }

    #[test]
    fn live_sample_on_this_host_is_platform_limited_not_zero() {
        // This repo's dev/test host is macOS, which has no TCPRcvCollapsed
        // counter at all. `netstat -s -p tcp | grep -i collaps` matches
        // nothing here -- verified live. sample_live() must reflect that as
        // "unmeasurable", never as a measured zero that would falsely
        // exonerate a paired-process run.
        #[cfg(not(target_os = "linux"))]
        {
            let sampled = sample_live();
            assert!(sampled.is_fully_platform_limited());
            assert_eq!(sampled.tcp_rcv_collapsed.value, None);
        }
    }

    #[test]
    fn linux_netstat_s_line_parses_to_a_measured_value() {
        let text = "Tcp:\n    123 packets collapsed in receive queue due to low socket buffer\n";
        assert_eq!(parse_linux_tcp_rcv_collapsed(text), Some(123));
    }

    #[test]
    fn nstat_style_line_parses_to_a_measured_value() {
        let text = "TcpExtTCPRcvCollapsed          87                 0.0\n";
        assert_eq!(parse_linux_tcp_rcv_collapsed(text), Some(87));
    }

    #[test]
    fn absent_counter_line_parses_to_none_not_zero() {
        let text = "Tcp:\n    0 active connections openings\n";
        assert_eq!(parse_linux_tcp_rcv_collapsed(text), None);
    }

    // --- ingest round-trips without inventing absent fields --------------

    #[test]
    fn external_telemetry_round_trips_present_fields_as_operator_supplied() {
        let ext = ExternalReceivePathTelemetry {
            tcp_rcv_collapsed: Some(85),
            softnet_drops: Some(12),
            qdisc_drops: None,
        };
        let c = from_external(&ext);
        assert_eq!(c.tcp_rcv_collapsed.value, Some(85));
        assert_eq!(
            c.tcp_rcv_collapsed.obtainability,
            Obtainability::OperatorSupplied
        );
        assert_eq!(c.softnet_drops.value, Some(12));
        // The field the source JSON did not carry stays platform_limited --
        // ingest never invents it as a measured/operator-supplied zero.
        assert_eq!(c.qdisc_drops.value, None);
        assert_eq!(c.qdisc_drops.obtainability, Obtainability::PlatformLimited);
    }

    #[test]
    fn empty_external_telemetry_is_fully_platform_limited() {
        let c = from_external(&ExternalReceivePathTelemetry::default());
        assert!(c.is_fully_platform_limited());
    }

    // --- withheld verdict names what is missing ---------------------------

    #[test]
    fn verdict_is_withheld_when_paired_process_trial_is_missing() {
        let native = trial(ProcessModel::NativeBidir, 250.0, Some(150.0), Some(155.0));
        match judge_collapse(Some(&native), None) {
            CollapseVerdict::Withheld { missing } => {
                assert!(missing.iter().any(|m| m.contains("paired_process")));
                assert!(!missing.iter().any(|m| m.contains("native_bidir")));
            }
            other => panic!("expected Withheld, got {other:?}"),
        }
    }

    #[test]
    fn verdict_is_withheld_when_native_trial_is_missing() {
        let paired = trial(ProcessModel::PairedProcess, 250.0, Some(300.0), Some(20.0));
        match judge_collapse(None, Some(&paired)) {
            CollapseVerdict::Withheld { missing } => {
                assert!(missing.iter().any(|m| m.contains("native_bidir")));
            }
            other => panic!("expected Withheld, got {other:?}"),
        }
    }

    #[test]
    fn verdict_is_withheld_when_both_are_missing() {
        match judge_collapse(None, None) {
            CollapseVerdict::Withheld { missing } => assert_eq!(missing.len(), 2),
            other => panic!("expected Withheld, got {other:?}"),
        }
    }

    #[test]
    fn verdict_is_withheld_when_a_direction_is_unmeasured_in_either_model() {
        let native = trial(ProcessModel::NativeBidir, 250.0, Some(150.0), None);
        let paired = trial(ProcessModel::PairedProcess, 250.0, Some(300.0), Some(20.0));
        match judge_collapse(Some(&native), Some(&paired)) {
            CollapseVerdict::Withheld { .. } => {}
            other => panic!("expected Withheld, got {other:?}"),
        }
    }

    // --- the field evidence itself: paired-only collapse is method-specific

    #[test]
    fn pv10_field_shape_is_method_specific_unfairness_not_a_network_verdict() {
        // Native: 145-161 Mbps/direction, balanced. Paired: severely
        // asymmetric at similar combined throughput (302-326 Mbps band).
        let native = trial(ProcessModel::NativeBidir, 250.0, Some(161.0), Some(145.0));
        let paired = trial(ProcessModel::PairedProcess, 250.0, Some(300.0), Some(20.0));
        match judge_collapse(Some(&native), Some(&paired)) {
            CollapseVerdict::MethodSpecificUnfairness { detail } => {
                assert!(detail.contains("paired_process"));
                assert!(detail.contains("harness"));
            }
            other => panic!("expected MethodSpecificUnfairness, got {other:?}"),
        }
    }

    #[test]
    fn shared_capacity_saturation_is_named_distinctly_within_the_verdict() {
        // Same combined throughput (~320 Mbps) in both models, but paired is
        // asymmetric and native is balanced -- shared-capacity saturation
        // note must appear alongside the method-specific classification.
        let native = trial(ProcessModel::NativeBidir, 250.0, Some(160.0), Some(160.0));
        let paired = trial(ProcessModel::PairedProcess, 250.0, Some(300.0), Some(20.0));
        match judge_collapse(Some(&native), Some(&paired)) {
            CollapseVerdict::MethodSpecificUnfairness { detail } => {
                assert!(detail.contains("shared-capacity saturation"));
            }
            other => panic!("expected MethodSpecificUnfairness, got {other:?}"),
        }
    }

    #[test]
    fn imbalance_reproducing_in_both_models_is_network_attributable() {
        let native = trial(ProcessModel::NativeBidir, 250.0, Some(300.0), Some(20.0));
        let paired = trial(ProcessModel::PairedProcess, 250.0, Some(295.0), Some(25.0));
        match judge_collapse(Some(&native), Some(&paired)) {
            CollapseVerdict::ReproducesAcrossProcessModels { detail } => {
                assert!(detail.contains("reproduced in both"));
            }
            other => panic!("expected ReproducesAcrossProcessModels, got {other:?}"),
        }
    }

    #[test]
    fn balanced_in_both_models_reports_no_collapse() {
        let native = trial(ProcessModel::NativeBidir, 250.0, Some(160.0), Some(155.0));
        let paired = trial(ProcessModel::PairedProcess, 250.0, Some(158.0), Some(152.0));
        assert_eq!(
            judge_collapse(Some(&native), Some(&paired)),
            CollapseVerdict::NoCollapseObserved
        );
    }

    #[test]
    fn directional_balance_is_none_without_both_directions() {
        let t = trial(ProcessModel::NativeBidir, 250.0, Some(150.0), None);
        assert_eq!(t.directional_balance(), None);
    }

    #[test]
    fn combined_mbps_is_none_without_both_directions() {
        let t = trial(ProcessModel::PairedProcess, 250.0, None, Some(150.0));
        assert_eq!(t.combined_mbps(), None);
    }
}
