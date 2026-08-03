//! Shared load-phase execution guard (GAP-027 radio guard + GAP-047 load
//! budget/abort guard). One mechanism: every load-generating command wraps
//! its phase in `LoadGuard::run` to get budget enforcement, progressive
//! ramp, pre/during/post radio + counter snapshots, abort thresholds, and a
//! structural validity verdict that blocks derived ratios on invalid runs.

pub mod ap_identity;
pub mod budget;
pub mod counter_deltas;
pub mod counters;
pub mod guard;
pub mod independent_rates;
pub mod radio;
pub mod radio_diagnostic;
pub mod route;
pub mod tcp_vs_udp;
pub mod wdutil;

pub use ap_identity::{compare as compare_ap_identity, label_for_bssid, load_or_create_salt, ApComparison, ApIdentity};
pub use budget::{AbortThresholds, BudgetError, LoadBudget, RunMode};
pub use counter_deltas::{compute_delta, CounterDelta, DeltaQualification, NormalizedDelta};
pub use counters::InterfaceCounters;
pub use independent_rates::{
    first_lossy_rate, merge_timeline, Direction, DirectionSweep, FirstLossyRate, MergedTimeline,
    RatePoint, SessionWindow,
};
pub use radio_diagnostic::{build_diagnostic, diagnose_live, RadioDiagnostic};
pub use tcp_vs_udp::{tcp_result, udp_result, Protocol, ProtocolResult, TcpVsUdpComparison};
pub use guard::{
    compute_derived_ratio, real_sources_for_interface, CounterSource, DerivedMetrics, GuardReport,
    InvalidReason, LoadGuard, LoadPhase, PhaseTick, RadioSource, RadioTimeline, RawMetrics,
    StopReason, Validity,
};
pub use radio::{classify_rf, RadioSnapshot, RfQuality};
pub use route::{detect_live as detect_default_route, RouteInfo};
pub use wdutil::{parse_wdutil_info, snapshot_live as wdutil_snapshot_live, WdutilError, WdutilFields};
