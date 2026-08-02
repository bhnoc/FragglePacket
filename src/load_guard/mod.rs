//! Shared load-phase execution guard (GAP-027 radio guard + GAP-047 load
//! budget/abort guard). One mechanism: every load-generating command wraps
//! its phase in `LoadGuard::run` to get budget enforcement, progressive
//! ramp, pre/during/post radio + counter snapshots, abort thresholds, and a
//! structural validity verdict that blocks derived ratios on invalid runs.

pub mod budget;
pub mod counters;
pub mod guard;
pub mod radio;
pub mod route;

pub use budget::{AbortThresholds, BudgetError, LoadBudget, RunMode};
pub use counters::InterfaceCounters;
pub use guard::{
    compute_derived_ratio, CounterSource, DerivedMetrics, GuardReport, InvalidReason, LoadGuard,
    LoadPhase, PhaseTick, RadioSource, RadioTimeline, RawMetrics, StopReason, Validity,
};
pub use radio::{classify_rf, RadioSnapshot, RfQuality};
pub use route::{detect_live as detect_default_route, RouteInfo};
