//! Load budget and abort thresholds (GAP-047).
//!
//! A `LoadBudget` is mandatory input — there is no `Default` impl and no
//! all-zero constructor that "just works." Callers must state a target rate,
//! a max duration, and max concurrency, or the guard refuses to start.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RunMode {
    Maintenance,
    LiveEvent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadBudget {
    pub mode: RunMode,
    pub target_rate_mbps: f64,
    pub max_duration_secs: u64,
    pub max_concurrency: u32,
    pub ramp_steps: u32,
    pub abort: AbortThresholds,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct AbortThresholds {
    pub max_gateway_latency_ms: f64,
    pub max_loss_pct: f64,
}

pub const LIVE_EVENT_MAX_RATE_MBPS: f64 = 50.0;
pub const LIVE_EVENT_MAX_DURATION_SECS: u64 = 30;
pub const LIVE_EVENT_MAX_CONCURRENCY: u32 = 2;

pub const MAINTENANCE_MAX_RATE_MBPS: f64 = 1000.0;
pub const MAINTENANCE_MAX_DURATION_SECS: u64 = 300;
pub const MAINTENANCE_MAX_CONCURRENCY: u32 = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BudgetError {
    RateExceedsCap {
        requested: String,
        cap: String,
        mode: RunMode,
    },
    DurationExceedsCap {
        requested: u64,
        cap: u64,
        mode: RunMode,
    },
    ConcurrencyExceedsCap {
        requested: u32,
        cap: u32,
        mode: RunMode,
    },
    ZeroRamp,
}

impl std::fmt::Display for BudgetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BudgetError::RateExceedsCap {
                requested,
                cap,
                mode,
            } => write!(
                f,
                "target rate {requested} Mbps exceeds {mode:?} cap of {cap} Mbps"
            ),
            BudgetError::DurationExceedsCap {
                requested,
                cap,
                mode,
            } => write!(
                f,
                "max duration {requested}s exceeds {mode:?} cap of {cap}s"
            ),
            BudgetError::ConcurrencyExceedsCap {
                requested,
                cap,
                mode,
            } => write!(
                f,
                "max concurrency {requested} exceeds {mode:?} cap of {cap}"
            ),
            BudgetError::ZeroRamp => {
                write!(f, "ramp_steps must be >= 1 (no starting at full rate)")
            }
        }
    }
}

impl LoadBudget {
    pub fn live_event(target_rate_mbps: f64, max_duration_secs: u64, max_concurrency: u32) -> Self {
        Self {
            mode: RunMode::LiveEvent,
            target_rate_mbps,
            max_duration_secs,
            max_concurrency,
            ramp_steps: 4,
            abort: AbortThresholds {
                max_gateway_latency_ms: 50.0,
                max_loss_pct: 2.0,
            },
        }
    }

    pub fn maintenance(
        target_rate_mbps: f64,
        max_duration_secs: u64,
        max_concurrency: u32,
    ) -> Self {
        Self {
            mode: RunMode::Maintenance,
            target_rate_mbps,
            max_duration_secs,
            max_concurrency,
            ramp_steps: 4,
            abort: AbortThresholds {
                max_gateway_latency_ms: 200.0,
                max_loss_pct: 10.0,
            },
        }
    }

    fn caps(&self) -> (f64, u64, u32) {
        match self.mode {
            RunMode::LiveEvent => (
                LIVE_EVENT_MAX_RATE_MBPS,
                LIVE_EVENT_MAX_DURATION_SECS,
                LIVE_EVENT_MAX_CONCURRENCY,
            ),
            RunMode::Maintenance => (
                MAINTENANCE_MAX_RATE_MBPS,
                MAINTENANCE_MAX_DURATION_SECS,
                MAINTENANCE_MAX_CONCURRENCY,
            ),
        }
    }

    /// Validates the budget against its mode's cap. This is the enforcement
    /// point for "never start maximum stress by default": a caller cannot
    /// request more than the mode allows, and live-event mode's caps are
    /// materially stricter than maintenance's.
    pub fn validate(&self) -> Result<(), BudgetError> {
        let (rate_cap, dur_cap, conc_cap) = self.caps();
        if self.target_rate_mbps > rate_cap {
            return Err(BudgetError::RateExceedsCap {
                requested: format!("{:.1}", self.target_rate_mbps),
                cap: format!("{:.1}", rate_cap),
                mode: self.mode,
            });
        }
        if self.max_duration_secs > dur_cap {
            return Err(BudgetError::DurationExceedsCap {
                requested: self.max_duration_secs,
                cap: dur_cap,
                mode: self.mode,
            });
        }
        if self.max_concurrency > conc_cap {
            return Err(BudgetError::ConcurrencyExceedsCap {
                requested: self.max_concurrency,
                cap: conc_cap,
                mode: self.mode,
            });
        }
        if self.ramp_steps == 0 {
            return Err(BudgetError::ZeroRamp);
        }
        Ok(())
    }

    /// Progressive ramp schedule: rates rising from a fraction of target to
    /// full target over `ramp_steps` steps, never starting at full rate.
    pub fn ramp_schedule(&self) -> Vec<f64> {
        (1..=self.ramp_steps)
            .map(|step| self.target_rate_mbps * (step as f64 / self.ramp_steps as f64))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_event_caps_stricter_than_maintenance() {
        assert!(LIVE_EVENT_MAX_RATE_MBPS < MAINTENANCE_MAX_RATE_MBPS);
        assert!(LIVE_EVENT_MAX_DURATION_SECS < MAINTENANCE_MAX_DURATION_SECS);
        assert!(LIVE_EVENT_MAX_CONCURRENCY < MAINTENANCE_MAX_CONCURRENCY);
    }

    #[test]
    fn live_event_rejects_maintenance_scale_rate() {
        let b = LoadBudget::live_event(500.0, 10, 1);
        assert!(matches!(
            b.validate(),
            Err(BudgetError::RateExceedsCap { .. })
        ));
    }

    #[test]
    fn maintenance_accepts_higher_rate_live_event_would_reject() {
        let b = LoadBudget::maintenance(500.0, 10, 1);
        assert!(b.validate().is_ok());
        let b2 = LoadBudget::live_event(500.0, 10, 1);
        assert!(b2.validate().is_err());
    }

    #[test]
    fn ramp_never_starts_at_full_rate() {
        let b = LoadBudget::maintenance(100.0, 10, 1);
        let schedule = b.ramp_schedule();
        assert!(schedule.first().copied().unwrap() < 100.0);
        assert_eq!(schedule.last().copied().unwrap(), 100.0);
    }

    #[test]
    fn zero_ramp_rejected() {
        let mut b = LoadBudget::maintenance(10.0, 10, 1);
        b.ramp_steps = 0;
        assert_eq!(b.validate(), Err(BudgetError::ZeroRamp));
    }
}
