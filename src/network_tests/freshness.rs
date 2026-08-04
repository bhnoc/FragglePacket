//! GAP-075: an observation used to derive a figure must still be valid at the
//! moment the figure is emitted.
//!
//! A long sweep samples radio, interface, and route state once at the start and
//! keeps deriving from it for the rest of the run. GAP-035 already guards phase
//! boundaries against association changes, but nothing invalidated a figure
//! whose *input* aged out mid-run: a roam, DHCP renewal, or link-speed
//! renegotiation at t=30s leaves every later figure derived from the t=0
//! snapshot presented as though it had just been measured.
//!
//! `phy_normalized` is the concrete case. It divides offered load by
//! `phy_capacity_mbps`, a value read from one radio snapshot. If the client
//! roams to a 2x2 radio partway through, the denominator describes a link that
//! no longer exists, and every `offered_phy_fraction` after that point is wrong
//! while looking perfectly well-formed.
//!
//! Modelled on NOC's `CheckStatus.expired`: a stale answer resolves to
//! "unknown", never to the last known value. Time is tracked as
//! `elapsed_secs` from run start -- monotonic and consistent with the existing
//! `rf_survey` convention -- so a wall-clock step never fabricates staleness.

use serde::{Deserialize, Serialize};

/// How long a class of observation stays usable after it is taken.
///
/// These are deliberately short for properties that change without warning and
/// long for properties that are effectively static within one run. A horizon is
/// a claim about volatility, not about how expensive the measurement was.
pub mod horizons {
    /// Radio association state: band, width, MCS, PHY capacity. A roam can
    /// change all of it in under a second and gives no notification.
    pub const RADIO_SECS: f64 = 30.0;
    /// Interface counters and link speed: renegotiation is rare but a
    /// flap-and-relink at a lower speed is exactly what GAP-058 hunts.
    pub const LINK_SECS: f64 = 60.0;
    /// Assigned address and default route: bounded by DHCP lease renewal.
    pub const ADDRESSING_SECS: f64 = 120.0;
    /// Name resolution: bounded by the record's own TTL in principle, but a
    /// conservative floor is used because a diagnostic must not cache a
    /// steering decision across a whole run.
    pub const RESOLUTION_SECS: f64 = 60.0;
}

/// One observation plus when it was taken and how long it stays valid.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Observation<T> {
    pub value: T,
    /// Seconds from run start, monotonic. Not a wall clock: a clock step must
    /// never invent or erase staleness.
    pub taken_at_elapsed_secs: f64,
    /// Seconds after `taken_at_elapsed_secs` that this value remains usable.
    pub valid_for_secs: f64,
}

impl<T> Observation<T> {
    pub fn new(value: T, taken_at_elapsed_secs: f64, valid_for_secs: f64) -> Self {
        Observation { value, taken_at_elapsed_secs, valid_for_secs }
    }

    /// Age of this observation at `now_elapsed_secs`. Negative elapsed
    /// differences clamp to zero: an input timestamped after the figure is a
    /// caller bug, and treating it as negative age would silently mark a stale
    /// value fresh.
    pub fn age_secs(&self, now_elapsed_secs: f64) -> f64 {
        (now_elapsed_secs - self.taken_at_elapsed_secs).max(0.0)
    }

    /// Whether this observation may still be used at `now_elapsed_secs`.
    ///
    /// Non-finite timestamps or horizons are treated as stale rather than
    /// fresh: an unusable time value is a reason to refuse, not to trust.
    pub fn is_fresh_at(&self, now_elapsed_secs: f64) -> bool {
        if !self.taken_at_elapsed_secs.is_finite()
            || !self.valid_for_secs.is_finite()
            || !now_elapsed_secs.is_finite()
            || self.valid_for_secs < 0.0
        {
            return false;
        }
        self.age_secs(now_elapsed_secs) <= self.valid_for_secs
    }

    /// The value, but only while still inside its horizon. This is the whole
    /// point: a caller that reaches for the value through this method cannot
    /// accidentally use a stale one.
    pub fn fresh_value_at(&self, now_elapsed_secs: f64) -> Option<&T> {
        if self.is_fresh_at(now_elapsed_secs) {
            Some(&self.value)
        } else {
            None
        }
    }
}

/// Why a derived figure was withheld, or that it was not.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Freshness {
    /// Every input was inside its validity horizon.
    Fresh,
    /// At least one input aged out. Names the inputs and the worst overrun so
    /// the artifact says which observation went stale, not merely that one did.
    Stale { stale_inputs: Vec<String>, worst_age_secs: f64, horizon_secs: f64 },
}

impl Freshness {
    /// A derived figure may be emitted as a current measurement.
    pub fn permits_derived_figure(&self) -> bool {
        matches!(self, Freshness::Fresh)
    }
}

/// One named input's timing, for checking a whole figure at once.
#[derive(Debug, Clone)]
pub struct InputTiming {
    pub name: String,
    pub taken_at_elapsed_secs: f64,
    pub valid_for_secs: f64,
}

impl InputTiming {
    pub fn new(name: &str, taken_at_elapsed_secs: f64, valid_for_secs: f64) -> Self {
        InputTiming {
            name: name.to_string(),
            taken_at_elapsed_secs,
            valid_for_secs,
        }
    }
}

/// Checks every input behind a derived figure at the instant the figure is
/// emitted.
///
/// An empty input list is `Fresh`: a figure derived from nothing time-sensitive
/// has nothing to go stale. Callers that must not accept a figure with no
/// evidence at all should use the GAP-073 coverage rules, which is the question
/// of whether evidence exists rather than whether it is current.
pub fn check_freshness(inputs: &[InputTiming], now_elapsed_secs: f64) -> Freshness {
    let mut stale_inputs = Vec::new();
    let mut worst_age = 0.0f64;
    let mut worst_horizon = 0.0f64;

    for i in inputs {
        let obs = Observation::new((), i.taken_at_elapsed_secs, i.valid_for_secs);
        if !obs.is_fresh_at(now_elapsed_secs) {
            let age = obs.age_secs(now_elapsed_secs);
            stale_inputs.push(i.name.clone());
            // Report the input that overran its horizon by the most, which is
            // the one most likely to have actually changed.
            if age - i.valid_for_secs > worst_age - worst_horizon {
                worst_age = age;
                worst_horizon = i.valid_for_secs;
            }
        }
    }

    if stale_inputs.is_empty() {
        Freshness::Fresh
    } else {
        Freshness::Stale { stale_inputs, worst_age_secs: worst_age, horizon_secs: worst_horizon }
    }
}

/// A line for the artifact explaining a withheld figure. Returns `None` when
/// nothing was stale, so callers can emit unconditionally.
pub fn staleness_note(figure: &str, f: &Freshness) -> Option<String> {
    match f {
        Freshness::Fresh => None,
        Freshness::Stale { stale_inputs, worst_age_secs, horizon_secs } => Some(format!(
            "{figure}: withheld -- {} went stale ({:.0}s old, valid for {:.0}s). \
             The underlying state may have changed since it was sampled, so this \
             figure is not known now rather than being the last known value.",
            stale_inputs.join(", "),
            worst_age_secs,
            horizon_secs,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The motivating case: a radio snapshot taken at t=0 cannot justify a
    /// normalized fraction emitted at t=120.
    #[test]
    fn a_radio_snapshot_goes_stale_across_a_long_sweep() {
        let obs = Observation::new(1200.0, 0.0, horizons::RADIO_SECS);
        assert!(obs.is_fresh_at(10.0), "10s old is inside a 30s horizon");
        assert!(!obs.is_fresh_at(120.0), "120s old must not still be usable");
        assert_eq!(obs.fresh_value_at(120.0), None);
        assert_eq!(obs.fresh_value_at(10.0), Some(&1200.0));
    }

    #[test]
    fn a_stale_input_withholds_the_derived_figure() {
        let inputs = vec![
            InputTiming::new("phy_capacity_mbps", 0.0, horizons::RADIO_SECS),
            InputTiming::new("offered_mbps", 118.0, horizons::LINK_SECS),
        ];
        let f = check_freshness(&inputs, 120.0);
        assert!(!f.permits_derived_figure());
        match &f {
            Freshness::Stale { stale_inputs, .. } => {
                assert_eq!(stale_inputs, &vec!["phy_capacity_mbps".to_string()]);
            }
            other => panic!("expected Stale, got {other:?}"),
        }
        let note = staleness_note("offered_phy_fraction", &f).expect("must explain the withholding");
        assert!(note.contains("phy_capacity_mbps"), "{note}");
        assert!(note.contains("not known now"), "{note}");
    }

    #[test]
    fn all_inputs_inside_their_horizons_is_fresh() {
        let inputs = vec![
            InputTiming::new("phy_capacity_mbps", 100.0, horizons::RADIO_SECS),
            InputTiming::new("offered_mbps", 118.0, horizons::LINK_SECS),
        ];
        let f = check_freshness(&inputs, 120.0);
        assert_eq!(f, Freshness::Fresh);
        assert!(f.permits_derived_figure());
        assert!(staleness_note("offered_phy_fraction", &f).is_none());
    }

    /// Exactly at the horizon is still valid; one tick past is not.
    #[test]
    fn the_horizon_boundary_is_inclusive() {
        let obs = Observation::new(1, 0.0, 30.0);
        assert!(obs.is_fresh_at(30.0), "exactly at the horizon must remain usable");
        assert!(!obs.is_fresh_at(30.001), "past the horizon must not");
    }

    /// A clock that appears to move backwards must not make a stale value look
    /// fresh via negative age.
    #[test]
    fn a_backwards_time_step_never_refreshes_a_stale_value() {
        let obs = Observation::new(1, 100.0, 5.0);
        assert_eq!(obs.age_secs(50.0), 0.0, "negative elapsed clamps to zero");
        // Age 0 is inside the horizon, but the caller asked about a moment
        // before the sample existed; that is a caller bug, not freshness.
        // What must never happen is a LATER stale check passing.
        assert!(!obs.is_fresh_at(200.0));
    }

    #[test]
    fn a_nonfinite_timestamp_is_treated_as_stale_not_fresh() {
        let bad_taken = Observation::new(1, f64::NAN, 30.0);
        assert!(!bad_taken.is_fresh_at(10.0));
        let bad_horizon = Observation::new(1, 0.0, f64::NAN);
        assert!(!bad_horizon.is_fresh_at(10.0));
        let bad_now = Observation::new(1, 0.0, 30.0);
        assert!(!bad_now.is_fresh_at(f64::INFINITY));
    }

    #[test]
    fn a_negative_horizon_is_stale_not_permanently_valid() {
        let obs = Observation::new(1, 0.0, -5.0);
        assert!(!obs.is_fresh_at(0.0));
    }

    /// Several stale inputs must all be named, not just the first found.
    #[test]
    fn every_stale_input_is_named() {
        let inputs = vec![
            InputTiming::new("radio", 0.0, horizons::RADIO_SECS),
            InputTiming::new("route", 0.0, horizons::ADDRESSING_SECS),
            InputTiming::new("recent", 300.0, horizons::LINK_SECS),
        ];
        match check_freshness(&inputs, 310.0) {
            Freshness::Stale { stale_inputs, .. } => {
                assert_eq!(stale_inputs.len(), 2, "{stale_inputs:?}");
                assert!(stale_inputs.contains(&"radio".to_string()));
                assert!(stale_inputs.contains(&"route".to_string()));
            }
            other => panic!("expected Stale, got {other:?}"),
        }
    }

    /// Nothing time-sensitive means nothing to go stale.
    #[test]
    fn no_inputs_is_fresh_not_stale() {
        assert_eq!(check_freshness(&[], 1000.0), Freshness::Fresh);
    }
}
