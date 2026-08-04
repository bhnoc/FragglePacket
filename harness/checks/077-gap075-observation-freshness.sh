#!/usr/bin/env bash
# GAP-075: an observation used to derive a figure must still be valid at the
# moment the figure is emitted.
#
# phy-normalized divides offered load by phy_capacity_mbps, a value read from
# one radio snapshot at the start of a run. A roam changes PHY capacity in under
# a second and gives no notification, so every fraction computed after that point
# described a link that no longer existed -- while looking perfectly well-formed.
#
# The rule this locks: staleness reads as "not known now", never as the last
# known value. Modelled on NOC's CheckStatus.expired, which drops an expired
# check into unknown rather than serving it as current.
#
# Offline and deterministic: all of this is pure time arithmetic over
# operator-supplied JSON, so nothing here needs a network.

check_ok "cargo test covers observation horizons and staleness" \
    cargo test --release --lib network_tests::freshness --manifest-path "$REPO_ROOT/Cargo.toml"

check_ok "cargo test proves a radio snapshot goes stale across a long sweep" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib network_tests::freshness::tests::a_radio_snapshot_goes_stale_across_a_long_sweep 2>&1 | grep -q '1 passed'"

check_ok "cargo test proves a stale input withholds the derived figure" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib network_tests::freshness::tests::a_stale_input_withholds_the_derived_figure 2>&1 | grep -q '1 passed'"

# A non-finite or backwards clock must fail closed, not open.
check_ok "cargo test proves a nonfinite timestamp is stale, not fresh" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib network_tests::freshness::tests::a_nonfinite_timestamp_is_treated_as_stale_not_fresh 2>&1 | grep -q '1 passed'"

check_ok "cargo test proves a backwards time step never refreshes a stale value" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib network_tests::freshness::tests::a_backwards_time_step_never_refreshes_a_stale_value 2>&1 | grep -q '1 passed'"

# --- the horizon must be applied by the consumer, not just defined ---
check_ok "cargo test proves a stale PHY denominator withholds the fraction" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib network_tests::phy_normalized::tests::a_stale_phy_denominator_withholds_the_fraction 2>&1 | grep -q '1 passed'"

check_ok "cargo test proves a fresh denominator still yields a fraction" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib network_tests::phy_normalized::tests::a_fresh_phy_denominator_still_yields_a_fraction 2>&1 | grep -q '1 passed'"

# A withheld figure must not silently drag a cohort mean toward zero. This was a
# real pre-existing bug found while wiring the horizon in: the mean divided a
# FILTERED sum by the UNFILTERED sample count.
check_ok "cargo test proves a stratum mean divides by the usable sample count" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib network_tests::phy_normalized::tests::a_stratum_mean_divides_by_the_usable_sample_count 2>&1 | grep -q '1 passed'"

check_ok "cargo test proves a zero PHY capacity withholds rather than producing NaN" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib network_tests::phy_normalized::tests::a_zero_phy_capacity_withholds_rather_than_producing_nan 2>&1 | grep -q '1 passed'"

check_ok "cargo test proves attribution is withheld when a cohort fraction is absent" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib network_tests::phy_normalized::tests::attribution_is_withheld_when_a_cohort_fraction_is_absent 2>&1 | grep -q '1 passed'"

# --- end to end: a stale denominator must print as withheld, never as a number ---
fr_dir="$WORK_DIR/gap075-freshness"
rm -rf "$fr_dir"; mkdir -p "$fr_dir"

# Sampled at t=0, measured at t=600: ten minutes past a 30s radio horizon.
cat > "$fr_dir/stale.json" <<'JSON'
[{
  "node": {
    "node_id": "PV10", "phy_generation": "He", "driver": "brcm", "kernel": "24.0.0",
    "phy_capacity_mbps": 866.0, "rf_quality": "Strong", "directional_control": true
  },
  "offered_mbps": 400.0,
  "loss_percent": 1.0,
  "phy_sampled_at_elapsed_secs": 0.0,
  "measured_at_elapsed_secs": 600.0
}]
JSON

stale_out="$("$BIN" phy-normalized --measurements-file "$fr_dir/stale.json" 2>&1 || true)"
if [ -z "$stale_out" ]; then
    skip "a stale PHY denominator prints as withheld" "no output"
else
    check_contains "a stale PHY denominator prints as withheld" "withheld" \
        bash -c 'printf "%s" "$1"' _ "$stale_out"

    # The figure must be absent, not rendered as a percentage.
    if printf '%s' "$stale_out" | grep -qE '[0-9]+\.[0-9]% of PHY'; then
        fail "a stale run prints no PHY percentage" "a percentage was printed from a stale denominator"
    else
        pass "a stale run prints no PHY percentage"
    fi

    # The reason must be stated, not merely the absence.
    check_contains "the stale run names the input that expired" "phy_capacity_mbps" \
        bash -c 'printf "%s" "$1"' _ "$stale_out"

    # Absolute inputs are still reported: only the DERIVED figure is withheld.
    check_contains "the stale run still reports the absolute offered rate" "400" \
        bash -c 'printf "%s" "$1"' _ "$stale_out"
fi

# A fresh run must still produce its fraction, or the horizon is just breakage.
cat > "$fr_dir/fresh.json" <<'JSON'
[{
  "node": {
    "node_id": "PV10", "phy_generation": "He", "driver": "brcm", "kernel": "24.0.0",
    "phy_capacity_mbps": 866.0, "rf_quality": "Strong", "directional_control": true
  },
  "offered_mbps": 400.0,
  "loss_percent": 1.0,
  "phy_sampled_at_elapsed_secs": 100.0,
  "measured_at_elapsed_secs": 110.0
}]
JSON

fresh_out="$("$BIN" phy-normalized --measurements-file "$fr_dir/fresh.json" 2>&1 || true)"
if [ -z "$fresh_out" ]; then
    skip "a fresh run still reports its PHY fraction" "no output"
elif printf '%s' "$fresh_out" | grep -qE '% of PHY'; then
    pass "a fresh run still reports its PHY fraction"
else
    fail "a fresh run still reports its PHY fraction" \
        "the horizon suppressed a figure that was inside it"
fi

# Timing is optional: existing callers that record none must keep working.
cat > "$fr_dir/untimed.json" <<'JSON'
[{
  "node": {
    "node_id": "PV10", "phy_generation": "He", "driver": "brcm", "kernel": "24.0.0",
    "phy_capacity_mbps": 866.0, "rf_quality": "Strong", "directional_control": true
  },
  "offered_mbps": 400.0,
  "loss_percent": 1.0
}]
JSON

untimed_out="$("$BIN" phy-normalized --measurements-file "$fr_dir/untimed.json" 2>&1 || true)"
if [ -z "$untimed_out" ]; then
    skip "an untimed measurement is still normalized" "no output"
elif printf '%s' "$untimed_out" | grep -qE '% of PHY'; then
    pass "an untimed measurement is still normalized"
else
    fail "an untimed measurement is still normalized" \
        "adding optional timing fields broke callers that omit them"
fi
