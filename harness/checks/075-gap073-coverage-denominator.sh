#!/usr/bin/env bash
# GAP-073: an aggregate verdict must be computed over what was ATTEMPTED.
#
# kitchen-sink used to collect "all successful MTU measurements" and divide by
# that collection's length. A target that never answered contributed no entry,
# so it left the denominator entirely: 18 of 20 unreachable plus 2 answering at
# 1500 printed "PASS - No MTU changes needed" at "100% of tests at 1500 MTU".
#
# The rule this locks: a probe that did not answer is missing evidence, never a
# silent pass, and an all-skipped set must never aggregate to success. This is
# the same failure family as GAP-009 (zero latency), GAP-019 (phantom oversize
# frames), and GAP-031 (clean qualification from counters never read).

check_ok "cargo test covers the coverage denominator and vacuous-set rules" \
    cargo test --release --lib network_tests::coverage --manifest-path "$REPO_ROOT/Cargo.toml"

# The field case: unreachable targets stay in the denominator.
check_ok "cargo test proves unreachable targets stay in the denominator" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib network_tests::coverage::tests::unreachable_targets_stay_in_the_denominator 2>&1 | grep -q '1 passed'"

# Vacuous truth: nothing measured must never read as success.
check_ok "cargo test proves an all-skipped set never aggregates to success" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib network_tests::coverage::tests::all_skipped_never_aggregates_to_success 2>&1 | grep -q '1 passed'"

# 0/0 is unknown, not 0%.
check_ok "cargo test proves nothing-attempted is unknown, not zero percent" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib network_tests::coverage::tests::nothing_attempted_is_unknown_not_zero_percent 2>&1 | grep -q '1 passed'"

# --- the coverage gate must be wired into the command, not just the library ---
# A library that enforces this while the caller ignores it is the original bug.
ks_src="$REPO_ROOT/src/cli/commands/kitchen_sink.rs"
if [ ! -f "$ks_src" ]; then
    fail "kitchen-sink consults the coverage gate before printing a verdict" "source file absent"
elif grep -q "supports_conclusion" "$ks_src"; then
    pass "kitchen-sink consults the coverage gate before printing a verdict"
else
    fail "kitchen-sink consults the coverage gate before printing a verdict" \
        "no supports_conclusion() call: the verdict is not coverage-gated"
fi

# The denominator must never be the count of successful measurements again.
if grep -qE 'as f64 / (total_tests|mtu_values\.len\(\)) as f64\) \* 100\.0' "$ks_src" \
    && ! grep -q "coverage" "$ks_src"; then
    fail "the pass rate is not divided by the successful-measurement count alone" \
        "pct is derived from measured count with no coverage accounting"
else
    pass "the pass rate is not divided by the successful-measurement count alone"
fi

# --- end-to-end: a mostly-unreachable target list must refuse a verdict ---
# TEST-NET-1 (RFC 5737 192.0.2.0/24) is reserved and never routed, so these
# targets cannot answer. Offline-safe: it needs no working network, only that
# these addresses stay silent.
ks_dir="$WORK_DIR/gap073-kitchen-sink"
rm -rf "$ks_dir"; mkdir -p "$ks_dir"
{
    printf '192.0.2.1,dead-1,443\n'
    printf '192.0.2.2,dead-2,443\n'
    printf '192.0.2.3,dead-3,443\n'
    printf '192.0.2.4,dead-4,443\n'
    printf '192.0.2.5,dead-5,443\n'
} > "$ks_dir/targets.txt"

ks_out="$(cd "$ks_dir" && "$BIN" kitchen-sink --max 1500 2>&1)"

if [ -z "$ks_out" ]; then
    skip "an all-unreachable run refuses a verdict" "no output"
else
    # Must NOT claim a pass off zero characterized targets.
    if printf '%s' "$ks_out" | grep -qE '^\s+PASS '; then
        fail "an all-unreachable run refuses a verdict" \
            "printed PASS with no target characterized"
    else
        pass "an all-unreachable run refuses a verdict"
    fi

    check_contains "the refusal names coverage as the reason" "NO VERDICT" \
        bash -c 'printf "%s" "$1"' _ "$ks_out"

    # The artifact must state what was missing, not merely omit it.
    if printf '%s' "$ks_out" | grep -qiE "did not answer|not attempted|of 5 characterized"; then
        pass "the run states how many targets went uncharacterized"
    else
        fail "the run states how many targets went uncharacterized" \
            "no attempted-vs-characterized accounting in output"
    fi

    # A percentage that would read as network-wide health must not stand alone.
    if printf '%s' "$ks_out" | grep -qE 'No MTU changes needed'; then
        fail "an unreachable run never recommends keeping the current MTU" \
            "recommended no change despite measuring nothing"
    else
        pass "an unreachable run never recommends keeping the current MTU"
    fi
fi
