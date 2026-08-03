#!/usr/bin/env bash
# GAP-064: two commands (media-quality, burst-analysis) already refuse to
# report one-way delay without a verified clock offset -- this locks the
# guard that supplies that verification honestly. CENTRAL REGRESSION: an
# offset must never be reported bare (without its uncertainty bound), and
# a skew beyond the configured threshold must refuse the one-way claim
# and name the measured skew, never silently adjust for it. All offline
# via unit tests exercising the pure decision logic; a live NTP round trip
# is exercised separately in the report, not this gate.

check_contains "clock-guard advertises --max-skew-ms" "--max-skew-ms" \
    "$BIN" clock-guard --help
check_contains "clock-guard advertises --ntp-server" "--ntp-server" \
    "$BIN" clock-guard --help

check_ok "cargo test: within-tolerance skew permits a one-way claim" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib network_tests::clock_guard::tests::within_tolerance_permits_one_way_claim 2>&1 | grep -q '1 passed'"
check_ok "cargo test CENTRAL REGRESSION: skew beyond threshold refuses the one-way claim and names the skew" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib network_tests::clock_guard::tests::exceeds_tolerance_refuses_one_way_claim_and_names_skew 2>&1 | grep -q '1 passed'"
check_ok "cargo test: uncertainty inflates the bound past tolerance rather than being ignored" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib network_tests::clock_guard::tests::uncertainty_inflates_the_bound_past_tolerance 2>&1 | grep -q '1 passed'"
check_ok "cargo test CENTRAL REGRESSION: a failed NTP query never defaults offset to zero" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib network_tests::clock_guard::tests::failed_ntp_query_never_defaults_to_zero_offset 2>&1 | grep -q '1 passed'"
check_ok "cargo test: offset is never reported without its uncertainty bound" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib network_tests::clock_guard::tests::offset_is_never_reported_without_its_uncertainty 2>&1 | grep -q '1 passed'"
check_ok "cargo test: both monotonic and wall-clock timestamps are always present" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib network_tests::clock_guard::tests::both_timestamp_kinds_are_always_present 2>&1 | grep -q '1 passed'"
check_ok "cargo test: same-node events correlate monotonically without a clock verdict" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib network_tests::clock_guard::tests::same_node_events_correlate_monotonically_without_a_clock_verdict 2>&1 | grep -q '1 passed'"
check_ok "cargo test: cross-node merge without a verified clock is unverified, not assumed ordered" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib network_tests::clock_guard::tests::cross_node_merge_without_verified_clocks_is_unverified 2>&1 | grep -q '1 passed'"
check_ok "cargo test: cross-node merge with both verified reports a combined uncertainty bound" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib network_tests::clock_guard::tests::cross_node_merge_with_both_verified_reports_combined_uncertainty 2>&1 | grep -q '1 passed'"

# --- OffsetWithBound structurally cannot exist without uncertainty_ms ---
check_contains "OffsetWithBound always carries uncertainty_ms alongside offset_ms" "uncertainty_ms" \
    grep -A 8 "pub struct OffsetWithBound" "$REPO_ROOT/src/network_tests/clock_guard.rs"

if net_guard; then
    out="$("$BIN" clock-guard --ntp-server time.apple.com --max-skew-ms 1000 --timeout-secs 5 --json 2>/dev/null | sed -n '/^{/,$p')"
    if [ -z "$out" ]; then
        skip "live clock-guard run reports offset with uncertainty" "no output / no network"
    else
        offset="$(printf '%s' "$out" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["offset"]["offset_ms"] if d["offset"] else None)' 2>/dev/null)"
        uncertainty="$(printf '%s' "$out" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["offset"]["uncertainty_ms"] if d["offset"] else None)' 2>/dev/null)"
        if [ "$offset" != "None" ] && [ "$uncertainty" != "None" ]; then
            pass "live clock-guard run against time.apple.com reports offset ($offset ms) with uncertainty ($uncertainty ms)"
        else
            skip "live clock-guard run reports offset with uncertainty" "offset=$offset uncertainty=$uncertainty (network condition)"
        fi
    fi
else
    skip "live clock-guard run against time.apple.com" "FP_HARNESS_OFFLINE=1"
fi
