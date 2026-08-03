#!/usr/bin/env bash
# GAP-017: run confidence and endpoint-normalization controls, generalized
# from protocol_compare.rs's per-command version. CENTRAL REGRESSION this
# locks: a single-sample run can never claim more than Low confidence, and
# constructing RunStats with sample_count<=1 forces variance to None even
# if a caller (mistakenly) passes Some(0.0) -- there is no shape in which a
# one-sample run reports a real-looking variance of 0.0.

check_ok "cargo test covers run_confidence's stats/confidence logic" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib network_tests::run_confidence:: 2>&1 | grep -q 'test result: ok'"
check_ok "cargo test CENTRAL REGRESSION: a single sample never exceeds Low confidence" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib network_tests::run_confidence::tests::single_sample_never_exceeds_low_confidence 2>&1 | grep -q '1 passed'"
check_ok "cargo test CENTRAL REGRESSION: single-sample construction forces variance to None even if a caller passes Some(0.0)" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib network_tests::run_confidence::tests::single_sample_construction_forces_variance_none_even_if_caller_passes_a_value 2>&1 | grep -q '1 passed'"
check_ok "cargo test: three clean samples with warm-up handled reaches High" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib network_tests::run_confidence::tests::three_clean_samples_with_warm_up_not_skipped_reaches_high 2>&1 | grep -q '1 passed'"
check_ok "cargo test: a skipped warm-up caps confidence below High" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib network_tests::run_confidence::tests::skipped_warm_up_caps_confidence_below_high 2>&1 | grep -q '1 passed'"
check_ok "cargo test: multiple samples with no computed variance still cap at Low" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib network_tests::run_confidence::tests::two_samples_without_computed_variance_is_low 2>&1 | grep -q '1 passed'"
check_ok "cargo test: matching per-leg endpoint IPs report no mismatch" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib network_tests::run_confidence::tests::matching_endpoints_report_no_mismatch 2>&1 | grep -q '1 passed'"
check_ok "cargo test: differing per-leg endpoint IPs report a mismatch with detail" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib network_tests::run_confidence::tests::differing_endpoints_report_mismatch_with_detail 2>&1 | grep -q '1 passed'"
check_ok "cargo test: variance computed via Welford's method matches the manual calculation" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib network_tests::run_confidence::tests::variance_computed_via_welford_matches_manual_calc 2>&1 | grep -q '1 passed'"

# --- wired into provider-path: a single trace sample reports Low confidence, never a bare/high one ---
if net_guard; then
    single_out="$("$BIN" provider-path github.com --interface en8 --trace-samples 1 --max-hops 3 --wait-secs 1 --json 2>/dev/null | sed -n '/^{/,$p')"
    if [ -z "$single_out" ]; then
        skip "provider-path with a single trace sample reports Low run confidence" "no output / no network / no en8"
    else
        confidence="$(printf '%s' "$single_out" | python3 -c 'import json,sys; print(json.load(sys.stdin)["run_confidence"])' 2>/dev/null)"
        variance="$(printf '%s' "$single_out" | python3 -c 'import json,sys; print(json.load(sys.stdin)["run_stats"]["variance"])' 2>/dev/null)"
        if [ "$confidence" = "Low" ]; then
            pass "provider-path with a single trace sample reports Low run confidence"
        else
            fail "provider-path with a single trace sample reports Low run confidence" "got: $confidence"
        fi
        if [ "$variance" = "None" ]; then
            pass "provider-path with a single trace sample reports variance as unavailable (None), never 0.0"
        else
            fail "provider-path with a single trace sample reports variance as unavailable (None), never 0.0" "got: $variance"
        fi
    fi

    multi_out="$("$BIN" provider-path github.com --interface en8 --trace-samples 3 --max-hops 3 --wait-secs 1 --json 2>/dev/null | sed -n '/^{/,$p')"
    if [ -n "$multi_out" ]; then
        sample_count="$(printf '%s' "$multi_out" | python3 -c 'import json,sys; print(json.load(sys.stdin)["run_stats"]["sample_count"])' 2>/dev/null)"
        if [ "$sample_count" = "3" ]; then
            pass "provider-path with 3 trace samples records sample_count=3"
        else
            fail "provider-path with 3 trace samples records sample_count=3" "got: $sample_count"
        fi
    else
        skip "provider-path with 3 trace samples records sample_count=3" "no output / no network / no en8"
    fi
else
    skip "provider-path run-confidence live checks" "FP_HARNESS_OFFLINE=1"
fi
check_contains "human output states run confidence and sample count" "run confidence:" \
    "$BIN" provider-path 127.0.0.1 --trace-samples 1 --max-hops 2 --wait-secs 1
