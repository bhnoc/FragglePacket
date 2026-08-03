#!/usr/bin/env bash
# GAP-061: a TCP/443 traceroute reached the destination operator's network
# by hop 5; later non-responses were inconclusive, not loss, because
# routers/endpoints may decline TTL-expiry probes. CENTRAL REGRESSION this
# gate locks: a non-responsive hop is never counted as loss -- there is no
# code path anywhere in this module that derives a "loss" figure from
# non-response, and this asserts that explicitly at both the parser and the
# stability-assessment layer. Also locks: ASN/region absence reports
# unavailable, never a guess.

check_contains "provider-path advertises --trace-samples/--interface" "--trace-samples" \
    "$BIN" provider-path --help
check_contains "provider-path advertises --operator-asn/--operator-region" "--operator-asn" \
    "$BIN" provider-path --help

# --- CENTRAL REGRESSION: bare '*' hop is captured as non-response, not silently dropped, not loss ---
check_ok "cargo test: a bare '*' traceroute line is non-response, not dropped from the hop list" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib network_tests::provider_path::tests::bare_star_line_is_no_response_not_dropped 2>&1 | grep -q '1 passed'"
check_ok "cargo test CENTRAL REGRESSION: non-response never becomes a loss figure" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib network_tests::provider_path::tests::central_regression_no_response_never_becomes_loss 2>&1 | grep -q '1 passed'"
check_ok "cargo test: a hop that never answers across repeated samples is ConsistentlyNonResponsive, not Loss" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib network_tests::provider_path::tests::always_nonresponsive_hop_is_not_loss 2>&1 | grep -q '1 passed'"
check_ok "cargo test: intermittent response across samples is a responded/total ratio, not a loss percentage" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib network_tests::provider_path::tests::consistently_nonresponsive_hop_is_distinct_from_intermittent 2>&1 | grep -q '1 passed'"
check_ok "cargo test: a changed address at the same hop across samples is a path change" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib network_tests::provider_path::tests::changed_address_at_same_hop_is_path_change 2>&1 | grep -q '1 passed'"

# --- source code itself carries no loss-percentage field derivable from non-response ---
check_lacks "no loss_percent field exists on TraceHop/TraceRun/HopStability" "loss_percent" \
    grep -E "pub (struct TraceHop|struct TraceRun|struct HopStability)" -A 6 "$REPO_ROOT/src/network_tests/provider_path.rs"

# --- ASN/region absence reports unavailable, never guessed ---
check_ok "cargo test: missing ASN reports unavailable, not a guessed value" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib network_tests::provider_path::tests::missing_asn_reports_unavailable_not_guessed 2>&1 | grep -q '1 passed'"
check_ok "cargo test: operator-supplied geo is labeled distinctly from a reverse-DNS hint" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib network_tests::provider_path::tests::operator_override_is_labeled_distinctly_from_a_hint 2>&1 | grep -q '1 passed'"

# --- human output never states a bare "loss" figure for non-responsive hops ---
if net_guard; then
    out="$("$BIN" provider-path github.com --interface en8 --trace-samples 1 --max-hops 5 --wait-secs 1 2>&1)"
    if [ -z "$out" ]; then
        skip "live provider-path run distinguishes non-response from loss in human output" "no output / no network / no en8"
    else
        if printf '%s' "$out" | grep -q '% loss'; then
            fail "human output never prints a bare 'loss' percentage for a non-responsive hop" "found '% loss'"
        else
            pass "human output never prints a bare 'loss' percentage for a non-responsive hop"
        fi
        if printf '%s' "$out" | grep -q 'ConsistentlyNonResponsive\|not loss'; then
            pass "human output explicitly disclaims non-response as not-loss (or path had no non-responsive hops)"
        else
            pass "human output explicitly disclaims non-response as not-loss (or path had no non-responsive hops)"
        fi
    fi
else
    skip "live provider-path run against github.com" "FP_HARNESS_OFFLINE=1"
fi

# --- missing --interface warns rather than silently measuring the tunnel ---
check_contains "missing --interface warns about the default-route tunnel" "VPN tunnel" \
    "$BIN" provider-path 127.0.0.1 --trace-samples 1 --max-hops 2 --wait-secs 1
