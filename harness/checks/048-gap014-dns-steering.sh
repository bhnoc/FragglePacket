#!/usr/bin/env bash
# GAP-014: UDP/DoT/DoH health alone doesn't expose resolver steering.
# Field evidence: internal and public resolvers returned different GitHub
# edge IPs for the same query. This locks: two resolvers returning
# different endpoint sets is reported as steering divergence, not one
# resolver being "wrong"; resolution timing/TTLs stay per-resolver, never
# averaged; and a comparison whose legs used different resolvers is
# flagged. All offline via the underlying unit tests plus CLI --help/error
# path checks -- live divergence detection depends on network conditions
# outside this gate's control, so the decision logic itself is what's
# locked here, exercised directly rather than via a live query.

check_contains "dns-steering advertises --resolver (repeatable)" "--resolver" \
    "$BIN" dns-steering --help
check_contains "dns-steering advertises --json" "--json" \
    "$BIN" dns-steering --help

# --- fewer than two resolvers refuses to run rather than guessing ---
check_fails "dns-steering with no --resolver refuses to run" \
    "$BIN" dns-steering github.com

# --- unit-level guarantees behind the divergence/consistency decision ---
check_ok "cargo test proves identical answers report consistent" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib network_tests::dns_steering::tests::identical_endpoints_report_consistent 2>&1 | grep -q '1 passed'"
check_ok "cargo test proves different answers are divergence, not a fault label" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib network_tests::dns_steering::tests::different_endpoints_are_divergence_not_a_fault_label 2>&1 | grep -q '1 passed'"
check_ok "cargo test proves fewer than two answering resolvers is inconclusive, not a forced verdict" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib network_tests::dns_steering::tests::fewer_than_two_answering_resolvers_is_inconclusive 2>&1 | grep -q '1 passed'"
check_ok "cargo test proves an absent record type is reported absent, not an error" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib network_tests::dns_steering::tests::empty_answer_is_absent_not_error 2>&1 | grep -q '1 passed'"
check_ok "cargo test proves TTL is captured per-answer" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib network_tests::dns_steering::tests::parses_dig_answer_line_with_ttl 2>&1 | grep -q '1 passed'"

# --- resolver-mismatch warning mirrors protocol-compare's endpoint check ---
check_ok "cargo test proves the resolver-mismatch warning fires only on distinct resolvers" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib network_tests::dns_steering::tests::mismatch_warning_fires_only_on_different_resolvers 2>&1 | grep -q '1 passed'"

# --- human output never states "resolver X is wrong" ---
if net_guard; then
    out="$("$BIN" dns-steering github.com --resolver 1.1.1.1 --resolver 8.8.8.8 --timeout-secs 2 2>&1)"
    if [ -z "$out" ]; then
        skip "live dns-steering run produces per-resolver output" "no output / no network"
    else
        check_lacks "human output never labels a resolver as wrong/incorrect" "wrong" \
            "$BIN" dns-steering github.com --resolver 1.1.1.1 --resolver 8.8.8.8 --timeout-secs 2
        check_contains "human output shows per-resolver query timing, not one averaged figure" "query_time_ms (per-resolver, not averaged)" \
            "$BIN" dns-steering github.com --resolver 1.1.1.1 --resolver 8.8.8.8 --timeout-secs 2
    fi
else
    skip "live dns-steering run against public resolvers" "FP_HARNESS_OFFLINE=1"
fi
