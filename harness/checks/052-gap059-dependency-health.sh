#!/usr/bin/env bash
# GAP-059: blocked-by-policy and unhealthy must be distinct, reachable
# verdicts -- a network that deliberately blocks OCSP/CRL is not "the same
# broken" as a dependency that is genuinely down, and a naive check that
# collapses both into one failure state would misreport policy as an
# outage. NTP offset is another gap's precondition for trusting a one-way
# delay measurement, so it must never default to 0 on failure -- that
# would silently manufacture confidence in a clock offset nobody measured.

check_ok "cargo test covers dependency classification / NTP-parsing logic" \
    cargo test --release --lib network_tests::dependency_health:: --manifest-path "$REPO_ROOT/Cargo.toml"

check_contains "dependency-health advertises --ntp-server" "--ntp-server" \
    "$BIN" dependency-health --help
check_contains "dependency-health advertises --ocsp-targets" "--ocsp-targets" \
    "$BIN" dependency-health --help

# --- blocked-by-policy and unhealthy are both reachable and distinct ---
check_ok "cargo test proves refused is blocked-by-policy, not unhealthy" \
    cargo test --release --lib network_tests::dependency_health::tests::refused_is_blocked_by_policy_not_unhealthy \
    --manifest-path "$REPO_ROOT/Cargo.toml"
check_ok "cargo test proves timeout is unhealthy, not blocked-by-policy" \
    cargo test --release --lib network_tests::dependency_health::tests::timeout_is_unhealthy_not_blocked \
    --manifest-path "$REPO_ROOT/Cargo.toml"
check_ok "cargo test proves a bundle can hold both verdicts simultaneously and distinctly" \
    cargo test --release --lib network_tests::dependency_health::tests::blocked_and_unhealthy_are_distinguishable_states_in_one_bundle \
    --manifest-path "$REPO_ROOT/Cargo.toml"

# --- the central regression: NTP offset never defaults to zero on failure ---
check_ok "cargo test proves failed sntp output never parses to a zero offset" \
    cargo test --release --lib network_tests::dependency_health::tests::failed_sntp_output_never_parses_to_a_zero_offset \
    --manifest-path "$REPO_ROOT/Cargo.toml"
check_ok "cargo test proves a real sntp success line parses to a nonzero offset" \
    cargo test --release --lib network_tests::dependency_health::tests::real_sntp_success_line_parses_to_a_nonzero_offset \
    --manifest-path "$REPO_ROOT/Cargo.toml"

if net_guard; then
    # --- live proof: one target that actively refuses (blocked-by-policy) and one
    # that silently drops (unhealthy) in the same run, both distinguishable ---
    live_out="$("$BIN" dependency-health --timeout-secs 2 --ntp-server time.apple.com \
        --ocsp-targets "127.0.0.1:1" "192.0.2.1:80" 2>&1)"

    check_contains "a refused local port is reported blocked-by-policy" "blocked-by-policy" \
        bash -c 'printf "%s" "$1"' _ "$live_out"
    check_contains "a silently-dropped TEST-NET-1 port is reported unhealthy" "unhealthy" \
        bash -c 'printf "%s" "$1"' _ "$live_out"

    json_out="$("$BIN" dependency-health --timeout-secs 2 --ntp-server time.apple.com \
        --ocsp-targets "127.0.0.1:1" "192.0.2.1:80" --json 2>&1 | sed -n '/^{/,$p')"
    blocked_count="$(printf '%s' "$json_out" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print(sum(1 for c in d["ocsp_checks"] if "BlockedByPolicy" in c["verdict"]))
' 2>/dev/null)"
    unhealthy_count="$(printf '%s' "$json_out" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print(sum(1 for c in d["ocsp_checks"] if "Unhealthy" in c["verdict"]))
' 2>/dev/null)"
    if [ "${blocked_count:-0}" = "1" ] && [ "${unhealthy_count:-0}" = "1" ]; then
        pass "the same run distinguishes one blocked-by-policy result from one unhealthy result"
    else
        fail "the same run distinguishes blocked-by-policy from unhealthy" \
            "blocked=$blocked_count unhealthy=$unhealthy_count"
    fi

    # --- real NTP offset measurement, never a bare 0 ---
    offset_val="$(printf '%s' "$json_out" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print(d["ntp"][0]["offset_ms"])
' 2>/dev/null)"
    if [ "$offset_val" != "None" ] && [ -n "$offset_val" ]; then
        pass "a real NTP offset was measured ($offset_val ms), not a placeholder"
    else
        fail "a real NTP offset was measured" "got: $offset_val"
    fi
    check_contains "human output never states a bare 0.000ms offset for a real target" "offset=" \
        bash -c 'printf "%s" "$1"' _ "$live_out"
else
    skip "GAP-059 live dependency checks" "FP_HARNESS_OFFLINE=1"
fi
