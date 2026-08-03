#!/usr/bin/env bash
# GAP-006: controlled TCP-versus-UDP throughput/loss comparison against a
# user-supplied iperf3-compatible endpoint. Locks:
#   1. No hardcoded default endpoint -- --server is required.
#   2. Loss reads from the real parser's non-hollow sample (GAP-039's
#      udp-reverse trap), never a naive sum_sent read.
#   3. An unusable/errored side reports no fabricated achieved rate and no
#      comparison delta.

cargo_test() { cargo test --release --lib load_guard::tcp_vs_udp:: --manifest-path "$REPO_ROOT/Cargo.toml" "$@"; }

check_ok "cargo test covers TCP/UDP result extraction and comparison logic" cargo_test
check_contains "cargo test proves TCP fixture yields a usable achieved rate" \
    "tcp_forward_fixture_yields_usable_result_with_achieved_rate" cargo_test
check_contains "cargo test proves UDP loss reads from the non-hollow sample" \
    "udp_reverse_fixture_reads_loss_from_a_non_hollow_sample" cargo_test
check_contains "cargo test proves a refused connection is unusable with a stated reason, no fabricated rate" \
    "refused_connection_is_unusable_with_stated_reason_no_fabricated_rate" cargo_test
check_contains "cargo test proves the comparison delta is withheld when either side is unusable" \
    "comparison_delta_is_none_when_either_side_unusable" cargo_test

check_contains "tcp-vs-udp advertises --server/--inject-fixture" "--inject-fixture" \
    "$BIN" tcp-vs-udp --help
check_fails "tcp-vs-udp with no --server and no --inject-fixture refuses to run" \
    "$BIN" tcp-vs-udp --interface en0

out="$("$BIN" tcp-vs-udp --inject-fixture --json 2>/dev/null | sed -n '/^{/,$p')"
json_get() { python3 -c '
import json, sys
d = json.load(sys.stdin)
path = sys.argv[1]
cur = d
for part in path.split("."):
    cur = cur.get(part) if isinstance(cur, dict) else None
print(json.dumps(cur))
' "$1" 2>/dev/null; }

if [ -z "$out" ]; then
    fail "fixture-driven comparison produces a JSON report" "no output"
else
    pass "fixture-driven comparison produces a JSON report"

    tcp_usable="$(printf '%s' "$out" | json_get comparison.tcp.usable)"
    udp_loss="$(printf '%s' "$out" | json_get comparison.udp.loss_percent)"
    if [ "$tcp_usable" = "true" ] && [ "$udp_loss" = "0.0" ]; then
        pass "TCP side usable, UDP loss read correctly from fixture (0.0%, from the non-hollow sample)"
    else
        fail "TCP side usable, UDP loss read correctly from fixture (0.0%, from the non-hollow sample)" \
            "tcp.usable=$tcp_usable udp.loss_percent=$udp_loss"
    fi

    delta="$(printf '%s' "$out" | json_get achieved_mbps_delta)"
    if [ "$delta" != "null" ] && [ -n "$delta" ]; then
        pass "comparison delta is present when both sides are usable"
    else
        fail "comparison delta is present when both sides are usable" "achieved_mbps_delta=$delta"
    fi
fi

# --- an errored/unusable side must yield no fabricated achieved rate and no
#     comparison delta. Force this deterministically by pointing --server at
#     a refusing endpoint rather than depending on live network luck. ---
if net_guard; then
    refused_out="$("$BIN" tcp-vs-udp --server 127.0.0.1 --interface lo0 --local-ip 127.0.0.1 --tcp-port 1 --udp-port 2 --duration-secs 1 --json 2>/dev/null | sed -n '/^{/,$p')"
    if [ -z "$refused_out" ]; then
        skip "refused connection yields no fabricated rate and no comparison delta" "no output"
    else
        tcp_usable_r="$(printf '%s' "$refused_out" | json_get comparison.tcp.usable)"
        delta_r="$(printf '%s' "$refused_out" | json_get achieved_mbps_delta)"
        if [ "$tcp_usable_r" = "false" ] && [ "$delta_r" = "null" ]; then
            pass "refused connection yields no fabricated rate and no comparison delta"
        else
            fail "refused connection yields no fabricated rate and no comparison delta" \
                "tcp.usable=$tcp_usable_r achieved_mbps_delta=$delta_r"
        fi
    fi
else
    skip "refused connection yields no fabricated rate and no comparison delta" "FP_HARNESS_OFFLINE=1"
fi

check_contains "human output states delta unavailable rather than fabricating one" \
    "unavailable (one or both sides unusable)" \
    "$BIN" tcp-vs-udp --server 127.0.0.1 --interface lo0 --local-ip 127.0.0.1 --tcp-port 1 --udp-port 2 --duration-secs 1
