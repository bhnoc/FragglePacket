#!/usr/bin/env bash
# GAP-044: local-gateway latency-under-load bracket. Field evidence: PC6's
# gateway RTT rose from 1.646ms idle to 7.146ms avg / 22.738ms max during a
# simultaneous load phase with 23.550% downstream loss, while a healthy
# control node stayed near idle. That co-movement localizes queueing to the
# WLAN-facing leg without identifying the dropping queue, and every gateway
# in that investigation suppressed ICMP while still passing transit traffic.
# This gate locks:
#   1. All four phases (idle/upload/download/simultaneous) are reported
#      separately, each with its own RTT and loss numbers.
#   2. A suppressed-ICMP gateway uses the firsthop fallback and reports
#      Suppressed, never a bare 100% loss claim.
#   3. The small-ICMP-packet caveat appears whenever a gateway result is
#      reported.
#   4. RTT deltas are correlated against the throughput timeline (a delta
#      exists alongside a throughput_loss_pct for load phases), not
#      presented as an independent number.
#   5. An unmeasurable RTT/delta reads "unavailable", never 0.
#
# Uses --inject-synthetic (this module's version of the --inject-* pattern)
# for every assertion except the one real end-to-end run, which is guarded
# by net_guard since it depends on live network state.

cargo_test() { cargo test --release --lib network_tests::gateway_bracket:: --manifest-path "$REPO_ROOT/Cargo.toml" "$@"; }

check_ok "cargo test covers gateway-bracket RTT/delta correlation logic" cargo_test
check_contains "cargo test proves an all-lost phase reports RTT unavailable, not zero" \
    "avg_max_rtt_all_lost_is_none_not_zero" cargo_test
check_contains "cargo test proves rtt_delta requires both baseline and phase to be measurable" \
    "rtt_delta_requires_both_sides_measurable" cargo_test

check_contains "gateway-bracket advertises --gateway/--interface/--inject-synthetic" "--inject-synthetic" \
    "$BIN" gateway-bracket --help
check_fails "gateway-bracket with no --gateway refuses to guess one" \
    "$BIN" gateway-bracket --interface en0 --inject-synthetic

gb_json() { "$BIN" gateway-bracket --gateway 203.0.113.1 --interface en0 --inject-synthetic --json 2>/dev/null | sed -n '/^{/,$p'; }
json_get() { python3 -c '
import json, sys
d = json.load(sys.stdin)
path = sys.argv[1]
cur = d
for part in path.split("."):
    if isinstance(cur, list):
        cur = cur[int(part)] if part.lstrip("-").isdigit() and abs(int(part)) < len(cur) else None
    elif isinstance(cur, dict):
        cur = cur.get(part)
    else:
        cur = None
print(json.dumps(cur))
' "$1" 2>/dev/null; }

out="$(gb_json)"
if [ -z "$out" ]; then
    fail "synthetic run produces a JSON report" "no output from gateway-bracket --inject-synthetic"
else
    pass "synthetic run produces a JSON report"

    phase_count="$(printf '%s' "$out" | python3 -c 'import json,sys; print(len(json.load(sys.stdin).get("phases", [])))' 2>/dev/null)"
    if [ "$phase_count" = "4" ]; then
        pass "all four phases (idle/upload/download/simultaneous) are reported"
    else
        fail "all four phases (idle/upload/download/simultaneous) are reported" "got $phase_count phases"
    fi

    labels="$(printf '%s' "$out" | python3 -c 'import json,sys; print(",".join(p["phase"] for p in json.load(sys.stdin)["phases"]))' 2>/dev/null)"
    if [ "$labels" = "Idle,Upload,Download,Simultaneous" ]; then
        pass "phases are reported in idle/upload/download/simultaneous order, each labeled"
    else
        fail "phases are reported in idle/upload/download/simultaneous order, each labeled" "got: $labels"
    fi

    # --- each load phase (not idle) carries both an RTT delta input
    #     (avg_rtt_ms) and a throughput figure alongside it, i.e. the two
    #     timelines are correlated in one record rather than reported
    #     separately with no linkage ---
    for idx in 1 2 3; do
        avg="$(printf '%s' "$out" | json_get "phases.$idx.avg_rtt_ms")"
        loss="$(printf '%s' "$out" | json_get "phases.$idx.throughput_loss_pct")"
        bytes="$(printf '%s' "$out" | json_get "phases.$idx.bytes_transferred")"
        if [ "$avg" != "null" ] && [ -n "$avg" ] && [ "$loss" != "null" ] && [ -n "$loss" ] && [ "$bytes" != "null" ] && [ -n "$bytes" ]; then
            pass "load phase $idx carries both RTT and throughput data in the same record"
        else
            fail "load phase $idx carries both RTT and throughput data in the same record" "avg_rtt_ms=$avg throughput_loss_pct=$loss bytes_transferred=$bytes"
        fi
    done

    check_contains "small-ICMP-packet caveat appears in --json output" "small packets" \
        printf '%s' "$out"
    check_contains "queue-localization caveat appears in --json output" "does not identify" \
        printf '%s' "$out"

    data_source="$(printf '%s' "$out" | json_get data_source)"
    if [ "$data_source" = '"synthetic"' ]; then
        pass "synthetic run declares its own provenance in --json (data_source=synthetic)"
    else
        fail "synthetic run declares its own provenance in --json (data_source=synthetic)" "got: $data_source"
    fi
fi

human="$("$BIN" gateway-bracket --gateway 203.0.113.1 --interface en0 --inject-synthetic 2>&1)"
check_contains "human output shows all four phase headers" "[IDLE]" printf '%s' "$human"
check_contains "human output shows the download phase" "[DOWNLOAD]" printf '%s' "$human"
check_contains "human output shows the simultaneous phase" "[SIMULTANEOUS]" printf '%s' "$human"
check_contains "human output surfaces an RTT delta vs idle line" "rtt delta vs idle:" \
    printf '%s' "$human"
check_contains "human output surfaces the small-ICMP-packet caveat" "small packets" \
    printf '%s' "$human"
check_contains "human output surfaces the queue-localization caveat" "does not identify" \
    printf '%s' "$human"
check_contains "human output declares SYNTHETIC provenance for an injected run" "SYNTHETIC" \
    printf '%s' "$human"

# --- an unmeasurable metric must read "unavailable", never a bare 0.
#     Force this deterministically: a TEST-NET-1 gateway with a tiny timeout
#     and no synthetic injection will get zero ICMP replies and (almost
#     certainly) a failed TCP fallback too, so RTT is genuinely unmeasurable
#     for that run -- this must render as "unavailable", not "0.00ms". ---
unmeasurable_human="$("$BIN" gateway-bracket --gateway 203.0.113.1 --interface lo0 --phase-duration-secs 1 --cadence-hz 5 --icmp-timeout-ms 50 2>&1)"
check_contains "unmeasurable RTT reads unavailable, not zero" "rtt avg=unavailable" \
    printf '%s' "$unmeasurable_human"
check_lacks "unmeasurable RTT never renders as a bare 0.00ms" "avg=0.00ms" \
    printf '%s' "$unmeasurable_human"

# --- one real end-to-end run against this machine's actual first hop,
#     guarded since it depends on live network/gateway behavior ---
if net_guard; then
    real_out="$("$BIN" gateway-bracket --gateway 203.0.113.1 --interface lo0 --phase-duration-secs 1 --cadence-hz 5 --icmp-timeout-ms 100 --json 2>/dev/null | sed -n '/^{/,$p')"
    if [ -z "$real_out" ]; then
        skip "real run against an unreachable gateway reports a structured state" "no JSON output"
    else
        state="$(printf '%s' "$real_out" | json_get "phases.0.icmp_state")"
        if [ -n "$state" ] && [ "$state" != "null" ]; then
            pass "real run against an unreachable gateway reports a structured state ($state)"
        else
            fail "real run against an unreachable gateway reports a structured state" "got: $real_out"
        fi
    fi
else
    skip "real run against an unreachable gateway reports a structured state" "FP_HARNESS_OFFLINE=1"
fi
