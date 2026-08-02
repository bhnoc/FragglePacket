#!/usr/bin/env bash
# GAP-031: normalized, qualified per-phase interface-counter deltas. Field
# evidence: a wired interface accumulated 17,517 cumulative drops across a
# near-gigabit suite while a separately bracketed 350 Mbps bidirectional UDP
# phase, timed with its own before/after snapshot, added zero. Cumulative
# counters attributed nothing to anything; the per-phase bracket attributed
# everything. This gate locks:
#   1. A delta is reported per-phase, never as a bare cumulative total.
#   2. A wrapped/reset counter is qualified, not silently negative or huge.
#   3. host/driver errors are a distinct field from anything resembling
#      remote loss.
#   4. A shared interface (en0/eth*/wlan*) withholds the normalized rate by
#      default -- a drop delta there is not attributable to the phase alone.

cargo_test() { cargo test --release --lib load_guard::counter_deltas:: --manifest-path "$REPO_ROOT/Cargo.toml" "$@"; }

check_ok "cargo test covers counter-delta normalization/qualification logic" cargo_test
check_contains "cargo test proves a wrapped/reset counter withholds the normalized delta" \
    "wrapped_counters_withhold_normalized_delta" cargo_test
check_contains "cargo test proves a shared interface withholds the normalized delta by default" \
    "shared_interface_without_isolation_flag_withholds_normalized_delta" cargo_test
check_contains "cargo test proves host/driver errors are a distinct field from remote loss" \
    "host_driver_errors_are_distinct_field_from_any_remote_concept" cargo_test

check_contains "counter-deltas advertises --interface/--assume-isolated/--inject-wrap" "--assume-isolated" \
    "$BIN" counter-deltas --help
check_fails "counter-deltas with no --interface refuses to run" \
    "$BIN" counter-deltas --rate-mbps 1 --duration-secs 1

cd_json() { "$BIN" counter-deltas --interface en0 --rate-mbps 1 --duration-secs 1 "$@" --json 2>/dev/null | sed -n '/^{/,$p'; }
json_get() { python3 -c '
import json, sys
d = json.load(sys.stdin)
path = sys.argv[1]
cur = d
for part in path.split("."):
    cur = cur.get(part) if isinstance(cur, dict) else None
print(json.dumps(cur))
' "$1" 2>/dev/null; }

# --- en0 is a shared interface by default: the delta must be withheld, and
#     the report must be per-phase, never a cumulative-since-boot figure ---
out="$(cd_json)"
if [ -z "$out" ]; then
    fail "counter-deltas produces a per-phase JSON report" "no output"
else
    pass "counter-deltas produces a per-phase JSON report"

    qual="$(printf '%s' "$out" | json_get qualification)"
    if [ "$qual" = '"SharedInterfaceUnrelatedTraffic"' ]; then
        pass "en0 (shared interface) is qualified, not silently reported clean"
    else
        fail "en0 (shared interface) is qualified, not silently reported clean" "got: $qual"
    fi

    normalized="$(printf '%s' "$out" | json_get normalized)"
    if [ "$normalized" = "null" ]; then
        pass "a qualified (shared-interface) delta withholds the normalized rate"
    else
        fail "a qualified (shared-interface) delta withholds the normalized rate" "normalized field present"
    fi

    before="$(printf '%s' "$out" | json_get before)"
    after="$(printf '%s' "$out" | json_get after)"
    if [ "$before" != "null" ] && [ -n "$before" ] && [ "$after" != "null" ] && [ -n "$after" ]; then
        pass "raw before/after counters are retained even when the derived rate is withheld"
    else
        fail "raw before/after counters are retained even when the derived rate is withheld" "before=$before after=$after"
    fi
fi

# --- --assume-isolated overrides the shared-interface qualification and
#     yields a normalized, per-phase (not cumulative) rate ---
isolated_out="$(cd_json --assume-isolated)"
if [ -z "$isolated_out" ]; then
    fail "--assume-isolated yields a clean, normalized per-phase delta" "no output"
else
    isolated_qual="$(printf '%s' "$isolated_out" | json_get qualification)"
    isolated_normalized="$(printf '%s' "$isolated_out" | json_get normalized)"
    if [ "$isolated_qual" = '"Clean"' ] && [ "$isolated_normalized" != "null" ] && [ -n "$isolated_normalized" ]; then
        pass "--assume-isolated yields a clean, normalized per-phase delta"
    else
        fail "--assume-isolated yields a clean, normalized per-phase delta" "qualification=$isolated_qual normalized=$isolated_normalized"
    fi

    rx_delta="$(printf '%s' "$isolated_out" | json_get normalized.rx_packets_delta)"
    if [ -n "$rx_delta" ] && [ "$rx_delta" != "null" ]; then
        pass "normalized rate is a per-phase delta field, not a cumulative counter"
    else
        fail "normalized rate is a per-phase delta field, not a cumulative counter" "rx_packets_delta=$rx_delta"
    fi
fi

# --- injected wrap/reset must be qualified as such and withhold the rate ---
wrap_out="$(cd_json --assume-isolated --inject-wrap)"
if [ -z "$wrap_out" ]; then
    fail "injected counter wrap is qualified CounterWrappedOrReset with no normalized rate" "no output"
else
    wrap_qual="$(printf '%s' "$wrap_out" | json_get qualification)"
    wrap_normalized="$(printf '%s' "$wrap_out" | json_get normalized)"
    if [ "$wrap_qual" = '"CounterWrappedOrReset"' ] && [ "$wrap_normalized" = "null" ]; then
        pass "injected counter wrap is qualified CounterWrappedOrReset with no normalized rate"
    else
        fail "injected counter wrap is qualified CounterWrappedOrReset with no normalized rate" "qualification=$wrap_qual normalized=$wrap_normalized"
    fi
fi

# --- host/driver error field must never be named/labeled as remote loss ---
check_lacks "human output never labels host/driver errors as remote loss" "remote_loss" \
    "$BIN" counter-deltas --interface en0 --rate-mbps 1 --duration-secs 1 --assume-isolated
check_contains "human output distinguishes host/driver errors from remote loss explicitly" \
    "not a remote-loss measurement" \
    "$BIN" counter-deltas --interface en0 --rate-mbps 1 --duration-secs 1 --assume-isolated

# --- withheld delta reads as "none", never a fabricated rate ---
check_contains "withheld delta's human output states none, not a fabricated rate" \
    "normalized: none" \
    "$BIN" counter-deltas --interface en0 --rate-mbps 1 --duration-secs 1
