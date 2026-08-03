#!/usr/bin/env bash
# GAP-047: load phases require an explicit budget, must never default to
# maximum stress, must enforce materially stricter live-event caps than
# maintenance caps, and must record a structured reason for every stop
# (including operator cancellation, which must still emit a report).
#
# Uses --fake-radio for every check that gets past budget validation, since
# the real radio path (system_profiler) costs several seconds per call and
# this file has nothing to prove about radio hardware — GAP-047 is a budget
# and execution-validity gate, not a radio gate (that's 005's job).

json_get() { python3 -c '
import json, sys
d = json.load(sys.stdin)
path = sys.argv[1]
cur = d
for part in path.split("."):
    cur = cur.get(part) if isinstance(cur, dict) else None
print(json.dumps(cur))
' "$1" 2>/dev/null; }

# --- no budget: refuses to start ---
check_fails "load-guard with no budget flags refuses to start" \
    "$BIN" load-guard --interface en0 --live-event
check_contains "no-budget refusal names the missing flags" "--rate-mbps" \
    "$BIN" load-guard --interface en0 --live-event
check_fails "load-guard with no --interface refuses to start" \
    "$BIN" load-guard --rate-mbps 1 --duration-secs 1 --concurrency 1 --live-event

# --- maximum stress is not the default: a maintenance-scale rate must be
#     rejected under live-event mode, proving live-event caps are real and
#     that nothing silently promotes a request to unrestricted stress ---
check_fails "live-event mode rejects a maintenance-scale rate" \
    "$BIN" load-guard --interface en0 --rate-mbps 500 --duration-secs 5 --concurrency 4 --live-event --fake-radio
check_contains "live-event rejection names the exceeded cap" "exceeds LiveEvent cap" \
    "$BIN" load-guard --interface en0 --rate-mbps 500 --duration-secs 5 --concurrency 4 --live-event --fake-radio

# --- the same rate that live-event rejects must be legal in maintenance mode,
#     proving live-event caps are materially stricter, not just differently
#     labeled ---
check_ok "maintenance mode accepts the rate live-event mode rejects" \
    "$BIN" load-guard --interface en0 --rate-mbps 100 --duration-secs 1 --concurrency 1 --maintenance --fake-radio --json
check_fails "live-event mode rejects that same 100 Mbps rate" \
    "$BIN" load-guard --interface en0 --rate-mbps 100 --duration-secs 1 --concurrency 1 --live-event --fake-radio

# --- neither mode flag given: command must not silently pick one ---
check_fails "load-guard with neither --live-event nor --maintenance refuses to start" \
    "$BIN" load-guard --interface en0 --rate-mbps 1 --duration-secs 1 --concurrency 1 --fake-radio

# --- structured stop reason on normal completion (tiny budget clears the
#     undershoot floor so this is a clean completion, not an execution defect) ---
out="$("$BIN" load-guard --interface en0 --rate-mbps 0.01 --duration-secs 1 --concurrency 1 --live-event --fake-radio --json 2>/dev/null | sed -n '/^{/,$p')"
if [ -z "$out" ]; then
    fail "normal completion records a structured stop reason" "no output from load-guard --fake-radio"
else
    stop_reason="$(printf '%s' "$out" | json_get stop_reason)"
    if printf '%s' "$stop_reason" | grep -qi "completed"; then
        pass "normal completion records stop_reason=Completed"
    else
        fail "normal completion records stop_reason=Completed" "got: $stop_reason"
    fi
fi

# --- operator cancellation still emits a full report, not silence ---
cancel_out="$("$BIN" load-guard --interface en0 --rate-mbps 1 --duration-secs 5 --concurrency 1 --live-event --fake-radio --inject-cancel --json 2>/dev/null | sed -n '/^{/,$p')"
if [ -z "$cancel_out" ]; then
    fail "operator cancellation still emits a report" "no JSON output produced on cancellation"
else
    cancel_reason="$(printf '%s' "$cancel_out" | json_get stop_reason)"
    if printf '%s' "$cancel_reason" | grep -qi "OperatorCancelled"; then
        pass "operator cancellation records stop_reason=OperatorCancelled and still reports"
    else
        fail "operator cancellation records stop_reason=OperatorCancelled and still reports" "got: $cancel_reason"
    fi
fi

check_contains "human output surfaces a stop reason line" "stop reason:" \
    "$BIN" load-guard --interface en0 --rate-mbps 1 --duration-secs 1 --concurrency 1 --live-event --fake-radio --inject-cancel

# --- ramp: zero ramp steps must not be accepted as "start at full rate" ---
check_fails "load-guard rejects a zero-step ramp" \
    "$BIN" load-guard --interface en0 --rate-mbps 1 --duration-secs 1 --concurrency 1 --live-event --fake-radio --ramp-steps 0

# --- a phase that completes normally but moved far less than its target byte
#     volume must not be reported as a healthy ratio. The CLI's demo phase
#     sends a fixed trickle per tick, so a large rate/duration budget against
#     it reliably undershoots without needing to fake anything else. ---
undershoot_out="$("$BIN" load-guard --interface en0 --rate-mbps 5 --duration-secs 2 --concurrency 1 --maintenance --fake-radio --json 2>/dev/null | sed -n '/^{/,$p')"
if [ -z "$undershoot_out" ]; then
    fail "phase that undershoots target is marked invalid with no ratio" "no output from load-guard --fake-radio"
else
    undershoot_validity="$(printf '%s' "$undershoot_out" | json_get validity)"
    if printf '%s' "$undershoot_validity" | grep -q "PhaseTargetUndershoot"; then
        pass "phase that undershoots target is marked invalid (PhaseTargetUndershoot)"
    else
        fail "phase that undershoots target is marked invalid (PhaseTargetUndershoot)" "got: $undershoot_validity"
    fi

    undershoot_derived="$(printf '%s' "$undershoot_out" | json_get derived)"
    if [ "$undershoot_derived" = "null" ]; then
        pass "undershooting phase emits no derived collapse/retention ratio in --json"
    else
        fail "undershooting phase emits no derived collapse/retention ratio in --json" "derived field present"
    fi

    elapsed="$(printf '%s' "$undershoot_out" | json_get raw.elapsed_secs)"
    # elapsed_secs must reflect the phase loop, not instrumentation overhead —
    # locks the "measured window must reflect the load, not radio sampling"
    # requirement. With --fake-radio there is no real system_profiler/ioreg
    # cost to hide behind, so any regression here is unambiguous.
    within_budget="$(python3 -c "print(1 if $elapsed <= 2 * 1.5 else 0)" 2>/dev/null)"
    if [ "$within_budget" = "1" ]; then
        pass "elapsed_secs reflects the load phase, not instrumentation overhead"
    else
        fail "elapsed_secs reflects the load phase, not instrumentation overhead" "elapsed_secs=$elapsed for a 2s budget"
    fi
fi

check_lacks "undershooting phase's human output has no collapse_ratio wording" "collapse_ratio=" \
    "$BIN" load-guard --interface en0 --rate-mbps 5 --duration-secs 2 --concurrency 1 --maintenance --fake-radio

# --- human output must never leak Rust's Option debug formatting. ---
check_lacks "human output never contains a Some( debug artifact" "Some(" \
    "$BIN" load-guard --interface en0 --rate-mbps 1 --duration-secs 1 --concurrency 1 --live-event --fake-radio
check_lacks "invalid run's human output never contains a Some( debug artifact" "Some(" \
    "$BIN" load-guard --interface en0 --rate-mbps 5 --duration-secs 2 --concurrency 1 --maintenance --fake-radio
check_lacks "roamed run's human output never contains a Some( debug artifact" "Some(" \
    "$BIN" load-guard --interface en0 --rate-mbps 1 --duration-secs 1 --concurrency 1 --live-event --fake-radio --inject-band-change

# --- one check exercises the real end-to-end timing (system_profiler cost
#     bracketing the phase, not blocking inside it), guarded since it needs
#     live Wi-Fi and always costs several seconds regardless of fix quality ---
if net_guard; then
    real_out="$("$BIN" load-guard --interface en0 --rate-mbps 5 --duration-secs 2 --concurrency 1 --maintenance --json 2>/dev/null | sed -n '/^{/,$p')"
    if [ -z "$real_out" ]; then
        skip "real run's elapsed_secs reflects the phase, not system_profiler cost" "no live radio source on this host"
    else
        real_elapsed="$(printf '%s' "$real_out" | json_get raw.elapsed_secs)"
        real_within_budget="$(python3 -c "print(1 if $real_elapsed <= 2 * 1.5 else 0)" 2>/dev/null)"
        if [ "$real_within_budget" = "1" ]; then
            pass "real run's elapsed_secs reflects the phase, not system_profiler cost"
        else
            fail "real run's elapsed_secs reflects the phase, not system_profiler cost" "elapsed_secs=$real_elapsed for a 2s budget"
        fi
    fi
else
    skip "real run's elapsed_secs reflects the phase, not system_profiler cost" "FP_HARNESS_OFFLINE=1"
fi
