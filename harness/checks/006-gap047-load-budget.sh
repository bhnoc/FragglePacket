#!/usr/bin/env bash
# GAP-047: load phases require an explicit budget, must never default to
# maximum stress, must enforce materially stricter live-event caps than
# maintenance caps, and must record a structured reason for every stop
# (including operator cancellation, which must still emit a report).

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
    "$BIN" load-guard --interface en0 --rate-mbps 500 --duration-secs 5 --concurrency 4 --live-event
check_contains "live-event rejection names the exceeded cap" "exceeds LiveEvent cap" \
    "$BIN" load-guard --interface en0 --rate-mbps 500 --duration-secs 5 --concurrency 4 --live-event

# --- the same rate that live-event rejects must be legal in maintenance mode,
#     proving live-event caps are materially stricter, not just differently
#     labeled ---
check_ok "maintenance mode accepts the rate live-event mode rejects" \
    "$BIN" load-guard --interface en0 --rate-mbps 100 --duration-secs 1 --concurrency 1 --maintenance --json
check_fails "live-event mode rejects that same 100 Mbps rate" \
    "$BIN" load-guard --interface en0 --rate-mbps 100 --duration-secs 1 --concurrency 1 --live-event

# --- neither mode flag given: command must not silently pick one ---
check_fails "load-guard with neither --live-event nor --maintenance refuses to start" \
    "$BIN" load-guard --interface en0 --rate-mbps 1 --duration-secs 1 --concurrency 1

# --- structured stop reason on normal completion ---
out="$("$BIN" load-guard --interface en0 --rate-mbps 1 --duration-secs 1 --concurrency 1 --live-event --json 2>/dev/null | sed -n '/^{/,$p')"
if [ -z "$out" ]; then
    skip "normal completion records a structured stop reason" "no output (radio/counter source unavailable)"
else
    stop_reason="$(printf '%s' "$out" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print(json.dumps(d.get("stop_reason")))
' 2>/dev/null)"
    if printf '%s' "$stop_reason" | grep -qi "completed"; then
        pass "normal completion records stop_reason=Completed"
    else
        fail "normal completion records stop_reason=Completed" "got: $stop_reason"
    fi
fi

# --- operator cancellation still emits a full report, not silence ---
cancel_out="$("$BIN" load-guard --interface en0 --rate-mbps 1 --duration-secs 5 --concurrency 1 --live-event --inject-cancel --json 2>/dev/null | sed -n '/^{/,$p')"
if [ -z "$cancel_out" ]; then
    fail "operator cancellation still emits a report" "no JSON output produced on cancellation"
else
    cancel_reason="$(printf '%s' "$cancel_out" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print(json.dumps(d.get("stop_reason")))
' 2>/dev/null)"
    if printf '%s' "$cancel_reason" | grep -qi "OperatorCancelled"; then
        pass "operator cancellation records stop_reason=OperatorCancelled and still reports"
    else
        fail "operator cancellation records stop_reason=OperatorCancelled and still reports" "got: $cancel_reason"
    fi
fi

check_contains "human output surfaces a stop reason line" "stop reason:" \
    "$BIN" load-guard --interface en0 --rate-mbps 1 --duration-secs 1 --concurrency 1 --live-event --inject-cancel

# --- ramp: zero ramp steps must not be accepted as "start at full rate" ---
check_fails "load-guard rejects a zero-step ramp" \
    "$BIN" load-guard --interface en0 --rate-mbps 1 --duration-secs 1 --concurrency 1 --live-event --ramp-steps 0

# --- a phase that completes normally but moved far less than its target byte
#     volume must not be reported as a healthy ratio. The CLI's demo phase
#     sends a fixed trickle per tick, so a large rate/duration budget against
#     it reliably undershoots without needing to fake anything else. ---
undershoot_out="$("$BIN" load-guard --interface en0 --rate-mbps 5 --duration-secs 2 --concurrency 1 --maintenance --json 2>/dev/null | sed -n '/^{/,$p')"
if [ -z "$undershoot_out" ]; then
    skip "phase that undershoots target is marked invalid with no ratio" "no output (radio/counter source unavailable)"
else
    undershoot_validity="$(printf '%s' "$undershoot_out" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print(json.dumps(d.get("validity")))
' 2>/dev/null)"
    if printf '%s' "$undershoot_validity" | grep -q "PhaseTargetUndershoot"; then
        pass "phase that undershoots target is marked invalid (PhaseTargetUndershoot)"
    else
        fail "phase that undershoots target is marked invalid (PhaseTargetUndershoot)" "got: $undershoot_validity"
    fi

    undershoot_derived="$(printf '%s' "$undershoot_out" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print("null" if d.get("derived") is None else "present")
' 2>/dev/null)"
    if [ "$undershoot_derived" = "null" ]; then
        pass "undershooting phase emits no derived collapse/retention ratio in --json"
    else
        fail "undershooting phase emits no derived collapse/retention ratio in --json" "derived field present"
    fi
fi

check_lacks "undershooting phase's human output has no collapse_ratio wording" "collapse_ratio=" \
    "$BIN" load-guard --interface en0 --rate-mbps 5 --duration-secs 2 --concurrency 1 --maintenance

# --- human output must never leak Rust's Option debug formatting. The
#     duration/undershoot fix and this fix landed together because both were
#     found in the same real run; lock both from the same evidence. ---
check_lacks "human output never contains a Some( debug artifact" "Some(" \
    "$BIN" load-guard --interface en0 --rate-mbps 1 --duration-secs 1 --concurrency 1 --live-event
check_lacks "invalid run's human output never contains a Some( debug artifact" "Some(" \
    "$BIN" load-guard --interface en0 --rate-mbps 5 --duration-secs 2 --concurrency 1 --maintenance
check_lacks "roamed run's human output never contains a Some( debug artifact" "Some(" \
    "$BIN" load-guard --interface en0 --rate-mbps 1 --duration-secs 1 --concurrency 1 --live-event --inject-band-change
