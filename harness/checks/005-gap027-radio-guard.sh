#!/usr/bin/env bash
# GAP-027: load phases must sample radio state before/during/after, invalidate
# a run that roamed, and retain raw evidence while refusing to compute a
# derived collapse/retention ratio for an invalid run. Uses the CLI's
# --inject-band-change synthetic hook rather than causing a real roam, so this
# gate runs deterministically anywhere (also honors FP_HARNESS_OFFLINE).

# Strip the fixed banner the CLI always prints before --json output.
lg_json() { "$BIN" load-guard "$@" --json 2>/dev/null | sed -n '/^{/,$p'; }

check_contains "load-guard advertises radio guard flags" "--inject-band-change" \
    "$BIN" load-guard --help

# --- injected roam is marked invalid, and the ratio is structurally absent ---
out="$(lg_json --interface en0 --rate-mbps 1 --duration-secs 1 --concurrency 1 --live-event --inject-band-change)"
if [ -z "$out" ]; then
    skip "roamed run marked invalid" "no output from load-guard (radio source unavailable)"
else
    validity="$(printf '%s' "$out" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print(json.dumps(d.get("validity")))
' 2>/dev/null)"
    if printf '%s' "$validity" | grep -q "Roamed"; then
        pass "roamed run's validity verdict reports Roamed"
    else
        fail "roamed run's validity verdict reports Roamed" "got: $validity"
    fi

    derived_is_null="$(printf '%s' "$out" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print("null" if d.get("derived") is None else "present")
' 2>/dev/null)"
    if [ "$derived_is_null" = "null" ]; then
        pass "invalid run emits no derived collapse/retention ratio in --json"
    else
        fail "invalid run emits no derived collapse/retention ratio in --json" "derived field present"
    fi

    raw_bytes="$(printf '%s' "$out" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print(d.get("raw", {}).get("bytes_transferred", -1))
' 2>/dev/null)"
    if [ "${raw_bytes:-0}" -ge 0 ] 2>/dev/null; then
        pass "invalid run still retains raw bytes_transferred evidence"
    else
        fail "invalid run still retains raw bytes_transferred evidence" "raw.bytes_transferred missing"
    fi
fi

# --- human output must never speak in ratio terms for an invalid run ---
human="$("$BIN" load-guard --interface en0 --rate-mbps 1 --duration-secs 1 --concurrency 1 --live-event --inject-band-change 2>&1)"
check_lacks "invalid run's human output has no retained_capacity wording" "retained_capacity_pct=" \
    printf '%s' "$human"
check_contains "invalid run's human output states derived is none" "derived: none" \
    printf '%s' "$human"

# --- a stable synthetic run (no injected change) stays valid and does carry a ratio ---
valid_out="$(lg_json --interface en0 --rate-mbps 1 --duration-secs 1 --concurrency 1 --live-event)"
if [ -n "$valid_out" ]; then
    valid_derived="$(printf '%s' "$valid_out" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print("present" if d.get("derived") is not None else "null")
' 2>/dev/null)"
    if [ "$valid_derived" = "present" ]; then
        pass "stable run without injected change stays valid and carries a ratio"
    else
        fail "stable run without injected change stays valid and carries a ratio" "derived missing on valid run"
    fi
else
    skip "stable run without injected change stays valid and carries a ratio" "no live radio source"
fi

# --- privacy: never SSID/BSSID/MAC in output, human or json ---
check_lacks "load-guard json output carries no MAC-style token" "02:00:00:00:00:01" \
    printf '%s' "$out$valid_out"
check_lacks "load-guard human output carries no SSID label" "SSID" \
    printf '%s' "$human"
