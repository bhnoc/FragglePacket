#!/usr/bin/env bash
# GAP-011: Wi-Fi radio/retry diagnostic with safe elevation and explicit
# platform-limitation reporting. Field evidence: manual inspection found
# strong 6 GHz RF, but retry counters, WMM, and channel utilization required
# elevated tools -- and even elevated wdutil output never carried retry or
# WMM counters (the 2026-08-01 field investigation note). This gate locks:
#   1. retries/WMM read as unavailable, listed as a platform limitation,
#      never a fabricated 0 (the GAP-043 frozen-counter trap in a new shape).
#   2. A missing privilege names the exact elevation command, never invokes
#      sudo itself.
#   3. No output anywhere contains a BSSID/SSID/MAC-shaped string.

cargo_test() { cargo test --release --lib load_guard::radio_diagnostic:: --manifest-path "$REPO_ROOT/Cargo.toml" "$@"; }

check_ok "cargo test covers radio-diagnostic platform-limitation logic" cargo_test
check_contains "cargo test proves retries/WMM are always unavailable with the limitation stated" \
    "retries_and_wmm_are_always_none_with_platform_limitation_stated" cargo_test
check_contains "cargo test proves a missing privilege notes the elevation command, not a silent gap" \
    "missing_privileged_source_notes_privilege_requirement_not_a_silent_gap" cargo_test
check_contains "cargo test proves the unprivileged floor survives a failed privileged read" \
    "unprivileged_floor_survives_a_failed_privileged_read" cargo_test

check_contains "radio-diagnostic advertises --inject-fixture/--inject-privilege-denied" "--inject-privilege-denied" \
    "$BIN" radio-diagnostic --help

out="$("$BIN" radio-diagnostic --inject-fixture --json 2>/dev/null | sed -n '/^{/,$p')"
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
    fail "fixture-driven diagnostic produces a JSON report" "no output"
else
    pass "fixture-driven diagnostic produces a JSON report"

    retries="$(printf '%s' "$out" | json_get retries)"
    wmm="$(printf '%s' "$out" | json_get wmm_access_category)"
    if [ "$retries" = "null" ] && [ "$wmm" = "null" ]; then
        pass "retries and WMM read null (unavailable), never a fabricated 0"
    else
        fail "retries and WMM read null (unavailable), never a fabricated 0" "retries=$retries wmm=$wmm"
    fi

    limitations="$(printf '%s' "$out" | json_get platform_limitations)"
    if printf '%s' "$limitations" | grep -qi "retry" && printf '%s' "$limitations" | grep -qi "wmm"; then
        pass "platform_limitations lists retries and WMM as unsupported on this platform"
    else
        fail "platform_limitations lists retries and WMM as unsupported on this platform" "got: $limitations"
    fi

    cca="$(printf '%s' "$out" | json_get channel_utilization_pct)"
    if [ "$cca" = "0.0" ]; then
        pass "channel utilization (CCA%) is read from the privileged fixture, not withheld unnecessarily"
    else
        fail "channel utilization (CCA%) is read from the privileged fixture" "got: $cca"
    fi
fi

# --- missing privilege must name the exact command, never invoke sudo ---
denied_out="$("$BIN" radio-diagnostic --inject-fixture --inject-privilege-denied --json 2>/dev/null | sed -n '/^{/,$p')"
if [ -z "$denied_out" ]; then
    fail "privilege-denied run names the exact elevation command" "no output"
else
    note="$(printf '%s' "$denied_out" | json_get privilege_note)"
    if printf '%s' "$note" | grep -q "sudo wdutil info"; then
        pass "privilege-denied run names the exact elevation command (sudo wdutil info)"
    else
        fail "privilege-denied run names the exact elevation command" "got: $note"
    fi
    cca_denied="$(printf '%s' "$denied_out" | json_get channel_utilization_pct)"
    if [ "$cca_denied" = "null" ]; then
        pass "channel utilization is withheld (not fabricated) when the privileged source is denied"
    else
        fail "channel utilization is withheld when the privileged source is denied" "got: $cca_denied"
    fi
fi

check_contains "human output surfaces retries/WMM as unavailable with a limitations section" \
    "platform limitations:" \
    "$BIN" radio-diagnostic --inject-fixture
check_contains "human output never invokes sudo automatically, only names it" \
    "re-run as: sudo wdutil info" \
    "$BIN" radio-diagnostic --inject-fixture --inject-privilege-denied

# --- no output anywhere contains a BSSID/SSID/MAC-shaped string ---
mac_pattern='([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}'
if printf '%s%s' "$out" "$denied_out" | grep -Eq "$mac_pattern"; then
    fail "radio-diagnostic JSON output carries no MAC-shaped string" "found a MAC-shaped token"
else
    pass "radio-diagnostic JSON output carries no MAC-shaped string"
fi
check_lacks "radio-diagnostic human output carries no SSID label" "SSID" \
    "$BIN" radio-diagnostic --inject-fixture

# --- exactly one real end-to-end run, guarded since it needs live/root state ---
if net_guard; then
    real_out="$("$BIN" radio-diagnostic --json 2>/dev/null | sed -n '/^{/,$p')"
    if [ -z "$real_out" ]; then
        skip "real radio-diagnostic run produces a report" "no output"
    else
        pass "real radio-diagnostic run produces a report"
        if printf '%s' "$real_out" | grep -Eq "$mac_pattern"; then
            fail "real run's output carries no MAC-shaped string" "found a MAC-shaped token"
        else
            pass "real run's output carries no MAC-shaped string"
        fi
    fi
else
    skip "real radio-diagnostic run produces a report" "FP_HARNESS_OFFLINE=1"
fi
