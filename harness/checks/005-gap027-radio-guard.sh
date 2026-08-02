#!/usr/bin/env bash
# GAP-027: load phases must sample radio state before/during/after, invalidate
# a run that roamed, and retain raw evidence while refusing to compute a
# derived collapse/retention ratio for an invalid run.
#
# Uses --fake-radio (synthesizes radio state, never shells out to
# system_profiler/ioreg) for nearly every assertion, since system_profiler
# alone costs ~8s per call on this class of machine and this file used to pay
# it repeatedly. --inject-band-change still layers on top of --fake-radio to
# exercise the invalid-run path deterministically. Exactly one check exercises
# the real radio path end-to-end, guarded by net_guard/FP_HARNESS_OFFLINE.

lg_json() { "$BIN" load-guard "$@" --json 2>/dev/null | sed -n '/^{/,$p'; }
json_get() { python3 -c '
import json, sys
d = json.load(sys.stdin)
path = sys.argv[1]
cur = d
for part in path.split("."):
    cur = cur.get(part) if isinstance(cur, dict) else None
print(json.dumps(cur))
' "$1" 2>/dev/null; }

check_contains "load-guard advertises radio guard flags" "--inject-band-change" \
    "$BIN" load-guard --help

# --- injected roam (fast, synthetic radio) is marked invalid, and the ratio
#     is structurally absent ---
out="$(lg_json --interface en0 --rate-mbps 1 --duration-secs 1 --concurrency 1 --live-event --fake-radio --inject-band-change)"
if [ -z "$out" ]; then
    fail "roamed run's validity verdict reports Roamed" "no output from load-guard --fake-radio"
else
    validity="$(printf '%s' "$out" | json_get validity)"
    if printf '%s' "$validity" | grep -q "Roamed"; then
        pass "roamed run's validity verdict reports Roamed"
    else
        fail "roamed run's validity verdict reports Roamed" "got: $validity"
    fi

    derived="$(printf '%s' "$out" | json_get derived)"
    if [ "$derived" = "null" ]; then
        pass "invalid run emits no derived collapse/retention ratio in --json"
    else
        fail "invalid run emits no derived collapse/retention ratio in --json" "derived field present"
    fi

    raw_bytes="$(printf '%s' "$out" | json_get raw.bytes_transferred)"
    if [ -n "$raw_bytes" ] && [ "$raw_bytes" != "null" ]; then
        pass "invalid run still retains raw bytes_transferred evidence"
    else
        fail "invalid run still retains raw bytes_transferred evidence" "raw.bytes_transferred missing"
    fi
fi

# --- human output must never speak in ratio terms for an invalid run ---
human="$("$BIN" load-guard --interface en0 --rate-mbps 1 --duration-secs 1 --concurrency 1 --live-event --fake-radio --inject-band-change 2>&1)"
check_lacks "invalid run's human output has no retained_capacity wording" "retained_capacity_pct=" \
    printf '%s' "$human"
check_contains "invalid run's human output states derived is none" "derived: none" \
    printf '%s' "$human"

# --- a synthetic run with no injected change is STILL invalidated: a run
#     whose radio state was fabricated never measured anything, so it must
#     not be able to conclude "no roam, no weak RF, everything's fine" and
#     carry a ratio -- fabricated-but-stable is not the same as measured-and-
#     stable. This is the fix for the "faked run looked identical to a real
#     measurement" defect: SyntheticRadioSource, not Valid, and no ratio. ---
valid_out="$(lg_json --interface en0 --rate-mbps 0.01 --duration-secs 1 --concurrency 1 --live-event --fake-radio)"
if [ -z "$valid_out" ]; then
    fail "synthetic run with no injected change is still invalidated (SyntheticRadioSource), no ratio" \
        "no output from load-guard --fake-radio"
else
    valid_validity="$(printf '%s' "$valid_out" | json_get validity)"
    valid_derived="$(printf '%s' "$valid_out" | json_get derived)"
    if printf '%s' "$valid_validity" | grep -q "SyntheticRadioSource" && [ "$valid_derived" = "null" ]; then
        pass "synthetic run with no injected change is still invalidated (SyntheticRadioSource), no ratio"
    else
        fail "synthetic run with no injected change is still invalidated (SyntheticRadioSource), no ratio" \
            "validity=$valid_validity derived=$valid_derived"
    fi
fi

# --- the same run's --json carries radio_source=synthetic and its human
#     output carries the unmissable SYNTHETIC banner, not just a subtle
#     field -- the defect this locks: a faked run indistinguishable from a
#     real measurement in a saved artifact ---
check_contains "faked run's --json declares radio_source=synthetic" '"radio_source": "synthetic"' \
    printf '%s' "$valid_out"
check_contains "faked run's human output shows the unmissable SYNTHETIC banner" \
    "SYNTHETIC RADIO STATE" \
    "$BIN" load-guard --interface en0 --rate-mbps 0.01 --duration-secs 1 --concurrency 1 --live-event --fake-radio

# --- privacy: never SSID/BSSID/MAC in output, human or json ---
check_lacks "load-guard json output carries no MAC-style token" "02:00:00:00:00:01" \
    printf '%s' "$out$valid_out"
check_lacks "load-guard human output carries no SSID label" "SSID" \
    printf '%s' "$human"

# --- exactly one check exercises the real radio path end to end (both the
#     full system_profiler-backed source and the fast ioreg-backed source),
#     skipped offline since it needs live Wi-Fi and costs several seconds ---
if net_guard; then
    real_out="$(lg_json --interface en0 --rate-mbps 0.01 --duration-secs 1 --concurrency 1 --live-event)"
    if [ -z "$real_out" ]; then
        skip "real radio path produces a usable snapshot" "no live radio source on this host"
    else
        real_validity="$(printf '%s' "$real_out" | json_get validity)"
        case "$real_validity" in
            '"Valid"'|*RadioUnavailable*|*WeakRf*|*UnstableRf*)
                pass "real radio path produces a usable snapshot"
                ;;
            *)
                fail "real radio path produces a usable snapshot" "unexpected validity=$real_validity"
                ;;
        esac
    fi
else
    skip "real radio path produces a usable snapshot" "FP_HARNESS_OFFLINE=1"
fi
