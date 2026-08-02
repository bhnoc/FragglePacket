#!/usr/bin/env bash
# Any flag that fabricates or injects state must say so in the output.
#
# The harness needs synthetic inputs to stay fast and deterministic, so these
# flags are legitimate. The danger is the artifact: a saved report from a faked
# run that looks identical to a real measurement. That is the same
# unknown-presented-as-a-measurement failure behind GAP-009 (zero latency),
# GAP-019 (phantom oversize frames), and GAP-027 (ratios from invalid runs), and
# it must not reappear via a test affordance.
#
# A consumer must be able to tell a fabricated report from a real one using the
# artifact alone, with no access to the command line that produced it.

# Discover every state-fabricating flag rather than hardcoding a list, so a new
# one added later is covered automatically.
synthetic_flags=""
for sub in $("$BIN" --help 2>&1 | awk '/^Commands:/{f=1;next} /^Options:/{f=0} f && NF && $1 !~ /^-/ {print $1}' | grep -v '^help$'); do
    for flag in $("$BIN" "$sub" --help 2>&1 | grep -oE '\-\-[a-z][a-z0-9-]*' | sort -u); do
        case "$flag" in
            --fake-*|--inject-*|--synthetic*|--simulate*)
                synthetic_flags="$synthetic_flags $sub:$flag"
                ;;
        esac
    done
done

if [ -z "${synthetic_flags// /}" ]; then
    skip "synthetic flags declare provenance" "no state-fabricating flags found"
else
    note "state-fabricating flags:${synthetic_flags}"
fi

# load-guard is the one command that currently fabricates radio state.
if printf '%s' "$synthetic_flags" | grep -q 'load-guard:--fake-radio'; then
    base="--interface en0 --rate-mbps 5 --duration-secs 1 --concurrency 1 --maintenance"

    faked="$("$BIN" load-guard $base --fake-radio --json 2>/dev/null | sed -n '/^{/,$p')"
    if [ -z "$faked" ]; then
        fail "faked run emits JSON" "no JSON from --fake-radio run"
    else
        # The artifact must declare that its radio state was invented.
        if printf '%s' "$faked" | python3 -c '
import json, sys
d = json.load(sys.stdin)
blob = json.dumps(d).lower()
sys.exit(0 if any(k in blob for k in ("synthetic", "fake", "simulated")) else 1)
' 2>/dev/null; then
            pass "faked run declares synthetic provenance in JSON"
        else
            fail "faked run declares synthetic provenance in JSON" \
                "a fabricated report is indistinguishable from a real measurement"
        fi

        check_contains "faked run declares synthetic provenance in human output" "SYNTHETIC" \
            "$BIN" load-guard $base --fake-radio
    fi

    # The marker must reflect reality, not be hardcoded: a real run must NOT
    # claim to be synthetic. Guarded because it pays real radio sampling cost.
    if net_guard; then
        real="$("$BIN" load-guard $base --json 2>/dev/null | sed -n '/^{/,$p')"
        if [ -z "$real" ]; then
            skip "real run does not claim synthetic provenance" "no JSON from real run"
        elif printf '%s' "$real" | python3 -c '
import json, sys
d = json.load(sys.stdin)
src = str(d.get("radio_source", "")).lower()
sys.exit(0 if "synth" not in src and "fake" not in src else 1)
' 2>/dev/null; then
            pass "real run does not claim synthetic provenance"
        else
            fail "real run does not claim synthetic provenance" "marker appears hardcoded to synthetic"
        fi
    else
        skip "real run does not claim synthetic provenance" "FP_HARNESS_OFFLINE=1"
    fi
fi
