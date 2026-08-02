#!/usr/bin/env bash
# GAP-025: an endpoint that never advertises/offers a protocol must be
# reported as unsupported (or inconclusive), never as network filtering.
# The field bug: speed.cloudflare.com and www.apple.com failed HTTP/3 in the
# same session where cloudflare.com, google.com, and Apple's dedicated
# network-quality endpoint succeeded on the same Wi-Fi. A single failing host
# must never produce a "network blocks QUIC" verdict.

pf_json() { "$BIN" preflight "$@" --json 2>/dev/null | sed -n '/^{/,$p'; }

check_contains "preflight advertises --endpoint/--force-ip/--json flags" "--force-ip" \
    "$BIN" preflight --help
check_contains "preflight --help lists http3 as a protocol choice" "http3" \
    "$BIN" preflight --help

# --- offline-safe: verdict logic over synthetic single-endpoint failure ---
# This does not touch the network: it exercises the same corroboration gate
# the live checks below hit, using the documented CLI contract that a single
# unresolved/unreachable host never becomes a network-level Filtered verdict.
if net_guard; then
    :
else
    note "network checks skipped (FP_HARNESS_OFFLINE=1); running offline-safe check only"
fi

# --unreachable.invalid never resolves, so this never touches the network,
# yet still exercises the single-host corroboration gate end to end.
offline_out="$(pf_json --no-defaults --endpoint unreachable.invalid --protocol http3 --timeout-ms 500)"
if [ -z "$offline_out" ]; then
    fail "single unresolvable host never yields a Filtered network verdict" "no JSON output from preflight"
else
    verdict_kind="$(printf '%s' "$offline_out" | python3 -c '
import json, sys
d = json.load(sys.stdin)
nv = d["protocols"][0]["network_verdict"]
print(list(nv.keys())[0] if isinstance(nv, dict) else nv)
' 2>/dev/null)"
    if [ "$verdict_kind" = "filtered" ]; then
        fail "single unresolvable host never yields a Filtered network verdict" "got: $verdict_kind"
    else
        pass "single unresolvable host never yields a Filtered network verdict (got: $verdict_kind)"
    fi

    ep_verdict="$(printf '%s' "$offline_out" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print(d["protocols"][0]["endpoints"][0]["verdict"])
' 2>/dev/null)"
    case "$ep_verdict" in
        timeout|handshake-rejected) pass "unresolvable host gets an honest per-endpoint verdict ($ep_verdict)" ;;
        *) fail "unresolvable host gets an honest per-endpoint verdict" "got: $ep_verdict" ;;
    esac
fi

if ! net_guard; then
    skip "live: speed.cloudflare.com h3 comes back unsupported, not filtered" "FP_HARNESS_OFFLINE=1"
    skip "live: known-capable defaults negotiate h3 end to end" "FP_HARNESS_OFFLINE=1"
else
    # --- the actual anti-regression: a known-incapable host, tested alone,
    # must never be labeled filtered/blocked ---
    live_out="$(pf_json --no-defaults --endpoint speed.cloudflare.com --protocol http3 --timeout-ms 5000)"
    if [ -z "$live_out" ]; then
        skip "live: speed.cloudflare.com h3 comes back unsupported, not filtered" "no network / preflight produced no JSON"
    else
        ep_verdict="$(printf '%s' "$live_out" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print(d["protocols"][0]["endpoints"][0]["verdict"])
' 2>/dev/null)"
        case "$ep_verdict" in
            unsupported) pass "live: speed.cloudflare.com h3 endpoint verdict is unsupported" ;;
            filtered) fail "live: speed.cloudflare.com h3 endpoint verdict is unsupported" "got filtered -- false network-blocking diagnosis" ;;
            *) skip "live: speed.cloudflare.com h3 endpoint verdict is unsupported" "got: $ep_verdict (network condition, not a code defect)" ;;
        esac

        net_kind="$(printf '%s' "$live_out" | python3 -c '
import json, sys
d = json.load(sys.stdin)
nv = d["protocols"][0]["network_verdict"]
print(list(nv.keys())[0] if isinstance(nv, dict) else nv)
' 2>/dev/null)"
        if [ "$net_kind" = "filtered" ]; then
            fail "live: single-host h3 run never yields network verdict filtered" "got filtered from one host"
        else
            pass "live: single-host h3 run never yields network verdict filtered (got: $net_kind)"
        fi
    fi

    # --- known-capable defaults should mostly negotiate h3 for real ---
    defaults_out="$(pf_json --protocol http3 --timeout-ms 5000)"
    if [ -z "$defaults_out" ]; then
        skip "live: known-capable defaults negotiate h3 end to end" "no network / preflight produced no JSON"
    else
        ok_count="$(printf '%s' "$defaults_out" | python3 -c '
import json, sys
d = json.load(sys.stdin)
eps = d["protocols"][0]["endpoints"]
print(sum(1 for e in eps if e["verdict"] == "ok"))
' 2>/dev/null)"
        if [ "${ok_count:-0}" -ge 1 ] 2>/dev/null; then
            pass "live: at least one built-in known-capable endpoint negotiates h3 (ok_count=$ok_count)"
        else
            fail "live: at least one built-in known-capable endpoint negotiates h3" "ok_count=$ok_count"
        fi
    fi
fi
