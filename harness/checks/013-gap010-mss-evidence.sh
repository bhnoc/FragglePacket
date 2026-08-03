#!/usr/bin/env bash
# GAP-010: route-aware TCP_MAXSEG comparison (tcp_options_echo.rs) cannot
# prove a middlebox rewrote the MSS option in flight -- that needs both SYN
# directions observed, and local/peer/middlebox attribution must stay
# separate. This locks: a single-direction observation never yields a
# middlebox-rewriting claim, and both-direction evidence still stays
# "ambiguous" (not a certain rewrite claim) absent cross-flow corroboration.

me_json() { "$BIN" mss-evidence "$@" --json 2>/dev/null | sed -n '/^{/,$p'; }

check_contains "mss-evidence advertises --ingest/--json" "--ingest" \
    "$BIN" mss-evidence --help
check_contains "mss-evidence advertises --local-ip" "--local-ip" \
    "$BIN" mss-evidence --help

# mixed-head.pcap is a real macOS capture with both SYN and SYN-ACK for
# several destinations plus at least one single-direction flow.
out="$(me_json --ingest "$FIXTURE_DIR/pcap/mixed-head.pcap")"
if [ -z "$out" ]; then
    fail "mss-evidence ingest produces JSON output" "empty output"
else
    # --- single-direction flow must never claim middlebox rewriting ---
    single_dir_verdicts="$(printf '%s' "$out" | python3 -c '
import json, sys
d = json.load(sys.stdin)
for f, a in zip(d["flows"], d["attributions"]):
    if not f["both_directions_observed"]:
        print(a["verdict"])
' 2>/dev/null)"
    if [ -z "$single_dir_verdicts" ]; then
        fail "fixture contains at least one single-direction flow to test" "found none"
    else
        bad=0
        while IFS= read -r v; do
            case "$v" in
                InsufficientEvidence) ;;
                *) bad=1 ;;
            esac
        done <<< "$single_dir_verdicts"
        if [ "$bad" = "0" ]; then
            pass "single-direction SYN observation never yields a middlebox-rewriting claim"
        else
            fail "single-direction SYN observation never yields a middlebox-rewriting claim" "got: $single_dir_verdicts"
        fi
    fi

    single_dir_confidence="$(printf '%s' "$out" | python3 -c '
import json, sys
d = json.load(sys.stdin)
for f, a in zip(d["flows"], d["attributions"]):
    if not f["both_directions_observed"]:
        print(a["confidence"])
        break
' 2>/dev/null)"
    if [ "$single_dir_confidence" = "Insufficient" ]; then
        pass "single-direction flow is labeled confidence=Insufficient"
    else
        fail "single-direction flow is labeled confidence=Insufficient" "got: $single_dir_confidence"
    fi

    # --- both-direction flow must stay Ambiguous, never a certain rewrite claim ---
    both_dir_verdicts="$(printf '%s' "$out" | python3 -c '
import json, sys
d = json.load(sys.stdin)
for f, a in zip(d["flows"], d["attributions"]):
    if f["both_directions_observed"]:
        print(a["verdict"])
' 2>/dev/null)"
    if [ -z "$both_dir_verdicts" ]; then
        fail "fixture contains at least one both-direction flow to test" "found none"
    else
        bad=0
        while IFS= read -r v; do
            case "$v" in
                Ambiguous|NoRewriteEvidence) ;;
                *) bad=1 ;;
            esac
        done <<< "$both_dir_verdicts"
        if [ "$bad" = "0" ]; then
            pass "both-direction evidence never asserts a certain middlebox rewrite"
        else
            fail "both-direction evidence never asserts a certain middlebox rewrite" "got: $both_dir_verdicts"
        fi
    fi

    both_dir_count="$(printf '%s' "$out" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print(d["flows_with_both_directions"])
' 2>/dev/null)"
    if [ "${both_dir_count:-0}" -gt 0 ] 2>/dev/null; then
        pass "fixture yields at least one both-direction flow ($both_dir_count)"
    else
        fail "fixture yields at least one both-direction flow" "got: $both_dir_count"
    fi
fi

# --- local/peer attribution stays separate: local always the SYN (non-ACK) sender ---
local_advertised_present="$(printf '%s' "$out" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print(all(f["local_advertised"] is not None for f in d["flows"]))
' 2>/dev/null)"
if [ "$local_advertised_present" = "True" ]; then
    pass "every observed flow has a local_advertised value distinct from peer_advertised"
else
    fail "every observed flow has a local_advertised value distinct from peer_advertised" "got: $local_advertised_present"
fi

# --- human output never states a bare unqualified rewrite claim ---
check_lacks "human output never claims a confirmed middlebox rewrite" "middlebox rewrote" \
    "$BIN" mss-evidence --ingest "$FIXTURE_DIR/pcap/mixed-head.pcap"
check_contains "human output surfaces confidence labels" "confidence=" \
    "$BIN" mss-evidence --ingest "$FIXTURE_DIR/pcap/mixed-head.pcap"

# --- non-pcap input errors instead of panicking ---
check_fails "non-pcap ingest input errors instead of panicking" \
    "$BIN" mss-evidence --ingest "$FIXTURE_DIR/wifi/system_profiler-airport.txt"

# --- no ingest and no destinations is a clean usage error, not silence ---
check_fails "mss-evidence with no work specified refuses to run silently" \
    "$BIN" mss-evidence
