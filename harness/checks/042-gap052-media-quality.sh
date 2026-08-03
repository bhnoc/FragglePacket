#!/usr/bin/env bash
# GAP-052: real-time voice/video/WebRTC quality test. Speed tests can pass
# while conferencing fails -- calls care about one-way delay, jitter, burst
# loss, and setup, not average throughput. This gate locks the two honesty
# rules the acceptance criteria hedges on: one-way delay never comes from
# halving an RTT, and the MOS-style figure is always labeled an estimate.

check_ok "cargo test covers media-quality setup/one-way-delay/MOS/concealment logic" \
    cargo test --release --lib network_tests::media_quality:: --manifest-path "$REPO_ROOT/Cargo.toml"

# --- one-way delay is never derived from RTT/2 ---
check_contains "cargo test proves one-way delay is never derived from RTT" \
    "one_way_delay_never_derived_from_rtt" \
    cargo test --release --lib network_tests::media_quality:: --manifest-path "$REPO_ROOT/Cargo.toml"

# --- the MOS-style figure always carries an estimate label + its inputs ---
check_contains "cargo test proves the MOS-style figure is always labeled an estimate with its inputs" \
    "mos_is_always_labeled_an_estimate_with_inputs" \
    cargo test --release --lib network_tests::media_quality:: --manifest-path "$REPO_ROOT/Cargo.toml"

# --- concealment/freeze risk derive from burst structure, not mean loss ---
check_contains "cargo test proves concealment/freeze risk derive from burst structure, not mean loss" \
    "concealment_and_freeze_risk_derive_from_burst_structure_not_mean_loss" \
    cargo test --release --lib network_tests::media_quality:: --manifest-path "$REPO_ROOT/Cargo.toml"

# --- setup failure is a distinct state from a degraded-but-live call ---
check_contains "cargo test proves an unestablished setup is distinct from a degraded call" \
    "setup_never_established_is_distinct_from_a_degraded_call" \
    cargo test --release --lib network_tests::media_quality:: --manifest-path "$REPO_ROOT/Cargo.toml"

check_contains "cargo test proves zero bursts is Indeterminate concealment, not LikelyConcealed" \
    "indeterminate_concealment_when_no_bursts_occurred" \
    cargo test --release --lib network_tests::media_quality:: --manifest-path "$REPO_ROOT/Cargo.toml"

# --- CLI surface: never places a real call / signs into a service ---
check_lacks "media-quality --help offers no --sign-in or account flag" "--sign-in" \
    "$BIN" media-quality --help
check_contains "media-quality --help documents ICE candidate path coverage" "TURN" \
    "$BIN" media-quality --help
check_fails "media-quality with neither --live-event nor --maintenance refuses to start" \
    "$BIN" media-quality --interface lo0 --target 127.0.0.1

# --- CLI: an unattempted TURN path (no --turn-relay) is reported Refused
#     with an explicit "not attempted" reason, never silently omitted ---
if net_guard; then
    py="$(command -v python3 || true)"
    if [ -z "$py" ]; then
        skip "live audio-profile run reports RTT/MOS/one-way-delay unavailable and unattempted TURN paths" "python3 unavailable"
    else
        echo_port=39777
        "$py" -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(15)
s.bind(('127.0.0.1', $echo_port))
try:
    while True:
        data, addr = s.recvfrom(2000)
        s.sendto(data, addr)
except socket.timeout:
    pass
" &
        echo_pid=$!
        sleep 0.3

        out="$("$BIN" media-quality --interface lo0 --target 127.0.0.1 --port "$echo_port" \
            --profile audio --count 60 --maintenance --json 2>/dev/null | sed -n '/^{/,$p')"
        kill "$echo_pid" 2>/dev/null
        wait "$echo_pid" 2>/dev/null

        if [ -z "$out" ]; then
            fail "live audio-profile run reports RTT/MOS/one-way-delay unavailable and unattempted TURN paths" "no JSON output"
        else
            check="$(printf '%s' "$out" | python3 -c '
import json, sys
d = json.load(sys.stdin)
owd_ok = "Unavailable" in d.get("one_way_delay", {})
mos_label = d.get("mos", {}).get("label", "")
mos_ok = "estimate" in mos_label.lower() and "NOT an ITU-T P.800" in mos_label
turn_refused = [c for c in d.get("ice_candidates", []) if c.get("path") in ("TurnUdp","TurnTcp","TurnTls")]
turn_ok = len(turn_refused) == 3 and all("Refused" in c.get("setup", {}) for c in turn_refused)
print("ok" if owd_ok and mos_ok and turn_ok else "bad")
' 2>/dev/null)"
            if [ "$check" = "ok" ]; then
                pass "live audio-profile run reports RTT/MOS/one-way-delay unavailable and unattempted TURN paths"
            else
                fail "live audio-profile run reports RTT/MOS/one-way-delay unavailable and unattempted TURN paths" "got: $out"
            fi
        fi
    fi
else
    skip "live audio-profile run reports RTT/MOS/one-way-delay unavailable and unattempted TURN paths" "FP_HARNESS_OFFLINE=1"
fi
