#!/usr/bin/env bash
# GAP-066: burst-loss, reordering, duplication, and microburst analysis.
# Average loss/throughput hides the failures that break media/interactive
# traffic (field evidence: 16.3% -> 65.1% Wi-Fi downstream loss just from
# shrinking payload size at a fixed byte rate -- a packet-rate ceiling, not
# a byte-rate one, invisible to a mean). This gate locks the pure analysis
# logic in src/network_tests/burst_analysis.rs against deterministic
# synthetic input, so correctness never depends on real network behavior.

check_ok "cargo test covers burst-analysis run-length/gap/reorder/duplicate/queue-delay logic" \
    cargo test --release --lib network_tests::burst_analysis:: --manifest-path "$REPO_ROOT/Cargo.toml"

# --- known burst structure produces the correct run-length distribution and gaps ---
check_contains "cargo test proves a known burst structure yields correct run lengths and gap durations" \
    "known_burst_structure_produces_correct_run_lengths_and_gaps" \
    cargo test --release --lib network_tests::burst_analysis:: --manifest-path "$REPO_ROOT/Cargo.toml"

# --- reordered packets are never counted as lost ---
check_contains "cargo test proves a reordered packet is not counted as lost" \
    "reordered_packet_is_not_counted_as_lost" \
    cargo test --release --lib network_tests::burst_analysis:: --manifest-path "$REPO_ROOT/Cargo.toml"

# --- duplicates are reported separately from loss and reordering ---
check_contains "cargo test proves duplicates are reported separately from loss and reordering" \
    "duplicates_are_reported_separately_from_loss_and_reordering" \
    cargo test --release --lib network_tests::burst_analysis:: --manifest-path "$REPO_ROOT/Cargo.toml"

# --- an unmeasurable metric reports unavailable, never a fabricated zero ---
check_contains "cargo test proves an unmeasurable gap duration is unavailable, not zero" \
    "unmeasurable_gap_duration_is_unavailable_not_zero" \
    cargo test --release --lib network_tests::burst_analysis:: --manifest-path "$REPO_ROOT/Cargo.toml"
check_contains "cargo test proves zero bursts reports mean_run_length unavailable, not 0.0" \
    "no_bursts_reports_none_mean_run_length_not_zero" \
    cargo test --release --lib network_tests::burst_analysis:: --manifest-path "$REPO_ROOT/Cargo.toml"

# --- a capture-derived figure carries the offload/vantage qualification ---
check_contains "cargo test proves capture-derived qualification travels into the report" \
    "capture_qualification_travels_into_the_report" \
    cargo test --release --lib network_tests::burst_analysis:: --manifest-path "$REPO_ROOT/Cargo.toml"

# --- queue-delay correlation distinguishes rising-delay bursts (queueing) ---
check_contains "cargo test proves rising delay before a burst is detected" \
    "rising_delay_before_burst_is_detected" \
    cargo test --release --lib network_tests::burst_analysis:: --manifest-path "$REPO_ROOT/Cargo.toml"

# --- CLI surface: bounded by construction, no unbounded/continuous mode ---
check_contains "burst-analysis advertises --count (bounded sequence length)" "--count" \
    "$BIN" burst-analysis --help
check_contains "burst-analysis --help documents the bounded, non-continuous design" "bounded" \
    "$BIN" burst-analysis --help
check_contains "burst-analysis advertises --ramped for representative-vs-ramped comparison" "--ramped" \
    "$BIN" burst-analysis --help
check_contains "burst-analysis requires an explicit mode (no default budget)" "--maintenance" \
    "$BIN" burst-analysis --help

check_fails "burst-analysis with neither --live-event nor --maintenance refuses to start" \
    "$BIN" burst-analysis --interface lo0 --target 127.0.0.1 --count 5

# --- live end-to-end sanity: a short bounded loopback UDP echo pass produces
#     a structured report with the fields this gate locks, all present even
#     when there happens to be no loss/reordering/duplication on loopback ---
if net_guard; then
    py="$(command -v python3 || true)"
    if [ -z "$py" ]; then
        skip "live bounded loopback pass produces a structured burst report" "python3 unavailable for throwaway echo server"
    else
        echo_port=39199
        "$py" -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(15)
s.bind(('127.0.0.1', $echo_port))
try:
    while True:
        data, addr = s.recvfrom(1024)
        s.sendto(data, addr)
except socket.timeout:
    pass
" &
        echo_pid=$!
        sleep 0.3

        out="$("$BIN" burst-analysis --interface lo0 --target 127.0.0.1 --port "$echo_port" \
            --rate-pps 20 --count 40 --maintenance --json 2>/dev/null | sed -n '/^{/,$p')"
        kill "$echo_pid" 2>/dev/null
        wait "$echo_pid" 2>/dev/null

        if [ -z "$out" ]; then
            fail "live bounded loopback pass produces a structured burst report" "no JSON output"
        else
            has_fields="$(printf '%s' "$out" | python3 -c '
import json, sys
d = json.load(sys.stdin)
n = d.get("normal", {})
required = ["sent_count", "received_count", "loss_percent", "burst", "reordering", "duplicate_count", "jitter", "queue_delay_correlation"]
print("ok" if all(k in n for k in required) else "missing")
' 2>/dev/null)"
            if [ "$has_fields" = "ok" ]; then
                pass "live bounded loopback pass produces a structured burst report"
            else
                fail "live bounded loopback pass produces a structured burst report" "got: $out"
            fi
        fi
    fi
else
    skip "live bounded loopback pass produces a structured burst report" "FP_HARNESS_OFFLINE=1"
fi
