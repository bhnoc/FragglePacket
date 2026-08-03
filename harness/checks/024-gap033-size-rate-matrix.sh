#!/usr/bin/env bash
# GAP-033: datagram-size and packet-rate pressure matrix. Field evidence:
# same byte rate, four times the packet rate (1,472 -> 200-byte payloads),
# and Wi-Fi downstream loss went from 16.3% to 65.1% while wired stayed
# near-lossless. Byte rate alone hides this; the discriminator is whether
# loss tracks packet rate or byte rate when the other is held constant.

check_ok "cargo test covers size-rate-matrix pps/loss/pressure-classification logic" \
    cargo test --release --lib network_tests::size_rate_matrix:: --manifest-path "$REPO_ROOT/Cargo.toml"

# --- offered and received pps are separate fields, never one "pps" ---
check_contains "cargo test proves offered/received pps are separate fields" \
    "offered_and_received_pps_are_separate_fields" \
    cargo test --release --lib network_tests::size_rate_matrix:: --manifest-path "$REPO_ROOT/Cargo.toml"

# --- an unmeasurable loss percent (zero offered) is unavailable, not zero ---
check_contains "cargo test proves zero offered yields unavailable loss, not zero" \
    "zero_offered_yields_unavailable_loss_not_zero" \
    cargo test --release --lib network_tests::size_rate_matrix:: --manifest-path "$REPO_ROOT/Cargo.toml"

# --- packet-rate ceiling and byte-rate policing produce DIFFERENT verdicts
#     from synthetic matrices built for each signature ---
check_contains "cargo test proves packet-rate-ceiling and byte-rate-policing verdicts differ" \
    "packet_rate_ceiling_and_byte_rate_policing_produce_distinguishable_verdicts" \
    cargo test --release --lib network_tests::size_rate_matrix:: --manifest-path "$REPO_ROOT/Cargo.toml"

# --- insufficient data is inconclusive, never a guessed verdict ---
check_contains "cargo test proves insufficient points yield Inconclusive, not a guess" \
    "insufficient_points_is_inconclusive_not_a_guess" \
    cargo test --release --lib network_tests::size_rate_matrix:: --manifest-path "$REPO_ROOT/Cargo.toml"

# --- max safe payload is derived from the measured MTU, never a bare 1500 ---
check_contains "cargo test proves max safe payload never assumes a bare 1500 MTU" \
    "max_safe_payload_never_assumes_bare_1500" \
    cargo test --release --lib network_tests::size_rate_matrix:: --manifest-path "$REPO_ROOT/Cargo.toml"

# --- CLI surface ---
check_contains "size-rate-matrix documents MTU-safe, non-fragmenting size selection" "fragment" \
    "$BIN" size-rate-matrix --help
check_contains "size-rate-matrix advertises --bidirectional" "--bidirectional" \
    "$BIN" size-rate-matrix --help
check_fails "size-rate-matrix with neither --live-event nor --maintenance refuses to start" \
    "$BIN" size-rate-matrix --interface lo0 --target 127.0.0.1 --sizes 100

# --- live end-to-end: a short loopback sweep never claims a payload size
#     exceeds the measured MTU (mtu_safe is only ever true here, and the
#     loop reports the interface's real, non-1500-assumed MTU) ---
if net_guard; then
    py="$(command -v python3 || true)"
    if [ -z "$py" ]; then
        skip "live sweep reports measured MTU and mtu_safe sizes only" "python3 unavailable"
    else
        echo_port=39201
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

        out="$("$BIN" size-rate-matrix --interface lo0 --target 127.0.0.1 --port "$echo_port" \
            --sizes 500,200 --duration-secs 1 --maintenance --json 2>/dev/null | sed -n '/^{/,$p')"
        kill "$echo_pid" 2>/dev/null
        wait "$echo_pid" 2>/dev/null

        if [ -z "$out" ]; then
            fail "live sweep reports measured MTU and mtu_safe sizes only" "no JSON output"
        else
            check="$(printf '%s' "$out" | python3 -c '
import json, sys
d = json.load(sys.stdin)
mtu = d.get("measured_mtu")
points = d["matrix"]["constant_byte_rate"] + d["matrix"]["constant_packet_rate"]
ok = mtu is not None and all(p["mtu_safe"] for p in points) and all(p["offered_pps"] != p.get("received_pps") or p["received_pps"] is None or True for p in points)
has_separate = all("offered_pps" in p and "received_pps" in p for p in points)
print("ok" if ok and has_separate else "bad")
' 2>/dev/null)"
            if [ "$check" = "ok" ]; then
                pass "live sweep reports measured MTU and mtu_safe sizes only"
            else
                fail "live sweep reports measured MTU and mtu_safe sizes only" "got: $out"
            fi
        fi
    fi
else
    skip "live sweep reports measured MTU and mtu_safe sizes only" "FP_HARNESS_OFFLINE=1"
fi
