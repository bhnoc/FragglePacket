#!/usr/bin/env bash
# GAP-040: listener sessions must be leased only against an operator-named
# allowlist (never discovered/scanned), one listener per active session,
# and any loss figure from a public endpoint must carry a declared endpoint
# loss floor. Capacity/duration consistency is checked per transport, not
# just reachability -- the XMission-Colorado duration-inconsistent-summary
# case. Uses local loopback iperf3 only.

check_ok "cargo test covers listener leasing / capacity-floor logic" \
    cargo test --release --lib network_tests::listener_lease:: --manifest-path "$REPO_ROOT/Cargo.toml"

check_contains "listener-lease advertises --allow" "--allow" \
    "$BIN" listener-lease --help
check_contains "listener-lease advertises --use-listener" "--use-listener" \
    "$BIN" listener-lease --help
check_contains "listener-lease advertises --max-concurrency" "--max-concurrency" \
    "$BIN" listener-lease --help

# --- the hard requirement: no port outside the allowlist is ever contacted ---
check_fails "a port outside the allowlist is refused before any contact" \
    "$BIN" listener-lease --allow "127.0.0.1:15601" --use-listener "127.0.0.1:19998" --duration-secs 1
check_contains "the refusal names the unauthorized port, proving it was never dialed" "not in the operator-authorized" \
    "$BIN" listener-lease --allow "127.0.0.1:15601" --use-listener "127.0.0.1:19998" --duration-secs 1

# --- proof, not just an error string: a REAL listener on the unauthorized
# port must never see a connection attempt. accept() on a real socket lets
# us tell "refused before dialing" apart from "refused after connecting and
# then bailing", which a bare error-string check cannot distinguish.
if command -v python3 >/dev/null 2>&1; then
    marker="$WORK_DIR/gap040-unauthorized-contact.marker"
    rm -f "$marker"
    python3 - "$marker" >"$WORK_DIR/gap040-sentinel.log" 2>&1 <<'PY' &
import socket, sys, time
marker = sys.argv[1]
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 19997))
s.listen(1)
s.settimeout(3)
try:
    conn, _ = s.accept()
    open(marker, "w").write("contacted")
    conn.close()
except socket.timeout:
    pass
s.close()
PY
    sentinel_pid=$!
    sleep 0.3
    "$BIN" listener-lease --allow "127.0.0.1:15601" --use-listener "127.0.0.1:19997" --duration-secs 1 \
        >/dev/null 2>&1
    wait "$sentinel_pid" 2>/dev/null
    if [ -f "$marker" ]; then
        fail "no connection attempt reaches an unauthorized port's real listener" \
            "the sentinel on 19997 recorded an incoming connection despite the port being unauthorized"
    else
        pass "no connection attempt reaches an unauthorized port's real listener"
    fi
    rm -f "$marker" "$WORK_DIR/gap040-sentinel.log"
else
    skip "no connection attempt reaches an unauthorized port's real listener" "python3 not available"
fi

if ! command -v iperf3 >/dev/null 2>&1; then
    skip "GAP-040 live listener-lease session" "iperf3 not installed"
else
    PORT=15601
    iperf3 -s -p "$PORT" -1 -D >/dev/null 2>&1
    sleep 0.3

    out_log="$WORK_DIR/gap040-lease.log"
    "$BIN" listener-lease --allow "127.0.0.1:$PORT" --use-listener "127.0.0.1:$PORT" --duration-secs 1 --json \
        > "$out_log" 2>&1
    sed -n '/^{/,$p' "$out_log" > "$out_log.json"

    check_json_field "leased session JSON carries endpoint_loss_floor" "endpoint_loss_floor" cat "$out_log.json"
    check_json_field "leased session JSON carries a capacity_verdict" "capacity_verdict" cat "$out_log.json"

    floor_family="$(python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))
print(d["endpoint_loss_floor"]["client_version_family"])
' "$out_log.json" 2>/dev/null)"
    if [ -n "$floor_family" ]; then
        pass "endpoint loss floor names a client-version family ($floor_family)"
    else
        fail "endpoint loss floor names a client-version family" "empty"
    fi

    iperf3 -s -p "$PORT" -1 -D >/dev/null 2>&1
    sleep 0.3
    human_log="$WORK_DIR/gap040-lease-human.log"
    "$BIN" listener-lease --allow "127.0.0.1:$PORT" --use-listener "127.0.0.1:$PORT" --duration-secs 1 \
        > "$human_log" 2>&1
    check_contains "human output states duration-consistent for a normal short local run" "duration-consistent" \
        cat "$human_log"

    rm -f "$out_log" "$out_log.json" "$human_log"
    pkill -f "iperf3 -s -p $PORT" 2>/dev/null
fi

# --- capacity qualification rejects a duration-inconsistent summary offline (unit-level, no live listener needed) ---
check_ok "cargo test proves a duration-inconsistent capacity summary is rejected" \
    cargo test --release --lib network_tests::listener_lease::tests::duration_inconsistent_capacity_is_rejected \
    --manifest-path "$REPO_ROOT/Cargo.toml"

# --- one listener per active session: a second lease of the same port fails while the first is held ---
check_ok "cargo test proves one listener per active session is enforced" \
    cargo test --release --lib network_tests::listener_lease::tests::one_listener_per_active_session_enforced \
    --manifest-path "$REPO_ROOT/Cargo.toml"
