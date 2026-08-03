#!/usr/bin/env bash
# GAP-036: endpoint capability discovery must probe only an explicit,
# operator-named allowlist of ports -- never a range, never a scan. This is
# an authorization boundary, not a style preference: contacting a port the
# operator did not name is a different act than measuring a named listener.
# Runs fully offline against 127.0.0.1 with no listener present, so every
# probe is a fast local connection refusal and nothing here needs the
# network to be reachable.

check_contains "iperf-analyze advertises --allow-port" "--allow-port" \
    "$BIN" iperf-analyze --help

# --- exactly the named ports are probed, nothing else ---
out="$("$BIN" iperf-analyze --target 127.0.0.1 --allow-port 54331 --allow-port 54332 --json 2>/dev/null | sed -n '/^{/,$p')"
if [ -z "$out" ]; then
    fail "discovery against an explicit allowlist produces JSON output" "empty output"
else
    ports="$(printf '%s' "$out" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print(",".join(str(c["port"]) for c in d["capabilities"]))
' 2>/dev/null)"
    if [ "$ports" = "54331,54332" ]; then
        pass "discovery probes exactly the allowlisted ports, in the given order, nothing else"
    else
        fail "discovery probes exactly the allowlisted ports, in the given order, nothing else" "got: $ports"
    fi

    allowlisted="$(printf '%s' "$out" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print(",".join(str(p) for p in d["allowlisted_ports"]))
' 2>/dev/null)"
    if [ "$allowlisted" = "54331,54332" ]; then
        pass "reported allowlisted_ports matches exactly what was passed in"
    else
        fail "reported allowlisted_ports matches exactly what was passed in" "got: $allowlisted"
    fi
fi

# --- a single allowlisted port never causes any other port to be contacted ---
single_out="$("$BIN" iperf-analyze --target 127.0.0.1 --allow-port 54399 --json 2>/dev/null | sed -n '/^{/,$p')"
count="$(printf '%s' "$single_out" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(len(d["capabilities"]))' 2>/dev/null)"
if [ "${count:-0}" = "1" ]; then
    pass "a single-port allowlist yields exactly one probed capability entry"
else
    fail "a single-port allowlist yields exactly one probed capability entry" "got: $count"
fi

# --- unreachable ports are reported honestly, not silently dropped ---
reachable="$(printf '%s' "$single_out" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["capabilities"][0]["reachable"])' 2>/dev/null)"
if [ "$reachable" = "False" ]; then
    pass "an unreachable allowlisted port is reported as unreachable, not omitted"
else
    fail "an unreachable allowlisted port is reported as unreachable, not omitted" "got: $reachable"
fi

# --- --allow-port with no --target refuses cleanly rather than guessing a target ---
check_fails "--allow-port without --target refuses cleanly" \
    "$BIN" iperf-analyze --allow-port 5201

# --- human output states which ports were probed, for auditability ---
check_contains "human output states the allowlisted ports probed" "allowlisted ports (probed, and only these)" \
    "$BIN" iperf-analyze --target 127.0.0.1 --allow-port 54388

# --- unit-level guarantee: the underlying discovery function's port list
# equals the input allowlist exactly (belt-and-suspenders on the CLI check above) ---
check_ok "cargo test allowlist_never_probes_a_port_outside_the_list" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib network_tests::iperf::tests::allowlist_never_probes_a_port_outside_the_list 2>&1 | grep -q '1 passed'"
