#!/usr/bin/env bash
# GAP-038: the management bastion must never be assigned a test phase (the
# control channel's own congestion would become the measurement), node
# labels must never reveal the management address they were derived from,
# concurrency/timeouts must be real bounds (not decorative flags), and an
# excluded node (timeout) must never be averaged in as zero. This gate
# uses only the built-in mock inventory -- no live SSH/fanout is attempted,
# per this task's explicit no-live-connection constraint for this session.

check_ok "cargo test covers label/plan/fanout/summary logic" \
    cargo test --release --lib network_tests::fleet_orchestrator:: --manifest-path "$REPO_ROOT/Cargo.toml"

check_contains "fleet-orchestrator advertises --mock-inventory" "--mock-inventory" \
    "$BIN" fleet-orchestrator --help
check_contains "fleet-orchestrator advertises --max-concurrency" "--max-concurrency" \
    "$BIN" fleet-orchestrator --help
check_contains "fleet-orchestrator advertises --per-node-timeout-secs" "--per-node-timeout-secs" \
    "$BIN" fleet-orchestrator --help

# --- without --mock-inventory, refuses (no live-connection path exists to fall back to) ---
check_fails "without --mock-inventory the command refuses (no real-fanout path exists)" \
    "$BIN" fleet-orchestrator

out="$("$BIN" fleet-orchestrator --mock-inventory --mock-node-count 6 --max-concurrency 3 --per-node-timeout-secs 3 2>&1)"

# --- no management address, hostname, or IP-shaped token in output ---
check_lacks "output carries no IPv4-shaped address" "10.220." bash -c 'printf "%s" "$1"' _ "$out"
check_lacks "output carries no bastion hostname" "anderton" bash -c 'printf "%s" "$1"' _ "$out"
check_lacks "output carries no bastion hostname (precog-00)" "precog-00" bash -c 'printf "%s" "$1"' _ "$out"
check_lacks "output carries no SSH key path" ".ssh/precog" bash -c 'printf "%s" "$1"' _ "$out"

# --- a timed-out node is excluded with a reason, never a zero measurement ---
check_contains "a timed-out node is reported excluded with a reason" "timed out" \
    bash -c 'printf "%s" "$1"' _ "$out"
check_lacks "the excluded node is never labeled with a zero-valued metric" "0 Mbps" \
    bash -c 'printf "%s" "$1"' _ "$out"

json_out="$("$BIN" fleet-orchestrator --mock-inventory --mock-node-count 6 --max-concurrency 3 --per-node-timeout-secs 3 --json 2>&1 | sed -n '/^{/,$p')"
completed="$(printf '%s' "$json_out" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print(d["summary"]["completed"])
' 2>/dev/null)"
excluded_count="$(printf '%s' "$json_out" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print(len(d["summary"]["excluded_with_reason"]))
' 2>/dev/null)"
if [ "${completed:-0}" -gt 0 ] 2>/dev/null && [ "${excluded_count:-0}" -gt 0 ] 2>/dev/null; then
    pass "summary reports both completed and excluded counts distinctly ($completed completed, $excluded_count excluded)"
else
    fail "summary reports both completed and excluded counts distinctly" "completed=$completed excluded=$excluded_count"
fi

# --- labels are stable across two separate runs ---
labels_a="$(printf '%s' "$json_out" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print(sorted(r["label"] for r in d["results"]))
' 2>/dev/null)"
json_out2="$("$BIN" fleet-orchestrator --mock-inventory --mock-node-count 6 --max-concurrency 3 --per-node-timeout-secs 3 --json 2>&1 | sed -n '/^{/,$p')"
labels_b="$(printf '%s' "$json_out2" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print(sorted(r["label"] for r in d["results"]))
' 2>/dev/null)"
if [ "$labels_a" = "$labels_b" ] && [ -n "$labels_a" ]; then
    pass "node labels are stable across two separate runs"
else
    fail "node labels are stable across two separate runs" "run1=$labels_a run2=$labels_b"
fi

# --- concurrency bound is real, not decorative ---
check_ok "cargo test proves the concurrency bound is respected under a larger fanout" \
    cargo test --release --lib network_tests::fleet_orchestrator::tests::concurrency_bound_is_respected_under_a_larger_fanout \
    --manifest-path "$REPO_ROOT/Cargo.toml"
check_ok "cargo test proves the bastion never receives a test phase" \
    cargo test --release --lib network_tests::fleet_orchestrator::tests::fanout_only_runs_test_nodes_never_the_bastion \
    --manifest-path "$REPO_ROOT/Cargo.toml"
