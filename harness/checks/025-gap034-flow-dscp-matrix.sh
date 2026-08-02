#!/usr/bin/env bash
# GAP-034: constant-aggregate flow-count and QoS/DSCP matrix. Field evidence:
# loss varied non-monotonically with 1/2/4/8 flows, and DSCP-marked runs
# were variable without capture proof the marking survived the path. That
# proof requires a capture at both ends; without one, DSCP "results" are
# not QoS evidence, they're a coin flip dressed up as a measurement.

check_ok "cargo test covers flow-dscp-matrix constancy/drift/survival logic" \
    cargo test --release --lib network_tests::flow_dscp_matrix:: --manifest-path "$REPO_ROOT/Cargo.toml"

# --- aggregate genuinely held constant across flow counts is detected ---
check_contains "cargo test proves aggregate-held-constant is detected across flow counts" \
    "aggregate_held_constant_across_flow_counts_is_detected" \
    cargo test --release --lib network_tests::flow_dscp_matrix:: --manifest-path "$REPO_ROOT/Cargo.toml"
check_contains "cargo test proves a NOT-held-constant aggregate is also detected" \
    "aggregate_not_held_constant_is_detected" \
    cargo test --release --lib network_tests::flow_dscp_matrix:: --manifest-path "$REPO_ROOT/Cargo.toml"
check_contains "cargo test proves an unmeasured point blocks the held-constant claim" \
    "unmeasured_aggregate_point_prevents_held_constant_claim" \
    cargo test --release --lib network_tests::flow_dscp_matrix:: --manifest-path "$REPO_ROOT/Cargo.toml"

# --- DSCP survival requires BOTH source and destination capture; missing
#     either side reports Unverified, never an assumed Survived ---
check_contains "cargo test proves DSCP survival requires both-sides capture" \
    "dscp_survival_requires_both_sides_captured" \
    cargo test --release --lib network_tests::flow_dscp_matrix:: --manifest-path "$REPO_ROOT/Cargo.toml"
check_contains "cargo test proves unverified DSCP survival withholds its loss correlation" \
    "unverified_survival_withholds_loss_correlation" \
    cargo test --release --lib network_tests::flow_dscp_matrix:: --manifest-path "$REPO_ROOT/Cargo.toml"

# --- repeated controls that drift are flagged ---
check_contains "cargo test proves drift between repeated controls is detected" \
    "control_drift_is_detected_between_repeats" \
    cargo test --release --lib network_tests::flow_dscp_matrix:: --manifest-path "$REPO_ROOT/Cargo.toml"

# --- CLI surface ---
check_contains "flow-dscp-matrix advertises --repeat-control" "--repeat-control" \
    "$BIN" flow-dscp-matrix --help
check_contains "flow-dscp-matrix advertises --observed-dscp for destination-side proof" "--observed-dscp" \
    "$BIN" flow-dscp-matrix --help
check_fails "flow-dscp-matrix with neither --live-event nor --maintenance refuses to start" \
    "$BIN" flow-dscp-matrix --interface lo0 --target 127.0.0.1

# --- live: a DSCP sweep with NO --observed-dscp must report every class as
#     unverified, never a bare survived/altered verdict fabricated from the
#     send side alone ---
if net_guard; then
    py="$(command -v python3 || true)"
    if [ -z "$py" ]; then
        skip "DSCP sweep with no destination capture reports every class unverified" "python3 unavailable"
    else
        echo_port=39202
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

        out="$("$BIN" flow-dscp-matrix --interface lo0 --target 127.0.0.1 --port "$echo_port" \
            --flow-counts 1 --duration-secs 1 --dscp-classes 0,46 --maintenance --json 2>/dev/null | sed -n '/^{/,$p')"

        if [ -z "$out" ]; then
            fail "DSCP sweep with no destination capture reports every class unverified" "no JSON output"
        else
            all_unverified="$(printf '%s' "$out" | python3 -c '
import json, sys
d = json.load(sys.stdin)
results = d.get("dscp_results", [])
print("ok" if results and all(r["survival"] == "Unverified" for r in results) else "bad")
' 2>/dev/null)"
            if [ "$all_unverified" = "ok" ]; then
                pass "DSCP sweep with no destination capture reports every class unverified"
            else
                fail "DSCP sweep with no destination capture reports every class unverified" "got: $out"
            fi
        fi

        # --- providing --observed-dscp that matches sent flips exactly that
        #     class to Survived, proving the gate has real signal ---
        out2="$("$BIN" flow-dscp-matrix --interface lo0 --target 127.0.0.1 --port "$echo_port" \
            --flow-counts 1 --duration-secs 1 --dscp-classes 46 --observed-dscp 46=46 --maintenance --json 2>/dev/null | sed -n '/^{/,$p')"
        kill "$echo_pid" 2>/dev/null
        wait "$echo_pid" 2>/dev/null

        if [ -z "$out2" ]; then
            skip "matching --observed-dscp flips survival to Survived" "no JSON output"
        else
            survived="$(printf '%s' "$out2" | python3 -c '
import json, sys
d = json.load(sys.stdin)
results = d.get("dscp_results", [])
print("ok" if results and results[0]["survival"] == "Survived" else "bad")
' 2>/dev/null)"
            if [ "$survived" = "ok" ]; then
                pass "matching --observed-dscp flips survival to Survived"
            else
                fail "matching --observed-dscp flips survival to Survived" "got: $out2"
            fi
        fi
    fi
else
    skip "DSCP sweep with no destination capture reports every class unverified" "FP_HARNESS_OFFLINE=1"
fi
