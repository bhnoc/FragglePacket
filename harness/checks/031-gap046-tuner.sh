#!/usr/bin/env bash
# GAP-046: the throughput tuner must reject any trial whose reported
# duration is inconsistent with what was requested (never score it), must
# preflight-skip candidates that would exceed local socket/CPU limits, and
# must keep synthetic-maximum and representative-application throughput as
# genuinely separate fields. Uses local loopback iperf3 only.

check_ok "cargo test covers trial evaluation / preflight / verdict-separation logic" \
    cargo test --release --lib network_tests::throughput_tuner:: --manifest-path "$REPO_ROOT/Cargo.toml"

check_contains "throughput-tuner advertises --representative-streams" "--representative-streams" \
    "$BIN" throughput-tuner --help
check_contains "throughput-tuner advertises --drift-baseline-repeats" "--drift-baseline-repeats" \
    "$BIN" throughput-tuner --help

# --- offline: duration-inconsistent trial (the field's 16-stream/15.84s case) is rejected, never scored ---
check_ok "cargo test proves a duration-inconsistent trial is rejected not scored" \
    cargo test --release --lib network_tests::throughput_tuner::tests::duration_inconsistent_trial_is_rejected_not_scored \
    --manifest-path "$REPO_ROOT/Cargo.toml"

# --- offline: preflight refuses a candidate that would exceed the fd/CPU budget ---
check_ok "cargo test proves preflight flags a socket-limit risk" \
    cargo test --release --lib network_tests::throughput_tuner::tests::preflight_flags_socket_limit_risk \
    --manifest-path "$REPO_ROOT/Cargo.toml"

# --- offline: synthetic-maximum and representative-application are independent fields ---
check_ok "cargo test proves synthetic-maximum and representative-application are independent" \
    cargo test --release --lib network_tests::throughput_tuner::tests::synthetic_maximum_and_representative_are_independent_fields \
    --manifest-path "$REPO_ROOT/Cargo.toml"

if ! command -v iperf3 >/dev/null 2>&1; then
    skip "GAP-046 live throughput-tuner run" "iperf3 not installed"
else
    PORT=15701
    iperf3 -s -p "$PORT" -D >/dev/null 2>&1
    sleep 0.3

    out_log="$WORK_DIR/gap046-tuner.log"
    "$BIN" throughput-tuner \
        --host 127.0.0.1 --port "$PORT" \
        --streams 2 4 --block-sizes-kib 64 128 \
        --trial-duration-secs 1 --representative-streams 2 --representative-block-kib 64 \
        --cohort-label loopback-test --json \
        > "$out_log" 2>&1
    sed -n '/^{/,$p' "$out_log" > "$out_log.json"

    check_json_field "tuner JSON carries synthetic_maximum_bps" "verdict.synthetic_maximum_bps" cat "$out_log.json"
    check_json_field "tuner JSON carries representative_application_bps" "verdict.representative_application_bps" cat "$out_log.json"
    check_json_field "tuner JSON carries preflight_limits.cpu_cores" "preflight_limits.cpu_cores" cat "$out_log.json"

    synth="$(python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))
print(d["verdict"]["synthetic_maximum_bps"])
' "$out_log.json" 2>/dev/null)"
    rep="$(python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))
print(d["verdict"]["representative_application_bps"])
' "$out_log.json" 2>/dev/null)"
    if [ -n "$synth" ] && [ "$synth" != "None" ] && [ -n "$rep" ] && [ "$rep" != "None" ]; then
        pass "a real local run produces both a synthetic-maximum and a representative-application figure"
    else
        fail "a real local run produces both a synthetic-maximum and a representative-application figure" \
            "synth=$synth rep=$rep"
    fi

    human_log="$WORK_DIR/gap046-tuner-human.log"
    "$BIN" throughput-tuner \
        --host 127.0.0.1 --port "$PORT" \
        --streams 2 --block-sizes-kib 64 \
        --trial-duration-secs 1 --representative-streams 2 --representative-block-kib 64 \
        --cohort-label loopback-human \
        > "$human_log" 2>&1
    check_contains "human output labels the synthetic maximum distinctly from the representative figure" \
        "synthetic maximum:" cat "$human_log"
    check_contains "human output labels the representative-application figure distinctly" \
        "representative-application:" cat "$human_log"

    # --- a candidate deliberately sized to exceed a tiny fd limit is preflight-skipped, never attempted ---
    huge_log="$WORK_DIR/gap046-huge.log"
    "$BIN" throughput-tuner \
        --host 127.0.0.1 --port "$PORT" \
        --streams 4096 --block-sizes-kib 64 \
        --trial-duration-secs 1 --representative-streams 2 --representative-block-kib 64 \
        > "$huge_log" 2>&1
    check_contains "an absurd stream count is preflight-skipped, not attempted against the listener" \
        "preflight-skipped" cat "$huge_log"

    rm -f "$out_log" "$out_log.json" "$human_log" "$huge_log"
    pkill -f "iperf3 -s -p $PORT" 2>/dev/null
fi
