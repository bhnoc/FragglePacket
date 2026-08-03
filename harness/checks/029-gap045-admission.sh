#!/usr/bin/env bash
# GAP-045: a synchronized public-listener fanout must classify admission
# per listener and never let a listener that never connected become a
# 0 Mbps measurement. Field evidence: 21 same-second probes, 12 completed,
# 9 timed out without ever establishing a connection; those 9 were excluded
# from the field investigation's aggregate, not recorded as zero. This gate
# locks that exact behavior using local loopback iperf3 servers -- never a
# real public listener -- so it stays fast and does no harm to anyone else's
# infrastructure.

check_ok "cargo test covers admission classification/cohort logic" \
    cargo test --release --lib network_tests::listener_admission:: --manifest-path "$REPO_ROOT/Cargo.toml"

check_contains "admission-fanout advertises --target/--streams/--safety-timeout-secs" "--safety-timeout-secs" \
    "$BIN" admission-fanout --help
check_contains "admission-fanout advertises --minimum-valid-cohort" "--minimum-valid-cohort" \
    "$BIN" admission-fanout --help

if ! command -v iperf3 >/dev/null 2>&1; then
    skip "GAP-045 live admission fanout" "iperf3 not installed"
else
    GOOD_PORT_A=15501
    GOOD_PORT_B=15502
    DEAD_PORT=15599

    iperf3 -s -p "$GOOD_PORT_A" -1 -D >/dev/null 2>&1
    iperf3 -s -p "$GOOD_PORT_B" -1 -D >/dev/null 2>&1
    sleep 0.3

    out_log="$WORK_DIR/gap045-fanout.log"
    "$BIN" admission-fanout \
        --target "127.0.0.1:$GOOD_PORT_A" \
        --target "127.0.0.1:$GOOD_PORT_B" \
        --target "127.0.0.1:$DEAD_PORT" \
        --streams 2 --duration-secs 1 --safety-timeout-secs 5 --json \
        > "$out_log" 2>&1
    sed -n '/^{/,$p' "$out_log" > "$out_log.json"

    # --- the central regression: the never-admitted listener is never zero throughput ---
    never_admitted_bps="$(python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))
for r in d["results"]:
    if r["target"]["port"] == '"$DEAD_PORT"':
        print(r["receiver_bits_per_second"])
' "$out_log.json" 2>/dev/null)"
    if [ "$never_admitted_bps" = "None" ]; then
        pass "a listener that never admitted is never reported as 0 throughput (receiver_bits_per_second is null)"
    else
        fail "a listener that never admitted is never reported as 0 throughput" "got: $never_admitted_bps"
    fi

    never_admitted_outcome="$(python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))
for r in d["results"]:
    if r["target"]["port"] == '"$DEAD_PORT"':
        print(list(r["outcome"].keys())[0] if isinstance(r["outcome"], dict) else r["outcome"])
' "$out_log.json" 2>/dev/null)"
    if [ "$never_admitted_outcome" = "NeverAdmitted" ]; then
        pass "the dead listener is classified NeverAdmitted with a reason, not silently dropped"
    else
        fail "the dead listener is classified NeverAdmitted with a reason" "got: $never_admitted_outcome"
    fi

    fully_admitted="$(python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))
print(sum(1 for r in d["results"] if r["outcome"] == "FullyAdmitted" or (isinstance(r["outcome"], dict) and "FullyAdmitted" in r["outcome"])))
' "$out_log.json" 2>/dev/null)"
    if [ "${fully_admitted:-0}" = "2" ]; then
        pass "both real loopback listeners are fully admitted (2/3)"
    else
        fail "both real loopback listeners are fully admitted" "got: $fully_admitted"
    fi

    human_log="$WORK_DIR/gap045-fanout-human.log"
    "$BIN" admission-fanout \
        --target "127.0.0.1:$GOOD_PORT_A" \
        --target "127.0.0.1:$DEAD_PORT" \
        --streams 2 --duration-secs 1 --safety-timeout-secs 5 \
        > "$human_log" 2>&1
    check_contains "human output never counts the dead listener as zero throughput" \
        "no throughput (excluded)" cat "$human_log"
    check_lacks "human output never prints '0.0 Mbps' for the excluded listener line" \
        "0.0 Mbps" cat "$human_log"

    # --- minimum-valid-cohort blocks an aggregate when too few sessions admit ---
    strict_log="$WORK_DIR/gap045-strict.log"
    "$BIN" admission-fanout \
        --target "127.0.0.1:$DEAD_PORT" \
        --streams 2 --duration-secs 1 --safety-timeout-secs 3 --minimum-valid-cohort 1 --json \
        > "$strict_log" 2>&1
    sed -n '/^{/,$p' "$strict_log" > "$strict_log.json"
    aggregate="$(python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))
print(d.get("aggregate_receiver_bps") if "aggregate_receiver_bps" in d else "n/a")
' "$strict_log.json" 2>/dev/null)"
    # aggregate_receiver_bps is a method, not a serialized field; check the
    # human-readable withholding message instead, which is what a caller sees.
    withheld_out="$WORK_DIR/gap045-withheld.log"
    "$BIN" admission-fanout \
        --target "127.0.0.1:$DEAD_PORT" \
        --streams 2 --duration-secs 1 --safety-timeout-secs 3 --minimum-valid-cohort 1 \
        > "$withheld_out" 2>&1
    check_contains "an all-failed fanout withholds the aggregate figure" "WITHHELD" cat "$withheld_out"
    check_lacks "an all-failed fanout never prints a 0 Mbps aggregate" "aggregate receiver throughput: 0.0 Mbps" cat "$withheld_out"

    rm -f "$out_log" "$out_log.json" "$strict_log" "$strict_log.json" "$withheld_out"
    pkill -f "iperf3 -s -p $GOOD_PORT_A" 2>/dev/null
    pkill -f "iperf3 -s -p $GOOD_PORT_B" 2>/dev/null
fi
