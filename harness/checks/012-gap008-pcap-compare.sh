#!/usr/bin/env bash
# GAP-008: pcap-report gains a comparison mode across two or more captures,
# so field triage no longer needs external tshark/capinfos to compare TCP vs
# QUIC flow counts, sizes, and retransmissions side by side. Built directly
# on the GAP-019 streaming analyzer -- comparing never re-reads a whole file
# into memory, and inherits (never discards) the offload/truncation
# qualifications each input capture already carries.

check_ok "cargo test covers protocol breakdown / comparison logic" \
    cargo test --release --lib network_tests::pcap_report:: --manifest-path "$REPO_ROOT/Cargo.toml"

check_contains "pcap-report advertises --compare" "--compare" \
    "$BIN" pcap-report --help

cmp_json() { "$BIN" pcap-report "$@" --json 2>/dev/null | sed -n '/^{/,$p'; }

# --- two files automatically trigger comparison mode (no extra flag needed) ---
two_file_out="$("$BIN" pcap-report "$FIXTURE_DIR/pcap/tcp-anomalies.pcap" "$FIXTURE_DIR/pcap/quic-443.pcap" 2>&1)"
check_contains "two files auto-trigger comparison output (human)" "== Comparison ==" \
    bash -c 'printf "%s" "$1"' _ "$two_file_out"

cmp_out="$(cmp_json "$FIXTURE_DIR/pcap/tcp-anomalies.pcap" "$FIXTURE_DIR/pcap/quic-443.pcap")"
if [ -z "$cmp_out" ]; then
    fail "comparison produces JSON output" "empty output"
else
    n_reports="$(printf '%s' "$cmp_out" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print(len(d["reports"]))
' 2>/dev/null)"
    if [ "${n_reports:-0}" = "2" ]; then
        pass "comparison JSON carries per-file reports for both inputs"
    else
        fail "comparison JSON carries per-file reports for both inputs" "got: $n_reports"
    fi

    # --- per-file transport/flow stats: TCP-heavy fixture vs QUIC-candidate fixture ---
    tcp_pkts_0="$(printf '%s' "$cmp_out" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print(d["reports"][0]["protocol_breakdown"]["tcp_packets"])
' 2>/dev/null)"
    quic_pkts_1="$(printf '%s' "$cmp_out" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print(d["reports"][1]["protocol_breakdown"]["quic_candidate_packets"])
' 2>/dev/null)"
    if [ "${tcp_pkts_0:-0}" -gt 0 ] 2>/dev/null; then
        pass "tcp-anomalies.pcap comparison entry carries a nonzero TCP packet count ($tcp_pkts_0)"
    else
        fail "tcp-anomalies.pcap comparison entry carries a nonzero TCP packet count" "got: $tcp_pkts_0"
    fi
    if [ "${quic_pkts_1:-0}" -gt 0 ] 2>/dev/null; then
        pass "quic-443.pcap comparison entry carries a nonzero QUIC-candidate packet count ($quic_pkts_1)"
    else
        fail "quic-443.pcap comparison entry carries a nonzero QUIC-candidate packet count" "got: $quic_pkts_1"
    fi

    # --- the offload qualification from GAP-019 must survive into the comparison ---
    any_suspect="$(printf '%s' "$cmp_out" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print(d["any_offload_suspect"])
' 2>/dev/null)"
    if [ "$any_suspect" = "True" ]; then
        pass "comparison flags any_offload_suspect when an input capture is host-side"
    else
        fail "comparison flags any_offload_suspect when an input capture is host-side" "got: $any_suspect"
    fi
fi

check_contains "comparison human output states retransmissions per file" "retransmissions=" \
    bash -c 'printf "%s" "$1"' _ "$two_file_out"
check_contains "comparison human output qualifies offload-suspect retransmissions" \
    "NOT on-wire evidence" \
    bash -c 'printf "%s" "$1"' _ "$two_file_out"
check_lacks "comparison human output never states a bare unqualified network-fault verdict" \
    "network fault" \
    bash -c 'printf "%s" "$1"' _ "$two_file_out"

# --- a single file does not accidentally trigger comparison mode ---
single_out="$("$BIN" pcap-report "$FIXTURE_DIR/pcap/mixed-head.pcap" 2>&1)"
check_lacks "a single file does not show comparison output" "== Comparison ==" \
    bash -c 'printf "%s" "$1"' _ "$single_out"

# --- --compare forces comparison mode even for one file ---
forced_out="$("$BIN" pcap-report "$FIXTURE_DIR/pcap/mixed-head.pcap" --compare 2>&1)"
check_contains "--compare forces comparison output for a single file" "== Comparison ==" \
    bash -c 'printf "%s" "$1"' _ "$forced_out"

# --- streaming: comparing the fixtures stays fast and low-memory (no full-file load) ---
start_ts=$(date +%s)
"$BIN" pcap-report "$FIXTURE_DIR/pcap/tcp-anomalies.pcap" "$FIXTURE_DIR/pcap/mixed-head.pcap" "$FIXTURE_DIR/pcap/quic-443.pcap" --json > /dev/null 2>&1
end_ts=$(date +%s)
elapsed=$((end_ts - start_ts))
if [ "$elapsed" -le 10 ]; then
    pass "comparing three fixtures completes quickly (${elapsed}s), consistent with streaming analysis"
else
    fail "comparing three fixtures completes quickly" "took ${elapsed}s"
fi

# --- non-pcap input alongside a valid file errors cleanly on the bad file
# instead of panicking, and still reports the valid one ---
mixed_valid_out="$("$BIN" pcap-report "$FIXTURE_DIR/wifi/system_profiler-airport.txt" "$FIXTURE_DIR/pcap/mixed-head.pcap" 2>&1)"
mixed_valid_exit=$?
check_contains "non-pcap input among files reports its own error, not a panic" \
    "unrecognized capture format" \
    bash -c 'printf "%s" "$1"' _ "$mixed_valid_out"
if [ "$mixed_valid_exit" -ne 0 ]; then
    fail "a mix of bad and good files still completes (does not crash the process)" "exited $mixed_valid_exit"
else
    pass "a mix of bad and good files still completes (does not crash the process)"
fi
check_fails "all-bad input errors instead of panicking" \
    "$BIN" pcap-report "$FIXTURE_DIR/wifi/system_profiler-airport.txt"
