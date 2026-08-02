#!/usr/bin/env bash
# GAP-039: iperf3 JSON parsing is not version- or direction-aware.
# udp-reverse-3.21.json is the confirmed live trap: sum_sent reports
# packets:0 while sum/sum_received report the real transfer at a different
# packet count -- reading sum_sent.lost_percent would give 0% loss computed
# from a field that measured nothing. error-refused.json carries an empty
# end alongside a top-level error string; a parser that doesn't check error
# first would report figures from an aborted run. All offline, fixture-only.

ia_json() { "$BIN" iperf-analyze "$@" --json 2>/dev/null | sed -n '/^{/,$p'; }

check_contains "iperf-analyze advertises --parse-file/--json" "--parse-file" \
    "$BIN" iperf-analyze --help

# --- error detected before any figure is read ---
check_fails "error-refused.json is detected as an error (nonzero exit)" \
    "$BIN" iperf-analyze --parse-file "$FIXTURE_DIR/iperf/error-refused.json"
check_contains "error-refused.json human output states the error, not a figure" \
    "unable to connect" \
    "$BIN" iperf-analyze --parse-file "$FIXTURE_DIR/iperf/error-refused.json"
check_lacks "error-refused.json never prints a bps figure" "bps" \
    "$BIN" iperf-analyze --parse-file "$FIXTURE_DIR/iperf/error-refused.json"

# --- udp-reverse: sum_sent (packets:0) must never surface as a rate/loss figure ---
udp_out="$(ia_json --parse-file "$FIXTURE_DIR/iperf/udp-reverse-3.21.json")"
if [ -z "$udp_out" ]; then
    fail "udp-reverse-3.21.json produces JSON output" "empty output"
else
    sent_is_null="$(printf '%s' "$udp_out" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["forward"]["sent"] is None)' 2>/dev/null)"
    if [ "$sent_is_null" = "True" ]; then
        pass "udp-reverse-3.21.json: hollow sum_sent (packets:0) is filtered to unavailable, not a 0%-loss result"
    else
        fail "udp-reverse-3.21.json: hollow sum_sent (packets:0) is filtered to unavailable, not a 0%-loss result" \
            "sent block was not null: $udp_out"
    fi

    received_packets="$(printf '%s' "$udp_out" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["forward"]["received"]["packets"])' 2>/dev/null)"
    if [ "$received_packets" = "460" ]; then
        pass "udp-reverse-3.21.json: received rate is read from sum_received (460 packets), not the hollow sum_sent"
    else
        fail "udp-reverse-3.21.json: received rate is read from sum_received (460 packets)" "got: $received_packets"
    fi

    estimated_packets="$(printf '%s' "$udp_out" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["forward"]["estimated_received"]["packets"])' 2>/dev/null)"
    if [ "$estimated_packets" = "489" ] && [ "$estimated_packets" != "$received_packets" ]; then
        pass "udp-reverse-3.21.json: legacy sum (489 packets) kept distinct from sum_received (460), not merged"
    else
        fail "udp-reverse-3.21.json: legacy sum kept distinct from sum_received" "estimated=$estimated_packets received=$received_packets"
    fi
fi
check_lacks "udp-reverse-3.21.json human output never claims 0.00% from a hollow sent block" \
    "sent:     0.0 bps, 0 bytes, 0 packets, loss=0.00%" \
    "$BIN" iperf-analyze --parse-file "$FIXTURE_DIR/iperf/udp-reverse-3.21.json"

# --- tcp-bidir: both directions must be present, not just sum_sent/sum_received ---
bidir_out="$(ia_json --parse-file "$FIXTURE_DIR/iperf/tcp-bidir-3.21.json")"
if [ -z "$bidir_out" ]; then
    fail "tcp-bidir-3.21.json produces JSON output" "empty output"
else
    has_reverse="$(printf '%s' "$bidir_out" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["bidir_reverse"] is not None)' 2>/dev/null)"
    if [ "$has_reverse" = "True" ]; then
        pass "tcp-bidir-3.21.json yields bidir_reverse evidence, not just the forward direction"
    else
        fail "tcp-bidir-3.21.json yields bidir_reverse evidence" "got: $has_reverse"
    fi

    fwd_recv="$(printf '%s' "$bidir_out" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["forward"]["received"] is not None)' 2>/dev/null)"
    rev_recv="$(printf '%s' "$bidir_out" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["bidir_reverse"]["received"] is not None)' 2>/dev/null)"
    if [ "$fwd_recv" = "True" ] && [ "$rev_recv" = "True" ]; then
        pass "tcp-bidir-3.21.json: both forward and reverse directions carry received evidence"
    else
        fail "tcp-bidir-3.21.json: both forward and reverse directions carry received evidence" "forward=$fwd_recv reverse=$rev_recv"
    fi
fi
check_contains "tcp-bidir-3.21.json human output shows both [forward] and [bidir-reverse]" "[bidir-reverse]" \
    "$BIN" iperf-analyze --parse-file "$FIXTURE_DIR/iperf/tcp-bidir-3.21.json"

# --- offered/sent/received are distinguishable, never collapsed to one number ---
check_contains "human output labels offered separately from sent/received" "offered:" \
    "$BIN" iperf-analyze --parse-file "$FIXTURE_DIR/iperf/udp-reverse-3.21.json"
check_contains "human output labels sent separately from received" "sent:" \
    "$BIN" iperf-analyze --parse-file "$FIXTURE_DIR/iperf/tcp-forward-3.21.json"

# --- a missing required field reports unavailable, not zero ---
missing_field_file="$WORK_DIR/gap039-missing-fields.json"
printf '%s' '{"start":{"version":"iperf 3.21","test_start":{"protocol":"TCP","reverse":0,"bidir":0}},"intervals":[],"end":{}}' > "$missing_field_file"
missing_field_out="$(ia_json --parse-file "$missing_field_file")"
if [ -z "$missing_field_out" ]; then
    fail "a document with no sum_sent/sum_received reports unavailable, not zero" "empty output"
else
    sent_null="$(printf '%s' "$missing_field_out" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["forward"]["sent"] is None)' 2>/dev/null)"
    missing_list="$(printf '%s' "$missing_field_out" | python3 -c 'import json,sys; d=json.load(sys.stdin); print("sum_sent" in d["required_fields_missing"])' 2>/dev/null)"
    if [ "$sent_null" = "True" ] && [ "$missing_list" = "True" ]; then
        pass "a document missing sum_sent/sum_received reports unavailable and names the missing field"
    else
        fail "a document missing sum_sent/sum_received reports unavailable and names the missing field" \
            "sent_null=$sent_null missing_list=$missing_list"
    fi
fi
rm -f "$missing_field_file"
