#!/usr/bin/env bash
# GAP-019: a host-side capture was mis-triaged as evidence of on-wire
# oversize frames and heavy loss. The oversize claim was a measurement bug
# (frame length compared against a bare 1500, forgetting the 14-byte
# Ethernet header); the retransmission counts are real numbers but
# unusable as network-fault evidence off a host-side (offload-subject)
# capture. This check locks both corrections plus capture-health honesty
# (truncated snaplen, unknown drop counts) using local fixtures only.

pr_json() { "$BIN" pcap-report "$@" --json 2>/dev/null | sed -n '/^\[/,$p'; }

check_contains "pcap-report advertises --json" "--json" \
    "$BIN" pcap-report --help

# --- the exact false positive this gap exists to prevent ---
# mixed-head.pcap is a real macOS host capture with 1,510-byte Ethernet
# frames (IP total_len 1,496): legal at MTU 1500, never oversize.
# mixed-head.pcap's real 1,510-byte Ethernet frames (IP total_len 1,496)
# must show zero frames counted over the MTU+L2 threshold.
check_contains "1510-byte frame is never reported as oversize (human output)" "frames over threshold:  0" \
    "$BIN" pcap-report "$FIXTURE_DIR/pcap/mixed-head.pcap"

mixed_out="$(pr_json "$FIXTURE_DIR/pcap/mixed-head.pcap")"
if [ -z "$mixed_out" ]; then
    fail "mixed-head.pcap produces JSON output" "empty output"
else
    oversize_count="$(printf '%s' "$mixed_out" | python3 -c '
import json, sys
d = json.load(sys.stdin)[0]
print(d["frame_size"]["observed_over_threshold"])
' 2>/dev/null)"
    if [ "${oversize_count:-x}" = "0" ]; then
        pass "mixed-head.pcap: zero frames over MTU+L2 threshold in --json"
    else
        fail "mixed-head.pcap: zero frames over MTU+L2 threshold in --json" "got: $oversize_count"
    fi

    threshold="$(printf '%s' "$mixed_out" | python3 -c '
import json, sys
d = json.load(sys.stdin)[0]
print(d["frame_size"]["oversize_threshold"])
' 2>/dev/null)"
    if [ "${threshold:-0}" = "1514" ]; then
        pass "oversize threshold is link MTU (1500) + Ethernet header (14), not a bare 1500"
    else
        fail "oversize threshold is link MTU (1500) + Ethernet header (14)" "got: $threshold"
    fi

    max_frame="$(printf '%s' "$mixed_out" | python3 -c '
import json, sys
d = json.load(sys.stdin)[0]
print(d["frame_size"]["max_observed_frame_len"])
' 2>/dev/null)"
    if [ "${max_frame:-0}" -le 1514 ] 2>/dev/null; then
        pass "mixed-head.pcap max observed frame length is at or under 1514 ($max_frame)"
    else
        fail "mixed-head.pcap max observed frame length is at or under 1514" "got: $max_frame"
    fi
fi

# --- truncated snaplen must be detected and suppress payload verdicts ---
check_contains "truncated snaplen fixture is flagged as truncated (human output)" "truncated:    true" \
    "$BIN" pcap-report "$FIXTURE_DIR/pcap/mixed-head.pcap"

truncated_flag="$(printf '%s' "$mixed_out" | python3 -c '
import json, sys
d = json.load(sys.stdin)[0]
print(d["health"]["truncated"])
' 2>/dev/null)"
if [ "$truncated_flag" = "True" ]; then
    pass "mixed-head.pcap health.truncated is true in --json"
else
    fail "mixed-head.pcap health.truncated is true in --json" "got: $truncated_flag"
fi

suppressed="$(printf '%s' "$mixed_out" | python3 -c '
import json, sys
d = json.load(sys.stdin)[0]
print(d["payload_analysis_suppressed"])
' 2>/dev/null)"
if [ "$suppressed" = "True" ]; then
    pass "mixed-head.pcap suppresses payload-dependent verdicts when truncated"
else
    fail "mixed-head.pcap suppresses payload-dependent verdicts when truncated" "got: $suppressed"
fi

# --- unknown drop counts must never read as zero ---
drops_known="$(printf '%s' "$mixed_out" | python3 -c '
import json, sys
d = json.load(sys.stdin)[0]
print(d["health"]["drops_known"])
' 2>/dev/null)"
if [ "$drops_known" = "None" ]; then
    pass "mixed-head.pcap drop count reports unknown (null), never zero"
else
    fail "mixed-head.pcap drop count reports unknown (null), never zero" "got: $drops_known"
fi
check_contains "human output reports drops as unknown, not zero" "drops:        unknown" \
    "$BIN" pcap-report "$FIXTURE_DIR/pcap/mixed-head.pcap"

# --- retransmission-heavy fixture must be qualified, not an unqualified network verdict ---
anom_out="$(pr_json "$FIXTURE_DIR/pcap/tcp-anomalies.pcap")"
if [ -z "$anom_out" ]; then
    fail "tcp-anomalies.pcap produces JSON output" "empty output"
else
    retrans="$(printf '%s' "$anom_out" | python3 -c '
import json, sys
d = json.load(sys.stdin)[0]
print(d["tcp_anomalies"]["retransmissions"])
' 2>/dev/null)"
    if [ "${retrans:-0}" -gt 0 ] 2>/dev/null; then
        pass "tcp-anomalies.pcap: retransmissions counted (real number, $retrans)"
    else
        fail "tcp-anomalies.pcap: retransmissions counted (expected > 0)" "got: $retrans"
    fi

    qualified="$(printf '%s' "$anom_out" | python3 -c '
import json, sys
d = json.load(sys.stdin)[0]
print(d["tcp_anomalies"]["qualification_required"])
' 2>/dev/null)"
    if [ "$qualified" = "True" ]; then
        pass "tcp-anomalies.pcap retransmission counts are flagged as requiring qualification"
    else
        fail "tcp-anomalies.pcap retransmission counts are flagged as requiring qualification" "got: $qualified"
    fi
fi

check_contains "human output qualifies retransmission counts as not on-wire evidence" \
    "NOT usable as on-wire network-fault evidence" \
    "$BIN" pcap-report "$FIXTURE_DIR/pcap/tcp-anomalies.pcap"
check_lacks "human output never states a bare unqualified network-fault verdict" \
    "network fault" \
    "$BIN" pcap-report "$FIXTURE_DIR/pcap/tcp-anomalies.pcap"

# --- vantage classification runs and is honest about confidence ---
check_contains "human output states vantage classification" "vantage:" \
    "$BIN" pcap-report "$FIXTURE_DIR/pcap/quic-443.pcap"
check_contains "human output states a confidence level" "confidence:" \
    "$BIN" pcap-report "$FIXTURE_DIR/pcap/quic-443.pcap"

# --- streaming/robustness: a non-pcap file errors cleanly instead of panicking ---
check_fails "non-pcap input errors instead of panicking" \
    "$BIN" pcap-report "$FIXTURE_DIR/wifi/system_profiler-airport.txt"
