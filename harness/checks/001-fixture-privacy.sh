#!/usr/bin/env bash
# Fixtures are a standing leak risk. GAP-018 and GAP-020 require identifiers be
# redacted by default; this holds the repo's own test data to that same rule.

# Binary captures are checked FIRST and separately, because every text rule
# below uses grep -I, which silently skips binary files. Three pcaps carved from
# a real host capture once lived here and this gate passed the whole time: the
# MAC rule could not see into them. Anything binary must be synthetic, and the
# only way to keep that honest is to assert on the decoded packets.
if command -v tcpdump >/dev/null 2>&1; then
    pcap_leaks=""
    while IFS= read -r cap; do
        [ -n "$cap" ] || continue
        decoded="$(tcpdump -ner "$cap" 2>/dev/null || true)"
        # Globally-unique (real hardware) MACs: locally-administered addresses
        # have bit 0x02 set in the first octet, so the second hex digit is
        # 2/3/6/7/a/b/e/f. Anything else came off real silicon.
        if printf '%s' "$decoded" | grep -qoE '\b[0-9a-f][0-9a-f](:[0-9a-f]{2}){5}\b' \
            && printf '%s' "$decoded" | grep -oE '\b[0-9a-f][0-9a-f](:[0-9a-f]{2}){5}\b' \
               | grep -qvE '^[0-9a-f][2367abef]:'; then
            pcap_leaks="$pcap_leaks $cap(hardware-MAC)"
        fi
    done <<EOF
$(find "$FIXTURE_DIR" -type f \( -name '*.pcap' -o -name '*.pcapng' \) 2>/dev/null)
EOF
    if [ -n "${pcap_leaks// /}" ]; then
        fail "binary captures carry no real hardware MAC" "$pcap_leaks"
    else
        pass "binary captures carry no real hardware MAC"
    fi
else
    skip "binary captures carry no real hardware MAC" "tcpdump absent"
fi

# Text fixtures must not carry a real MAC. 02:00:00:00:00:01 is the placeholder.
mac_hits="$(grep -rlEI '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}' "$FIXTURE_DIR" 2>/dev/null \
    | while read -r f; do
        if grep -oEI '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}' "$f" | grep -qv '^02:00:00:00:00:01$'; then
            printf '%s ' "$f"
        fi
      done)"
if [ -n "${mac_hits// /}" ]; then
    fail "fixtures carry no real MAC address" "$mac_hits"
else
    pass "fixtures carry no real MAC address"
fi

# The captured Wi-Fi fixture must have its SSIDs redacted by system_profiler.
if [ -f "$FIXTURE_DIR/wifi/system_profiler-airport.txt" ]; then
    check_contains "wifi fixture SSIDs are redacted" "<redacted>" \
        cat "$FIXTURE_DIR/wifi/system_profiler-airport.txt"
else
    skip "wifi fixture SSIDs are redacted" "fixture absent"
fi

# Fixtures must stay small enough to live in git. The 2.1 GB source capture is
# gitignored; a carve that creeps back toward that size defeats the point.
big="$(find "$FIXTURE_DIR" -type f -size +2M 2>/dev/null | tr '\n' ' ')"
if [ -n "${big// /}" ]; then
    fail "no fixture exceeds 2 MB" "$big"
else
    pass "no fixture exceeds 2 MB"
fi

# The Darwin ping fixtures are the spec for GAP-009. Assert they still contain
# the exact strings the parser must handle, so a careless re-capture can't
# quietly turn them into Linux-format files.
check_contains "darwin ping fixture uses round-trip spelling" "round-trip min/avg/max/stddev" \
    cat "$FIXTURE_DIR/ping/darwin-ping-ok.txt"
check_lacks "darwin ping fixture is not Linux format" "rtt min/avg/max/mdev" \
    cat "$FIXTURE_DIR/ping/darwin-ping-ok.txt"
check_contains "darwin timeout fixture has no round-trip line" "100.0% packet loss" \
    cat "$FIXTURE_DIR/ping/darwin-ping-timeout.txt"
check_lacks "darwin timeout fixture reports no latency" "round-trip" \
    cat "$FIXTURE_DIR/ping/darwin-ping-timeout.txt"
check_contains "darwin DF fixture shows sendto refusal" "Message too long" \
    cat "$FIXTURE_DIR/ping/darwin-ping-df-toobig.txt"
