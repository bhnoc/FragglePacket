#!/usr/bin/env bash
# Fixtures are captured from a real network, so they are a standing leak risk.
# GAP-018 and GAP-020 require identifiers be redacted by default; this holds the
# repo's own test data to that same rule.

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
