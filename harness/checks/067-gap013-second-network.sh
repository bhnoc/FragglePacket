#!/usr/bin/env bash
# GAP-013: second-network control workflow. Locks: a saved bundle round-trips
# without storing SSID/BSSID unless explicitly requested via
# --retain-network-label, and comparing two bundles never fabricates a delta
# for a metric missing on either side.

check_ok "cargo test covers bundle save/compare and privacy logic" \
    cargo test --release --lib network_tests::second_network:: --manifest-path "$REPO_ROOT/Cargo.toml"

check_contains "cargo test proves a saved bundle never stores SSID/BSSID" \
    "a_saved_bundle_round_trips_without_storing_ssid_or_bssid" \
    cargo test --release --lib network_tests::second_network:: --manifest-path "$REPO_ROOT/Cargo.toml"

check_contains "cargo test proves operator_label is the only field that can carry SSID text, and only when supplied" \
    "operator_label_is_the_only_field_that_can_carry_ssid_shaped_text_and_only_when_supplied" \
    cargo test --release --lib network_tests::second_network:: --manifest-path "$REPO_ROOT/Cargo.toml"

check_contains "second-network advertises --save" "--save" \
    "$BIN" second-network --help
check_contains "second-network advertises --compare" "--compare" \
    "$BIN" second-network --help
check_contains "second-network advertises --retain-network-label as opt-in" "--retain-network-label" \
    "$BIN" second-network --help

RUN1="$WORK_DIR/second-network-run1.json"
RUN2="$WORK_DIR/second-network-run2.json"

"$BIN" second-network --save "$RUN1" --bssid "aa:bb:cc:dd:ee:01" --band 6GHz --channel 37 \
    --metric download_mbps=320.5 --metric loss_pct=0.1 >/dev/null 2>&1
"$BIN" second-network --save "$RUN2" --bssid "aa:bb:cc:dd:ee:99" --band 5GHz --channel 40 \
    --metric download_mbps=45.2 --metric loss_pct=8.4 >/dev/null 2>&1

# --- no MAC-shaped token anywhere in a default (no --retain-network-label) save ---
mac_shape_grep='([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}'
if grep -qE "$mac_shape_grep" "$RUN1" 2>/dev/null; then
    fail "a default save never stores a MAC/BSSID-shaped token" "found MAC-shaped text in $RUN1"
else
    pass "a default save never stores a MAC/BSSID-shaped token"
fi

check_lacks "a default save carries no operator_label value" '"operator_label": "' cat "$RUN1"

# --- explicit opt-in DOES retain the label ---
RUN3="$WORK_DIR/second-network-run3.json"
"$BIN" second-network --save "$RUN3" --bssid "aa:bb:cc:dd:ee:02" --retain-network-label "Hotel Guest WiFi" \
    --metric download_mbps=10.0 >/dev/null 2>&1
check_contains "an explicit --retain-network-label is honored" "Hotel Guest WiFi" cat "$RUN3"

# --- comparison across a genuine AP change ---
compare_out="$("$BIN" second-network --compare "$RUN1" "$RUN2" --json 2>&1 | sed -n '/^{/,$p')"
check_contains "comparing two different-AP bundles reports a genuine second-network relationship" \
    "genuine second-network control" bash -c 'printf "%s" "$1"' _ "$compare_out"

# --- a metric present on only one side never fabricates a delta ---
RUN_PARTIAL="$WORK_DIR/second-network-partial.json"
"$BIN" second-network --save "$RUN_PARTIAL" --bssid "aa:bb:cc:dd:ee:03" --metric only_here_mbps=99.0 >/dev/null 2>&1
partial_cmp="$("$BIN" second-network --compare "$RUN1" "$RUN_PARTIAL" --json 2>&1 | sed -n '/^{/,$p')"
delta_null="$(printf '%s' "$partial_cmp" | python3 -c '
import json, sys
d = json.load(sys.stdin)
m = [x for x in d["metrics"] if x["name"] == "download_mbps"]
print(m[0]["delta"] if m else "MISSING")
' 2>/dev/null)"
if [ "$delta_null" = "None" ] || [ "$delta_null" = "null" ]; then
    pass "a metric missing on one side reports delta as null, never a fabricated swing"
else
    fail "a metric missing on one side reports delta as null, never a fabricated swing" "got '$delta_null'"
fi

check_fails "second-network with neither --save nor --compare refuses" "$BIN" second-network
