#!/usr/bin/env bash
# GAP-058: wired edge/AP-uplink/LLDP/PoE health bundle. Locks: a wired-edge
# conclusion is refused when telemetry is absent, naming what's missing;
# PoE-driven reduced-functionality is flagged as a distinct risk, not a
# checkbox; a missing counter never reports a fabricated (e.g. 0W) value.

check_ok "cargo test covers wired-edge delta/verdict/PoE-risk logic" \
    cargo test --release --lib network_tests::wired_edge:: --manifest-path "$REPO_ROOT/Cargo.toml"

check_contains "cargo test proves an empty bundle never reports a fabricated 0W PoE draw" \
    "an_empty_bundle_never_reports_zero_watts_as_a_measurement" \
    cargo test --release --lib network_tests::wired_edge:: --manifest-path "$REPO_ROOT/Cargo.toml"

check_contains "cargo test proves reduced power with a wattage shortfall is flagged as a risk" \
    "reduced_power_state_with_a_wattage_shortfall_is_flagged_as_a_risk" \
    cargo test --release --lib network_tests::wired_edge:: --manifest-path "$REPO_ROOT/Cargo.toml"

check_contains "cargo test proves a backwards counter never fabricates a delta" \
    "a_backwards_counter_never_reports_a_fabricated_delta" \
    cargo test --release --lib network_tests::wired_edge:: --manifest-path "$REPO_ROOT/Cargo.toml"

check_contains "wired-edge advertises --bracket" "--bracket" "$BIN" wired-edge --help

check_fails "wired-edge requires --bracket" "$BIN" wired-edge

MANIFESTS="$FIXTURE_DIR/wired_edge"

# --- refusal on incomplete telemetry, naming what's missing ---
refuse_out="$("$BIN" wired-edge --bracket "$MANIFESTS/refuse.json" 2>&1)"
check_contains "an incomplete bracket refuses a conclusion" "REFUSED" bash -c 'printf "%s" "$1"' _ "$refuse_out"
check_contains "the refusal names a missing PoE field" "poe_negotiated_watts" bash -c 'printf "%s" "$1"' _ "$refuse_out"
check_contains "the refusal names a missing counter field" "crc_errors" bash -c 'printf "%s" "$1"' _ "$refuse_out"

# --- a healthy bracket with no movement ---
check_contains "a healthy bracket reports healthy" "healthy" \
    "$BIN" wired-edge --bracket "$MANIFESTS/healthy.json"

# --- the field-flagged PoE risk: reduced functionality from wattage shortfall ---
degraded_out="$("$BIN" wired-edge --bracket "$MANIFESTS/reduced-power.json" 2>&1)"
check_contains "reduced PoE power on an AP is surfaced as degraded" "degraded" bash -c 'printf "%s" "$1"' _ "$degraded_out"
check_contains "the degraded detail names the PoE shortfall explicitly" "reduced-power state" \
    bash -c 'printf "%s" "$1"' _ "$degraded_out"
check_contains "the degraded detail names new CRC errors" "new CRC errors" bash -c 'printf "%s" "$1"' _ "$degraded_out"

check_json_field "json output carries the verdict" "verdict" \
    "$BIN" wired-edge --bracket "$MANIFESTS/healthy.json" --json
check_json_field "json output carries the counter delta" "delta" \
    "$BIN" wired-edge --bracket "$MANIFESTS/healthy.json" --json

check_fails "a missing bracket file errors rather than assuming defaults" \
    "$BIN" wired-edge --bracket "$WORK_DIR/definitely-not-here.json"

check_contains "human output restates this is read-only" "never modifies switch or AP configuration" \
    "$BIN" wired-edge --bracket "$MANIFESTS/healthy.json"
