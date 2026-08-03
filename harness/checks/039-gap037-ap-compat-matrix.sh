#!/usr/bin/env bash
# GAP-037: an AP-generation/radio-mode compatibility matrix must refuse a
# verdict, and name exactly which required comparison cells are missing,
# until all of them are present. The field investigation confirmed every
# probe-associated AP was a C-460 on 21.3.0M-13, yet AP model/firmware/power
# mode alone could not explain the VHT/HE cohort split -- only a matched
# BE-vs-AX-vs-6E-AP comparison can, and this tool cannot generate that
# comparison itself (changing radio mode is an infrastructure action). A
# verdict extrapolated from one or two cells would point a TAC case at the
# wrong firmware, which is the same "plausible value for a missing
# measurement" bug this project keeps re-finding, just at the conclusion
# layer instead of the measurement layer.

check_ok "cargo test covers matrix classification/verdict/digest logic" \
    cargo test --release --lib network_tests::ap_compat_matrix:: --manifest-path "$REPO_ROOT/Cargo.toml"

check_contains "ap-compat-matrix advertises --sample-client" "--sample-client" \
    "$BIN" ap-compat-matrix --help
check_contains "ap-compat-matrix advertises --ingest-cells" "--ingest-cells" \
    "$BIN" ap-compat-matrix --help

# --- single-cell input never yields a verdict; refusal names missing cells ---
one_cell="$WORK_DIR/gap037-one-cell.json"
cat > "$one_cell" <<'JSON'
[
  {
    "label": "single-cell",
    "client": {
      "negotiated_generation": "He",
      "phy_mode_raw": "802.11ax",
      "band": "6GHz",
      "channel": 197,
      "width_mhz": 80,
      "mcs_index": 7,
      "tx_rate_mbps": 680.0,
      "nss": null,
      "mlo_active": null,
      "ap_identity": null,
      "platform_limitations": []
    },
    "ap": {
      "ap_identity": null,
      "model": "C-460",
      "firmware_version": "21.3.0M-13",
      "power_mode_raw": "POE_PLUS",
      "low_power_supply": true,
      "radio_mode": "Be",
      "mlo_supported": true,
      "band_advertised": "6GHz",
      "width_advertised_mhz": 320,
      "nss_advertised": 4
    },
    "client_hardware_generation": "Wifi7"
  }
]
JSON

single_out="$("$BIN" ap-compat-matrix --ingest-cells "$one_cell" --json 2>&1)"
single_json="$(printf '%s' "$single_out" | sed -n '/^{/,$p')"

check_json_field "single-cell run produces a verdict object" "verdict" \
    bash -c 'printf "%s" "$1"' _ "$single_json"

missing_count="$(printf '%s' "$single_json" | python3 -c '
import json, sys
d = json.load(sys.stdin)
v = d["verdict"]
missing = v.get("InsufficientCells", {}).get("missing")
print(len(missing) if missing is not None else -1)
' 2>/dev/null)"
if [ "${missing_count:-0}" -gt 0 ] 2>/dev/null; then
    pass "single-cell matrix refuses a verdict and names missing cells ($missing_count missing)"
else
    fail "single-cell matrix refuses a verdict and names missing cells" "got missing_count=$missing_count"
fi

check_contains "single-cell human output states insufficient cells" "INSUFFICIENT CELLS" \
    "$BIN" ap-compat-matrix --ingest-cells "$one_cell"
check_lacks "single-cell human output never claims COMPARABLE" "verdict: COMPARABLE" \
    "$BIN" ap-compat-matrix --ingest-cells "$one_cell"

# --- empty matrix (no client, no ingest) refuses to run at all ---
check_fails "no cells at all refuses to run" \
    "$BIN" ap-compat-matrix

# --- ingest never invents an absent field: missing firmware stays null, not guessed ---
no_firmware="$WORK_DIR/gap037-no-firmware.json"
cat > "$no_firmware" <<'JSON'
[
  {
    "label": "no-firmware",
    "client": {
      "negotiated_generation": "Eht",
      "phy_mode_raw": "802.11be",
      "band": "6GHz",
      "channel": 37,
      "width_mhz": 320,
      "mcs_index": null,
      "tx_rate_mbps": null,
      "nss": null,
      "mlo_active": null,
      "ap_identity": null,
      "platform_limitations": []
    },
    "ap": {
      "ap_identity": null,
      "model": "C-460",
      "firmware_version": null,
      "power_mode_raw": null,
      "low_power_supply": null,
      "radio_mode": "Be",
      "mlo_supported": null,
      "band_advertised": null,
      "width_advertised_mhz": null,
      "nss_advertised": null
    },
    "client_hardware_generation": "Wifi7"
  }
]
JSON

nf_json="$("$BIN" ap-compat-matrix --ingest-cells "$no_firmware" --json 2>&1 | sed -n '/^{/,$p')"
firmware_val="$(printf '%s' "$nf_json" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print(d["matrix"]["cells"][0]["ap"]["firmware_version"])
' 2>/dev/null)"
if [ "$firmware_val" = "None" ]; then
    pass "a missing firmware field round-trips as null (unavailable), never a guessed value"
else
    fail "a missing firmware field round-trips as null" "got: $firmware_val"
fi
check_contains "human output shows the missing firmware as unavailable, not fabricated" "firmware=unavailable" \
    "$BIN" ap-compat-matrix --ingest-cells "$no_firmware"

# --- no BSSID/SSID/MAC ever appears in output, ingested or sampled ---
check_lacks "ingested-cell output carries no BSSID/MAC-shaped token" \
    "02:00:00:00:00:01" "$BIN" ap-compat-matrix --ingest-cells "$one_cell"

# --- client negotiated mode stays distinct from AP capability: an AX-negotiated
# client on a BE-capable/BE-mode AP must show He, never Eht, on the client side ---
he_on_be_json="$("$BIN" ap-compat-matrix --ingest-cells "$one_cell" --json 2>&1 | sed -n '/^{/,$p')"
client_gen="$(printf '%s' "$he_on_be_json" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print(d["matrix"]["cells"][0]["client"]["negotiated_generation"])
' 2>/dev/null)"
ap_mode="$(printf '%s' "$he_on_be_json" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print(d["matrix"]["cells"][0]["ap"]["radio_mode"])
' 2>/dev/null)"
if [ "$client_gen" = "He" ] && [ "$ap_mode" = "Be" ]; then
    pass "client-negotiated mode (He) stays distinct from AP-advertised capability (Be) -- not blurred into one fact"
else
    fail "client-negotiated mode stays distinct from AP capability" "client=$client_gen ap_mode=$ap_mode"
fi

# --- a real run against this machine's own association ---
if net_guard; then
    real_out="$("$BIN" ap-compat-matrix --sample-client --client-hardware-generation wifi7 2>&1)"
    if [ -z "$real_out" ]; then
        skip "real client-self-sample run" "no output"
    else
        check_contains "real run states this client's own negotiated generation" "client negotiated:" \
            bash -c 'printf "%s" "$1"' _ "$real_out"
        note "real client sample: $(printf '%s' "$real_out" | grep 'client negotiated' | head -1)"
        pass "real run against this client's own Wi-Fi association produced output"
    fi
else
    skip "real client-self-sample run" "FP_HARNESS_OFFLINE=1"
fi

rm -f "$one_cell" "$no_firmware"
