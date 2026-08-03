#!/usr/bin/env bash
# GAP-063: cross-platform and power-save client matrix. Field evidence: two
# observed cohorts differed by adapter, driver, kernel, AND iperf version
# simultaneously (VHT/5.10/iperf3-3.9 vs HE/6.1/iperf3-3.16). This gate
# locks that a throughput/loss difference is only ever attributed to a
# single capability axis when exactly one axis varied; multiple entangled
# axes must withhold attribution rather than guess.

check_ok "cargo test covers platform-matrix confound/attribution logic" \
    cargo test --release --lib network_tests::platform_matrix:: --manifest-path "$REPO_ROOT/Cargo.toml"

# --- power-save (TWT/U-APSD) is reported platform-limited, never defaulted Active ---
check_contains "cargo test proves power-save state is platform-limited, never defaulted Active" \
    "power_save_state_is_platform_limited_not_defaulted_active" \
    cargo test --release --lib network_tests::platform_matrix:: --manifest-path "$REPO_ROOT/Cargo.toml"

# --- exactly one varying axis yields a real attribution ---
check_contains "cargo test proves a single varying axis yields an attribution" \
    "single_varying_axis_yields_attribution" \
    cargo test --release --lib network_tests::platform_matrix:: --manifest-path "$REPO_ROOT/Cargo.toml"

# --- the field-evidence shape (multiple entangled axes) withholds attribution ---
check_contains "cargo test proves the field-evidence entangled confound withholds attribution" \
    "field_evidence_four_entangled_axes_withholds_attribution" \
    cargo test --release --lib network_tests::platform_matrix:: --manifest-path "$REPO_ROOT/Cargo.toml"

check_contains "cargo test proves identical capability yields NoVariation" \
    "identical_capability_yields_no_variation" \
    cargo test --release --lib network_tests::platform_matrix:: --manifest-path "$REPO_ROOT/Cargo.toml"

# --- CLI surface: never collects a personal device identifier. Checks for
#     an actual --hostname/--serial/--mac FLAG, not the word "hostname"
#     appearing in a privacy disclaimer (the help text says "never a
#     hostname" as documentation of what this command deliberately omits). ---
check_lacks "platform-matrix --help offers no --hostname/--serial/--mac flag" "--hostname" \
    "$BIN" platform-matrix --help
check_lacks "platform-matrix --help offers no --serial-number flag" "--serial" \
    "$BIN" platform-matrix --help
check_lacks "platform-matrix --help offers no --mac-address flag" "--mac" \
    "$BIN" platform-matrix --help
check_contains "platform-matrix documents coarse (non-identifying) driver/kernel fields" "Never a hostname" \
    "$BIN" platform-matrix --help

# --- offline, deterministic: two locally-run invocations with an entangled
#     confound (driver + kernel + phy + iperf all differing) must withhold
#     attribution end to end through the real CLI, not just the library fn ---
compare_file="$WORK_DIR/platform-matrix-compare.json"
cat > "$compare_file" <<'EOF'
{"capability":{"os_family":"linux","driver_family":"iwlwifi","kernel_major":"6","phy_generation":"Wifi6","power_save":{"value":null,"obtainability":"PlatformLimited"},"iperf_version":"3.16"},"power_save_during_test":"Unknown","throughput_mbps":410.0,"loss_percent":2.0}
EOF
entangled_out="$("$BIN" platform-matrix --os-family linux --driver-family ath10k --kernel-major 5 \
    --phy-generation wifi5 --iperf-version 3.9 --throughput-mbps 280.0 --compare-in "$compare_file" --json 2>/dev/null | sed -n '/^{/,$p')"
if [ -z "$entangled_out" ]; then
    fail "CLI withholds attribution when driver+kernel+phy+iperf all differ" "no JSON output"
else
    check="$(printf '%s' "$entangled_out" | python3 -c '
import json, sys
d = json.load(sys.stdin)
attr = d.get("attribution", {})
print("ok" if "ConfoundedEntangled" in attr else "bad")
' 2>/dev/null)"
    if [ "$check" = "ok" ]; then
        pass "CLI withholds attribution when driver+kernel+phy+iperf all differ"
    else
        fail "CLI withholds attribution when driver+kernel+phy+iperf all differ" "got: $entangled_out"
    fi
fi

# --- the same CLI path with exactly one varying axis DOES attribute,
#     proving the withholding above is a real discrimination, not just
#     "always inconclusive" ---
compare_file2="$WORK_DIR/platform-matrix-compare2.json"
cat > "$compare_file2" <<'EOF'
{"capability":{"os_family":"linux","driver_family":"iwlwifi","kernel_major":"6","phy_generation":"Wifi6","power_save":{"value":null,"obtainability":"PlatformLimited"},"iperf_version":"3.9"},"power_save_during_test":"Unknown","throughput_mbps":450.0,"loss_percent":1.0}
EOF
single_out="$("$BIN" platform-matrix --os-family linux --driver-family iwlwifi --kernel-major 6 \
    --phy-generation wifi5 --iperf-version 3.9 --throughput-mbps 300.0 --compare-in "$compare_file2" --json 2>/dev/null | sed -n '/^{/,$p')"
if [ -z "$single_out" ]; then
    fail "CLI attributes a difference when exactly one axis varies" "no JSON output"
else
    check2="$(printf '%s' "$single_out" | python3 -c '
import json, sys
d = json.load(sys.stdin)
attr = d.get("attribution", {})
sf = attr.get("SinglePlatformFactor")
print("ok" if sf and sf.get("axis") == "phy_generation" else "bad")
' 2>/dev/null)"
    if [ "$check2" = "ok" ]; then
        pass "CLI attributes a difference when exactly one axis varies"
    else
        fail "CLI attributes a difference when exactly one axis varies" "got: $single_out"
    fi
fi
