#!/usr/bin/env bash
# GAP-074: when two independent sources describe the same property and
# disagree, the disagreement is the finding.
#
# `ApContext` carried band/width/NSS the AP advertises and `ClientAssociation`
# carried what the client actually negotiated. Both were recorded, side by side,
# and never compared. An AP advertising 160 MHz to a client that negotiated 80
# MHz means either the client cannot use the advertised width or the radio is
# not offering it -- opposite fixes -- and the tool said nothing.
#
# The rule this locks: a contested property yields no usable value, both
# provenances are named, and no figure derived from it is emitted. Modelled on
# NOC's bilateral link confirmation, which refuses to assert a link one side
# denies rather than picking a winner.

check_ok "cargo test covers corroboration, contradiction, and provenance" \
    cargo test --release --lib network_tests::corroboration --manifest-path "$REPO_ROOT/Cargo.toml"

check_ok "cargo test proves a contested property has no usable value" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib network_tests::corroboration::tests::a_switch_and_client_link_speed_disagreement_is_contradicted 2>&1 | grep -q '1 passed'"

check_ok "cargo test proves absent sources are Unknown, not Contradicted and not zero" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib network_tests::corroboration::tests::no_source_is_unknown_not_contradicted_and_not_zero 2>&1 | grep -q '1 passed'"

check_ok "cargo test proves a nonsense tolerance cannot swallow a real disagreement" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib network_tests::corroboration::tests::a_nonsense_tolerance_falls_back_to_the_default 2>&1 | grep -q '1 passed'"

check_ok "cargo test proves AP-advertised vs client-negotiated width is compared" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib network_tests::ap_compat_matrix::tests::advertised_and_negotiated_width_disagreement_is_reported 2>&1 | grep -q '1 passed'"

check_ok "cargo test proves band text formatting is not reported as a fault" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib network_tests::ap_compat_matrix::tests::band_text_formatting_is_not_reported_as_a_fault 2>&1 | grep -q '1 passed'"

# --- the comparison must be wired into the command, not only the library ---
# A library enforcing this while the caller ignores it IS the original bug.
cli_src="$REPO_ROOT/src/cli/commands/ap_compat_matrix.rs"
if [ ! -f "$cli_src" ]; then
    fail "ap-compat-matrix surfaces source disagreements" "source file absent"
elif grep -q "ap_client_disagreements" "$cli_src"; then
    pass "ap-compat-matrix surfaces source disagreements"
else
    fail "ap-compat-matrix surfaces source disagreements" \
        "the CLI never calls ap_client_disagreements(): findings stay invisible"
fi

# --- end-to-end: a real contradicted cell must name both values ---
dis_dir="$WORK_DIR/gap074-disagreement"
rm -rf "$dis_dir"; mkdir -p "$dis_dir"
cat > "$dis_dir/cells.json" <<'JSON'
[{
  "label": "be-mode-ap",
  "client": {
    "negotiated_generation": "He", "phy_mode_raw": "802.11ax",
    "band": "6GHz", "channel": 197, "width_mhz": 80, "mcs_index": 7,
    "tx_rate_mbps": 680.0, "nss": 2, "mlo_active": null,
    "ap_identity": null, "platform_limitations": []
  },
  "ap": {
    "ap_identity": null, "model": "C-460", "firmware_version": "21.3.0M-13",
    "power_mode_raw": "POE_PLUS", "low_power_supply": true,
    "radio_mode": "Be", "mlo_supported": true,
    "band_advertised": "6 GHz", "width_advertised_mhz": 160, "nss_advertised": 4
  },
  "client_hardware_generation": "Wifi6e"
}]
JSON

dis_out="$("$BIN" ap-compat-matrix --ingest-cells "$dis_dir/cells.json" 2>&1)"

if [ -z "$dis_out" ]; then
    skip "a contradicted cell reports the disagreement" "no output"
else
    check_contains "a contradicted cell reports the disagreement" "source disagreement" \
        bash -c 'printf "%s" "$1"' _ "$dis_out"

    # Both values must appear: "they disagree" without the numbers is not
    # actionable.
    if printf '%s' "$dis_out" | grep -q "160" && printf '%s' "$dis_out" | grep -q "80"; then
        pass "the disagreement names both the advertised and negotiated values"
    else
        fail "the disagreement names both the advertised and negotiated values" \
            "one or both values absent from the finding"
    fi

    check_contains "the disagreement states the derived figure is withheld" "withheld" \
        bash -c 'printf "%s" "$1"' _ "$dis_out"

    # "6 GHz" vs "6GHz" is formatting, not a fault. A gate that fires on this
    # would be noise and would train operators to ignore the real ones.
    if printf '%s' "$dis_out" | grep -qi "band: AP advertises"; then
        fail "matching bands differing only in spacing are not flagged" \
            "reported a band disagreement between '6 GHz' and '6GHz'"
    else
        pass "matching bands differing only in spacing are not flagged"
    fi
fi

# --- an agreeing cell must stay silent, or the finding means nothing ---
cat > "$dis_dir/agree.json" <<'JSON'
[{
  "label": "agreeing-ap",
  "client": {
    "negotiated_generation": "He", "phy_mode_raw": "802.11ax",
    "band": "6GHz", "channel": 197, "width_mhz": 160, "mcs_index": 7,
    "tx_rate_mbps": 680.0, "nss": 4, "mlo_active": null,
    "ap_identity": null, "platform_limitations": []
  },
  "ap": {
    "ap_identity": null, "model": "C-460", "firmware_version": "21.3.0M-13",
    "power_mode_raw": "FOUR_PPoE", "low_power_supply": false,
    "radio_mode": "Be", "mlo_supported": true,
    "band_advertised": "6GHz", "width_advertised_mhz": 160, "nss_advertised": 4
  },
  "client_hardware_generation": "Wifi7"
}]
JSON

agree_out="$("$BIN" ap-compat-matrix --ingest-cells "$dis_dir/agree.json" 2>&1)"
if [ -z "$agree_out" ]; then
    skip "an agreeing cell reports no disagreement" "no output"
elif printf '%s' "$agree_out" | grep -q "source disagreement"; then
    fail "an agreeing cell reports no disagreement" "flagged a disagreement where both sources match"
else
    pass "an agreeing cell reports no disagreement"
fi
