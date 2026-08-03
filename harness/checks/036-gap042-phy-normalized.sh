#!/usr/bin/env bash
# GAP-042: a fixed absolute offered rate conflates capacity/airtime
# saturation with a real AP compatibility defect. Field evidence: fixed
# 100 Mbps produced 27.0% VHT loss vs 0.98% HE loss (looked like a
# compatibility defect); PHY-normalized retesting at matched offered
# fractions (~46% of each client's own PHY ceiling) narrowed the gap
# sharply (1.67% vs 0.578%). This locks: offered load is expressed as a
# PHY fraction, not an absolute rate; two clients at the same absolute rate
# but different PHY capacity are not comparable; and a cohort attribution
# is withheld without strong-RF directional controls.

pn_json() { "$BIN" phy-normalized "$@" --json 2>/dev/null | sed -n '/^{/,$p'; }

check_contains "phy-normalized advertises --measurements-file" "--measurements-file" \
    "$BIN" phy-normalized --help
check_contains "phy-normalized advertises --cohort-a/--cohort-b" "--cohort-a" \
    "$BIN" phy-normalized --help

fixture="$WORK_DIR/gap042-measurements.json"
cat > "$fixture" <<'EOF'
[
  {"node": {"node_id": "PC6", "phy_generation": "Vht", "driver": "ath10k", "kernel": "5.10", "phy_capacity_mbps": 130.0, "rf_quality": "Strong", "directional_control": true}, "offered_mbps": 100.0, "loss_percent": 27.0},
  {"node": {"node_id": "PV03", "phy_generation": "He", "driver": "ath11k", "kernel": "5.15", "phy_capacity_mbps": 866.0, "rf_quality": "Strong", "directional_control": true}, "offered_mbps": 100.0, "loss_percent": 0.98},
  {"node": {"node_id": "PC6b", "phy_generation": "Vht", "driver": "ath10k", "kernel": "5.10", "phy_capacity_mbps": 130.0, "rf_quality": "Strong", "directional_control": true}, "offered_mbps": 60.0, "loss_percent": 1.67},
  {"node": {"node_id": "PV03b", "phy_generation": "He", "driver": "ath11k", "kernel": "5.15", "phy_capacity_mbps": 866.0, "rf_quality": "Strong", "directional_control": true}, "offered_mbps": 400.0, "loss_percent": 0.578},
  {"node": {"node_id": "PC6-weak", "phy_generation": "Vht", "driver": "ath10k", "kernel": "5.10", "phy_capacity_mbps": 130.0, "rf_quality": "Weak", "directional_control": true}, "offered_mbps": 60.0, "loss_percent": 15.0},
  {"node": {"node_id": "PV03-simul", "phy_generation": "He", "driver": "ath11k", "kernel": "5.15", "phy_capacity_mbps": 866.0, "rf_quality": "Strong", "directional_control": false}, "offered_mbps": 400.0, "loss_percent": 0.6}
]
EOF

out="$(pn_json --measurements-file "$fixture")"
if [ -z "$out" ]; then
    fail "phy-normalized produces JSON output" "empty output"
else
    fraction_pc6="$(printf '%s' "$out" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(round(d["normalized"][0]["offered_phy_fraction"],2))' 2>/dev/null)"
    fraction_pv03="$(printf '%s' "$out" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(round(d["normalized"][1]["offered_phy_fraction"],2))' 2>/dev/null)"
    if [ "$fraction_pc6" != "$fraction_pv03" ]; then
        pass "offered load is expressed as a per-client PHY fraction, not an absolute rate (PC6=$fraction_pc6 PV03=$fraction_pv03 at the same 100 Mbps)"
    else
        fail "offered load is expressed as a per-client PHY fraction, not an absolute rate" "PC6=$fraction_pc6 PV03=$fraction_pv03"
    fi
fi

# --- same absolute rate, different PHY capacity -> not comparable ---
incomparable_out="$(pn_json --measurements-file "$fixture" --cohort-a 0 --cohort-b 1)"
verdict="$(printf '%s' "$incomparable_out" | python3 -c 'import json,sys; print(json.load(sys.stdin)["attribution"]["verdict"])' 2>/dev/null)"
if [ "$verdict" = "WithheldIncomparableTargets" ]; then
    pass "two clients at the same absolute 100 Mbps but different PHY capacity are reported incomparable, not attributed"
else
    fail "two clients at the same absolute 100 Mbps but different PHY capacity are reported incomparable" "got: $verdict"
fi
check_contains "human output states the fixed-rate pair is withheld" "WITHHELD (incomparable PHY fractions)" \
    "$BIN" phy-normalized --measurements-file "$fixture" --cohort-a 0 --cohort-b 1

# --- matched PHY fraction, strong RF, directional -> attributable ---
comparable_out="$(pn_json --measurements-file "$fixture" --cohort-a 2 --cohort-b 3)"
verdict="$(printf '%s' "$comparable_out" | python3 -c 'import json,sys; print(json.load(sys.stdin)["attribution"]["verdict"])' 2>/dev/null)"
if [ "$verdict" = "Attributable" ]; then
    pass "matched offered-PHY-fraction cohorts with strong-RF directional controls are attributable"
else
    fail "matched offered-PHY-fraction cohorts with strong-RF directional controls are attributable" "got: $verdict"
fi

# --- weak RF in one cohort withholds attribution even at matched fraction ---
weak_rf_out="$(pn_json --measurements-file "$fixture" --cohort-a 2 --cohort-b 4)"
verdict="$(printf '%s' "$weak_rf_out" | python3 -c 'import json,sys; print(json.load(sys.stdin)["attribution"]["verdict"])' 2>/dev/null)"
if [ "$verdict" = "WithheldMissingControls" ]; then
    pass "a cohort containing a weak-RF sample withholds the AP-compatibility attribution"
else
    fail "a cohort containing a weak-RF sample withholds the AP-compatibility attribution" "got: $verdict"
fi

# --- non-directional (simultaneous) sample withholds attribution too ---
simul_out="$(pn_json --measurements-file "$fixture" --cohort-a 3 --cohort-b 5)"
verdict="$(printf '%s' "$simul_out" | python3 -c 'import json,sys; print(json.load(sys.stdin)["attribution"]["verdict"])' 2>/dev/null)"
if [ "$verdict" = "WithheldMissingControls" ]; then
    pass "a cohort containing a non-directional (simultaneous-load) sample withholds the AP-compatibility attribution"
else
    fail "a cohort containing a non-directional (simultaneous-load) sample withholds the AP-compatibility attribution" "got: $verdict"
fi
check_contains "human output never prints Attributable for a weak-RF or non-directional cohort" "WITHHELD (missing strong-RF/directional controls)" \
    "$BIN" phy-normalized --measurements-file "$fixture" --cohort-a 2 --cohort-b 4

# --- stratification by generation/driver/kernel is present ---
check_contains "output stratifies by PHY generation/driver/kernel" "Strata (generation/driver/kernel)" \
    "$BIN" phy-normalized --measurements-file "$fixture"

rm -f "$fixture"
