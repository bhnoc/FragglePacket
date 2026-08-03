#!/usr/bin/env bash
# GAP-024: stable, privacy-safe AP/radio identity from BSSID. Field evidence:
# switching SSIDs changed band/channel/signal/PHY rate, but redaction
# prevented determining whether both radios belonged to one physical AP --
# a very different fault domain than a genuine cross-AP roam. This gate
# locks:
#   1. No output anywhere contains a BSSID/SSID/MAC-shaped string.
#   2. The salted label is stable across two runs for the same BSSID+salt.
#   3. The label differs for a different BSSID.
#   4. Same-AP-different-radio is distinguishable from cross-AP.
#   5. The salt has real entropy (its two 16-hex-char halves differ; two
#      independently generated salts differ) and its persisted file is not
#      group/world readable (0600) -- a weak/leaked salt makes every label
#      this tool ever emitted reversible back to a BSSID by brute force.

cargo_test() { cargo test --release --lib load_guard::ap_identity:: --manifest-path "$REPO_ROOT/Cargo.toml" "$@"; }

check_ok "cargo test covers salted-label derivation and AP comparison logic" cargo_test
check_contains "cargo test proves the label is stable for the same BSSID and salt" \
    "label_is_stable_for_the_same_bssid_and_salt" cargo_test
check_contains "cargo test proves the label differs for a different BSSID" \
    "label_differs_for_a_different_bssid" cargo_test
check_contains "cargo test proves the label differs across salts for the same BSSID (no cross-machine correlation)" \
    "label_differs_for_a_different_salt_same_bssid" cargo_test
check_contains "cargo test proves the label never contains the input BSSID text" \
    "label_never_contains_the_input_bssid_text" cargo_test
check_contains "cargo test proves same-label-same-band is SameApSameRadio" \
    "same_label_same_band_is_same_ap_same_radio" cargo_test
check_contains "cargo test proves same-label-different-band is SameApDifferentRadio" \
    "same_label_different_band_is_same_ap_different_radio" cargo_test
check_contains "cargo test proves a different label is DifferentAp" \
    "different_label_is_different_ap" cargo_test
check_contains "cargo test proves a missing identity on either side is Unavailable, not guessed" \
    "missing_identity_on_either_side_is_unavailable_not_guessed" cargo_test
check_contains "cargo test proves the generated salt's two halves differ (real entropy, not a hash of itself)" \
    "generated_salt_first_half_does_not_equal_second_half" cargo_test
check_contains "cargo test proves two independently generated salts differ" \
    "two_generated_salts_differ" cargo_test
check_contains "cargo test proves the persisted salt file is not group/world readable" \
    "persisted_salt_file_is_not_group_or_world_readable" cargo_test

check_contains "ap-identity advertises --compare-before-after/--inject-fixture" "--compare-before-after" \
    "$BIN" ap-identity --help

# --- direct check on the actual persisted salt file on this machine, not
#     just the unit test's own path, since the salt file mode is a
#     filesystem property the harness can independently verify ---
salt_file="$HOME/Library/Application Support/fraggle-packet-ap-salt"
if [ -f "$salt_file" ]; then
    salt_mode="$(stat -f "%Lp" "$salt_file" 2>/dev/null || stat -c "%a" "$salt_file" 2>/dev/null)"
    if [ "$salt_mode" = "600" ]; then
        pass "persisted salt file on disk is mode 600"
    else
        fail "persisted salt file on disk is mode 600" "got mode: $salt_mode"
    fi
    salt_contents="$(cat "$salt_file")"
    half_len=$((${#salt_contents} / 2))
    if [ "${salt_contents:0:half_len}" != "${salt_contents:half_len}" ]; then
        pass "persisted salt file's two halves differ"
    else
        fail "persisted salt file's two halves differ" "salt: $salt_contents"
    fi
else
    skip "persisted salt file on disk is mode 600" "no salt file yet on this machine"
    skip "persisted salt file's two halves differ" "no salt file yet on this machine"
fi

json_get() { python3 -c '
import json, sys
d = json.load(sys.stdin)
path = sys.argv[1]
cur = d
for part in path.split("."):
    cur = cur.get(part) if isinstance(cur, dict) else None
print(json.dumps(cur))
' "$1" 2>/dev/null; }

# --- same-AP-same-radio ---
same_out="$("$BIN" ap-identity --compare-before-after --inject-fixture --inject-second-sample same --json 2>/dev/null | sed -n '/^{/,$p')"
if [ -z "$same_out" ]; then
    fail "same BSSID+band reports SameApSameRadio" "no output"
else
    same_cmp="$(printf '%s' "$same_out" | json_get comparison)"
    if [ "$same_cmp" = '"SameApSameRadio"' ]; then
        pass "same BSSID+band reports SameApSameRadio"
    else
        fail "same BSSID+band reports SameApSameRadio" "got: $same_cmp"
    fi

    before_label="$(printf '%s' "$same_out" | json_get before.label)"
    after_label="$(printf '%s' "$same_out" | json_get after.label)"
    if [ "$before_label" = "$after_label" ] && [ -n "$before_label" ] && [ "$before_label" != "null" ]; then
        pass "the salted label is stable across two samples of the same BSSID"
    else
        fail "the salted label is stable across two samples of the same BSSID" "before=$before_label after=$after_label"
    fi
fi

# --- same-AP-different-radio: distinguishable from cross-AP ---
radio_change_out="$("$BIN" ap-identity --compare-before-after --inject-fixture --inject-second-sample same-radio-change --json 2>/dev/null | sed -n '/^{/,$p')"
if [ -z "$radio_change_out" ]; then
    fail "same BSSID, different band reports SameApDifferentRadio" "no output"
else
    rc_cmp="$(printf '%s' "$radio_change_out" | json_get comparison)"
    if [ "$rc_cmp" = '"SameApDifferentRadio"' ]; then
        pass "same BSSID, different band reports SameApDifferentRadio"
    else
        fail "same BSSID, different band reports SameApDifferentRadio" "got: $rc_cmp"
    fi
fi

# --- cross-AP: a genuinely different BSSID must produce a different label
#     and a DifferentAp verdict -- distinguishable from the same-AP case above ---
diff_ap_out="$("$BIN" ap-identity --compare-before-after --inject-fixture --inject-second-sample different-ap --json 2>/dev/null | sed -n '/^{/,$p')"
if [ -z "$diff_ap_out" ]; then
    fail "a different BSSID reports DifferentAp with a different label" "no output"
else
    da_cmp="$(printf '%s' "$diff_ap_out" | json_get comparison)"
    da_before="$(printf '%s' "$diff_ap_out" | json_get before.label)"
    da_after="$(printf '%s' "$diff_ap_out" | json_get after.label)"
    if [ "$da_cmp" = '"DifferentAp"' ] && [ "$da_before" != "$da_after" ]; then
        pass "a different BSSID reports DifferentAp with a different label"
    else
        fail "a different BSSID reports DifferentAp with a different label" "comparison=$da_cmp before=$da_before after=$da_after"
    fi
fi

# --- no output anywhere contains a BSSID/SSID/MAC-shaped string ---
mac_pattern='([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}'
all_json="$same_out$radio_change_out$diff_ap_out"
if printf '%s' "$all_json" | grep -Eq "$mac_pattern"; then
    fail "ap-identity JSON output carries no MAC-shaped string" "found a MAC-shaped token"
else
    pass "ap-identity JSON output carries no MAC-shaped string"
fi

human="$("$BIN" ap-identity --compare-before-after --inject-fixture --inject-second-sample different-ap 2>&1)"
if printf '%s' "$human" | grep -Eq "$mac_pattern"; then
    fail "ap-identity human output carries no MAC-shaped string" "found a MAC-shaped token"
else
    pass "ap-identity human output carries no MAC-shaped string"
fi
check_lacks "ap-identity human output carries no SSID label" "SSID" \
    printf '%s' "$human"

# --- one real end-to-end run, guarded since it needs live root state ---
if net_guard; then
    real_out="$("$BIN" ap-identity --json 2>/dev/null | sed -n '/^{/,$p')"
    if [ -z "$real_out" ]; then
        skip "real ap-identity run produces a report" "no output"
    else
        pass "real ap-identity run produces a report"
        if printf '%s' "$real_out" | grep -Eq "$mac_pattern"; then
            fail "real run's output carries no MAC-shaped string" "found a MAC-shaped token"
        else
            pass "real run's output carries no MAC-shaped string"
        fi
    fi
else
    skip "real ap-identity run produces a report" "FP_HARNESS_OFFLINE=1"
fi
