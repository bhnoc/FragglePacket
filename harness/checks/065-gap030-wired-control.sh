#!/usr/bin/env bash
# GAP-030: matched wired-versus-Wi-Fi fault-domain control. Field evidence:
# wired was lossless at 350 Mbps while matched Wi-Fi lost 8.3-30.1%
# downstream, but the two paths used different public egress IPs, which
# only localizes to "WLAN/controller path OR VLAN-specific NAT/egress" --
# not cleanly to the WLAN. This gate locks:
#   1. WLAN attribution is withheld when the two paths' egress identities
#      differ, naming that as the reason.
#   2. A clean wired control + matching egress + lossy Wi-Fi attributes to
#      WLAN.
#   3. A lossy wired control attributes to shared edge/WAN instead.
#   4. Missing loss or egress data withholds attribution, naming why.

cargo_test() { cargo test --release --lib load_guard::wired_control:: --manifest-path "$REPO_ROOT/Cargo.toml" "$@"; }

check_ok "cargo test covers wired-vs-WiFi attribution logic" cargo_test
check_contains "cargo test proves attribution is withheld when egress identities differ (the field-evidence shape)" \
    "attribution_is_withheld_when_egress_identities_differ" cargo_test
check_contains "cargo test proves attribution names WLAN when the control is clean and egress matches" \
    "attribution_names_wlan_when_control_is_clean_and_egress_matches" cargo_test
check_contains "cargo test proves attribution is shared edge/WAN when the wired control itself shows loss" \
    "attribution_is_shared_when_the_wired_control_itself_shows_loss" cargo_test
check_contains "cargo test proves attribution is withheld when loss is missing on either side" \
    "attribution_is_withheld_when_loss_is_missing_on_either_side" cargo_test
check_contains "cargo test proves attribution is withheld when egress identity was never sampled" \
    "attribution_is_withheld_when_egress_identity_was_never_sampled" cargo_test

check_contains "wired-control advertises --wired-egress/--wifi-egress" "--wired-egress" \
    "$BIN" wired-control --help

json_get() { python3 -c '
import json, sys
d = json.load(sys.stdin)
path = sys.argv[1]
cur = d
for part in path.split("."):
    if isinstance(cur, dict):
        cur = cur.get(part)
    elif isinstance(cur, list):
        try:
            cur = cur[int(part)]
        except (ValueError, IndexError):
            cur = None
    else:
        cur = None
print(json.dumps(cur))
' "$1" 2>/dev/null; }

# --- the central regression: different egress identities withhold WLAN
#     attribution, exactly reproducing the field evidence's own shape ---
diff_out="$("$BIN" wired-control --inject-fixture different-egress --json 2>/dev/null | sed -n '/^{/,$p')"
diff_reason="$(printf '%s' "$diff_out" | json_get attribution.Withheld.reason)"
if printf '%s' "$diff_reason" | grep -q "different public egress identities"; then
    pass "attribution is withheld when wired and Wi-Fi used different egress identities"
else
    fail "attribution is withheld on different egress identities" "got: $diff_reason"
fi
check_contains "human output states WITHHELD, not a fabricated WLAN verdict, on differing egress" \
    "WITHHELD" \
    "$BIN" wired-control --inject-fixture different-egress

# --- clean control + matching egress: attributes to WLAN ---
default_out="$("$BIN" wired-control --inject-fixture default --json 2>/dev/null | sed -n '/^{/,$p')"
default_detail="$(printf '%s' "$default_out" | json_get attribution.Wlan.detail)"
if [ -n "$default_detail" ] && [ "$default_detail" != "null" ]; then
    pass "a clean wired control with matching egress and lossy Wi-Fi attributes to WLAN"
else
    fail "a clean wired control with matching egress attributes to WLAN" "got: $default_out"
fi
check_contains "human output names WLAN when the control genuinely supports it" "WLAN" \
    "$BIN" wired-control --inject-fixture default

# --- lossy wired control: attributes to shared edge/WAN, not WLAN ---
shared_out="$("$BIN" wired-control --inject-fixture shared-edge --json 2>/dev/null | sed -n '/^{/,$p')"
shared_detail="$(printf '%s' "$shared_out" | json_get attribution.SharedEdgeOrWan.detail)"
if [ -n "$shared_detail" ] && [ "$shared_detail" != "null" ]; then
    pass "a lossy wired control attributes to shared edge/WAN, not WLAN"
else
    fail "a lossy wired control attributes to shared edge/WAN" "got: $shared_out"
fi
shared_wlan_field="$(printf '%s' "$shared_out" | json_get attribution.Wlan)"
if [ "$shared_wlan_field" = "null" ]; then
    pass "the shared-edge case never also carries a WLAN attribution"
else
    fail "the shared-edge case never also carries a WLAN attribution" "got: $shared_wlan_field"
fi

# --- missing egress: withheld, naming the reason ---
missing_out="$("$BIN" wired-control --inject-fixture missing-egress --json 2>/dev/null | sed -n '/^{/,$p')"
missing_reason="$(printf '%s' "$missing_out" | json_get attribution.Withheld.reason)"
if printf '%s' "$missing_reason" | grep -q "not sampled"; then
    pass "attribution is withheld when egress identity was never sampled on one side"
else
    fail "attribution is withheld when egress identity was never sampled" "got: $missing_reason"
fi

# --- no loss data at all: withheld, naming the reason (default CLI args
#     with nothing else supplied) ---
empty_out="$("$BIN" wired-control --json 2>/dev/null | sed -n '/^{/,$p')"
empty_reason="$(printf '%s' "$empty_out" | json_get attribution.Withheld.reason)"
if printf '%s' "$empty_reason" | grep -q "loss_pct missing"; then
    pass "attribution is withheld when no loss data was supplied at all, naming that reason"
else
    fail "attribution is withheld with no loss data supplied" "got: $empty_reason"
fi

# --- one real, offline-safe run using explicit flags (no fixture) ---
real_out="$("$BIN" wired-control --wired-mbps 350 --wired-loss-pct 0 --wired-egress 203.0.113.5 \
    --wifi-mbps 300 --wifi-loss-pct 15 --wifi-egress 203.0.113.5 --json 2>/dev/null | sed -n '/^{/,$p')"
real_detail="$(printf '%s' "$real_out" | json_get attribution.Wlan.detail)"
if [ -n "$real_detail" ] && [ "$real_detail" != "null" ]; then
    pass "a real (non-fixture) run with explicit matching egress attributes to WLAN"
else
    fail "a real run with explicit matching egress attributes to WLAN" "got: $real_out"
fi
