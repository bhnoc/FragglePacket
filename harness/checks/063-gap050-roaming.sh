#!/usr/bin/env bash
# GAP-050: controlled roaming/session-continuity test. Field evidence: a
# three-foot move changed the association and invalidated two runs -- this
# gate exists to measure that transition rather than discard it. Locks:
#   1. An AP transition is reported as salted-label A->B with no BSSID
#      present anywhere in output.
#   2. Handoff duration is measured or unavailable, never zero for a
#      transition that was never observed to complete.
#   3. VLAN/public-identity continuity is a distinct field from session
#      reset, and is "unavailable" (not "unchanged") when never sampled.

cargo_test() { cargo test --release --lib load_guard::roaming:: --manifest-path "$REPO_ROOT/Cargo.toml" "$@"; }

check_ok "cargo test covers roam-transition classification and identity-continuity logic" cargo_test
check_contains "cargo test proves a transition report never contains a BSSID-shaped value" \
    "a_transition_report_never_contains_a_bssid_shaped_value" cargo_test
check_contains "cargo test proves same-BSSID-same-band is SameApSameRadio" \
    "same_bssid_same_band_is_same_ap_same_radio" cargo_test
check_contains "cargo test proves same-label-different-band is SameApDifferentRadio" \
    "same_label_different_band_is_same_ap_different_radio" cargo_test
check_contains "cargo test proves a different label is DifferentAp" \
    "different_label_is_different_ap" cargo_test
check_contains "cargo test proves a missing identity on either side is Undetermined, not guessed" \
    "missing_either_side_is_undetermined_not_guessed" cargo_test
check_contains "cargo test proves an unobserved handoff reports duration as None, never zero" \
    "an_unobserved_handoff_reports_duration_as_none_never_zero" cargo_test
check_contains "cargo test proves a changed public identity is reported distinctly from unavailable" \
    "a_changed_public_identity_is_reported_distinctly_from_unavailable" cargo_test

check_contains "roaming advertises --wait-secs/--inject-fixture" "--wait-secs" \
    "$BIN" roaming --help

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

mac_pattern='([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}'

clean_out="$("$BIN" roaming --inject-fixture roam-clean --json 2>/dev/null | sed -n '/^{/,$p')"
if [ -z "$clean_out" ]; then
    fail "a clean roam fixture produces a JSON report" "no output"
else
    pass "a clean roam fixture produces a JSON report"
    kind="$(printf '%s' "$clean_out" | json_get transition.kind)"
    if [ "$kind" = '"DifferentAp"' ]; then
        pass "a transition between two distinct BSSIDs reports kind=DifferentAp"
    else
        fail "a transition between two distinct BSSIDs reports kind=DifferentAp" "got: $kind"
    fi
    before_label="$(printf '%s' "$clean_out" | json_get transition.before_label)"
    after_label="$(printf '%s' "$clean_out" | json_get transition.after_label)"
    if printf '%s%s' "$before_label" "$after_label" | grep -q '"ap-'; then
        pass "the transition is reported as salted labels (ap-XXXXXXXX), not raw identifiers"
    else
        fail "the transition is reported as salted labels" "before=$before_label after=$after_label"
    fi
fi

id_change_out="$("$BIN" roaming --inject-fixture roam-identity-change --json 2>/dev/null | sed -n '/^{/,$p')"
id_continuity="$(printf '%s' "$id_change_out" | json_get transition.identity_continuity)"
if [ "$id_continuity" = '"Changed"' ]; then
    pass "a transition with a different public identity on each side reports identity_continuity=Changed"
else
    fail "a transition with a different public identity reports Changed" "got: $id_continuity"
fi
check_contains "human output flags a changed VLAN/public identity distinctly" "CHANGED" \
    "$BIN" roaming --inject-fixture roam-identity-change

never_out="$("$BIN" roaming --inject-fixture roam-never-completed --json 2>/dev/null | sed -n '/^{/,$p')"
handoff="$(printf '%s' "$never_out" | json_get transition.handoff_duration_ms)"
if [ "$handoff" = "null" ]; then
    pass "a handoff that never completed reports handoff_duration_ms=null, never 0"
else
    fail "a never-completed handoff reports duration as null, never 0" "got: $handoff"
fi
never_continuity="$(printf '%s' "$never_out" | json_get transition.identity_continuity)"
if [ "$never_continuity" = '"Unavailable"' ]; then
    pass "identity continuity is Unavailable (not Unchanged) when the after-side was never sampled"
else
    fail "identity continuity is Unavailable when never sampled" "got: $never_continuity"
fi
check_contains "human output states the handoff was unavailable, not a fabricated 0ms" \
    "unavailable (handoff not observed to complete)" \
    "$BIN" roaming --inject-fixture roam-never-completed

# --- the central privacy regression: no BSSID-shaped string anywhere ---
all_out="$clean_out$id_change_out$never_out"
all_human="$("$BIN" roaming --inject-fixture roam-clean 2>&1)$("$BIN" roaming --inject-fixture roam-identity-change 2>&1)"
if printf '%s' "$all_out$all_human" | grep -Eq "$mac_pattern"; then
    fail "no BSSID-shaped string appears anywhere in roaming output" "found a MAC-shaped token"
else
    pass "no BSSID-shaped string appears anywhere in roaming output"
fi

# --- exactly one real, offline-safe run ---
real_out="$("$BIN" roaming --wait-secs 0 --json 2>/dev/null | sed -n '/^{/,$p')"
if [ -z "$real_out" ]; then
    fail "a real (non-fixture) roaming run produces a JSON report" "no output"
else
    pass "a real (non-fixture) roaming run produces a JSON report"
    if printf '%s' "$real_out" | grep -Eq "$mac_pattern"; then
        fail "the real run's output carries no BSSID-shaped string" "found a MAC-shaped token"
    else
        pass "the real run's output carries no BSSID-shaped string"
    fi
fi
