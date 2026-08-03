#!/usr/bin/env bash
# GAP-043: a counter that answers a read call is not proof it is live.
# Field evidence: privileged iw station counters on PC6/PV03 did not
# advance during known 100+100 Mbps traffic -- a frozen counter reporting
# 0 drops is indistinguishable from a healthy radio unless bracketed by a
# known stimulus. Central regression this gate locks: a frozen source must
# NEVER yield a zero-drop verdict, and reset/wrap/genuine-zero stay
# distinguishable from each other and from Frozen. Fully offline via
# --inject-before/--inject-after; the real bracket path is proven separately
# by a live run pasted in the report, not by this gate (which must stay
# fast and deterministic).

cl_json() { "$BIN" counter-liveness "$@" --json 2>/dev/null | sed -n '/^{/,$p'; }

check_contains "counter-liveness advertises --inject-before/--inject-after" "--inject-before" \
    "$BIN" counter-liveness --help
check_contains "counter-liveness advertises --corroborate" "--corroborate" \
    "$BIN" counter-liveness --help

# --- central regression: a frozen counter never yields a zero-drop verdict ---
frozen_out="$(cl_json --interface iw-station-sim --inject-before 500000 --inject-after 500000 --stimulus-packets 2000 --primary-drops 0 --corroborate capture=0)"
if [ -z "$frozen_out" ]; then
    fail "frozen counter produces JSON output" "empty output"
else
    bracket_verdict="$(printf '%s' "$frozen_out" | python3 -c 'import json,sys; print(json.load(sys.stdin)["bracket"]["verdict"])' 2>/dev/null)"
    if [ "$bracket_verdict" = "Frozen" ]; then
        pass "a counter with zero delta under a known stimulus is classified Frozen"
    else
        fail "a counter with zero delta under a known stimulus is classified Frozen" "got: $bracket_verdict"
    fi

    zero_drop_verdict="$(printf '%s' "$frozen_out" | python3 -c 'import json,sys; print(json.load(sys.stdin)["zero_drop_verdict"]["verdict"])' 2>/dev/null)"
    if [ "$zero_drop_verdict" = "None" ]; then
        pass "CENTRAL REGRESSION: a frozen counter never yields a zero-drop verdict, even with corroboration supplied"
    else
        fail "CENTRAL REGRESSION: a frozen counter never yields a zero-drop verdict" "got: $zero_drop_verdict"
    fi

    primary_live="$(printf '%s' "$frozen_out" | python3 -c 'import json,sys; print(json.load(sys.stdin)["zero_drop_verdict"]["primary_live"])' 2>/dev/null)"
    if [ "$primary_live" = "False" ]; then
        pass "frozen source is recorded as not-live in the zero-drop verdict"
    else
        fail "frozen source is recorded as not-live in the zero-drop verdict" "got: $primary_live"
    fi
fi
check_contains "human output never claims corroborated zero drops from a frozen source" "WITHHELD" \
    "$BIN" counter-liveness --interface iw-station-sim --inject-before 500000 --inject-after 500000 --stimulus-packets 2000 --corroborate capture=0
check_lacks "human output never prints CORROBORATED for a frozen source" "CORROBORATED" \
    "$BIN" counter-liveness --interface iw-station-sim --inject-before 500000 --inject-after 500000 --stimulus-packets 2000 --corroborate capture=0

# --- reset vs wrap vs frozen vs genuine live stay distinguishable ---
reset_out="$(cl_json --interface iw-station-sim --inject-before 5000 --inject-after 4950 --stimulus-packets 2000)"
reset_verdict="$(printf '%s' "$reset_out" | python3 -c 'import json,sys; print(json.load(sys.stdin)["bracket"]["verdict"])' 2>/dev/null)"
if [ "$reset_verdict" = "Reset" ]; then
    pass "a small backwards jump relative to the stimulus is classified Reset, not Wrapped or Frozen"
else
    fail "a small backwards jump relative to the stimulus is classified Reset, not Wrapped or Frozen" "got: $reset_verdict"
fi

wrap_out="$(cl_json --interface iw-station-sim --inject-before 4294966296 --inject-after 1000 --stimulus-packets 2000)"
wrap_verdict="$(printf '%s' "$wrap_out" | python3 -c 'import json,sys; print(json.load(sys.stdin)["bracket"]["verdict"])' 2>/dev/null)"
if [ "$wrap_verdict" = "Wrapped" ]; then
    pass "a backwards jump reconstructing to the known stimulus near a 32-bit boundary is classified Wrapped, not Reset"
else
    fail "a backwards jump reconstructing to the known stimulus near a 32-bit boundary is classified Wrapped, not Reset" "got: $wrap_verdict"
fi

live_out="$(cl_json --interface iw-station-sim --inject-before 100000 --inject-after 102000 --stimulus-packets 2000)"
live_verdict="$(printf '%s' "$live_out" | python3 -c 'import json,sys; print(json.load(sys.stdin)["bracket"]["verdict"])' 2>/dev/null)"
if [ "$live_verdict" = "Live" ]; then
    pass "an advance matching the known stimulus is classified Live"
else
    fail "an advance matching the known stimulus is classified Live" "got: $live_verdict"
fi

# --- a genuine zero-stimulus bracket is never confused with Frozen ---
no_stimulus_out="$(cl_json --interface iw-station-sim --inject-before 100 --inject-after 100 --stimulus-packets 0)"
no_stimulus_verdict="$(printf '%s' "$no_stimulus_out" | python3 -c 'import json,sys; print(json.load(sys.stdin)["bracket"]["verdict"])' 2>/dev/null)"
if [ "$no_stimulus_verdict" != "Frozen" ]; then
    pass "a zero-packet stimulus never produces a Frozen verdict (no known stimulus to compare against)"
else
    fail "a zero-packet stimulus never produces a Frozen verdict" "got: $no_stimulus_verdict"
fi

# --- zero-drop verdict requires corroboration even when the primary is live ---
live_no_corrob="$(cl_json --interface iw-station-sim --inject-before 100000 --inject-after 102000 --stimulus-packets 2000 --primary-drops 0)"
verdict_no_corrob="$(printf '%s' "$live_no_corrob" | python3 -c 'import json,sys; print(json.load(sys.stdin)["zero_drop_verdict"]["verdict"])' 2>/dev/null)"
if [ "$verdict_no_corrob" = "None" ]; then
    pass "a live primary source with zero drops and NO corroboration still withholds the zero-drop verdict"
else
    fail "a live primary source with zero drops and NO corroboration still withholds the zero-drop verdict" "got: $verdict_no_corrob"
fi

live_with_corrob="$(cl_json --interface iw-station-sim --inject-before 100000 --inject-after 102000 --stimulus-packets 2000 --primary-drops 0 --corroborate capture=0)"
verdict_with_corrob="$(printf '%s' "$live_with_corrob" | python3 -c 'import json,sys; print(json.load(sys.stdin)["zero_drop_verdict"]["verdict"])' 2>/dev/null)"
if [ "$verdict_with_corrob" = "True" ]; then
    pass "a live primary source with zero drops AND a corroborating source issues a zero-drop verdict"
else
    fail "a live primary source with zero drops AND a corroborating source issues a zero-drop verdict" "got: $verdict_with_corrob"
fi

# --- unit-level guarantee behind the CLI-level checks above ---
check_ok "cargo test proves the frozen-never-yields-zero-drop invariant" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib network_tests::counter_liveness::tests::zero_drop_verdict_withheld_when_primary_frozen 2>&1 | grep -q '1 passed'"
