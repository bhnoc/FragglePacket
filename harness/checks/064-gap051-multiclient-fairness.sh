#!/usr/bin/env bash
# GAP-051/GAP-067: coordinated multi-client capacity/fairness. Field
# evidence: a coordinated run measured severe degradation but could not
# reach a verdict because the peer's mode/listener/association/timestamps
# were never captured, and the two candidate explanations (shared-listener
# contention vs. background impairment) invert the conclusion from
# identical numbers. This gate locks:
#   1. A cross-client verdict is refused until BOTH role descriptors exist.
#   2. It is refused when descriptors exist but their phase windows do not
#      overlap in time.
#   3. Jain fairness is never computed from fewer than two rate samples.
#   4. A shared listener endpoint between roles is flagged as a confound.

cargo_test() { cargo test --release --lib load_guard::multiclient_fairness:: --manifest-path "$REPO_ROOT/Cargo.toml" "$@"; }

check_ok "cargo test covers cross-client verdict / Jain fairness / confound logic" cargo_test
check_contains "cargo test proves the verdict is refused when either descriptor is missing" \
    "cross_client_verdict_is_refused_when_either_descriptor_is_missing" cargo_test
check_contains "cargo test proves the verdict is refused when phase windows do not overlap" \
    "cross_client_verdict_is_refused_when_windows_dont_overlap" cargo_test
check_contains "cargo test proves the verdict is comparable when phase windows overlap" \
    "cross_client_verdict_is_comparable_when_windows_overlap" cargo_test
check_contains "cargo test proves a shared listener endpoint is flagged as a confound" \
    "shared_listener_endpoints_are_flagged_as_a_confound" cargo_test
check_contains "cargo test proves Jain fairness refuses a single sample" \
    "jain_fairness_index_refuses_a_single_sample" cargo_test
check_contains "cargo test proves Jain fairness is 1.0 for perfectly equal rates" \
    "jain_fairness_index_is_one_for_perfectly_equal_rates" cargo_test
check_contains "cargo test proves Jain fairness drops below 1.0 for unequal rates" \
    "jain_fairness_index_drops_below_one_for_unequal_rates" cargo_test
check_contains "cargo test proves an empty phase-mark set yields no window, not a zero-length one" \
    "phase_window_is_none_with_no_marks_not_a_zero_length_window" cargo_test

check_contains "multiclient-fairness advertises --emit-descriptor/--descriptor-a/--descriptor-b" \
    "--emit-descriptor" \
    "$BIN" multiclient-fairness --help

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

# --- missing descriptor B: refused, names what's missing ---
missing_out="$("$BIN" multiclient-fairness --inject-fixture missing-b --json 2>/dev/null | sed -n '/^{/,$p')"
missing_verdict="$(printf '%s' "$missing_out" | json_get verdict.Refused.reason)"
if printf '%s' "$missing_verdict" | grep -q "role descriptor B"; then
    pass "a missing second role descriptor is refused, naming what's missing"
else
    fail "a missing second role descriptor is refused, naming what's missing" "got: $missing_verdict"
fi
check_contains "human output states REFUSED for a missing descriptor" "REFUSED" \
    "$BIN" multiclient-fairness --inject-fixture missing-b

# --- both descriptors present but non-overlapping windows: refused ---
no_overlap_out="$("$BIN" multiclient-fairness --inject-fixture no-overlap --json 2>/dev/null | sed -n '/^{/,$p')"
no_overlap_verdict="$(printf '%s' "$no_overlap_out" | json_get verdict.Refused.reason)"
if printf '%s' "$no_overlap_verdict" | grep -q "do not overlap"; then
    pass "two descriptors with non-overlapping phase windows are refused (GAP-067's core requirement)"
else
    fail "non-overlapping phase windows are refused" "got: $no_overlap_verdict"
fi

# --- overlapping windows: comparable, and a shared listener is flagged ---
shared_out="$("$BIN" multiclient-fairness --inject-fixture shared-listener --rates-mbps 90,10 --json 2>/dev/null | sed -n '/^{/,$p')"
shared_verdict_present="$(printf '%s' "$shared_out" | json_get verdict.Comparable.clock_offset_secs)"
if [ "$shared_verdict_present" != "null" ] && [ -n "$shared_verdict_present" ]; then
    pass "overlapping phase windows with both descriptors present yield a Comparable verdict"
else
    fail "overlapping phase windows yield a Comparable verdict" "got: $shared_out"
fi
shared_listeners="$(printf '%s' "$shared_out" | json_get verdict.Comparable.shared_listeners)"
if printf '%s' "$shared_listeners" | grep -q "s:5202"; then
    pass "a shared listener endpoint between the two roles is flagged as a confound"
else
    fail "a shared listener endpoint is flagged as a confound" "got: $shared_listeners"
fi
check_contains "human output flags a shared-listener confound, not a silent network-fault claim" \
    "contention confound, not a network fault" \
    "$BIN" multiclient-fairness --inject-fixture shared-listener --rates-mbps 90,10

# --- Jain fairness only appears once a Comparable verdict + >=2 rates exist ---
fairness_present="$(printf '%s' "$shared_out" | json_get jain_fairness_index)"
if [ "$fairness_present" != "null" ]; then
    pass "Jain fairness is computed once a Comparable verdict and >=2 rate samples exist"
else
    fail "Jain fairness is computed once inputs are sufficient" "got: $fairness_present"
fi

no_rates_out="$("$BIN" multiclient-fairness --inject-fixture shared-listener --json 2>/dev/null | sed -n '/^{/,$p')"
no_rates_fairness="$(printf '%s' "$no_rates_out" | json_get jain_fairness_index)"
if [ "$no_rates_fairness" = "null" ]; then
    pass "Jain fairness is null (not a fabricated 1.0) when fewer than 2 rate samples were supplied"
else
    fail "Jain fairness is null with fewer than 2 rate samples" "got: $no_rates_fairness"
fi

refused_with_rates_out="$("$BIN" multiclient-fairness --inject-fixture no-overlap --rates-mbps 90,10 --json 2>/dev/null | sed -n '/^{/,$p')"
refused_with_rates_fairness="$(printf '%s' "$refused_with_rates_out" | json_get jain_fairness_index)"
if [ "$refused_with_rates_fairness" = "null" ]; then
    pass "Jain fairness is never computed when the cross-client verdict itself is Refused"
else
    fail "Jain fairness is never computed when the verdict is Refused" "got: $refused_with_rates_fairness"
fi

# --- emit-descriptor round-trips through real files ---
tmp_a="$WORK_DIR/desc-a.json"
tmp_b="$WORK_DIR/desc-b.json"
"$BIN" --help >/dev/null 2>&1
"$BIN" multiclient-fairness --emit-descriptor "$tmp_a" --role loading --client-id gate-a --interface en0 --listener-endpoints s:9001 >/dev/null 2>&1
"$BIN" multiclient-fairness --emit-descriptor "$tmp_b" --role observing --client-id gate-b --interface en0 --listener-endpoints s:9002 >/dev/null 2>&1
if [ -f "$tmp_a" ] && [ -f "$tmp_b" ]; then
    pass "--emit-descriptor writes a real descriptor file for each role"
else
    fail "--emit-descriptor writes a real descriptor file for each role" "missing: $tmp_a or $tmp_b"
fi
real_files_out="$("$BIN" multiclient-fairness --descriptor-a "$tmp_a" --descriptor-b "$tmp_b" --json 2>/dev/null | sed -n '/^{/,$p')"
if [ -n "$real_files_out" ]; then
    pass "evaluating two real descriptor files produces a verdict (Comparable or Refused, but not empty)"
else
    fail "evaluating two real descriptor files produces a verdict" "no output"
fi
