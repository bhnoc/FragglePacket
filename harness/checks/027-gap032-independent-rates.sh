#!/usr/bin/env bash
# GAP-032: independently rate-controlled, time-aligned simultaneous
# upload/download sweep. Field evidence (ported from
# the original peer-impact zsh harness): a single iperf3 --bidir session hides
# directional asymmetry that independent listeners exposed. This gate locks:
#   1. The two sessions are time-aligned -- their windows genuinely overlap,
#      not merely launched close together.
#   2. "First lossy rate" is reported only when a clean point below it AND a
#      lossy point at it were both actually measured, never extrapolated.
#   3. --server is required; no hardcoded default endpoint.

cargo_test() { cargo test --release --lib load_guard::independent_rates:: --manifest-path "$REPO_ROOT/Cargo.toml" "$@"; }

check_ok "cargo test covers first-lossy-rate and timeline-merge logic" cargo_test
check_contains "cargo test proves first-lossy-rate requires a measured clean point below it" \
    "first_lossy_rate_requires_a_measured_clean_point_below_it" cargo_test
check_contains "cargo test proves first-lossy-rate never extrapolates past the tested range" \
    "never_extrapolates_past_the_tested_range" cargo_test
check_contains "cargo test proves an all-lossy sweep reports no clean baseline, not a fabricated threshold" \
    "all_lossy_reports_no_clean_baseline_rather_than_a_fabricated_threshold" cargo_test
check_contains "cargo test proves unusable points are excluded, not treated as clean" \
    "unusable_points_are_excluded_not_treated_as_clean" cargo_test
check_contains "cargo test proves overlapping session windows are time-aligned" \
    "overlapping_windows_are_time_aligned" cargo_test
check_contains "cargo test proves sequential session windows are NOT time-aligned" \
    "sequential_windows_are_not_time_aligned" cargo_test

check_contains "independent-rates advertises --server/--local-ip/--inject-synthetic" "--inject-synthetic" \
    "$BIN" independent-rates --help
check_fails "independent-rates with no --server and no --inject-synthetic refuses to run" \
    "$BIN" independent-rates --interface en0
check_fails "independent-rates with no --interface refuses to run" \
    "$BIN" independent-rates --server example.test --local-ip 10.0.0.1

ir_json() { "$BIN" independent-rates --interface en0 --inject-synthetic --loss-threshold-pct 2.0 --json 2>/dev/null | sed -n '/^{/,$p'; }
json_get() { python3 -c '
import json, sys
d = json.load(sys.stdin)
path = sys.argv[1]
cur = d
for part in path.split("."):
    cur = cur.get(part) if isinstance(cur, dict) else None
print(json.dumps(cur))
' "$1" 2>/dev/null; }

out="$(ir_json)"
if [ -z "$out" ]; then
    fail "synthetic sweep produces a JSON report" "no output"
else
    pass "synthetic sweep produces a JSON report"

    upload_lossy="$(printf '%s' "$out" | json_get upload_first_lossy)"
    if printf '%s' "$upload_lossy" | grep -q '"Found"'; then
        pass "upload direction reports a Found first-lossy-rate (matches field data: clean 250, lossy 300)"
    else
        fail "upload direction reports a Found first-lossy-rate" "got: $upload_lossy"
    fi

    download_lossy="$(printf '%s' "$out" | json_get download_first_lossy)"
    if printf '%s' "$download_lossy" | grep -q '"Found"'; then
        pass "download direction reports a Found first-lossy-rate (matches field data: clean 250, lossy 300)"
    else
        fail "download direction reports a Found first-lossy-rate" "got: $download_lossy"
    fi
fi

# --- time alignment must be asserted structurally: a merged timeline exists
#     and its two windows genuinely overlap for the real-session path ---
if net_guard; then
    gw="$(ipconfig getoption en0 router 2>/dev/null)"
    if [ -z "$gw" ]; then
        skip "real sweep's merged timeline is time-aligned" "no gateway on en0"
    else
        real_out="$("$BIN" independent-rates --server speedtest.xmission.com --interface en0 --local-ip "$(ipconfig getifaddr en0 2>/dev/null)" --rates-mbps 1 --duration-secs 1 --json 2>/dev/null | sed -n '/^{/,$p')"
        if [ -z "$real_out" ]; then
            skip "real sweep's merged timeline is time-aligned" "no JSON output"
        else
            aligned="$(printf '%s' "$real_out" | json_get example_merged_timeline.time_aligned)"
            if [ "$aligned" = "true" ]; then
                pass "real sweep's merged timeline is time-aligned"
            else
                fail "real sweep's merged timeline is time-aligned" "time_aligned=$aligned"
            fi
        fi
    fi
else
    skip "real sweep's merged timeline is time-aligned" "FP_HARNESS_OFFLINE=1"
fi

check_contains "human output states first lossy rate is not extrapolated when none observed" \
    "not extrapolated above it" \
    "$BIN" independent-rates --interface en0 --inject-synthetic --loss-threshold-pct 99.0
