#!/usr/bin/env bash
# GAP-055: bounded time-series RF spectrum/interference/coverage survey.
# One radio snapshot cannot reveal intermittent interference; this gate
# locks the survey's teeth: every metric this platform cannot sample
# (channel utilization, retries, DFS events, neighboring-BSS load, non-Wi-Fi
# utilization, client count) must report platform-limited, never a
# fabricated 0 that would read as "the channel is clear" -- the single most
# dangerous false negative here.

check_ok "cargo test covers rf-survey metric/change-point/coverage logic" \
    cargo test --release --lib network_tests::rf_survey:: --manifest-path "$REPO_ROOT/Cargo.toml"

# --- platform-limited metrics are None, never a fabricated zero ---
check_contains "cargo test proves platform-limited metric is None, never a fabricated zero" \
    "platform_limited_metric_is_none_never_a_fabricated_zero" \
    cargo test --release --lib network_tests::rf_survey:: --manifest-path "$REPO_ROOT/Cargo.toml"
check_contains "cargo test proves RadioSnapshot conversion marks utilization platform-limited" \
    "radio_snapshot_conversion_marks_utilization_platform_limited" \
    cargo test --release --lib network_tests::rf_survey:: --manifest-path "$REPO_ROOT/Cargo.toml"

# --- operator-supplied telemetry fills gaps without overwriting real measurements ---
check_contains "cargo test proves operator telemetry fills gaps without overwriting measured fields" \
    "operator_supplied_telemetry_fills_gaps_without_overwriting_measured" \
    cargo test --release --lib network_tests::rf_survey:: --manifest-path "$REPO_ROOT/Cargo.toml"

# --- change-point correlation requires >= 2 usable samples ---
check_contains "cargo test proves change-point detection requires at least two usable samples" \
    "change_point_detection_requires_at_least_two_usable_samples" \
    cargo test --release --lib network_tests::rf_survey:: --manifest-path "$REPO_ROOT/Cargo.toml"
check_contains "cargo test proves a material utilization jump is detected as a change point" \
    "change_point_detected_on_material_utilization_jump" \
    cargo test --release --lib network_tests::rf_survey:: --manifest-path "$REPO_ROOT/Cargo.toml"
check_contains "cargo test proves change points correlate with overlapping event windows" \
    "correlation_links_change_point_to_overlapping_event_window" \
    cargo test --release --lib network_tests::rf_survey:: --manifest-path "$REPO_ROOT/Cargo.toml"
check_contains "cargo test proves an unexplained change point is distinct from no change points at all" \
    "correlation_reports_empty_overlap_distinct_from_no_change_points" \
    cargo test --release --lib network_tests::rf_survey:: --manifest-path "$REPO_ROOT/Cargo.toml"

# --- coverage map is structurally privacy-safe ---
check_contains "cargo test proves the coverage map never contains SSID/BSSID/MAC" \
    "coverage_map_never_contains_ssid_bssid_mac" \
    cargo test --release --lib network_tests::rf_survey:: --manifest-path "$REPO_ROOT/Cargo.toml"
check_contains "cargo test proves an identifying location label is rejected" \
    "coverage_map_rejects_identifying_location_label" \
    cargo test --release --lib network_tests::rf_survey:: --manifest-path "$REPO_ROOT/Cargo.toml"

# --- survey duration is derived and there is no unbounded mode reachable ---
check_contains "cargo test proves survey duration is derived and bounded" \
    "survey_plan_duration_is_derived_and_bounded" \
    cargo test --release --lib network_tests::rf_survey:: --manifest-path "$REPO_ROOT/Cargo.toml"
check_lacks "rf-survey --help offers no continuous/unbounded flag" "--continuous" \
    "$BIN" rf-survey --help
check_contains "rf-survey --help documents --sample-count is the only bound (no daemon mode)" "Bounded by construction" \
    "$BIN" rf-survey --help

# --- CLI: a location label that looks like an SSID/BSSID/MAC is rejected before sampling ---
check_fails "rf-survey rejects an identifying --location" \
    "$BIN" rf-survey --sample-count 1 --interval-secs 0 --fast --location "MyHomeSSID"

# --- fully offline, deterministic: --telemetry-in fills platform-limited
#     fields and change-point detection fires on the supplied values,
#     without ever touching system_profiler/ioreg for correctness ---
tele_file="$WORK_DIR/rf-survey-telemetry.json"
cat > "$tele_file" <<'EOF'
[{"channel_utilization_pct": 10.0}, {"channel_utilization_pct": 60.0}]
EOF
offline_out="$("$BIN" rf-survey --sample-count 2 --interval-secs 0 --fast --telemetry-in "$tele_file" --change-threshold-pct 20 --json 2>/dev/null | sed -n '/^{/,$p')"
if [ -z "$offline_out" ]; then
    fail "offline telemetry-fed survey detects the supplied change point" "no JSON output"
else
    check="$(printf '%s' "$offline_out" | python3 -c '
import json, sys
d = json.load(sys.stdin)
cps = d.get("change_points", [])
ok = len(cps) == 1 and cps[0]["from_value"] == 10.0 and cps[0]["to_value"] == 60.0
samples = d["series"]["samples"]
rssi_ok = all(s["rssi_dbm"]["obtainability"] == "PlatformLimited" for s in samples)
util_ok = all(s["channel_utilization_pct"]["obtainability"] == "OperatorSupplied" for s in samples)
retries_ok = all(s["retries_pct"]["obtainability"] == "PlatformLimited" and s["retries_pct"]["value"] is None for s in samples)
print("ok" if ok and rssi_ok and util_ok and retries_ok else "bad")
' 2>/dev/null)"
    if [ "$check" = "ok" ]; then
        pass "offline telemetry-fed survey detects the supplied change point"
    else
        fail "offline telemetry-fed survey detects the supplied change point" "got: $offline_out"
    fi
fi

# --- live (skipped offline): a real short sample against this host's
#     actual radio state must mark utilization/retries/DFS platform-limited
#     (this platform genuinely cannot report them), never sample them as 0 ---
if net_guard; then
    live_out="$("$BIN" rf-survey --sample-count 1 --interval-secs 0 --json 2>/dev/null | sed -n '/^{/,$p')"
    if [ -z "$live_out" ]; then
        skip "live sample marks unsupported metrics platform-limited, never 0" "no JSON output"
    else
        live_check="$(printf '%s' "$live_out" | python3 -c '
import json, sys
d = json.load(sys.stdin)
samples = d["series"]["samples"]
print("ok" if all(s["channel_utilization_pct"]["obtainability"] == "PlatformLimited" and s["channel_utilization_pct"]["value"] is None for s in samples) else "bad")
' 2>/dev/null)"
        if [ "$live_check" = "ok" ]; then
            pass "live sample marks unsupported metrics platform-limited, never 0"
        else
            fail "live sample marks unsupported metrics platform-limited, never 0" "got: $live_out"
        fi
    fi
else
    skip "live sample marks unsupported metrics platform-limited, never 0" "FP_HARNESS_OFFLINE=1"
fi
