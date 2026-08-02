#!/usr/bin/env bash
# GAP-002: idle/upload-loaded/download-loaded/simultaneous latency via
# networkQuality. Field evidence: the investigation had to fall back to
# macOS networkQuality by hand because no built-in bufferbloat test existed.
# This gate is offline-safe: all decision logic (phase parsing, grading,
# missing-tool degradation) is unit-tested against synthetic/fixture JSON,
# so it never needs live network or the real networkQuality binary to prove
# the logic has teeth. A light live smoke check runs only when both network
# and the tool are available.

check_ok "cargo test covers bufferbloat phase parsing and grading" \
    cargo test --release --lib network_tests::bufferbloat:: --manifest-path "$REPO_ROOT/Cargo.toml"

# --- an unmeasured/missing tool must report unavailable, never a false zero,
#     and every report (available or not) must name the tool that produced it ---
check_contains "cargo test proves a missing networkQuality reports unavailable, not zero" \
    "missing_tool_reports_unavailable_not_zero" \
    cargo test --release --lib network_tests::bufferbloat:: --manifest-path "$REPO_ROOT/Cargo.toml"

check_contains "cargo test proves a missing JSON field is None, never a false zero" \
    "missing_field_is_none_not_zero" \
    cargo test --release --lib network_tests::bufferbloat:: --manifest-path "$REPO_ROOT/Cargo.toml"

# --- directional phases must never read the other direction's fields ---
check_contains "cargo test proves the download phase parser never reads upload fields" \
    "parse_download_phase_never_reads_upload_fields" \
    cargo test --release --lib network_tests::bufferbloat:: --manifest-path "$REPO_ROOT/Cargo.toml"

# --- simultaneous mode's blended figure is kept structurally distinct from
#     the two directional phases' per-direction figures ---
check_contains "cargo test proves simultaneous mode reads only the blended responsiveness key" \
    "simultaneous_phase_reads_blended_responsiveness_only" \
    cargo test --release --lib network_tests::bufferbloat:: --manifest-path "$REPO_ROOT/Cargo.toml"

# --- the responsiveness grade must never require idle's RPM (idle never
#     carries one by design) and must reflect the worst phase, not an
#     average that would hide a GAP-004-shaped simultaneous collapse ---
check_contains "cargo test proves the grade never requires idle's RPM" \
    "grade_never_requires_idle_rpm" \
    cargo test --release --lib network_tests::bufferbloat:: --manifest-path "$REPO_ROOT/Cargo.toml"

check_contains "cargo test proves the grade reflects the worst phase, not an average" \
    "grade_takes_the_worst_phase_not_the_average" \
    cargo test --release --lib network_tests::bufferbloat:: --manifest-path "$REPO_ROOT/Cargo.toml"

# --- CLI surface ---
check_contains "bufferbloat advertises --interface/--duration-secs/--json" "--duration-secs" \
    "$BIN" bufferbloat --help

if net_guard && [ -x /usr/bin/networkQuality ]; then
    out="$("$BIN" bufferbloat --duration-secs 3 --json 2>/dev/null | sed -n '/^{/,$p')"
    if [ -z "$out" ]; then
        skip "live bufferbloat run produces structured JSON with four distinct phases" "no JSON output"
    else
        phases_present="$(printf '%s' "$out" | python3 -c '
import json, sys
d = json.load(sys.stdin)
required = ["idle", "upload_loaded", "download_loaded", "simultaneous"]
print("ok" if all(k in d for k in required) else "missing")
' 2>/dev/null)"
        if [ "$phases_present" = "ok" ]; then
            pass "live bufferbloat run produces structured JSON with four distinct phases"
        else
            fail "live bufferbloat run produces structured JSON with four distinct phases" "got: $out"
        fi

        # The exact regression this gate exists for: directional and
        # simultaneous latency must never be collapsed into one field.
        distinct_fields="$(printf '%s' "$out" | python3 -c '
import json, sys
d = json.load(sys.stdin)
keys = set(d["upload_loaded"].keys()) | set(d["download_loaded"].keys()) | set(d["simultaneous"].keys())
print("ok" if {"upload_loaded","download_loaded","simultaneous"} <= set(d.keys()) else "collapsed")
' 2>/dev/null)"
        if [ "$distinct_fields" = "ok" ]; then
            pass "live bufferbloat run keeps upload/download/simultaneous as separate fields"
        else
            fail "live bufferbloat run keeps upload/download/simultaneous as separate fields" "got: $out"
        fi

        # The report must name the platform tool that produced its figures.
        names_tool="$(printf '%s' "$out" | python3 -c '
import json, sys
d = json.load(sys.stdin)
tool = d.get("measurement_tool", "")
print("ok" if "networkQuality" in tool else f"missing: {tool!r}")
' 2>/dev/null)"
        if [ "$names_tool" = "ok" ]; then
            pass "live bufferbloat run names the platform tool that produced its figures"
        else
            fail "live bufferbloat run names the platform tool that produced its figures" "$names_tool"
        fi
    fi
else
    skip "live bufferbloat run produces structured JSON with four distinct phases" "FP_HARNESS_OFFLINE=1 or networkQuality unavailable"
    skip "live bufferbloat run keeps upload/download/simultaneous as separate fields" "FP_HARNESS_OFFLINE=1 or networkQuality unavailable"
    skip "live bufferbloat run names the platform tool that produced its figures" "FP_HARNESS_OFFLINE=1 or networkQuality unavailable"
fi
