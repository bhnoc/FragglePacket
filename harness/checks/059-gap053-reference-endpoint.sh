#!/usr/bin/env bash
# GAP-053: a managed reference endpoint must be able to INVALIDATE a client's
# measurement. If the endpoint was CPU-saturated, dropping on its own NIC, or
# reported an interval inconsistent with the request, the client's number
# describes the endpoint rather than the network under test. Accepting it would
# attribute the server's own bottleneck to the WLAN.
#
# The second invariant: an unread counter is never a healthy zero. Absent
# telemetry makes acceptance undetermined, not accepted.

check_ok "cargo test covers acceptance, limits, and calibration logic" \
    cargo test --release --quiet --lib --manifest-path "$REPO_ROOT/Cargo.toml" reference_endpoint

M="$FIXTURE_DIR/manifests"

# --- the server can reject a client result -----------------------------------
check_contains "a clean endpoint accepts the client result" "ACCEPTED" \
    "$BIN" reference-endpoint --health "$M/endpoint-health-clean.json"

check_contains "a saturated endpoint rejects the client result" "REJECTED" \
    "$BIN" reference-endpoint --health "$M/endpoint-health-saturated.json"

check_contains "the rejection names CPU saturation" "CPU was" \
    "$BIN" reference-endpoint --health "$M/endpoint-health-saturated.json"

check_contains "the rejection explains loss is not the network's" \
    "not attributable to the network under test" \
    "$BIN" reference-endpoint --health "$M/endpoint-health-saturated.json"

# The field case: a receiver duration inconsistent with the request makes any
# derived rate arithmetic nonsense.
check_contains "an inconsistent interval invalidates the measurement window" \
    "measurement window is not trustworthy" \
    "$BIN" reference-endpoint --health "$M/endpoint-health-saturated.json"

check_lacks "a rejected run is never also reported accepted" "ACCEPTED" \
    "$BIN" reference-endpoint --health "$M/endpoint-health-saturated.json"

# --- absent telemetry is undetermined, not healthy ---------------------------
check_contains "absent endpoint telemetry is undetermined" "UNDETERMINED" \
    "$BIN" reference-endpoint

check_contains "undetermined output states an unread counter is not a zero" \
    "not a healthy zero" "$BIN" reference-endpoint

check_lacks "absent telemetry never yields an acceptance" "ACCEPTED" \
    "$BIN" reference-endpoint

# --- resource limits ---------------------------------------------------------
check_contains "limits are reportable" "max concurrent sessions" \
    "$BIN" reference-endpoint --show-limits

# A reference endpoint its own tests can exhaust is not a reference.
check_fails "a session beyond the concurrency cap is refused" \
    "$BIN" reference-endpoint --admit "4,10,100"
check_fails "a session beyond the duration cap is refused" \
    "$BIN" reference-endpoint --admit "0,600,100"
check_fails "a session beyond the rate cap is refused" \
    "$BIN" reference-endpoint --admit "0,10,5000"
check_ok "a within-limits session is admitted" \
    "$BIN" reference-endpoint --admit "0,10,100"

# --- calibration requires a verified clock ----------------------------------
# Two other commands refuse one-way delay without this; the endpoint must not
# quietly assert synchronization it never measured.
check_contains "calibration without a measured clock refuses one-way metrics" \
    "not measured" "$BIN" reference-endpoint --calibrate

check_json_field "calibration json carries clock_verified" "clock_verified" \
    "$BIN" reference-endpoint --calibrate --health "$M/endpoint-health-clean.json" --json
check_json_field "acceptance json is machine-readable" "acceptance" \
    "$BIN" reference-endpoint --health "$M/endpoint-health-clean.json" --json
