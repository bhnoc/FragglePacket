#!/usr/bin/env bash
# GAP-070: a knee found by one method is not a finding.
#
# PC13 plateaued near 134-142 Mbps combined above 60 Mbps per direction while
# loaded gateway latency rose from 8 ms to 17-28 ms, and rate-controlled
# application traffic independently reproduced the knee (upload 44-47 against
# download ~72 at 70+70, latency 45-68 ms). Two things must not blur: a capacity
# plateau (both directions share a ceiling) is a different finding from
# directional unfairness (one direction collapses), and an unreproduced knee is
# unconfirmed rather than established -- GAP-069 showed a paired-process harness
# manufacturing a directional collapse that looked like a network fault.

check_ok "cargo test covers knee detection, cross-validation, and drift" \
    cargo test --release --quiet --lib --manifest-path "$REPO_ROOT/Cargo.toml" capacity_knee

# --- the two verdicts must stay distinct -----------------------------------
check_ok "cargo test proves plateau and unfairness are different verdicts" \
    cargo test --release --quiet --lib --manifest-path "$REPO_ROOT/Cargo.toml" \
    capacity_knee::tests::plateau_and_unfairness_are_different_verdicts

out="$("$BIN" capacity-knee --interface en0 --inject-fixture 2>&1)"

check_contains "the PC13 native sweep reports a capacity plateau" "capacity plateau" \
    printf '%s' "$out"
check_contains "the PC13 application sweep reports directional unfairness" \
    "directional unfairness" printf '%s' "$out"
check_contains "the plateau explains both directions share a ceiling" \
    "not one direction losing" printf '%s' "$out"
check_contains "the unfairness verdict names the collapsing direction" "upload fell to" \
    printf '%s' "$out"

# --- no knee must never be reported as the highest tested rate --------------
check_ok "cargo test proves a linear sweep reports no knee, not its top rate" \
    cargo test --release --quiet --lib --manifest-path "$REPO_ROOT/Cargo.toml" \
    capacity_knee::tests::a_sweep_that_never_plateaus_reports_no_knee_not_the_highest_rate

# --- a knee must survive reordering ----------------------------------------
# A knee visible only in a monotonic ascending pass could be drift or ordering
# artifact, which is why the sweep randomizes and repeats.
check_ok "cargo test proves execution order does not change the verdict" \
    cargo test --release --quiet --lib --manifest-path "$REPO_ROOT/Cargo.toml" \
    capacity_knee::tests::execution_order_does_not_change_the_verdict

# --- cross-validation gates the claim --------------------------------------
check_contains "both methods agreeing reports the knee reproduced" "REPRODUCED" \
    printf '%s' "$out"
check_contains "a reproduced, drift-free knee is established" "ESTABLISHED:" \
    printf '%s' "$out"

check_ok "cargo test proves an unreproduced knee is unconfirmed" \
    cargo test --release --quiet --lib --manifest-path "$REPO_ROOT/Cargo.toml" \
    capacity_knee::tests::a_knee_the_application_method_did_not_reproduce_is_unconfirmed
check_ok "cargo test proves no application sweep means not-attempted" \
    cargo test --release --quiet --lib --manifest-path "$REPO_ROOT/Cargo.toml" \
    capacity_knee::tests::no_application_sweep_means_not_attempted_not_reproduced

# A native-only run must not claim an established finding.
native_only="$("$BIN" capacity-knee --interface en0 \
    --native-points "$FIXTURE_DIR/knee/native-plateau.json" 2>&1 || true)"
if [ -n "$native_only" ]; then
    check_contains "a native-only sweep is unconfirmed" "UNCONFIRMED:" printf '%s' "$native_only"
    check_lacks "a native-only sweep claims nothing established" "ESTABLISHED:" \
        printf '%s' "$native_only"
else
    skip "a native-only sweep is unconfirmed" "fixture missing"
fi

# --- invalid points are rejected, never scored as zero ---------------------
check_ok "cargo test proves a duration-inconsistent point is rejected not scored" \
    cargo test --release --quiet --lib --manifest-path "$REPO_ROOT/Cargo.toml" \
    capacity_knee::tests::a_duration_inconsistent_point_is_rejected_not_scored
check_ok "cargo test proves a missing duration is schema-incomplete" \
    cargo test --release --quiet --lib --manifest-path "$REPO_ROOT/Cargo.toml" \
    capacity_knee::tests::a_missing_duration_is_schema_incomplete_not_valid
check_ok "cargo test proves a process failure is rejected before any rate is read" \
    cargo test --release --quiet --lib --manifest-path "$REPO_ROOT/Cargo.toml" \
    capacity_knee::tests::a_process_failure_is_rejected_before_any_rate_is_read

# --- drift is separate from the measurement --------------------------------
check_contains "endpoint drift is reported as its own line" "endpoint drift" \
    printf '%s' "$out"
check_ok "cargo test proves drift from one control is unavailable, never zero" \
    cargo test --release --quiet --lib --manifest-path "$REPO_ROOT/Cargo.toml" \
    capacity_knee::tests::drift_is_unavailable_from_one_control_never_zero
check_ok "cargo test proves a drifting endpoint blocks the established claim" \
    cargo test --release --quiet --lib --manifest-path "$REPO_ROOT/Cargo.toml" \
    capacity_knee::tests::a_drifting_endpoint_blocks_the_established_claim

# --- one qualified listener per phase --------------------------------------
check_ok "cargo test proves each phase records its own listener" \
    cargo test --release --quiet --lib --manifest-path "$REPO_ROOT/Cargo.toml" \
    capacity_knee::tests::each_point_records_its_own_listener

# --- surface --------------------------------------------------------------
check_contains "capacity-knee requires an explicit interface" "interface" \
    "$BIN" capacity-knee --help
check_fails "capacity-knee refuses to guess an interface" "$BIN" capacity-knee
check_fails "capacity-knee refuses to run with no points at all" \
    "$BIN" capacity-knee --interface en0
check_json_field "json output carries the native verdict" "native_verdict" \
    "$BIN" capacity-knee --interface en0 --inject-fixture --json
check_json_field "json output carries the cross-validation result" "cross_validation" \
    "$BIN" capacity-knee --interface en0 --inject-fixture --json
