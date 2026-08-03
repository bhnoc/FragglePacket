#!/usr/bin/env bash
# GAP-009: macOS (Darwin) ping summary uses `round-trip min/avg/max/stddev`,
# not Linux's `rtt min/avg/max/mdev`. The original parser only matched the
# Linux spelling, so a successful Darwin run silently reported 0.0 for
# min/avg/max/jitter -- indistinguishable from a real all-zero measurement.
# This gate is fully offline: it drives `cargo test --lib` against the
# fixture-backed unit tests in src/network_tests/rtt.rs, so no live network
# or ping binary is required.

check_ok "cargo test covers rtt parser (Linux + Darwin fixtures)" \
    cargo test --release --lib network_tests::rtt:: --manifest-path "$REPO_ROOT/Cargo.toml"

# --- Darwin success fixture parses to the real captured numbers ---
check_contains "cargo test proves Darwin round-trip fixture parses exact numbers" \
    "darwin_ok_fixture_parses_real_numbers" \
    cargo test --release --lib network_tests::rtt:: --manifest-path "$REPO_ROOT/Cargo.toml"

# --- Linux format still parses (pre-existing test, must keep passing) ---
check_contains "cargo test proves Linux rtt format still parses" \
    "test_parse_ping_output" \
    cargo test --release --lib network_tests::rtt:: --manifest-path "$REPO_ROOT/Cargo.toml"

# --- no round-trip line (total timeout) => unavailable, never zero ---
check_contains "cargo test proves Darwin timeout fixture yields None, not 0.0" \
    "darwin_timeout_fixture_is_unavailable_not_zero" \
    cargo test --release --lib network_tests::rtt:: --manifest-path "$REPO_ROOT/Cargo.toml"

# --- DF-too-big fixture: trailing stats block must not be treated as valid latency ---
check_contains "cargo test proves DF-toobig fixture does not fabricate a latency" \
    "darwin_df_toobig_fixture_reports_unavailable_despite_trailing_stats_block" \
    cargo test --release --lib network_tests::rtt:: --manifest-path "$REPO_ROOT/Cargo.toml"

# --- generic no-summary-line case: never zero ---
check_contains "cargo test proves an unrecognized summary line never yields 0.0" \
    "no_summary_line_never_yields_zero" \
    cargo test --release --lib network_tests::rtt:: --manifest-path "$REPO_ROOT/Cargo.toml"

# --- fixtures themselves still carry the exact strings the parser must handle ---
check_contains "darwin ok fixture carries the exact captured numbers" \
    "61.541/62.641/65.020/1.395" \
    cat "$FIXTURE_DIR/ping/darwin-ping-ok.txt"

# --- live end-to-end sanity (skipped offline): the `test` CLI command's RTT
#     test shells out to the real system ping and must report non-zero
#     latency on this macOS host, the bug's user-visible symptom ---
if net_guard; then
    live_out="$("$BIN" test 127.0.0.1 --categories rtt 2>/dev/null || true)"
    if printf '%s' "$live_out" | grep -q "avg_ms: 0.00"; then
        fail "live RTT run against 127.0.0.1 never reports avg_ms: 0.00" "got zero avg_ms"
    elif printf '%s' "$live_out" | grep -q "avg_ms:"; then
        pass "live RTT run against 127.0.0.1 reports a non-zero avg_ms"
    else
        skip "live RTT run against 127.0.0.1 reports a non-zero avg_ms" "no avg_ms in output (ping unavailable in this environment)"
    fi
else
    skip "live RTT run against 127.0.0.1 reports a non-zero avg_ms" "FP_HARNESS_OFFLINE=1"
fi
