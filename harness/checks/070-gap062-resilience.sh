#!/usr/bin/env bash
# GAP-062: controlled resilience/failover validation. Locks: no flag exists
# that initiates a component failover (assert the absence); the continuous
# session bundle requires --authorized; an outage that was never observed
# reports its duration as absent, never 0ms.

check_ok "cargo test covers resilience judging logic" \
    cargo test --release --lib network_tests::resilience:: --manifest-path "$REPO_ROOT/Cargo.toml"

check_contains "cargo test proves an unobserved outage reports duration as none, never zero" \
    "an_outage_that_was_never_observed_reports_duration_as_none_never_zero" \
    cargo test --release --lib network_tests::resilience:: --manifest-path "$REPO_ROOT/Cargo.toml"

check_contains "cargo test proves a never-sampled session is excluded, not counted as lost" \
    "a_session_never_sampled_is_excluded_not_counted_as_lost" \
    cargo test --release --lib network_tests::resilience:: --manifest-path "$REPO_ROOT/Cargo.toml"

check_contains "cargo test structurally proves this module never takes an action on a component" \
    "this_module_carries_no_function_that_takes_an_action_on_a_component" \
    cargo test --release --lib network_tests::resilience:: --manifest-path "$REPO_ROOT/Cargo.toml"

# --- the routing/failover-safety invariant: no flag may exist that performs
#     or requests a component action. Assert on the help surface. ---
help_text="$("$BIN" resilience --help 2>&1)"
for forbidden in --fail-over --failover --disable-component --kill --power-off --reboot --shutdown --bring-down --activate --deactivate; do
    check_lacks "resilience --help never advertises a --${forbidden#--} flag" "$forbidden" \
        bash -c 'printf "%s" "$1"' _ "$help_text"
done
check_contains "resilience advertises --run" "--run" bash -c 'printf "%s" "$1"' _ "$help_text"
check_contains "resilience advertises --authorized" "--authorized" bash -c 'printf "%s" "$1"' _ "$help_text"

# --- source-level check: no dangerous action verb near a component identifier ---
check_lacks "resilience source never calls a command/process spawn for a component action" \
    "Command::new" cat "$REPO_ROOT/src/network_tests/resilience.rs"

RUN="$FIXTURE_DIR/resilience/wan-failover.json"

# --- requires --authorized ---
check_fails "resilience refuses without --authorized" "$BIN" resilience --run "$RUN"

with_auth_out="$("$BIN" resilience --run "$RUN" --authorized "approved by NOC 03:00-03:30" 2>&1)"
check_contains "an authorized run judges the bundle" "outage duration:" bash -c 'printf "%s" "$1"' _ "$with_auth_out"
check_contains "human output restates that no failover is initiated" "never initiates a failover" \
    bash -c 'printf "%s" "$1"' _ "$with_auth_out"

# --- an outage that was never observed reports as not-measured, never 0ms ---
never_out="$("$BIN" resilience --run "$FIXTURE_DIR/resilience/never-observed.json" --authorized "approved" --json 2>&1 | sed -n '/^{/,$p')"
outage_val="$(printf '%s' "$never_out" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print(d["verdict"]["outage_duration_secs"])
' 2>/dev/null)"
if [ "$outage_val" = "None" ] || [ "$outage_val" = "null" ]; then
    pass "an outage that was never observed is reported as not-measured, never 0ms"
else
    fail "an outage that was never observed is reported as not-measured, never 0ms" "got '$outage_val'"
fi

check_json_field "json output carries sessions_lost distinctly from sessions_never_sampled" \
    "verdict.sessions_never_sampled" \
    "$BIN" resilience --run "$FIXTURE_DIR/resilience/never-observed.json" --authorized "approved" --json

check_fails "a missing run file errors rather than assuming defaults" \
    "$BIN" resilience --run "$WORK_DIR/definitely-not-here.json" --authorized "approved"
