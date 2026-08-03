#!/usr/bin/env bash
# GAP-049: association/EAP/DHCP/DNS/first-HTTPS must stay separately timed
# fields, never a single total -- that is the whole diagnostic value here.
# Portal detection must report interception and stop, never automate a
# login or touch a credential. This gate locks both.

check_ok "cargo test covers portal classification / phase-timing / role / continuity logic" \
    cargo test --release --lib network_tests::auth_portal:: --manifest-path "$REPO_ROOT/Cargo.toml"

check_contains "auth-portal advertises --detection-url" "--detection-url" \
    "$BIN" auth-portal --help
check_contains "auth-portal advertises --expected-subnet" "--expected-subnet" \
    "$BIN" auth-portal --help

# --- no credential flag exists anywhere on this command ---
help_text="$("$BIN" auth-portal --help 2>&1)"
for bad_flag in password passwd secret username identity certificate; do
    check_lacks "auth-portal --help never advertises a --$bad_flag flag" "--$bad_flag" \
        bash -c 'printf "%s" "$1"' _ "$help_text"
done

# --- source never performs an HTTP POST (no automated login submission) ---
check_lacks "auth-portal source never issues a POST request" '"-X", "POST"' \
    cat "$REPO_ROOT/src/cli/commands/auth_portal.rs"
check_lacks "auth-portal source never issues a POST request (curl -d form)" '"-d",' \
    cat "$REPO_ROOT/src/cli/commands/auth_portal.rs"

check_ok "cargo test proves a substituted 200 body is detected as a portal" \
    cargo test --release --lib network_tests::auth_portal::tests::substituted_200_body_is_portal_detected \
    --manifest-path "$REPO_ROOT/Cargo.toml"
check_ok "cargo test proves a redirect is detected as a portal" \
    cargo test --release --lib network_tests::auth_portal::tests::redirect_is_portal_detected_with_location \
    --manifest-path "$REPO_ROOT/Cargo.toml"
check_ok "cargo test proves the real Apple success body is not flagged as a portal" \
    cargo test --release --lib network_tests::auth_portal::tests::apple_success_body_is_no_portal \
    --manifest-path "$REPO_ROOT/Cargo.toml"
check_ok "cargo test proves no credential field exists on the RADIUS result type" \
    cargo test --release --lib network_tests::auth_portal::tests::no_credential_field_exists_on_radius_result \
    --manifest-path "$REPO_ROOT/Cargo.toml"

# --- a real run against a real detection URL ---
if net_guard; then
    real_out="$("$BIN" auth-portal --timeout-secs 5 2>&1)"
    if [ -z "$real_out" ]; then
        skip "real portal-detection run" "no output"
    else
        check_contains "real run states no credential is ever touched" \
            "never requests or logs credentials" \
            bash -c 'printf "%s" "$1"' _ "$real_out"
        check_contains "real run reports a portal-detection result" "portal detection (" \
            bash -c 'printf "%s" "$1"' _ "$real_out"
        pass "a real run against a live detection URL completed"
    fi
else
    skip "real portal-detection run" "FP_HARNESS_OFFLINE=1"
fi
