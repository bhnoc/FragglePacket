#!/usr/bin/env bash
# GAP-016: elevated traceroute/capture failures lack actionable status.
# Locks: a privileged failure preserves the underlying error text and names
# the exact required command, never an empty message; an unprivileged
# alternative still runs after a denial.

check_ok "cargo test covers privilege classification and the op inventory" \
    cargo test --release --lib probe::privilege_status:: --manifest-path "$REPO_ROOT/Cargo.toml"

check_contains "cargo test proves an empty pcap_activate()-style failure never reports an empty message" \
    "empty_stderr_with_eperm_errno_never_reports_an_empty_message" \
    cargo test --release --lib probe::privilege_status:: --manifest-path "$REPO_ROOT/Cargo.toml"

check_contains "cargo test proves worded stderr is preserved verbatim" \
    "worded_stderr_is_preserved_verbatim" \
    cargo test --release --lib probe::privilege_status:: --manifest-path "$REPO_ROOT/Cargo.toml"

check_contains "cargo test proves every declared privileged op names an unprivileged alternative" \
    "every_declared_op_names_a_command_and_an_unprivileged_path" \
    cargo test --release --lib probe::privilege_status:: --manifest-path "$REPO_ROOT/Cargo.toml"

check_contains "privilege-status advertises --classify-stderr" "--classify-stderr" \
    "$BIN" privilege-status --help

# --- the inventory command itself: every operation names a required command
#     and an unprivileged alternative in its human output ---
inv_out="$("$BIN" privilege-status 2>&1)"
check_contains "inventory names the BPF-capture requirement" "requires:" bash -c 'printf "%s" "$1"' _ "$inv_out"
check_contains "inventory offers an unprivileged alternative for every op" "without privilege:" \
    bash -c 'printf "%s" "$1"' _ "$inv_out"
check_lacks "inventory never reports a bare unelaborated denial" "without privilege: no alternative" \
    bash -c 'printf "%s" "$1"' _ "$inv_out"

# --- the exact field bug: an empty stderr body, classified via the errno
#     signal, must never surface as an empty/uninformative message ---
classify_out="$("$BIN" privilege-status --classify-stderr "" --as-eperm 2>&1)"
check_contains "an empty stderr classified via errno still yields a non-empty message" \
    "no message text" bash -c 'printf "%s" "$1"' _ "$classify_out"

worded_out="$("$BIN" privilege-status --classify-stderr "socket: Operation not permitted" 2>&1)"
check_contains "worded stderr is preserved verbatim in CLI output" \
    "Operation not permitted" bash -c 'printf "%s" "$1"' _ "$worded_out"

# --- a non-privilege failure is not misclassified ---
nonpriv_out="$("$BIN" privilege-status --classify-stderr "no such device: bogus0" 2>&1)"
check_contains "a non-privilege failure is reported as not a privilege problem" \
    "not a privilege problem" bash -c 'printf "%s" "$1"' _ "$nonpriv_out"

# --- JSON surface ---
check_json_field "json classification carries a status field" "status" \
    "$BIN" privilege-status --classify-stderr "Operation not permitted" --json
