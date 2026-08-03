#!/usr/bin/env bash
# GAP-041: a changed SSH host key is indistinguishable from a
# machine-in-the-middle without an independent side channel, so this is
# the one preflight failure mode that must have zero auto-accept paths.
# This gate asserts the bypass literally does not exist (no
# --skip-host-key-check-style flag anywhere), that a broken remote binary
# and a timeout are classified as non-network dependency/transport
# failures rather than network results, and that excluded nodes are never
# folded into a healthy-count as if they were zero-valued successes.

check_ok "cargo test covers SSH-error/dependency/clock-skew classification and rotation confirmation" \
    cargo test --release --lib network_tests::probe_preflight:: --manifest-path "$REPO_ROOT/Cargo.toml"

check_contains "probe-preflight advertises --mock-nodes" "--mock-nodes" \
    "$BIN" probe-preflight --help
check_contains "probe-preflight advertises --confirm-host-key-for" "--confirm-host-key-for" \
    "$BIN" probe-preflight --help

# --- the central security regression: no flag exists that bypasses host-key verification ---
help_text="$("$BIN" probe-preflight --help 2>&1)"
for bypass_flag in skip-host-key-check no-strict-host-key-checking insecure force-accept-host-key ignore-host-key trust-anyway accept-new; do
    check_lacks "probe-preflight --help never advertises a --$bypass_flag flag" "--$bypass_flag" \
        bash -c 'printf "%s" "$1"' _ "$help_text"
done
check_lacks "probe-preflight source never sets StrictHostKeyChecking=no" "StrictHostKeyChecking=no" \
    cat "$REPO_ROOT/src/cli/commands/probe_preflight.rs" "$REPO_ROOT/src/network_tests/probe_preflight.rs"
check_lacks "probe-preflight source never deletes/clears known_hosts" "known_hosts" \
    cat "$REPO_ROOT/src/cli/commands/probe_preflight.rs" "$REPO_ROOT/src/network_tests/probe_preflight.rs"

check_ok "cargo test proves there is no bypass path past HostKeyChanged" \
    cargo test --release --lib network_tests::probe_preflight::tests::there_is_no_flag_or_parameter_that_bypasses_host_key_changed \
    --manifest-path "$REPO_ROOT/Cargo.toml"
check_ok "cargo test proves a mismatched operator-confirmed fingerprint still refuses" \
    cargo test --release --lib network_tests::probe_preflight::tests::mismatched_operator_confirmed_fingerprint_still_refuses \
    --manifest-path "$REPO_ROOT/Cargo.toml"

# --- the field-evidence fixture: broken binary, timeout, changed host key, all quarantined with reasons ---
mock_out="$("$BIN" probe-preflight --mock-nodes 2>&1)"
check_contains "a broken remote binary is reported as a dependency failure, not a network result" \
    "dependency broken" bash -c 'printf "%s" "$1"' _ "$mock_out"
check_contains "a repeated timeout is reported distinctly" "connection timed out" \
    bash -c 'printf "%s" "$1"' _ "$mock_out"
check_contains "a changed host key is quarantined and named" "host key changed" \
    bash -c 'printf "%s" "$1"' _ "$mock_out"
check_contains "human output states no flag auto-accepts a changed host key" \
    "no flag on this command auto-accepts a changed host key" \
    bash -c 'printf "%s" "$1"' _ "$mock_out"

# --- excluded nodes never fold into the healthy count as zero-valued successes ---
mock_json="$("$BIN" probe-preflight --mock-nodes --json 2>&1 | sed -n '/^{/,$p')"
healthy_count="$(printf '%s' "$mock_json" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print(len(d["summary"]["healthy_labels"]))
' 2>/dev/null)"
excluded_count="$(printf '%s' "$mock_json" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print(len(d["summary"]["excluded_with_reason"]))
' 2>/dev/null)"
if [ "${healthy_count:-0}" = "1" ] && [ "${excluded_count:-0}" = "3" ]; then
    pass "the mock fixture's 1 healthy / 3 excluded split is reported exactly, nothing coerced"
else
    fail "the mock fixture's 1 healthy / 3 excluded split is reported exactly" \
        "healthy=$healthy_count excluded=$excluded_count"
fi

# --- a wrong operator-confirmed fingerprint is refused; a matching one clears the quarantine ---
check_fails "a wrong operator-confirmed fingerprint refuses to clear the quarantine" \
    "$BIN" probe-preflight --mock-nodes --confirm-host-key-for node-hostkey001 --confirmed-fingerprint "SHA256:wrong"
correct_out="$("$BIN" probe-preflight --mock-nodes --confirm-host-key-for node-hostkey001 --confirmed-fingerprint "SHA256:mocked-changed-fingerprint" 2>&1)"
check_contains "a correct, independently-supplied fingerprint clears the quarantine" \
    "node-hostkey001: healthy" bash -c 'printf "%s" "$1"' _ "$correct_out"
