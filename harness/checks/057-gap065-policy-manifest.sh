#!/usr/bin/env bash
# GAP-065: the manifest IS the allowlist. CENTRAL REGRESSION this gate
# locks: no destination outside the supplied manifest is ever contacted.
# Also locks: timeout/reject/redirect stay three distinct states; an
# expected-deny that's reachable AND an expected-allow that's blocked are
# both flagged as drift; the attendee-facing mode carries no hostname/port.
# Manifest entries point only at loopback, per the assignment's own
# instruction to keep test manifests local.

pm_json() { "$BIN" policy-manifest "$@" --json 2>/dev/null | sed -n '/^\[/,$p'; }

check_contains "policy-manifest advertises --manifest-file" "--manifest-file" \
    "$BIN" policy-manifest --help
check_contains "policy-manifest advertises --attendee-facing" "--attendee-facing" \
    "$BIN" policy-manifest --help

fixture="$WORK_DIR/gap065-manifest.json"
cat > "$fixture" <<'EOF'
[
  {"role":"guest","source_zone":"wlan-guest","destination_host":"127.0.0.1","destination_port":9,"protocol":"Tcp","expected":"Allow","http_check_path":null},
  {"role":"guest","source_zone":"wlan-guest","destination_host":"127.0.0.1","destination_port":9,"protocol":"Tcp","expected":"Deny","http_check_path":null}
]
EOF

out="$(pm_json --manifest-file "$fixture" --timeout-secs 1)"
if [ -z "$out" ]; then
    fail "policy-manifest produces JSON output" "empty output"
else
    # port 9 (discard) has nothing listening on this test host -> TimedOut/Rejected, never Reachable.
    observed0="$(printf '%s' "$out" | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["observed"])' 2>/dev/null)"
    drift0="$(printf '%s' "$out" | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["drift"])' 2>/dev/null)"
    if [ "$observed0" != "Reachable" ]; then
        pass "expected-Allow entry against an unreachable port observes non-Reachable ($observed0)"
        if [ "$drift0" = "UnexpectedlyBlocked" ]; then
            pass "expected-allow that is blocked is flagged as UnexpectedlyBlocked drift"
        else
            fail "expected-allow that is blocked is flagged as UnexpectedlyBlocked drift" "got: $drift0"
        fi
    else
        skip "expected-Allow/blocked drift case" "port 9 answered on this host"
    fi

    entry_count="$(printf '%s' "$out" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))' 2>/dev/null)"
    if [ "$entry_count" = "2" ]; then
        pass "exactly the 2 manifest entries were reported, nothing more"
    else
        fail "exactly the 2 manifest entries were reported, nothing more" "got: $entry_count"
    fi
fi

# --- CENTRAL REGRESSION: no destination outside the manifest is ever contacted ---
check_ok "cargo test CENTRAL REGRESSION: probing only indexes from the manifest, never a synthesized host" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib network_tests::policy_manifest::tests::probing_only_indexes_from_the_manifest_never_an_arbitrary_host 2>&1 | grep -q '1 passed'"

# --- timeout/reject/redirect distinctness ---
check_ok "cargo test: timeout, reject, and redirect are three pairwise-distinct observed states" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib network_tests::policy_manifest::tests::timeout_reject_redirect_are_three_distinct_variants 2>&1 | grep -q '1 passed'"
check_ok "cargo test: a refused connection classifies as Rejected, not TimedOut" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib network_tests::policy_manifest::tests::refused_connection_classifies_as_rejected_not_timed_out 2>&1 | grep -q '1 passed'"
check_ok "cargo test: a redirect on an expected-allow entry is InterceptedByPortal, not a clean match" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib network_tests::policy_manifest::tests::redirect_on_expected_allow_is_intercepted_not_a_clean_match 2>&1 | grep -q '1 passed'"

# --- drift in both directions ---
check_ok "cargo test: expected-deny reachable is UnexpectedlyAllowed" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib network_tests::policy_manifest::tests::expected_deny_reachable_is_unexpectedly_allowed 2>&1 | grep -q '1 passed'"
check_ok "cargo test: expected-allow rejected is UnexpectedlyBlocked" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib network_tests::policy_manifest::tests::expected_allow_rejected_is_unexpectedly_blocked 2>&1 | grep -q '1 passed'"

# --- attendee-facing redaction ---
check_ok "cargo test: attendee-facing report carries no hostname or port" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib network_tests::policy_manifest::tests::attendee_facing_report_carries_no_hostname_or_port 2>&1 | grep -q '1 passed'"
check_ok "cargo test: operator report carries hostname and port" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib network_tests::policy_manifest::tests::operator_report_carries_hostname_and_port 2>&1 | grep -q '1 passed'"

attendee_out="$(pm_json --manifest-file "$fixture" --timeout-secs 1 --attendee-facing)"
if [ -n "$attendee_out" ]; then
    if printf '%s' "$attendee_out" | grep -q "127.0.0.1"; then
        fail "attendee-facing CLI output contains no manifest hostname" "found 127.0.0.1 in attendee-facing JSON"
    else
        pass "attendee-facing CLI output contains no manifest hostname"
    fi
else
    skip "attendee-facing CLI output contains no manifest hostname" "empty output"
fi
check_contains "human attendee-facing output shows (redacted) instead of a destination" "(redacted)" \
    "$BIN" policy-manifest --manifest-file "$fixture" --timeout-secs 1 --attendee-facing

rm -f "$fixture"
