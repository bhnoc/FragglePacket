#!/usr/bin/env bash
# GAP-057: discovery/multicast/peer-isolation policy diagnostic. Field
# context: conference WLANs *intentionally* suppress ARP/ND/mDNS/SSDP for
# client isolation -- correct configuration, not a fault -- so a bare
# pass/fail here would report correct isolation as an outage. This gate
# locks:
#   1. No discovered peer hostname/device name/service instance name
#      appears anywhere in output (the central privacy regression).
#   2. Without a declared expected policy, observations are reported
#      without a pass/fail verdict.
#   3. With a declared policy, divergence is flagged in BOTH directions
#      (expected-blocked-but-reachable AND expected-reachable-but-blocked).
#   4. Peer isolation testing requires an explicitly named peer.
#   5. Probe counts are capped.
#   6. A tunnel interface warns.
#   7. No-response stays distinct from confirmed-blocked.

cargo_test() { cargo test --release --lib network_tests::multicast_isolation:: --manifest-path "$REPO_ROOT/Cargo.toml" "$@"; }

check_ok "cargo test covers expected-policy judgment / responder-tally / classification logic" cargo_test
check_contains "cargo test proves no declared expectation yields NoExpectationDeclared for every observation" \
    "with_no_declared_expectation_every_observation_yields_no_expectation_declared" cargo_test
check_contains "cargo test proves expected-blocked-but-reachable is flagged UnexpectedlyReachable" \
    "expected_blocked_but_observed_reachable_is_flagged_unexpectedly_reachable" cargo_test
check_contains "cargo test proves expected-reachable-but-blocked is flagged UnexpectedlyBlocked" \
    "expected_reachable_but_observed_blocked_is_flagged_unexpectedly_blocked" cargo_test
check_contains "cargo test proves matching either direction reports MatchesExpectation" \
    "matching_expectation_in_either_direction_reports_matches_expectation" cargo_test
check_contains "cargo test proves NoResponse never yields a pass/fail verdict even with a declared expectation" \
    "a_no_response_observation_never_yields_a_pass_fail_verdict_even_with_a_declared_expectation" cargo_test
check_contains "cargo test proves responders are tallied/classified without retaining raw bytes" \
    "tally_responses_counts_and_classifies_without_retaining_raw_bytes" cargo_test
check_contains "cargo test proves classification never matches on a personal-name substring" \
    "classify_response_never_matches_on_a_device_name_substring" cargo_test
check_contains "cargo test proves the probe count is capped regardless of caller argument" \
    "probe_count_is_capped_regardless_of_caller_argument" cargo_test

check_contains "multicast-isolation advertises --peer/--expect-mdns/--expect-ssdp/--inject-fixture" \
    "--expect-mdns" \
    "$BIN" multicast-isolation --help
check_contains "multicast-isolation documents peer isolation requires an explicitly named peer" \
    "Explicitly named peer" \
    "$BIN" multicast-isolation --help

json_get() { python3 -c '
import json, sys
d = json.load(sys.stdin)
path = sys.argv[1]
cur = d
for part in path.split("."):
    if isinstance(cur, dict):
        cur = cur.get(part)
    elif isinstance(cur, list):
        try:
            cur = cur[int(part)]
        except (ValueError, IndexError):
            cur = None
    else:
        cur = None
print(json.dumps(cur))
' "$1" 2>/dev/null; }

# --- name-shaped patterns: mDNS/SSDP records commonly carry a possessive
#     device name ("James's MacBook") or a "Name._service._tcp.local"
#     instance pattern. Assert against those shapes, not a specific string. ---
name_pattern="('s [A-Za-z]+)|([A-Za-z0-9_-]+\._[a-z]+\._tcp\.local)|(Living Room|Bedroom|Office) "

# --- no declared policy: every check reports without a pass/fail verdict ---
no_policy_out="$("$BIN" multicast-isolation --inject-fixture no-response --json 2>/dev/null | sed -n '/^{/,$p')"
if [ -z "$no_policy_out" ]; then
    fail "no-policy run produces a JSON report" "no output"
else
    pass "no-policy run produces a JSON report"
    mdns_verdict="$(printf '%s' "$no_policy_out" | json_get mdns.result.verdict)"
    ssdp_verdict="$(printf '%s' "$no_policy_out" | json_get ssdp.result.verdict)"
    if [ "$mdns_verdict" = '"no_expectation_declared"' ] && [ "$ssdp_verdict" = '"no_expectation_declared"' ]; then
        pass "with no declared policy, both mDNS and SSDP report no_expectation_declared, never a pass/fail"
    else
        fail "with no declared policy, checks report no_expectation_declared" "mdns=$mdns_verdict ssdp=$ssdp_verdict"
    fi
fi

# --- declared policy, divergence in BOTH directions in one run ---
mixed_out="$("$BIN" multicast-isolation --inject-fixture mixed \
    --expect-mdns blocked --expect-ssdp reachable --expect-multicast-delivery reachable \
    --peer 127.0.0.1:9 --expect-peer-isolation reachable --json 2>/dev/null | sed -n '/^{/,$p')"
if [ -z "$mixed_out" ]; then
    fail "mixed-policy run produces a JSON report" "no output"
else
    mdns_v="$(printf '%s' "$mixed_out" | json_get mdns.result.verdict)"
    ssdp_v="$(printf '%s' "$mixed_out" | json_get ssdp.result.verdict)"
    if [ "$mdns_v" = '"UNEXPECTEDLY_REACHABLE"' ]; then
        pass "expected-blocked-but-observed-reachable (mDNS) is flagged UNEXPECTEDLY_REACHABLE"
    else
        fail "expected-blocked-but-observed-reachable (mDNS) is flagged UNEXPECTEDLY_REACHABLE" "got: $mdns_v"
    fi
    if [ "$ssdp_v" = '"UNEXPECTEDLY_BLOCKED"' ]; then
        pass "expected-reachable-but-observed-blocked (SSDP) is flagged UNEXPECTEDLY_BLOCKED"
    else
        fail "expected-reachable-but-observed-blocked (SSDP) is flagged UNEXPECTEDLY_BLOCKED" "got: $ssdp_v"
    fi
fi

# --- no-response stays distinct from confirmed-blocked ---
noresp_out="$("$BIN" multicast-isolation --inject-fixture no-response --expect-mdns blocked --json 2>/dev/null | sed -n '/^{/,$p')"
noresp_obs="$(printf '%s' "$noresp_out" | json_get mdns.result.observation)"
noresp_verdict="$(printf '%s' "$noresp_out" | json_get mdns.result.verdict)"
if [ "$noresp_obs" = '"no_response"' ] && [ "$noresp_verdict" = '"observation_inconclusive"' ]; then
    pass "a query with no response reports no_response/observation_inconclusive, never confirmed_blocked"
else
    fail "a no-response observation stays distinct from confirmed_blocked" "obs=$noresp_obs verdict=$noresp_verdict"
fi
allblocked_out="$("$BIN" multicast-isolation --inject-fixture all-blocked --expect-mdns blocked --json 2>/dev/null | sed -n '/^{/,$p')"
allblocked_obs="$(printf '%s' "$allblocked_out" | json_get mdns.result.observation)"
if [ "$allblocked_obs" = '"confirmed_blocked"' ]; then
    pass "a corroborated block reports confirmed_blocked, distinct from no_response"
else
    fail "a corroborated block reports confirmed_blocked" "got: $allblocked_obs"
fi

# --- peer isolation requires an explicitly named peer ---
no_peer_out="$("$BIN" multicast-isolation --inject-fixture no-response --expect-peer-isolation reachable --json 2>/dev/null | sed -n '/^{/,$p')"
no_peer_field="$(printf '%s' "$no_peer_out" | json_get peer_isolation)"
if [ "$no_peer_field" = "null" ]; then
    pass "peer isolation is not run (null) when no --peer is named, even with an expectation declared"
else
    fail "peer isolation is not run when no --peer is named" "got: $no_peer_field"
fi
check_contains "human output states peer isolation was not run without a named peer" \
    "not run -- pass --peer" \
    "$BIN" multicast-isolation --inject-fixture no-response

with_peer_out="$("$BIN" multicast-isolation --inject-fixture no-response --peer 127.0.0.1:9 --json 2>/dev/null | sed -n '/^{/,$p')"
with_peer_field="$(printf '%s' "$with_peer_out" | json_get peer_isolation)"
if [ "$with_peer_field" != "null" ]; then
    pass "peer isolation runs once an explicit --peer is named"
else
    fail "peer isolation runs once an explicit --peer is named" "got: $with_peer_field"
fi

# --- probe counts are capped regardless of caller argument ---
cap_out="$("$BIN" multicast-isolation --inject-fixture no-response --probe-count 500 --json 2>/dev/null | sed -n '/^{/,$p')"
cap_field="$(printf '%s' "$cap_out" | json_get probe_cap_per_kind)"
if [ "$cap_field" -le 5 ] 2>/dev/null; then
    pass "the probe cap is reported and is not raised by a large --probe-count ($cap_field)"
else
    fail "the probe cap is not raised by a large --probe-count" "got: $cap_field"
fi

# --- tunnel interface warns ---
check_contains "a tunnel interface produces a loud warning naming why the result is meaningless" \
    "carries no local-segment" \
    "$BIN" multicast-isolation --interface utun6 --inject-fixture no-response
check_lacks "a non-tunnel interface produces no tunnel warning" \
    "carries no local-segment" \
    "$BIN" multicast-isolation --interface en0 --inject-fixture no-response

# --- the central privacy regression: no discovered name-shaped string
#     anywhere in output, across every fixture scenario exercised above ---
all_json="$no_policy_out$mixed_out$noresp_out$allblocked_out$no_peer_out$with_peer_out$cap_out"
all_human="$("$BIN" multicast-isolation --inject-fixture mixed --expect-mdns blocked --expect-ssdp reachable --peer 127.0.0.1:9 --expect-peer-isolation reachable 2>&1)"
if printf '%s' "$all_json$all_human" | grep -Eq "$name_pattern"; then
    fail "no discovered peer/device/service-instance name appears anywhere in output" "found a name-shaped token"
else
    pass "no discovered peer/device/service-instance name appears anywhere in output"
fi
check_lacks "responder tally is limited to a coarse service class, never a raw record string" \
    "_ipp._tcp.local" \
    "$BIN" multicast-isolation --inject-fixture mixed --json

# --- exactly one real, offline-safe run: mDNS/SSDP probes to real
#     multicast groups from loopback-bound sockets, tiny probe count,
#     no live network dependency (multicast send/recv on localhost does
#     not require net_guard -- it never leaves this host) ---
real_out="$("$BIN" multicast-isolation --probe-count 2 --listen-ms 300 --peer 127.0.0.1:9 --json 2>/dev/null | sed -n '/^{/,$p')"
if [ -z "$real_out" ]; then
    fail "a real (non-fixture) run produces a JSON report" "no output"
else
    pass "a real (non-fixture) run produces a JSON report"
    if printf '%s' "$real_out" | grep -Eq "$name_pattern"; then
        fail "the real run's output carries no name-shaped token" "found a name-shaped token"
    else
        pass "the real run's output carries no name-shaped token"
    fi
fi
