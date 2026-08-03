#!/usr/bin/env bash
# GAP-005: repeated STUN binding requests with validation and RTT,
# mapped-address change detection without exposing it by default, plus TURN
# UDP/TCP/TLS allocation and relay checks. Field evidence: a hand-built STUN
# binding test against stun.l.google.com:19302 proved UDP/NAT traversal
# healthy mid-incident, by hand, because FragglePacket could not do it.
# This gate locks:
#   1. The mapped address (public egress IP) is absent from default output
#      and present only with --reveal-mapped-address.
#   2. A STUN response failing validation is not counted as a successful
#      binding.
#   3. Unreachable (timeout) and unchanged (stable mapping) are distinct
#      states -- silence is never read as stability.
#   4. TURN without credentials skips cleanly (no_credentials_supplied),
#      never an opaque error.

cargo_test() { cargo test --release --lib network_tests::stun:: --manifest-path "$REPO_ROOT/Cargo.toml" "$@"; }

check_ok "cargo test covers STUN wire-format build/parse and TURN long-term-credential logic" cargo_test
check_contains "cargo test proves a well-formed success response yields the mapped address" \
    "a_well_formed_success_response_yields_the_mapped_address" cargo_test
check_contains "cargo test proves a transaction-ID mismatch is rejected" \
    "a_response_with_the_wrong_transaction_id_is_rejected" cargo_test
check_contains "cargo test proves a bad magic cookie is rejected" \
    "a_response_with_the_wrong_magic_cookie_is_rejected" cargo_test
check_contains "cargo test proves a STUN error response is not counted as success" \
    "a_binding_error_response_is_not_counted_as_success" cargo_test
check_contains "cargo test proves a success response missing MAPPED-ADDRESS is rejected" \
    "a_success_response_missing_the_mapped_address_attribute_is_rejected" cargo_test
check_contains "cargo test proves a truncated response is rejected, not a panic" \
    "a_truncated_response_is_rejected_not_panicking" cargo_test
check_contains "cargo test proves XOR-MAPPED-ADDRESS round-trips through encode/decode" \
    "xor_mapped_address_roundtrips_through_encode_and_decode" cargo_test
check_contains "cargo test proves TURN with no credentials reports no_credentials_supplied, not an error" \
    "turn_allocate_without_credentials_reports_no_credentials_supplied_not_an_error" cargo_test
check_contains "cargo test proves the long-term-credential key is MD5(username:realm:password)" \
    "long_term_key_matches_md5_of_username_realm_password" cargo_test

check_contains "stun-turn advertises --reveal-mapped-address/--turn-server/--turn-transport" \
    "--reveal-mapped-address" \
    "$BIN" stun-turn --help
check_contains "stun-turn documents the mapped address is hidden by default" \
    "sensitive identifier" \
    "$BIN" stun-turn --help

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

ip_pattern='([0-9]{1,3}\.){3}[0-9]{1,3}'

# --- default output: no mapped address anywhere, real IP-shaped string absent ---
default_out="$("$BIN" stun-turn --inject-fixture stable --json 2>/dev/null | sed -n '/^{/,$p')"
if [ -z "$default_out" ]; then
    fail "default run produces a JSON report" "no output"
else
    pass "default run produces a JSON report"
    addr0="$(printf '%s' "$default_out" | json_get bindings.0.mapped_address)"
    if [ "$addr0" = "null" ]; then
        pass "mapped_address is absent (null) by default"
    else
        fail "mapped_address is absent (null) by default" "got: $addr0"
    fi
    if printf '%s' "$default_out" | grep -Eq "$ip_pattern"; then
        fail "default JSON output carries no IP-shaped string" "found an IP-shaped token"
    else
        pass "default JSON output carries no IP-shaped string"
    fi
fi
default_human="$("$BIN" stun-turn --inject-fixture stable 2>&1)"
if printf '%s' "$default_human" | grep -Eq "$ip_pattern"; then
    fail "default human output carries no IP-shaped string" "found an IP-shaped token"
else
    pass "default human output carries no IP-shaped string"
fi
check_contains "default human output states the address is hidden, with the reveal flag named" \
    "--reveal-mapped-address" \
    "$BIN" stun-turn --inject-fixture stable

# --- --reveal-mapped-address: the real address now appears ---
reveal_out="$("$BIN" stun-turn --inject-fixture stable --reveal-mapped-address --json 2>/dev/null | sed -n '/^{/,$p')"
reveal_addr="$(printf '%s' "$reveal_out" | json_get bindings.0.mapped_address)"
if printf '%s' "$reveal_addr" | grep -Eq "$ip_pattern"; then
    pass "--reveal-mapped-address surfaces the real mapped address"
else
    fail "--reveal-mapped-address surfaces the real mapped address" "got: $reveal_addr"
fi

# --- stable vs changed vs unreachable verdicts are distinguishable ---
stable_verdict="$(printf '%s' "$default_out" | json_get mapping_change.verdict)"
if [ "$stable_verdict" = '"stable"' ]; then
    pass "an unchanging mapping reports verdict=stable"
else
    fail "an unchanging mapping reports verdict=stable" "got: $stable_verdict"
fi

changed_out="$("$BIN" stun-turn --inject-fixture changed --json 2>/dev/null | sed -n '/^{/,$p')"
changed_verdict="$(printf '%s' "$changed_out" | json_get mapping_change.verdict)"
if [ "$changed_verdict" = '"changed"' ]; then
    pass "a mapping that differs across attempts reports verdict=changed"
else
    fail "a mapping that differs across attempts reports verdict=changed" "got: $changed_verdict"
fi

# --- the core anti-silence assertion: an unreachable server must NOT read
#     as verdict=stable just because nothing ever changed (nothing ever
#     validated either) ---
unreachable_out="$("$BIN" stun-turn --inject-fixture unreachable --json 2>/dev/null | sed -n '/^{/,$p')"
unreachable_verdict="$(printf '%s' "$unreachable_out" | json_get mapping_change.verdict)"
if [ "$unreachable_verdict" = '"unavailable"' ]; then
    pass "every attempt timing out reports verdict=unavailable, never stable"
else
    fail "every attempt timing out reports verdict=unavailable, never stable" "got: $unreachable_verdict"
fi
unreachable_bindings0="$(printf '%s' "$unreachable_out" | json_get bindings.0.result)"
if [ "$unreachable_bindings0" = '"unreachable"' ]; then
    pass "a timed-out attempt is recorded as unreachable, a distinct state from mapped"
else
    fail "a timed-out attempt is recorded as unreachable, a distinct state from mapped" "got: $unreachable_bindings0"
fi
check_contains "human output distinguishes UNREACHABLE from a stable mapping" \
    "UNREACHABLE" \
    "$BIN" stun-turn --inject-fixture unreachable
check_contains "human output states unavailable is not evidence of stability" \
    "not evidence of stability" \
    "$BIN" stun-turn --inject-fixture unreachable

# --- TURN: no credentials skips cleanly, not an opaque error ---
no_creds_out="$("$BIN" stun-turn --inject-fixture turn-no-creds --turn-server example.com:3478 --json 2>/dev/null | sed -n '/^{/,$p')"
turn_outcome="$(printf '%s' "$no_creds_out" | json_get turn.outcome)"
if [ "$turn_outcome" = '"no_credentials_supplied"' ]; then
    pass "TURN allocation with no credentials skips cleanly (no_credentials_supplied)"
else
    fail "TURN allocation with no credentials skips cleanly" "got: $turn_outcome"
fi
check_contains "human output tells the operator how to attempt an authenticated TURN allocation" \
    "turn-username" \
    "$BIN" stun-turn --inject-fixture turn-no-creds --turn-server example.com:3478

# --- TURN: a successful allocation reports lifetime and a relayed address ---
allocated_out="$("$BIN" stun-turn --inject-fixture turn-allocated --turn-server example.com:3478 --turn-username u --turn-password p --json 2>/dev/null | sed -n '/^{/,$p')"
allocated_outcome="$(printf '%s' "$allocated_out" | json_get turn.outcome)"
allocated_lifetime="$(printf '%s' "$allocated_out" | json_get turn.lifetime_secs)"
if [ "$allocated_outcome" = '"allocated"' ] && [ "$allocated_lifetime" != "null" ]; then
    pass "a successful TURN allocation reports outcome=allocated with a lifetime"
else
    fail "a successful TURN allocation reports outcome=allocated with a lifetime" "outcome=$allocated_outcome lifetime=$allocated_lifetime"
fi

# --- no TURN server passed: the turn field is entirely absent, not a
#     fabricated "skipped" outcome for a check that never ran ---
no_turn_out="$("$BIN" stun-turn --inject-fixture stable --json 2>/dev/null | sed -n '/^{/,$p')"
no_turn_field="$(printf '%s' "$no_turn_out" | json_get turn)"
if [ "$no_turn_field" = "null" ]; then
    pass "omitting --turn-server yields turn=null, not a fabricated skip result"
else
    fail "omitting --turn-server yields turn=null" "got: $no_turn_field"
fi

# --- exactly one real end-to-end run against the public STUN server named
#     in the field evidence ---
if net_guard; then
    real_out="$("$BIN" stun-turn --repeat 2 --interval-ms 50 --json 2>/dev/null | sed -n '/^{/,$p')"
    if [ -z "$real_out" ]; then
        skip "a real STUN binding to stun.l.google.com:19302 reports an RTT" "no output"
    else
        real_rtt="$(printf '%s' "$real_out" | json_get bindings.0.rtt_ms)"
        real_verdict="$(printf '%s' "$real_out" | json_get mapping_change.verdict)"
        if [ "$real_verdict" != "null" ]; then
            pass "a real STUN binding to stun.l.google.com:19302 produces a mapping verdict ($real_verdict, rtt=$real_rtt)"
        else
            fail "a real STUN binding produces a mapping verdict" "got: $real_verdict"
        fi
        if printf '%s' "$real_out" | grep -Eq "$ip_pattern"; then
            fail "the real run's default JSON output carries no IP-shaped string" "found an IP-shaped token"
        else
            pass "the real run's default JSON output carries no IP-shaped string"
        fi
    fi
else
    skip "a real STUN binding to stun.l.google.com:19302 reports an RTT" "FP_HARNESS_OFFLINE=1"
fi
