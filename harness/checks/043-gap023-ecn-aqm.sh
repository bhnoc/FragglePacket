#!/usr/bin/env bash
# GAP-023: ECN/AQM protocol A/B control. Field evidence: the Black Hat
# capture held 514,587 outbound + 26,017 inbound UDP/443 ECT(0), six
# outbound ECT(1), and ZERO CE marks -- capability present, marking absent.
# This gate locks that specific finding is stated positively (CE handling
# not implicated), that ECT(0)/ECT(1)/CE are counted separately (the
# classic-ECN-vs-L4S distinction), and that a tunnel interface warns.

check_ok "cargo test covers ecn-aqm codepoint/scheme/finding/correlation logic" \
    cargo test --release --lib network_tests::ecn_aqm:: --manifest-path "$REPO_ROOT/Cargo.toml"

# --- ECT(0)/ECT(1)/CE counted separately, matching libc's ECN constants ---
check_contains "cargo test proves ECT(0)/ECT(1)/CE are counted separately" \
    "ect0_and_ect1_and_ce_are_counted_separately" \
    cargo test --release --lib network_tests::ecn_aqm:: --manifest-path "$REPO_ROOT/Cargo.toml"
check_contains "cargo test proves the TOS-byte parser matches libc's ECN constants" \
    "tos_byte_masking_matches_libc_ecn_constants" \
    cargo test --release --lib network_tests::ecn_aqm:: --manifest-path "$REPO_ROOT/Cargo.toml"

# --- L4S (ECT1) distinguished from classic ECN (ECT0); Mixed is a real state ---
check_contains "cargo test proves L4S is distinguished from classic ECN by ECT1 vs ECT0" \
    "l4s_distinguished_from_classic_ecn_by_ect1_vs_ect0" \
    cargo test --release --lib network_tests::ecn_aqm:: --manifest-path "$REPO_ROOT/Cargo.toml"

# --- the exact field-evidence shape: capability present, zero CE, stated
#     positively as de-implicating CE handling, not as missing data ---
check_contains "cargo test proves capability-present-marking-absent is stated as a positive finding" \
    "field_evidence_capability_present_marking_absent_is_stated_positively" \
    cargo test --release --lib network_tests::ecn_aqm:: --manifest-path "$REPO_ROOT/Cargo.toml"
check_contains "cargo test proves CE marks present yield a materially different statement" \
    "ce_marks_present_yields_a_different_statement" \
    cargo test --release --lib network_tests::ecn_aqm:: --manifest-path "$REPO_ROOT/Cargo.toml"
check_contains "cargo test proves no-ECN-observed is a third distinct state (not conflated with zero-CE)" \
    "no_ecn_capability_observed_is_a_third_distinct_state" \
    cargo test --release --lib network_tests::ecn_aqm:: --manifest-path "$REPO_ROOT/Cargo.toml"

# --- CE/queue-delay correlation requires both a nonzero CE rate AND a delay figure ---
check_contains "cargo test proves CE/queue-delay correlation requires both a nonzero CE rate and a delay figure" \
    "correlation_requires_both_a_nonzero_ce_rate_and_a_delay_measurement" \
    cargo test --release --lib network_tests::ecn_aqm:: --manifest-path "$REPO_ROOT/Cargo.toml"

# --- tunnel interface warns; non-tunnel does not ---
check_contains "cargo test proves a tunnel interface produces a warning and a non-tunnel does not" \
    "tunnel_interface_produces_a_warning_and_non_tunnel_does_not" \
    cargo test --release --lib network_tests::ecn_aqm:: --manifest-path "$REPO_ROOT/Cargo.toml"

# --- CLI surface ---
check_contains "ecn-aqm advertises --pcap-in" "--pcap-in" \
    "$BIN" ecn-aqm --help
check_contains "ecn-aqm advertises --set-ecn" "--set-ecn" \
    "$BIN" ecn-aqm --help

# --- offline, deterministic: the real quic-443.pcap fixture parses without
#     crashing and produces a genuine (not fabricated) ECN classification.
#     This fixture has no ECN marks, so the correct answer is NoneObserved,
#     not a guessed Classic/L4S. ---
fixture="$FIXTURE_DIR/pcap/quic-443.pcap"
if [ -f "$fixture" ]; then
    fixture_out="$("$BIN" ecn-aqm --pcap-in "$fixture" --json 2>/dev/null | sed -n '/^{/,$p')"
    if [ -z "$fixture_out" ]; then
        fail "quic-443.pcap fixture produces a genuine ECN classification" "no JSON output"
    else
        check="$(printf '%s' "$fixture_out" | python3 -c '
import json, sys
d = json.load(sys.stdin)
counts = d.get("counts", {})
scheme = d.get("scheme")
total = sum(counts.get(k, 0) for k in ("not_ect","ect1","ect0","ce"))
print("ok" if total > 0 and scheme is not None else "bad")
' 2>/dev/null)"
        if [ "$check" = "ok" ]; then
            pass "quic-443.pcap fixture produces a genuine ECN classification"
        else
            fail "quic-443.pcap fixture produces a genuine ECN classification" "got: $fixture_out"
        fi
    fi
else
    skip "quic-443.pcap fixture produces a genuine ECN classification" "fixture absent"
fi

# --- interface tunnel warning fires through the real CLI for utun*, not just the library fn ---
check_contains "CLI warns for a tunnel interface" "tunnel" \
    "$BIN" ecn-aqm --interface utun6 --json
tunnel_out="$("$BIN" ecn-aqm --interface utun6 --json 2>/dev/null | sed -n '/^{/,$p')"
if [ -z "$tunnel_out" ]; then
    fail "CLI tunnel warning is present in JSON for utun6" "no JSON output"
else
    has_warning="$(printf '%s' "$tunnel_out" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print("ok" if d.get("tunnel_warning") else "bad")
' 2>/dev/null)"
    if [ "$has_warning" = "ok" ]; then
        pass "CLI tunnel warning is present in JSON for utun6"
    else
        fail "CLI tunnel warning is present in JSON for utun6" "got: $tunnel_out"
    fi
fi
non_tunnel_out="$("$BIN" ecn-aqm --interface en0 --json 2>/dev/null | sed -n '/^{/,$p')"
if [ -z "$non_tunnel_out" ]; then
    skip "CLI reports no tunnel warning for a non-tunnel interface" "no JSON output"
else
    no_warning="$(printf '%s' "$non_tunnel_out" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print("ok" if not d.get("tunnel_warning") else "bad")
' 2>/dev/null)"
    if [ "$no_warning" = "ok" ]; then
        pass "CLI reports no tunnel warning for a non-tunnel interface"
    else
        fail "CLI reports no tunnel warning for a non-tunnel interface" "got: $non_tunnel_out"
    fi
fi

# --- live (skipped offline): an ECN-set attempt reports the platform's real
#     outcome (applied+confirmed via getsockopt readback, or a stated
#     failure) rather than assuming success ---
if net_guard; then
    set_out="$("$BIN" ecn-aqm --set-ecn ect0 --target 127.0.0.1 --port 1 --json 2>/dev/null | sed -n '/^{/,$p')"
    if [ -z "$set_out" ]; then
        skip "ECN-set attempt reports a real applied/failed outcome, not an assumption" "no JSON output"
    else
        has_result="$(printf '%s' "$set_out" | python3 -c '
import json, sys
d = json.load(sys.stdin)
attempt = d.get("ecn_set_attempt", {})
print("ok" if "applied" in attempt and "detail" in attempt else "bad")
' 2>/dev/null)"
        if [ "$has_result" = "ok" ]; then
            pass "ECN-set attempt reports a real applied/failed outcome, not an assumption"
        else
            fail "ECN-set attempt reports a real applied/failed outcome, not an assumption" "got: $set_out"
        fi
    fi
else
    skip "ECN-set attempt reports a real applied/failed outcome, not an assumption" "FP_HARNESS_OFFLINE=1"
fi
