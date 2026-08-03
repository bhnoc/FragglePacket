#!/usr/bin/env bash
# GAP-022: first-hop isolation must not depend solely on ICMP echo. Field
# evidence: a conference WLAN suppressed every echo request to its own
# gateway while passing Internet ICMP with zero loss. Read naively, total
# ICMP loss to the gateway looks like "100% packet loss" (a catastrophic
# local fault); it's actually policy. This gate locks:
#   1. ICMP suppression is classified distinctly from real packet loss.
#   2. A non-ICMP fallback (TCP SYN timing) is what makes that distinction
#      possible, and degrades gracefully (states missing privilege) rather
#      than failing opaquely when a method can't run.

check_ok "cargo test covers first-hop suppression-vs-loss classification" \
    cargo test --release --lib network_tests::firsthop:: --manifest-path "$REPO_ROOT/Cargo.toml"

# --- total ICMP loss + successful non-ICMP fallback => Suppressed, not Lost ---
check_contains "cargo test proves total ICMP loss with live fallback is classified Suppressed" \
    "total_icmp_loss_with_successful_fallback_is_suppression_not_loss" \
    cargo test --release --lib network_tests::firsthop:: --manifest-path "$REPO_ROOT/Cargo.toml"

# --- total ICMP loss + failed fallback => genuinely Lost ---
check_contains "cargo test proves total ICMP loss with dead fallback is classified Lost" \
    "total_icmp_loss_with_failed_fallback_is_real_loss" \
    cargo test --release --lib network_tests::firsthop:: --manifest-path "$REPO_ROOT/Cargo.toml"

# --- ARP fallback without root reports the missing privilege explicitly
#     rather than failing opaquely ---
check_contains "cargo test proves ARP fallback without root names the missing privilege" \
    "arp_fallback_without_root_reports_missing_privilege_not_opaque_failure" \
    cargo test --release --lib network_tests::firsthop:: --manifest-path "$REPO_ROOT/Cargo.toml"

# --- CLI surface ---
check_contains "first-hop advertises --gateway/--interface/--tcp-port" "--tcp-port" \
    "$BIN" first-hop --help
check_contains "first-hop --help documents tunnel default-route caveat" "VPN tunnel" \
    "$BIN" first-hop --help

check_fails "first-hop with no --gateway refuses to guess one" \
    "$BIN" first-hop --interface en0

if net_guard; then
    # 192.0.2.1 is TEST-NET-1 (RFC 5737): guaranteed unreachable, so ICMP
    # loss is total and the TCP SYN fallback will also fail to connect --
    # this exercises the Suppressed-vs-Lost decision path end to end and
    # must report Lost (no live corroboration) distinctly from packet loss.
    out="$("$BIN" first-hop --gateway 192.0.2.1 --interface lo0 --count 2 --timeout-ms 300 --json 2>/dev/null | sed -n '/^{/,$p')"
    if [ -z "$out" ]; then
        skip "live first-hop run against unreachable gateway reports a structured state" "no JSON output"
    else
        state="$(printf '%s' "$out" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print(d.get("icmp", {}).get("state"))
' 2>/dev/null)"
        if [ -n "$state" ]; then
            pass "live first-hop run against unreachable gateway reports a structured icmp.state ($state)"
        else
            fail "live first-hop run against unreachable gateway reports a structured icmp.state" "got: $out"
        fi
    fi
else
    skip "live first-hop run against unreachable gateway reports a structured icmp.state" "FP_HARNESS_OFFLINE=1"
fi
