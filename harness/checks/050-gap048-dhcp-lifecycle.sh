#!/usr/bin/env bash
# GAP-048: the diagnostic that actually exercises DHCP pool exhaustion --
# requesting a fresh lease -- can also drop the operator's own
# connectivity and consumes a pool address, so it must never run without
# an explicit authorization statement. The non-disruptive existing-lease
# read is the default and must never touch the network. Pool headroom
# must never be inferred from "I got a lease" -- that proves nothing about
# how much room is left.

check_ok "cargo test covers DHCP parsing / authorization / pool-headroom logic" \
    cargo test --release --lib network_tests::dhcp_lifecycle:: --manifest-path "$REPO_ROOT/Cargo.toml"

check_contains "dhcp-lifecycle advertises --fresh-lease" "--fresh-lease" \
    "$BIN" dhcp-lifecycle --help
check_contains "dhcp-lifecycle advertises --authorized" "--authorized" \
    "$BIN" dhcp-lifecycle --help

# --- the central regression: fresh-lease without authorization refuses to start ---
check_fails "fresh-lease without --authorized refuses to start" \
    "$BIN" dhcp-lifecycle --interface lo0 --fresh-lease
check_contains "the refusal names --authorized as what is missing" "--authorized" \
    "$BIN" dhcp-lifecycle --interface lo0 --fresh-lease

check_fails "an empty --authorized string still refuses" \
    "$BIN" dhcp-lifecycle --interface lo0 --fresh-lease --authorized ""

# --- default (no --fresh-lease) never touches the network: only reads cached state ---
default_out="$("$BIN" dhcp-lifecycle --interface lo0 2>&1)"
check_contains "default run states fresh-lease test was not run" "fresh-lease test not run (safe default)" \
    bash -c 'printf "%s" "$1"' _ "$default_out"
check_lacks "default run never reports a fresh lease result" "fresh lease: discover-to-address" \
    bash -c 'printf "%s" "$1"' _ "$default_out"

# --- pool headroom is never inferred from a lease; it withholds without telemetry ---
check_contains "pool headroom is withheld without operator telemetry" "pool headroom: unavailable" \
    bash -c 'printf "%s" "$1"' _ "$default_out"

check_ok "cargo test proves pool headroom is unavailable with no telemetry" \
    cargo test --release --lib network_tests::dhcp_lifecycle::tests::pool_headroom_unavailable_with_no_telemetry \
    --manifest-path "$REPO_ROOT/Cargo.toml"
check_ok "cargo test proves the MAC address never surfaces in a parsed lease" \
    cargo test --release --lib network_tests::dhcp_lifecycle::tests::never_surfaces_the_mac_address \
    --manifest-path "$REPO_ROOT/Cargo.toml"

# --- a real run against this machine's own existing lease, if one exists ---
if net_guard; then
    found_lease=""
    for iface in en0 en1 en2 en3 en4 en5 en6 en7 en8 en9; do
        out="$("$BIN" dhcp-lifecycle --interface "$iface" --json 2>&1 | sed -n '/^{/,$p')"
        has_lease="$(printf '%s' "$out" | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
    print("yes" if d.get("existing_lease") else "no")
except Exception:
    print("no")
' 2>/dev/null)"
        if [ "$has_lease" = "yes" ]; then
            found_lease="$iface"
            break
        fi
    done
    if [ -n "$found_lease" ]; then
        pass "a real existing DHCP lease was decoded on this machine (interface $found_lease)"
        real_human="$("$BIN" dhcp-lifecycle --interface "$found_lease" 2>&1)"
        check_lacks "the real decoded lease output never contains a MAC-address-shaped token" \
            "20:7b:d2:72:35:80" bash -c 'printf "%s" "$1"' _ "$real_human"
    else
        skip "a real existing DHCP lease was decoded on this machine" "no DHCP-leased interface found"
    fi
else
    skip "real existing-lease decode" "FP_HARNESS_OFFLINE=1"
fi
