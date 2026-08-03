#!/usr/bin/env bash
# GAP-060: VPN/encapsulation testing must never request, read, or capture a
# production VPN credential -- synthetic reachability probes and real
# protocol-level measurements only. Effective MTU/MSS must be MEASURED
# (a real TCP handshake's negotiated MSS) rather than assumed from the
# per-protocol overhead constants in src/cli/common.rs, which stay a
# planning aid, never a substitute for a measurement. This machine's own
# default route (utun6) is a live tunnel, so the effective-MTU check runs
# against real infrastructure, not a mock.

check_ok "cargo test covers protocol-probe/effective-MSS/idle-survival logic" \
    cargo test --release --lib network_tests::vpn_matrix:: --manifest-path "$REPO_ROOT/Cargo.toml"

check_contains "vpn-matrix advertises --interface" "--interface" \
    "$BIN" vpn-matrix --help
check_contains "vpn-matrix advertises --show-local-ip (off by default)" "--show-local-ip" \
    "$BIN" vpn-matrix --help

# --- no credential flag exists anywhere on this command ---
help_text="$("$BIN" vpn-matrix --help 2>&1)"
for bad_flag in password passwd secret psk private-key credential username; do
    check_lacks "vpn-matrix --help never advertises a --$bad_flag flag" "--$bad_flag" \
        bash -c 'printf "%s" "$1"' _ "$help_text"
done

# --- no credential-shaped source is ever read: the binary must not touch keychain/profile tooling ---
check_lacks "vpn-matrix source never shells out to security/keychain tooling" \
    "security find-generic-password" \
    cat "$REPO_ROOT/src/cli/commands/vpn_matrix.rs" "$REPO_ROOT/src/network_tests/vpn_matrix.rs"

# --- public egress IP is absent from default output (GAP-018 discipline) ---
if net_guard; then
    default_out="$("$BIN" vpn-matrix --target 1.1.1.1 --interface utun6 2>&1)"
    check_lacks "default vpn-matrix output carries no local IP address" \
        "192.168." bash -c 'printf "%s" "$1"' _ "$default_out"
    check_lacks "default vpn-matrix output states no bare public-egress-shaped field" \
        "public_ip" bash -c 'printf "%s" "$1"' _ "$default_out"

    # --- effective MTU/MSS is a real measurement, distinct from the reported interface MTU ---
    check_contains "human output labels the measured effective MSS as measured, not assumed" \
        "measured effective TCP MSS (real handshake)" \
        bash -c 'printf "%s" "$1"' _ "$default_out"
    check_contains "human output states the interface-reported MTU separately" \
        "interface-reported MTU:" \
        bash -c 'printf "%s" "$1"' _ "$default_out"

    json_out="$("$BIN" vpn-matrix --target 1.1.1.1 --interface utun6 --json 2>&1 | sed -n '/^{/,$p')"
    check_json_field "JSON carries effective_mtu.interface_mtu_reported" "effective_mtu.interface_mtu_reported" \
        bash -c 'printf "%s" "$1"' _ "$json_out"

    reported="$(printf '%s' "$json_out" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print(d["effective_mtu"]["interface_mtu_reported"])
' 2>/dev/null)"
    measured_mss="$(printf '%s' "$json_out" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print(d["effective_mss_bytes"])
' 2>/dev/null)"
    if [ "$reported" != "None" ] && [ "$measured_mss" != "None" ] && [ -n "$measured_mss" ]; then
        pass "utun6's real reported MTU ($reported) and a real measured effective MSS ($measured_mss) are both present and independent"
    else
        fail "utun6's reported MTU and measured MSS are both present" "reported=$reported measured_mss=$measured_mss"
    fi

    # The central "measured, not assumed" regression: a hardcoded 1460
    # (the bare-Ethernet default) is physically impossible on an interface
    # whose own reported MTU is 1412 -- a real measurement over this tunnel
    # can never exceed interface_mtu_reported - 40 (IP+TCP headers). If the
    # figure came from a constant instead of TCP_MAXSEG, it will slip past
    # that ceiling.
    if [ "$reported" != "None" ] && [ -n "$reported" ] && [ "$measured_mss" != "None" ] && [ -n "$measured_mss" ]; then
        ceiling=$((reported - 40))
        if [ "$measured_mss" -le "$ceiling" ] 2>/dev/null; then
            pass "measured MSS ($measured_mss) is physically consistent with a real handshake over utun6 (<= $ceiling), not a hardcoded constant"
        else
            fail "measured MSS is physically consistent with a real handshake over utun6" \
                "measured_mss=$measured_mss exceeds the tunnel's own reported-MTU-derived ceiling of $ceiling; this can only mean the figure was assumed, not measured"
        fi
    fi

    # --- protocol reachability probes never require a credential to run ---
    check_contains "human output states no credential is ever touched" \
        "never requests, reads, or logs a VPN credential" \
        bash -c 'printf "%s" "$1"' _ "$default_out"
    check_contains "WireGuard reachability probe ran" "WireGuard port" \
        bash -c 'printf "%s" "$1"' _ "$default_out"
else
    skip "GAP-060 live measurement checks" "FP_HARNESS_OFFLINE=1"
fi
