#!/usr/bin/env bash
# GAP-056: "IPv6 is absent" is a status, not a diagnosis. It cannot distinguish
# a missing router advertisement from a working RA whose default route is
# unreachable, and those have different owners. Every layer reports separately,
# IPv4 and IPv6 verdicts never blend, and a check that could not RUN is never
# counted as a check the network FAILED.

check_ok "cargo test covers ipv6 layer decomposition" \
    cargo test --release --quiet --lib --manifest-path "$REPO_ROOT/Cargo.toml" ipv6_validation

check_ok "cargo test proves an unavailable layer is not a network failure" \
    cargo test --release --quiet --lib --manifest-path "$REPO_ROOT/Cargo.toml" \
    ipv6_validation::tests::unavailable_is_never_counted_as_a_network_failure

check_ok "cargo test proves failed_layers lists only genuine failures" \
    cargo test --release --quiet --lib --manifest-path "$REPO_ROOT/Cargo.toml" \
    ipv6_validation::tests::failed_layers_lists_only_genuine_failures

check_ok "cargo test proves a NAT64 prefix is only derived from a well-known answer" \
    cargo test --release --quiet --lib --manifest-path "$REPO_ROOT/Cargo.toml" \
    ipv6_validation::tests::nat64_prefix_rejects_an_answer_without_the_well_known_suffix

check_contains "ipv6-validate requires an explicit interface" "interface" \
    "$BIN" ipv6-validate --help

# Requiring the interface is the guard against reporting a VPN tunnel's lack of
# IPv6 as the network's.
check_fails "ipv6-validate refuses to guess an interface" "$BIN" ipv6-validate

if net_guard; then
    out="$("$BIN" ipv6-validate --interface en0 2>&1)"

    if [ -z "$out" ]; then
        skip "GAP-056 live decomposition" "no output"
    else
        # The whole point: a bare boolean is replaced by named layers.
        for layer in link_local_address global_address router_advertisement dhcpv6 \
                     default_route neighbor_discovery dns_aaaa native_reachability \
                     nat64_prefix dns64; do
            if printf '%s' "$out" | grep -q "$layer"; then
                :
            else
                fail "every IPv6 layer is reported separately" "missing layer: $layer"
                break
            fi
        done
        printf '%s' "$out" | grep -q "nat64_prefix" && pass "every IPv6 layer is reported separately"

        # IPv4 and IPv6 verdicts must be distinct lines, never one blended claim.
        if printf '%s' "$out" | grep -q '^  IPv4:' && printf '%s' "$out" | grep -q '^  IPv6:'; then
            pass "IPv4 and IPv6 verdicts are reported separately"
        else
            fail "IPv4 and IPv6 verdicts are reported separately" "one or both verdict lines absent"
        fi

        # A privileged check that could not run must not appear in the failing
        # list. On this host the RA check is exactly that case.
        v6line="$(printf '%s' "$out" | grep '^  IPv6:' || true)"
        if printf '%s' "$v6line" | grep -q 'router_advertisement'; then
            fail "an unrunnable privileged check is not blamed on the network" \
                "router_advertisement appears in the failing-layer list despite being unavailable"
        else
            pass "an unrunnable privileged check is not blamed on the network"
        fi

        # An unavailable check must state what privilege it needed.
        if printf '%s' "$out" | grep -q 'unavailable'; then
            check_contains "an unavailable layer names its required privilege" "requires:" \
                printf '%s' "$out"
        else
            skip "an unavailable layer names its required privilege" "no unavailable layer on this host"
        fi

        # JSON must carry the same structure for downstream consumers.
        check_json_field "json output carries the ipv6 verdict" "ipv6_validation.ipv6_verdict" \
            "$BIN" ipv6-validate --interface en0 --json
        check_json_field "json output carries the ipv4 verdict separately" "ipv6_validation.ipv4_verdict" \
            "$BIN" ipv6-validate --interface en0 --json
    fi

    # A tunnel interface must warn that its absence of IPv6 may not be the
    # network's, which is the local footgun this whole session kept hitting.
    tunnel="$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')"
    case "$tunnel" in
        utun*|tun*|ppp*|ipsec*)
            check_contains "a tunnel interface is flagged as such" "tunnel" \
                "$BIN" ipv6-validate --interface "$tunnel"
            ;;
        *)
            skip "a tunnel interface is flagged as such" "default route is not a tunnel"
            ;;
    esac
else
    skip "GAP-056 live checks" "FP_HARNESS_OFFLINE=1"
fi
