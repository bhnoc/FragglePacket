#!/usr/bin/env bash
# GAP-001: the QUIC PMTU probe counted a successful local send_to() as path-MTU
# success, so it reported 8972-byte payloads as confirmed on a path that cannot
# carry them. Only a peer-acknowledged datagram may count.
#
# The unit tests in src/probe/pmtu_evidence.rs cover the verdict logic offline;
# these checks exercise the real command end to end.

check_ok "pmtu evidence unit tests pass" \
    cargo test --release --quiet --lib --manifest-path "$REPO_ROOT/Cargo.toml" pmtu_evidence

# The exact original false positive. 8972 bytes cannot traverse any ordinary
# path; it must never come back confirmed.
if net_guard; then
    out="$("$BIN" quic 1.1.1.1 2>&1)"

    if printf '%s' "$out" | grep -q 'size_8972_outcome = confirmed'; then
        fail "8972-byte payload is never reported confirmed" "regression: send-only counted as success"
    else
        pass "8972-byte payload is never reported confirmed"
    fi

    # The old code emitted this metric straight from send_to() return values.
    check_lacks "no largest_udp_payload_sent metric derived from send-only results" \
        "largest_udp_payload_sent" printf '%s' "$out"

    # Whatever is confirmed must be physically plausible: at or below the
    # default route's MTU minus IP and UDP headers.
    iface="$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')"
    mtu="$(ifconfig "$iface" 2>/dev/null | grep -oE 'mtu [0-9]+' | awk '{print $2}')"
    confirmed="$(printf '%s' "$out" | grep -oE 'confirmed_pmtu_bytes = [0-9]+' | awk '{print $3}')"
    if [ -n "$mtu" ] && [ -n "$confirmed" ]; then
        ceiling=$((mtu - 28))
        if [ "$confirmed" -le "$ceiling" ]; then
            pass "confirmed PMTU ($confirmed) fits the path MTU ceiling ($ceiling on $iface/$mtu)"
        else
            fail "confirmed PMTU ($confirmed) fits the path MTU ceiling ($ceiling on $iface/$mtu)" \
                "confirmed a size the interface cannot carry"
        fi
    else
        skip "confirmed PMTU fits the path MTU ceiling" "could not read interface MTU or no size confirmed"
    fi

    # A confirmation must cite acknowledgement, not a successful send.
    if printf '%s' "$out" | grep -q 'confirmed_pmtu_bytes'; then
        check_contains "confirmation cites acknowledged stream data" "acknowledged" \
            printf '%s' "$out"
    else
        check_contains "no confirmation means the verdict says undetermined" "undetermined" \
            printf '%s' "$out"
    fi

    # DF must actually be set. It was a no-op off Linux, so every macOS probe
    # silently measured fragmented delivery.
    check_contains "don't-fragment is applied on this platform" "df_applied = true" \
        printf '%s' "$out"

    # A host that does not answer QUIC at all must not yield a PMTU number.
    unans="$("$BIN" quic 192.0.2.1 2>&1)"
    check_lacks "an unresponsive host yields no confirmed PMTU" "confirmed_pmtu_bytes" \
        printf '%s' "$unans"
    check_contains "an unresponsive host reports undetermined" "undetermined" \
        printf '%s' "$unans"
else
    skip "GAP-001 live probes" "FP_HARNESS_OFFLINE=1"
fi
