#!/usr/bin/env bash
# GAP-015: an IPv6 family failure is user-visible latency that looks like a slow
# server. The fallback delay must be MEASURED, and when only one family could be
# attempted there is nothing to difference against -- so the field is
# unavailable, never zero and never an RFC constant.

check_ok "cargo test proves fallback delay is withheld when one family was untested" \
    cargo test --release --quiet --lib --manifest-path "$REPO_ROOT/Cargo.toml" \
    ipv6_validation::tests::fallback_delay_is_none_when_only_one_family_was_attempted

check_contains "happy-eyeballs mode is reachable" "happy-eyeballs" \
    "$BIN" ipv6-validate --help

if net_guard; then
    out="$("$BIN" ipv6-validate --interface en0 --happy-eyeballs 2>&1)"

    if [ -z "$out" ]; then
        skip "GAP-015 live checks" "no output"
    else
        check_contains "both families' offer status is recorded" "v6_offered=" printf '%s' "$out"
        check_contains "a winning family is reported" "winning family:" printf '%s' "$out"

        # The regression: a delay printed as 0.00ms when only one family
        # connected would read as "fallback was instant" rather than "there was
        # no fallback to measure".
        if printf '%s' "$out" | grep -q 'measured fallback delta: 0\.00ms'; then
            v6="$(printf '%s' "$out" | grep 'v6 connect:' || true)"
            if printf '%s' "$v6" | grep -q 'unavailable'; then
                fail "fallback delta is not fabricated when a family did not connect" \
                    "0.00ms reported despite IPv6 never connecting"
            else
                pass "fallback delta is not fabricated when a family did not connect"
            fi
        else
            pass "fallback delta is not fabricated when a family did not connect"
        fi

        # An unmeasurable delta must say so, and say why.
        if printf '%s' "$out" | grep -q 'v6 connect: unavailable'; then
            check_contains "an unmeasurable delta explains itself" "only one family was attempted" \
                printf '%s' "$out"
            check_lacks "an unmeasurable delta is not rendered as a number" \
                "measured fallback delta: 0" printf '%s' "$out"
        else
            skip "an unmeasurable delta explains itself" "both families connected on this host"
        fi

        # DNS offering a family that then fails to connect is the specific
        # user-visible case GAP-015 exists to surface.
        if printf '%s' "$out" | grep -q 'v6_offered=true' && \
           printf '%s' "$out" | grep -q 'v6 connect: unavailable'; then
            check_contains "a family-specific failure is called out" "family-specific failure" \
                printf '%s' "$out"
        else
            skip "a family-specific failure is called out" "no family-specific failure on this host"
        fi

        check_json_field "json carries the happy-eyeballs block" "happy_eyeballs.host" \
            "$BIN" ipv6-validate --interface en0 --happy-eyeballs --json
    fi
else
    skip "GAP-015 live checks" "FP_HARNESS_OFFLINE=1"
fi
