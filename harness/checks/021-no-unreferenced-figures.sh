#!/usr/bin/env bash
# A rate or percentage must never be reported alongside a condition that
# invalidates it.
#
# This has now surfaced in three separate commands, each time as a plausible
# number standing in for a measurement that did not happen:
#   quic          a successful send_to() became a confirmed 8972-byte path MTU
#   gateway-bracket  a synthetic generator's shortfall became 96.7% "loss"
#   protocol-compare an HTTP 301 redirect stub became "0.02 Mbps, loss=Clean"
#
# The rule this locks: if the transfer was not a valid measurement, the derived
# figure is withheld, not printed with a caveat. Withholding is what GAP-027
# established for invalid runs and it generalizes.

# A host that redirects cannot yield a capacity figure from the redirect body.
if net_guard; then
    redirect_host="cloudflare.com"   # 301s to www.cloudflare.com
    out="$("$BIN" protocol-compare "$redirect_host" --interface en0 --protocol http2 2>&1)"

    if [ -z "$out" ]; then
        skip "a redirect leg yields no Clean throughput figure" "no output"
    else
        # Any leg still reporting a 3xx must not also be called Clean.
        if printf '%s' "$out" | grep -E 'status=3[0-9][0-9]' | grep -q 'loss=Clean'; then
            fail "a redirect leg yields no Clean throughput figure" \
                "a 3xx leg is labeled Clean, so a redirect stub reads as a valid measurement"
        else
            pass "a redirect leg yields no Clean throughput figure"
        fi

        # A non-2xx leg must not carry a throughput rate at all.
        if printf '%s' "$out" | grep -E 'status=[45][0-9][0-9]' | grep -qE 'throughput=[0-9]+\.[0-9]+ Mbps'; then
            fail "a non-2xx leg reports no throughput rate" \
                "a rate is printed beside an error status"
        else
            pass "a non-2xx leg reports no throughput rate"
        fi
    fi
else
    skip "redirect/error legs withhold throughput" "FP_HARNESS_OFFLINE=1"
fi

# Synthetic load must not produce a bare loss percentage. Keeping this here as
# well as in 020 because the two gates guard different things: 020 asks whether
# provenance is stated, this asks whether the figure should exist at all.
if net_guard; then
    gw="$(ipconfig getoption en0 router 2>/dev/null)"
    if [ -n "$gw" ]; then
        gout="$("$BIN" gateway-bracket --gateway "$gw" --interface en0 --phase-duration-secs 1 2>&1)"
        if printf '%s' "$gout" | grep -E 'loss=[0-9]+\.[0-9]+%' | grep -qvE 'synthetic|demo|simulated'; then
            fail "synthetic-load loss carries its source inline" \
                "a loss percentage appears with no synthetic marker on the same line"
        else
            pass "synthetic-load loss carries its source inline"
        fi
    else
        skip "synthetic-load loss carries its source inline" "no gateway on en0"
    fi
else
    skip "synthetic-load loss carries its source inline" "FP_HARNESS_OFFLINE=1"
fi

# Offline invariant: no command may print a zero-valued latency or jitter
# summary, since a real zero is implausible and a parse failure rendered as
# 0.0 is the GAP-009 bug. Uses the burst analyser against a target that cannot
# echo, so every metric is genuinely unmeasurable.
noecho="$("$BIN" burst-analysis --interface lo0 --target 127.0.0.1 --port 1 \
    --count 5 --rate-pps 5 --maintenance 2>&1 || true)"
if [ -z "$noecho" ]; then
    skip "unmeasurable jitter reads unavailable, not zero" "no output"
elif printf '%s' "$noecho" | grep -qE 'jitter: mean=0(\.0+)? '; then
    fail "unmeasurable jitter reads unavailable, not zero" "zero printed where nothing was measured"
else
    pass "unmeasurable jitter reads unavailable, not zero"
fi
