#!/usr/bin/env bash
# GAP-026: on the external MGM control, Apple/Cloudflare/Google all
# negotiated MSS 1238 while 1500-byte DF probes succeeded -- strong evidence
# for a uniform TCP-specific clamp/proxy, NOT a 1280-byte PMTU ceiling,
# because a real PMTU ceiling would have broken those DF probes too. Contrast
# with the Black Hat WLANs, where MSS stayed destination-specific (Apple
# 1460, Cloudflare 1400, Google 1412). This locks the three-way verdict:
# converged MSS + passing large DF probe -> uniform-clamp-or-proxy, never
# true-pmtu-ceiling; destination-specific spread -> peer-specific.

mc_json() { "$BIN" mss-evidence "$@" --json 2>/dev/null | sed -n '/^{/,$p'; }

check_contains "mss-evidence advertises --destination/--large-df-probe-confirmed" "--destination" \
    "$BIN" mss-evidence --help
check_contains "mss-evidence advertises --confirm-df-target" "--confirm-df-target" \
    "$BIN" mss-evidence --help

# --- the MGM case: converged MSS + confirmed-passing large DF probe ---
mgm_out="$(mc_json --destination apple=1238 --destination cloudflare=1238 --destination google=1238 \
    --route-mtu 1500 --route-interface en0 --large-df-probe-confirmed true)"
if [ -z "$mgm_out" ]; then
    fail "MGM-case clustering produces JSON output" "empty output"
else
    verdict="$(printf '%s' "$mgm_out" | python3 -c 'import json,sys; print(json.load(sys.stdin)["verdict"])' 2>/dev/null)"
    if [ "$verdict" = "UniformClampOrProxy" ]; then
        pass "MGM case (converged MSS 1238, DF probe passes) reports uniform-clamp-or-proxy"
    else
        fail "MGM case (converged MSS 1238, DF probe passes) reports uniform-clamp-or-proxy" "got: $verdict"
    fi
    if [ "$verdict" = "TruePmtuCeiling" ]; then
        fail "MGM case must never report a true PMTU ceiling" "got: TruePmtuCeiling"
    else
        pass "MGM case never reports a true PMTU ceiling"
    fi
fi
check_contains "MGM case human output states uniform-clamp-or-proxy" "uniform-clamp-or-proxy" \
    "$BIN" mss-evidence --destination apple=1238 --destination cloudflare=1238 --destination google=1238 \
    --route-mtu 1500 --route-interface en0 --large-df-probe-confirmed true
check_lacks "MGM case human output never states true-pmtu-ceiling" "true-pmtu-ceiling" \
    "$BIN" mss-evidence --destination apple=1238 --destination cloudflare=1238 --destination google=1238 \
    --route-mtu 1500 --route-interface en0 --large-df-probe-confirmed true

# --- converged MSS but DF probe fails: this is the true-PMTU-ceiling case ---
ceiling_out="$(mc_json --destination a=1220 --destination b=1230 --route-mtu 1280 --large-df-probe-confirmed false)"
verdict="$(printf '%s' "$ceiling_out" | python3 -c 'import json,sys; print(json.load(sys.stdin)["verdict"])' 2>/dev/null)"
if [ "$verdict" = "TruePmtuCeiling" ]; then
    pass "converged MSS with a failing large DF probe reports true-pmtu-ceiling"
else
    fail "converged MSS with a failing large DF probe reports true-pmtu-ceiling" "got: $verdict"
fi

# --- the Black Hat WLAN case: destination-specific spread ---
bh_out="$(mc_json --destination apple=1460 --destination cloudflare=1400 --destination google=1412 \
    --route-mtu 1500 --route-interface en0 --large-df-probe-confirmed true)"
verdict="$(printf '%s' "$bh_out" | python3 -c 'import json,sys; print(json.load(sys.stdin)["verdict"])' 2>/dev/null)"
if [ "$verdict" = "PeerSpecific" ]; then
    pass "Black Hat WLAN case (MSS 1460/1400/1412) reports peer-specific"
else
    fail "Black Hat WLAN case (MSS 1460/1400/1412) reports peer-specific" "got: $verdict"
fi

# --- fewer than two destinations, or missing DF evidence, is inconclusive ---
one_dest_out="$(mc_json --destination apple=1238)"
verdict="$(printf '%s' "$one_dest_out" | python3 -c 'import json,sys; print(json.load(sys.stdin)["verdict"])' 2>/dev/null)"
if [ "$verdict" = "Inconclusive" ]; then
    pass "a single destination reports inconclusive, not a cluster verdict"
else
    fail "a single destination reports inconclusive, not a cluster verdict" "got: $verdict"
fi

no_df_out="$(mc_json --destination apple=1238 --destination cloudflare=1238)"
verdict="$(printf '%s' "$no_df_out" | python3 -c 'import json,sys; print(json.load(sys.stdin)["verdict"])' 2>/dev/null)"
if [ "$verdict" = "Inconclusive" ]; then
    pass "converged MSS with no DF-probe evidence reports inconclusive, not a forced verdict"
else
    fail "converged MSS with no DF-probe evidence reports inconclusive, not a forced verdict" "got: $verdict"
fi

# --- a tunnel default route must be surfaced, never silently used as "the network" ---
check_contains "tunnel route interface is flagged in human output" "TUNNEL" \
    "$BIN" mss-evidence --destination a=1400 --destination b=1400 --route-mtu 1412 --route-interface utun6 --large-df-probe-confirmed true
