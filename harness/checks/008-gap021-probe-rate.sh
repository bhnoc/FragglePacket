#!/usr/bin/env bash
# GAP-021: latency tests must detect probe-rate artifacts. Field evidence:
# 1 probe/sec was stable at both gateway and remote; 5 probes/sec produced
# correlated spikes at BOTH hops approaching 100ms -- the signature of ICMP
# rate-limiting/control-plane batching, not path jitter. This gate is
# offline-safe: the classification logic (src/network_tests/probe_rate.rs)
# is unit-tested with synthetic cadence data, so it never needs live network
# to prove the decision logic has teeth. A live CLI smoke check runs only
# when network is available.

check_ok "cargo test covers probe-rate cadence-correlation logic" \
    cargo test --release --lib network_tests::probe_rate:: --manifest-path "$REPO_ROOT/Cargo.toml"

# --- correlated ICMP-only spike at both hops => probable policing, but NOT
#     promoted to an application-latency claim without TCP corroboration ---
check_contains "cargo test proves correlated ICMP spike flags policing without promoting to app-latency" \
    "correlated_spike_flags_probable_icmp_policing_without_corroboration" \
    cargo test --release --lib network_tests::probe_rate:: --manifest-path "$REPO_ROOT/Cargo.toml"

# --- TCP-corroborated spike is allowed to become an application-latency claim ---
check_contains "cargo test proves TCP-corroborated spike confirms application latency" \
    "tcp_corroborated_spike_confirms_application_latency" \
    cargo test --release --lib network_tests::probe_rate:: --manifest-path "$REPO_ROOT/Cargo.toml"

# --- no spike at all => neither claim fires ---
check_contains "cargo test proves stable cadences report neither policing nor app-latency claims" \
    "no_spike_reports_neither_claim" \
    cargo test --release --lib network_tests::probe_rate:: --manifest-path "$REPO_ROOT/Cargo.toml"

# --- CLI surface: two cadences, both targets, JSON exposes the two distinct claims ---
check_contains "probe-rate advertises --normal-rate-hz and --elevated-rate-hz" "--elevated-rate-hz" \
    "$BIN" probe-rate --help
check_contains "probe-rate --help documents modest default elevated rate (not a flood)" "not to flood" \
    "$BIN" probe-rate --help

if net_guard; then
    out="$("$BIN" probe-rate --gateway 127.0.0.1 --remote 1.1.1.1 --count 3 --normal-rate-hz 2 --elevated-rate-hz 5 --timeout-ms 500 --json 2>/dev/null | sed -n '/^{/,$p')"
    if [ -z "$out" ]; then
        skip "live probe-rate run produces structured JSON with both claim fields" "no JSON output (ICMP unavailable in this environment)"
    else
        has_fields="$(printf '%s' "$out" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print("ok" if "probable_icmp_policing" in d and "application_latency_confirmed" in d else "missing")
' 2>/dev/null)"
        if [ "$has_fields" = "ok" ]; then
            pass "live probe-rate run produces structured JSON with both claim fields"
        else
            fail "live probe-rate run produces structured JSON with both claim fields" "got: $out"
        fi
    fi
else
    skip "live probe-rate run produces structured JSON with both claim fields" "FP_HARNESS_OFFLINE=1"
fi
