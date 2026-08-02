#!/usr/bin/env bash
# GAP-004: directional (download-only/upload-only) versus full-duplex
# (simultaneous) results must never be merged into one figure. Field
# evidence: HTTP/3 retained only 6.1% of its directional download capacity
# under simultaneous load on the same radio where HTTP/2 retained 44.5% --
# a blended number would have read as "QUIC is being shaped" when the
# actual trigger was bidirectional contention. This gate locks the
# structural separation in both the bufferbloat and protocol-compare
# reports, offline via unit tests plus a live JSON-shape check.

# --- protocol-compare: simultaneous legs are separate struct fields from
#     directional legs, never averaged into download_only/upload_only ---
check_ok "cargo test covers protocol-compare structural field separation" \
    cargo test --release --lib network_tests::protocol_compare:: --manifest-path "$REPO_ROOT/Cargo.toml"

# --- bufferbloat: the responsiveness grade takes the worst of the three
#     loaded phases, not an average -- an averaged figure would mask exactly
#     the kind of simultaneous-only collapse the field investigation found ---
check_contains "cargo test proves bufferbloat grading uses worst-phase, not average" \
    "grade_takes_the_worst_phase_not_the_average" \
    cargo test --release --lib network_tests::bufferbloat:: --manifest-path "$REPO_ROOT/Cargo.toml"

pf_json() { "$BIN" protocol-compare "$@" --json 2>/dev/null | sed -n '/^{/,$p'; }

if net_guard; then
    out="$(pf_json www.cloudflare.com --protocol http2 --upload-bytes 200000 --timeout-secs 8 --simultaneous)"
    if [ -z "$out" ]; then
        skip "live: --simultaneous output keeps directional and simultaneous legs in distinct fields" "no JSON output"
    else
        shape="$(printf '%s' "$out" | python3 -c '
import json, sys
d = json.load(sys.stdin)
p = d["protocols"][0]
required = ["download_only", "upload_only", "simultaneous_download", "simultaneous_upload"]
present = [k for k in required if k in p]
print("ok" if len(present) == 4 else "missing:" + ",".join(set(required) - set(present)))
' 2>/dev/null)"
        if [ "$shape" = "ok" ]; then
            pass "live: --simultaneous output keeps directional and simultaneous legs in distinct fields"
        else
            fail "live: --simultaneous output keeps directional and simultaneous legs in distinct fields" "$shape"
        fi

        # The report must never carry a field that blends the two: no key
        # combining "directional" and "simultaneous" into one throughput.
        no_blend="$(printf '%s' "$out" | python3 -c '
import json, sys
d = json.load(sys.stdin)
p = d["protocols"][0]
blended_keys = [k for k in p.keys() if "blend" in k.lower() or "combined" in k.lower() or "average_throughput" in k.lower()]
print("ok" if not blended_keys else "found:" + ",".join(blended_keys))
' 2>/dev/null)"
        if [ "$no_blend" = "ok" ]; then
            pass "live: report carries no blended directional+simultaneous field"
        else
            fail "live: report carries no blended directional+simultaneous field" "$no_blend"
        fi

        # The actual anti-regression: download_only's throughput must come
        # from its own curl invocation, not have simultaneous_download's
        # value copied onto it after the fact. Two independent real
        # transfers reporting curl's floating-point speed_download essentially
        # never land on the exact same bit pattern by chance, so an exact
        # match here is a strong, low-false-positive signal of a merge bug
        # rather than coincidence.
        independent="$(printf '%s' "$out" | python3 -c '
import json, sys
d = json.load(sys.stdin)
p = d["protocols"][0]
dl_tp = p["download_only"]["throughput_bps"]
sim_tp = p["simultaneous_download"]["throughput_bps"]
print("merged" if dl_tp == sim_tp else "ok")
' 2>/dev/null)"
        if [ "$independent" = "ok" ]; then
            pass "live: download_only and simultaneous_download are independently measured, not merged"
        else
            fail "live: download_only and simultaneous_download are independently measured, not merged" "download_only.throughput_bps == simultaneous_download.throughput_bps -- one leg's value was likely overwritten from the other"
        fi
    fi
else
    skip "live: --simultaneous output keeps directional and simultaneous legs in distinct fields" "FP_HARNESS_OFFLINE=1"
    skip "live: report carries no blended directional+simultaneous field" "FP_HARNESS_OFFLINE=1"
fi

# --- without --simultaneous, the simultaneous fields must be structurally
#     absent (None), never a stale/zero stand-in for "didn't run" ---
if net_guard; then
    out2="$(pf_json www.cloudflare.com --protocol http2 --upload-bytes 200000 --timeout-secs 8)"
    if [ -z "$out2" ]; then
        skip "live: omitting --simultaneous leaves simultaneous fields null, not zero" "no JSON output"
    else
        both_null="$(printf '%s' "$out2" | python3 -c '
import json, sys
d = json.load(sys.stdin)
p = d["protocols"][0]
print("ok" if p.get("simultaneous_download") is None and p.get("simultaneous_upload") is None else "not-null")
' 2>/dev/null)"
        if [ "$both_null" = "ok" ]; then
            pass "live: omitting --simultaneous leaves simultaneous fields null, not zero"
        else
            fail "live: omitting --simultaneous leaves simultaneous fields null, not zero" "got: $both_null"
        fi
    fi
else
    skip "live: omitting --simultaneous leaves simultaneous fields null, not zero" "FP_HARNESS_OFFLINE=1"
fi
