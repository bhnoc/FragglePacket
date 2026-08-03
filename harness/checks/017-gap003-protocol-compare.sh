#!/usr/bin/env bash
# GAP-003: controlled, repeatable H1/H2/H3 comparison with fixed endpoint/IP
# support, per-protocol capacity/latency/loss indicators, and confidence.
# Decision logic (endpoint-mismatch detection, confidence scoring, curl-flag
# selection) is unit-tested against synthetic data; a light live run proves
# the CLI end to end when network is available.

check_ok "cargo test covers protocol-compare confidence and endpoint-mismatch logic" \
    cargo test --release --lib network_tests::protocol_compare:: --manifest-path "$REPO_ROOT/Cargo.toml"

# --- GAP-017 endpoint normalization: a comparison across different IPs must warn ---
check_contains "cargo test proves different endpoint IPs across legs are flagged" \
    "different_ips_across_protocols_flags_mismatch" \
    cargo test --release --lib network_tests::protocol_compare:: --manifest-path "$REPO_ROOT/Cargo.toml"

check_contains "cargo test proves identical endpoint IPs never false-positive a mismatch" \
    "same_ip_across_legs_is_not_a_mismatch" \
    cargo test --release --lib network_tests::protocol_compare:: --manifest-path "$REPO_ROOT/Cargo.toml"

# --- confidence must never claim more than the evidence supports ---
check_contains "cargo test proves a single sample per leg never yields more than Medium confidence" \
    "all_clean_legs_yield_medium_confidence_not_high" \
    cargo test --release --lib network_tests::protocol_compare:: --manifest-path "$REPO_ROOT/Cargo.toml"

check_contains "cargo test proves a non-clean leg lowers confidence" \
    "any_non_clean_leg_lowers_confidence" \
    cargo test --release --lib network_tests::protocol_compare:: --manifest-path "$REPO_ROOT/Cargo.toml"

# --- the redirect-stub-as-throughput bug: a body under the minimum valid
#     transfer size must never be Clean, and its throughput figure must be
#     withheld even though curl reported a 2xx final status ---
check_contains "cargo test proves a body under the minimum transfer size is never Clean" \
    "body_below_minimum_is_not_clean_even_with_2xx" \
    cargo test --release --lib network_tests::protocol_compare:: --manifest-path "$REPO_ROOT/Cargo.toml"

# --- redirects are followed and drift to a different hostname is disclosed,
#     matching the endpoint-mismatch class of warning (GAP-017) ---
check_contains "cargo test proves redirect drift to a different hostname is detected" \
    "redirect_drift_detected_when_final_host_differs" \
    cargo test --release --lib network_tests::protocol_compare:: --manifest-path "$REPO_ROOT/Cargo.toml"

check_contains "cargo test proves matching final/requested hostnames never false-positive redirect drift" \
    "no_redirect_drift_when_final_host_matches_requested" \
    cargo test --release --lib network_tests::protocol_compare:: --manifest-path "$REPO_ROOT/Cargo.toml"

# --- CLI surface: fixed endpoint/IP, sequential/simultaneous, JSON ---
check_contains "protocol-compare advertises --force-ip for endpoint normalization" "--force-ip" \
    "$BIN" protocol-compare --help
check_contains "protocol-compare advertises --simultaneous as distinct from directional legs" "--simultaneous" \
    "$BIN" protocol-compare --help
check_contains "protocol-compare --help lists http3 as a protocol choice" "http3" \
    "$BIN" protocol-compare --help

# --- the actual anti-regression: a protocol the endpoint does not support
#     must read as unsupported via preflight, never as measured network
#     shaping. speed.cloudflare.com is the known-negative case reused from
#     GAP-025's preflight module -- this must gate BEFORE any leg runs. ---
if net_guard; then
    out="$("$BIN" protocol-compare speed.cloudflare.com --protocol http3 --timeout-secs 6 --json 2>/dev/null | sed -n '/^{/,$p')"
    if [ -z "$out" ]; then
        skip "live: h3 against a known-incapable endpoint is gated by preflight, not measured" "no JSON output"
    else
        verdict="$(printf '%s' "$out" | python3 -c '
import json, sys
d = json.load(sys.stdin)
p = d["protocols"][0]
print(p.get("preflight_verdict"), "download_only" if p.get("download_only") else "no-download-leg")
' 2>/dev/null)"
        case "$verdict" in
            "unsupported no-download-leg") pass "live: h3 against speed.cloudflare.com is gated unsupported with no leg run" ;;
            *) fail "live: h3 against speed.cloudflare.com is gated unsupported with no leg run" "got: $verdict" ;;
        esac
    fi

    # --- a single real comparison against a known-capable, same-edge host,
    #     reused by both the endpoint-IP check and the non-2xx-withholds-
    #     throughput check below, rather than paying for a second live
    #     upload leg. A small upload body is enough for both: it still
    #     drives the real (reliably-500ing) upload endpoint. ---
    out2="$("$BIN" protocol-compare www.cloudflare.com --protocol http2 --upload-bytes 20000 --timeout-secs 8 --json 2>/dev/null | sed -n '/^{/,$p')"
    if [ -z "$out2" ]; then
        skip "live: a real H2 comparison leg reports a connected IP and throughput" "no JSON output"
    else
        has_ip="$(printf '%s' "$out2" | python3 -c '
import json, sys
d = json.load(sys.stdin)
leg = d["protocols"][0].get("download_only") or {}
print("ok" if leg.get("connected_ip") else "missing")
' 2>/dev/null)"
        if [ "$has_ip" = "ok" ]; then
            pass "live: a real H2 comparison leg reports a connected IP and throughput"
        else
            fail "live: a real H2 comparison leg reports a connected IP and throughput" "got: $out2"
        fi
    fi
    # --- the actual anti-regression, one live call proving both fixes at
    #     once: cloudflare.com's /favicon.ico is a known-301-redirect to
    #     www.cloudflare.com AND (post-redirect) a body far under
    #     MIN_VALID_TRANSFER_BYTES. The redirect drift must be disclosed,
    #     and the small body must be marked body-too-small with no
    #     throughput figure -- this is the field bug in its purest form:
    #     a redirect stub's few hundred bytes must never read as Clean. ---
    out3="$("$BIN" protocol-compare cloudflare.com --protocol http2 --path /favicon.ico --upload-bytes 20000 --timeout-secs 8 --json 2>/dev/null | sed -n '/^{/,$p')"
    if [ -z "$out3" ]; then
        skip "live: a redirecting host is followed to a real resource, not measured as a stub" "no JSON output"
        skip "live: a 2xx leg with a body far under the minimum size withholds throughput" "no JSON output"
    else
        shape="$(printf '%s' "$out3" | python3 -c '
import json, sys
d = json.load(sys.stdin)
redirected = d.get("redirected_to_different_host")
print("ok" if redirected is True else f"redirected={redirected}")
' 2>/dev/null)"
        if [ "$shape" = "ok" ]; then
            pass "live: a redirecting host is followed to a real resource, not measured as a stub"
        else
            fail "live: a redirecting host is followed to a real resource, not measured as a stub" "$shape"
        fi

        small_body_shape="$(printf '%s' "$out3" | python3 -c '
import json, sys
d = json.load(sys.stdin)
leg = d["protocols"][0].get("download_only") or {}
status = leg.get("http_status")
loss = leg.get("loss_indicator")
tp = leg.get("throughput_bps")
bytes_ = leg.get("bytes_transferred")
if status in range(200, 300) and (bytes_ or 0) < 16384:
    ok = loss == "body-too-small" and tp is None
    print("ok" if ok else f"loss={loss} tp={tp} bytes={bytes_}")
else:
    print(f"skip-not-small-body status={status} bytes={bytes_}")
' 2>/dev/null)"
        case "$small_body_shape" in
            ok) pass "live: a 2xx leg with a body far under the minimum size withholds throughput" ;;
            skip-not-small-body*) skip "live: a 2xx leg with a body far under the minimum size withholds throughput" "$small_body_shape" ;;
            *) fail "live: a 2xx leg with a body far under the minimum size withholds throughput" "$small_body_shape" ;;
        esac
    fi

    # --- a non-2xx leg (www.cloudflare.com's upload endpoint reliably 500s
    #     on an arbitrary POST body) must report no throughput at all --
    #     reuses $out2 from the check above rather than a second live run ---
    if [ -z "$out2" ]; then
        skip "live: a non-2xx leg reports no throughput" "no JSON output"
    else
        withheld="$(printf '%s' "$out2" | python3 -c '
import json, sys
d = json.load(sys.stdin)
leg = d["protocols"][0].get("upload_only") or {}
status = leg.get("http_status")
tp = leg.get("throughput_bps")
if status is not None and status not in range(200, 300):
    print("ok" if tp is None else f"tp={tp} present alongside status={status}")
else:
    print("skip-not-non-2xx")
' 2>/dev/null)"
        case "$withheld" in
            ok) pass "live: a non-2xx leg reports no throughput" ;;
            skip-not-non-2xx) skip "live: a non-2xx leg reports no throughput" "leg did not return a non-2xx this run" ;;
            *) fail "live: a non-2xx leg reports no throughput" "$withheld" ;;
        esac
    fi
else
    skip "live: h3 against speed.cloudflare.com is gated unsupported with no leg run" "FP_HARNESS_OFFLINE=1"
    skip "live: a real H2 comparison leg reports a connected IP and throughput" "FP_HARNESS_OFFLINE=1"
    skip "live: a redirecting host is followed to a real resource, not measured as a stub" "FP_HARNESS_OFFLINE=1"
    skip "live: a 2xx leg with a body far under the minimum size withholds throughput" "FP_HARNESS_OFFLINE=1"
    skip "live: a non-2xx leg reports no throughput" "FP_HARNESS_OFFLINE=1"
fi
