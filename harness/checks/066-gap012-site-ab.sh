#!/usr/bin/env bash
# GAP-012: affected-site vs known-good-control A/B workflow. Drives
# protocol_compare::run_comparison against a named failing site and a
# known-good control. The must-lock clause: a redirected affected URL must
# surface that, never silently compare a stub's throughput.

check_ok "cargo test covers site-ab comparison and redirect-refusal logic" \
    cargo test --release --lib network_tests::site_ab:: --manifest-path "$REPO_ROOT/Cargo.toml"

check_contains "cargo test proves an affected-side redirect refuses throughput comparison" \
    "an_affected_side_redirect_refuses_throughput_comparison_rather_than_comparing_a_stub" \
    cargo test --release --lib network_tests::site_ab:: --manifest-path "$REPO_ROOT/Cargo.toml"

check_contains "cargo test proves a control-side redirect is also named distinctly" \
    "a_control_side_redirect_is_also_named_distinctly" \
    cargo test --release --lib network_tests::site_ab:: --manifest-path "$REPO_ROOT/Cargo.toml"

check_contains "cargo test proves no clean sample withholds rather than dividing by zero" \
    "no_clean_sample_on_either_side_withholds_rather_than_dividing_by_zero" \
    cargo test --release --lib network_tests::site_ab:: --manifest-path "$REPO_ROOT/Cargo.toml"

check_contains "site-ab advertises --affected-host and --control-host" "--affected-host" \
    "$BIN" site-ab --help
check_contains "site-ab advertises --control-host" "--control-host" \
    "$BIN" site-ab --help
check_contains "site-ab advertises --affected-force-ip for endpoint pinning" "--affected-force-ip" \
    "$BIN" site-ab --help
check_contains "site-ab advertises --repeat-samples" "--repeat-samples" \
    "$BIN" site-ab --help
check_contains "site-ab --help lists http3 as a protocol choice" "http3" \
    "$BIN" site-ab --help

check_fails "site-ab requires both --affected-host and --control-host" \
    "$BIN" site-ab --affected-host example.com

# --- live: the exact field bug this workflow exists to prevent. cloudflare.com
#     redirects to www.cloudflare.com; the A/B must surface that rather than
#     comparing a stub leg's few hundred bytes as throughput. ---
if net_guard; then
    out="$("$BIN" site-ab --affected-host example.com --control-host cloudflare.com --protocol http2 \
        --repeat-samples 1 --timeout-secs 8 --json 2>/dev/null | sed -n '/^{/,$p')"
    if [ -z "$out" ]; then
        skip "live site-ab redirect surfacing" "no output captured (network unavailable?)"
    elif printf '%s' "$out" | grep -q "RedirectedRatherThanCompared"; then
        pass "live run surfaces the control-side redirect rather than comparing a stub"
    else
        fail "live run surfaces the control-side redirect rather than comparing a stub" \
            "$(printf '%s' "$out" | tail -5 | tr '\n' ' ')"
    fi
else
    skip "live site-ab redirect surfacing" "FP_HARNESS_OFFLINE=1"
fi
