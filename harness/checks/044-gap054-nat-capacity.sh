#!/usr/bin/env bash
# GAP-054: creating enough session state to find a firewall/NAT ceiling is
# indistinguishable from a resource-exhaustion attack without an approved
# window, so the disruptive subset must refuse to run without an explicit,
# non-empty authorization statement. The observational subset (idle-mapping
# survival) is safe and must remain the default. This gate also locks that
# hitting this machine's own socket limit is never reported as a confirmed
# remote firewall ceiling -- the exact "plausible value for a missing
# measurement" bug this project keeps re-finding, here at the infrastructure-
# attribution layer.

check_ok "cargo test covers authorization gate / local-vs-remote classification / correlation logic" \
    cargo test --release --lib network_tests::nat_capacity:: --manifest-path "$REPO_ROOT/Cargo.toml"

check_contains "nat-capacity advertises --probe-session-rate" "--probe-session-rate" \
    "$BIN" nat-capacity --help
check_contains "nat-capacity advertises --authorized" "--authorized" \
    "$BIN" nat-capacity --help

# --- the central regression: capacity mode without authorization refuses to start ---
check_fails "capacity-probing without --authorized refuses to start" \
    "$BIN" nat-capacity --target 127.0.0.1 --port 1 --probe-session-rate
check_contains "the refusal names what is missing (an authorization statement)" \
    "requires --authorized" \
    "$BIN" nat-capacity --target 127.0.0.1 --port 1 --probe-session-rate

# --- an empty/whitespace authorization is not accepted as a real statement ---
check_fails "an empty --authorized string still refuses" \
    "$BIN" nat-capacity --target 127.0.0.1 --port 1 --probe-session-rate --authorized ""

# --- the non-disruptive subset (idle mapping) is the default: no --probe-session-rate needed ---
default_out="$("$BIN" nat-capacity --target 192.0.2.1 --idle-secs 0 2>&1)"
check_contains "default run performs the safe idle-mapping observation" "idle mapping" \
    bash -c 'printf "%s" "$1"' _ "$default_out"
check_contains "default run states the session-rate probe was not run" "session-rate probe not run (safe default)" \
    bash -c 'printf "%s" "$1"' _ "$default_out"
check_lacks "default run never attempts session creation" "session rate: attempted" \
    bash -c 'printf "%s" "$1"' _ "$default_out"

# --- unmeasurable idle-mapping reads as unknown, never coerced true/false ---
check_contains "an unresponsive target reads still-responsive as unknown, not false" \
    "unknown (no reply observed)" \
    bash -c 'printf "%s" "$1"' _ "$default_out"

# --- local-vs-remote distinction is real, not just a type that exists ---
check_ok "cargo test proves local resource exhaustion blocks remote-ceiling attribution" \
    cargo test --release --lib network_tests::nat_capacity::tests::local_exhaustion_blocks_remote_ceiling_attribution \
    --manifest-path "$REPO_ROOT/Cargo.toml"
check_ok "cargo test proves EMFILE classifies as local, not remote" \
    cargo test --release --lib network_tests::nat_capacity::tests::emfile_is_classified_as_local_resource_exhaustion \
    --manifest-path "$REPO_ROOT/Cargo.toml"

# --- correlation is withheld and names what's missing when telemetry is absent ---
check_ok "cargo test proves missing telemetry withholds correlation and names it" \
    cargo test --release --lib network_tests::nat_capacity::tests::missing_telemetry_withholds_correlation_and_names_it \
    --manifest-path "$REPO_ROOT/Cargo.toml"

# --- a real (authorized, local-only) session-rate run proves the mechanism works
# without exhausting anything: a handful of loopback sessions, not a stress test ---
if command -v iperf3 >/dev/null 2>&1; then
    PORT=15801
    iperf3 -s -p "$PORT" -D >/dev/null 2>&1
    sleep 0.3

    real_out="$("$BIN" nat-capacity --target 127.0.0.1 --port "$PORT" --probe-session-rate \
        --authorized "harness gate, loopback-only mechanism proof" --idle-secs 0 \
        --rate-mbps 1 --max-duration-secs 2 --max-concurrency 2 --interface lo0 2>&1)"
    pkill -f "iperf3 -s -p $PORT" 2>/dev/null

    created="$(printf '%s' "$real_out" | grep -oE 'created=[0-9]+' | head -1 | cut -d= -f2)"
    if [ -n "$created" ] && [ "$created" -gt 0 ] 2>/dev/null; then
        pass "authorized local session-rate probe creates sessions against a real loopback listener ($created)"
    else
        fail "authorized local session-rate probe creates sessions" "got: $real_out"
    fi
    check_contains "an uninterrupted run withholds remote-ceiling evidence rather than fabricating it" \
        "remote ceiling evidence: WITHHELD" \
        bash -c 'printf "%s" "$1"' _ "$real_out"
else
    skip "authorized local session-rate probe" "iperf3 not installed"
fi
