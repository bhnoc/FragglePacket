#!/usr/bin/env bash
# Endpoints that were exercised and failed must be recorded as failures, and
# never handed back out.
#
# Operators were hand-typing endpoints, so the ports already known to refuse or
# fail admission got retried every session. The deeper risk is GAP-045's: a
# port-open check is not admission validation. Eight of twenty-one probes in one
# fanout never established a connection after their port checks passed, and
# recording those as 0 Mbps would have implicated nine working clients. So a
# known-bad endpoint is refused, and its record explicitly says it is not a
# zero-throughput result.

check_ok "cargo test covers registry selection and known-bad filtering" \
    cargo test --release --quiet --lib --manifest-path "$REPO_ROOT/Cargo.toml" endpoint_registry

# --- the registry file itself -----------------------------------------------
REG="$FIXTURE_DIR/endpoints/public-iperf.json"
if [ ! -f "$REG" ]; then
    fail "the endpoint registry exists" "$REG missing"
else
    pass "the endpoint registry exists"
    check_ok "the registry is valid JSON" python3 -c "import json;json.load(open('$REG'))"
fi

# --- known-bad ports are refused, not retried -------------------------------
# This is the central regression. Every port the field exercised and lost must
# refuse, with a non-zero exit so a script cannot proceed past it.
for port in 5200 5202 5203 5204 5205 5206; do
    if "$BIN" endpoints --check "speedtest.xmission.com:$port" >/dev/null 2>&1; then
        fail "port $port is refused as known-bad" "it was accepted"
    else
        pass "port $port is refused as known-bad"
    fi
done

check_contains "the refusal states it is not a zero-throughput result" "zero throughput" \
    "$BIN" endpoints --check speedtest.xmission.com:5202

check_contains "the refusal explains why it matters" "implicated nine working clients" \
    "$BIN" endpoints --check speedtest.xmission.com:5202

# A verified listener must still pass, or the guard is useless.
check_ok "a verified listener is not refused" \
    "$BIN" endpoints --check speedtest.xmission.com:5201

# --- the lease allowlist cannot contain a known-bad port --------------------
allow="$("$BIN" endpoints --provider xmission --allowlist --json 2>/dev/null | sed -n '/^\[/,$p')"
if [ -z "$allow" ]; then
    fail "the allowlist is machine-readable" "no JSON emitted"
else
    pass "the allowlist is machine-readable"
    if printf '%s' "$allow" | python3 -c '
import json, sys
bad = {5200, 5202, 5203, 5204, 5205, 5206}
listeners = json.load(sys.stdin)
for l in listeners:
    if l.get("host") == "speedtest.xmission.com" and l.get("port") in bad:
        sys.stderr.write("known-bad port reached the allowlist\n")
        sys.exit(1)
sys.exit(0 if listeners else 1)
' 2>/dev/null; then
        pass "no known-bad port reaches the lease allowlist"
    else
        fail "no known-bad port reaches the lease allowlist" \
            "a port recorded as failing was handed to the lease layer"
    fi
fi

# Client source ports held 5-tuples stable across ECMP hash buckets. Probing
# them as listeners would be both wrong and rude.
if printf '%s' "$allow" | grep -qE '"port": 4001[0-9]'; then
    fail "client source ports never appear as listeners" "a 40010-40019 port is in the allowlist"
else
    pass "client source ports never appear as listeners"
fi

# --- per-direction selection carries its caveats ----------------------------
up="$("$BIN" endpoints --provider xmission --purpose upload 2>&1)"
check_contains "an upload listener is selectable" "speedtest.xmission.com:5201" printf '%s' "$up"
check_contains "selection states the endpoint loss floor" "loss floor" printf '%s' "$up"
check_contains "selection states the one-test-per-listener limit" "one test at a time" \
    printf '%s' "$up"
check_contains "selection warns the two directions use different paths" "DIFFERENT public paths" \
    printf '%s' "$up"

down="$("$BIN" endpoints --provider xmission --purpose download 2>&1)"
check_contains "a download listener is selectable" "iperf.soute.xmission.com" printf '%s' "$down"

# --- failure modes ----------------------------------------------------------
check_fails "an unknown provider errors rather than guessing" \
    "$BIN" endpoints --provider nope --purpose upload
check_contains "an unknown provider lists what is available" "available" \
    "$BIN" endpoints --provider nope --purpose upload
check_fails "an unmatched purpose errors rather than returning any listener" \
    "$BIN" endpoints --provider xmission --purpose multicast
check_fails "--allowlist without a provider errors" "$BIN" endpoints --allowlist

# The default listing must show the failures, not just the working endpoints.
listing="$("$BIN" endpoints 2>&1)"
check_contains "the default listing shows known-bad ports" "known bad" printf '%s' "$listing"
check_contains "the default listing explains why failures are listed" \
    "not a zero-throughput measurement" printf '%s' "$listing"
