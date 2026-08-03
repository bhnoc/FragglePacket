#!/usr/bin/env bash
# GAP-029: A-only / B-only / dual-active comparison from an operator manifest.
#
# Two things are locked here. First, FragglePacket must never change production
# routing: circuit state is a label the operator supplies after performing the
# failover in an approved window. Second, a verdict must be refused when the
# evidence is incomplete, naming what is missing -- a verdict from half the
# picture would point a provider escalation at the wrong circuit.

check_ok "cargo test covers circuit verdict and refusal logic" \
    cargo test --release --quiet --lib --manifest-path "$REPO_ROOT/Cargo.toml" circuit_workflow

MANIFESTS="$FIXTURE_DIR/manifests"

# --- the routing-safety invariant -------------------------------------------
# No flag may exist that performs or requests a failover. Assert on the help
# surface rather than a specific implementation detail.
for forbidden in --failover --switch-circuit --activate --deactivate --set-circuit --bring-down; do
    if "$BIN" circuit-compare --help 2>&1 | grep -q -- "$forbidden"; then
        fail "circuit-compare exposes no routing-change flag" "found $forbidden"
        break
    fi
done
"$BIN" circuit-compare --help 2>&1 | grep -q -- "--manifest" \
    && pass "circuit-compare exposes no routing-change flag"

check_contains "help states routing is never changed" "never changes routing" \
    "$BIN" circuit-compare --help

check_contains "human output restates that routing is untouched" "never initiates a failover" \
    "$BIN" circuit-compare --manifest "$MANIFESTS/circuit-shared.json"

# --- refusal on incomplete evidence -----------------------------------------
check_contains "an incomplete manifest refuses a verdict" "REFUSED" \
    "$BIN" circuit-compare --manifest "$MANIFESTS/circuit-refuse.json"

check_contains "the refusal names the missing b-only phase" "phase:b-only" \
    "$BIN" circuit-compare --manifest "$MANIFESTS/circuit-refuse.json"

check_contains "the refusal names the missing dual-active phase" "phase:dual-active" \
    "$BIN" circuit-compare --manifest "$MANIFESTS/circuit-refuse.json"

# An incomplete manifest must not produce a member attribution of any kind.
check_lacks "an incomplete manifest never implicates a member" "member-specific" \
    "$BIN" circuit-compare --manifest "$MANIFESTS/circuit-refuse.json"

# --- the negative finding must be stated positively --------------------------
# The field port sweep found no bimodal split, which argued AGAINST one bad
# member. That has to be a reportable conclusion, not an inconclusive shrug.
check_contains "symmetric members report a shared cause" "shared, not member-specific" \
    "$BIN" circuit-compare --manifest "$MANIFESTS/circuit-shared.json"

check_contains "the shared verdict explains why one bad member is unsupported" \
    "a single bad member is not supported" \
    "$BIN" circuit-compare --manifest "$MANIFESTS/circuit-shared.json"

# --- reproducibility ---------------------------------------------------------
d1="$("$BIN" circuit-compare --manifest "$MANIFESTS/circuit-shared.json" --digest-only 2>/dev/null | grep -oE '[0-9a-f]{16}')"
d2="$("$BIN" circuit-compare --manifest "$MANIFESTS/circuit-shared.json" --digest-only 2>/dev/null | grep -oE '[0-9a-f]{16}')"
if [ -n "$d1" ] && [ "$d1" = "$d2" ]; then
    pass "the manifest digest is reproducible across runs"
else
    fail "the manifest digest is reproducible across runs" "got '$d1' then '$d2'"
fi

dr="$("$BIN" circuit-compare --manifest "$MANIFESTS/circuit-refuse.json" --digest-only 2>/dev/null | grep -oE '[0-9a-f]{16}')"
if [ -n "$dr" ] && [ "$dr" != "$d1" ]; then
    pass "a different manifest yields a different digest"
else
    fail "a different manifest yields a different digest" "digests collided or were empty"
fi

check_json_field "json output carries the verdict" "verdict" \
    "$BIN" circuit-compare --manifest "$MANIFESTS/circuit-shared.json" --json
check_json_field "json output carries the digest" "digest" \
    "$BIN" circuit-compare --manifest "$MANIFESTS/circuit-shared.json" --json

check_fails "a missing manifest file errors rather than assuming defaults" \
    "$BIN" circuit-compare --manifest "$WORK_DIR/definitely-not-here.json"
