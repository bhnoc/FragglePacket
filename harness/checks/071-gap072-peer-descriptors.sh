#!/usr/bin/env bash
# GAP-072: a peer-impact test that cannot record the peer's own state produces an
# unfalsifiable 1:many verdict.
#
# The 2026-08-02 coordinated run measured severe degradation on the loading
# client, but the peer's mode, listener ports, association, and timestamps were
# never captured. The two candidate explanations then invert the conclusion from
# identical numbers: if the peer loaded the same public listeners, listener
# admission is a confound; if the peer was passive, the same figures record
# background impairment instead. Evidence that cannot distinguish those is not
# evidence.
#
# GAP-051's command carries this. These checks lock it as its own gap so the
# requirement survives a refactor of the fairness work.

check_ok "cargo test covers cross-client descriptor requirements" \
    cargo test --release --quiet --lib --manifest-path "$REPO_ROOT/Cargo.toml" multiclient_fairness

# --- both descriptors must exist -------------------------------------------
check_contains "each role can emit its own descriptor" "--emit-descriptor" \
    "$BIN" multiclient-fairness --help
check_contains "a role must declare loading or observing" "--role" \
    "$BIN" multiclient-fairness --help

# One side alone can never yield a verdict.
out_a="$("$BIN" multiclient-fairness --descriptor-a "$WORK_DIR/nope-a.json" 2>&1 || true)"
if printf '%s' "$out_a" | grep -qiE "refus|missing|error|could not"; then
    pass "a single descriptor never yields a cross-client verdict"
else
    fail "a single descriptor never yields a cross-client verdict" \
        "one-sided input produced: $(printf '%s' "$out_a" | tail -2 | tr '\n' ' ')"
fi

# --- phase windows must actually overlap -----------------------------------
# Two clients measured at different times say nothing about each other.
check_contains "non-overlapping phase windows are refused" "REFUSED" \
    "$BIN" multiclient-fairness --inject-fixture no-overlap
check_contains "the refusal explains the windows did not overlap" "do not overlap" \
    "$BIN" multiclient-fairness --inject-fixture no-overlap
check_lacks "a non-overlapping run never reports a fairness index value" \
    "Jain fairness index: 0" "$BIN" multiclient-fairness --inject-fixture no-overlap

# --- shared listeners are a labeled confound, not a result -----------------
check_contains "shared listeners between roles are surfaced" "shared listeners" \
    "$BIN" multiclient-fairness --inject-fixture shared-listener
check_contains "shared listeners are labeled a confound rather than a fault" \
    "contention confound, not a network fault" \
    "$BIN" multiclient-fairness --inject-fixture shared-listener

# --- fairness needs samples from independent roles -------------------------
# A Jain index computed from one side's data is meaningless, so it must be
# withheld rather than computed from whatever is available.
check_contains "fairness is withheld without samples from independent roles" \
    "unavailable" "$BIN" multiclient-fairness --inject-fixture shared-listener

# --- privacy ---------------------------------------------------------------
for fixture in no-overlap shared-listener; do
    out="$("$BIN" multiclient-fairness --inject-fixture "$fixture" 2>&1 || true)"
    if printf '%s' "$out" | grep -qE '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}'; then
        fail "descriptor output carries no MAC/BSSID ($fixture)" "MAC-shaped token present"
    else
        pass "descriptor output carries no MAC/BSSID ($fixture)"
    fi
done
