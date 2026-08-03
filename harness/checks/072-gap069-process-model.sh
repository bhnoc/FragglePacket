#!/usr/bin/env bash
# GAP-069: process-model equivalence and receive-path artifact guard.
#
# Field evidence (PV10, 250 Mbps-per-direction target): native `iperf3
# --bidir` stayed roughly balanced at 145-161 Mbps per direction with zero
# TCPRcvCollapsed, while the two-process/two-listener method
# (`independent_rates`) was often severely asymmetric with 70-102
# receive-collapse events per trial, at similar combined throughput
# (302-326 Mbps in both). This gate locks:
#   1. TCPRcvCollapsed/softnet/qdisc counters report platform-limited on
#      this (macOS) host, never a bare zero -- the central regression.
#   2. A directional-collapse verdict is withheld unless both process
#      models were measured, naming what is missing.
#   3. Shared-capacity saturation (similar combined throughput, differing
#      split) is classified distinctly from method-specific unfairness.
#   4. Ingested Linux counters round-trip without inventing absent fields.

cargo_test() { cargo test --release --lib load_guard::process_model:: --manifest-path "$REPO_ROOT/Cargo.toml" "$@"; }

check_ok "cargo test covers process-model equivalence guard logic" cargo_test

check_contains "cargo test proves platform-limited counters never report a bare zero" \
    "platform_limited_counters_never_report_a_bare_zero" cargo_test
check_contains "cargo test proves live sampling on this host is platform-limited, not zero" \
    "live_sample_on_this_host_is_platform_limited_not_zero" cargo_test
check_contains "cargo test proves absent counter lines parse to None, not zero" \
    "absent_counter_line_parses_to_none_not_zero" cargo_test
check_contains "cargo test proves ingest round-trips present fields without inventing absent ones" \
    "external_telemetry_round_trips_present_fields_as_operator_supplied" cargo_test
check_contains "cargo test proves a verdict is withheld when the paired-process trial is missing" \
    "verdict_is_withheld_when_paired_process_trial_is_missing" cargo_test
check_contains "cargo test proves a verdict is withheld when the native-bidir trial is missing" \
    "verdict_is_withheld_when_native_trial_is_missing" cargo_test
check_contains "cargo test proves the PV10 field shape is method-specific, not a network verdict" \
    "pv10_field_shape_is_method_specific_unfairness_not_a_network_verdict" cargo_test
check_contains "cargo test proves shared-capacity saturation is named distinctly in the verdict" \
    "shared_capacity_saturation_is_named_distinctly_within_the_verdict" cargo_test
check_contains "cargo test proves a collapse reproducing across both models is network-attributable" \
    "imbalance_reproducing_in_both_models_is_network_attributable" cargo_test

# The macOS-live central regression, asserted directly against the real
# binary and the real host command, not just the unit test above: this
# machine genuinely lacks the counter (verified independently of the CLI),
# and the CLI must say so explicitly rather than printing 0.
if netstat -s -p tcp 2>/dev/null | grep -qi collaps; then
    skip "host genuinely lacks TCPRcvCollapsed (regression not exercisable here)" "netstat -s -p tcp reports a collapse line on this host"
else
    out="$("$BIN" process-model --inject-fixture pv10-collapse 2>&1)"
    if printf '%s' "$out" | grep -qE 'TCPRcvCollapsed=platform-limited'; then
        pass "native-side TCPRcvCollapsed reports platform-limited on this macOS host"
    else
        fail "native-side TCPRcvCollapsed reports platform-limited on this macOS host" \
            "expected 'TCPRcvCollapsed=platform-limited' in output :: $(printf '%s' "$out" | tail -5 | tr '\n' ' ')"
    fi
    if printf '%s' "$out" | grep -qE 'TCPRcvCollapsed=0([^0-9]|$)'; then
        fail "TCPRcvCollapsed is never printed as a bare zero on this host" \
            "found a literal zero-valued TCPRcvCollapsed, which would falsely exonerate the paired-process method"
    else
        pass "TCPRcvCollapsed is never printed as a bare zero on this host"
    fi
fi

json_get() { python3 -c '
import json, sys
d = json.load(sys.stdin)
path = sys.argv[1]
cur = d
for part in path.split("."):
    if isinstance(cur, dict):
        cur = cur.get(part)
    elif isinstance(cur, list):
        try: cur = cur[int(part)]
        except Exception: cur = None
    else:
        cur = None
print(json.dumps(cur))
' "$1"; }

strip_banner() { sed -n '/^[[{]/,$p'; }

# 1. pv10-collapse fixture: paired-only collapse must classify as
#    method-specific unfairness, never as a bare network-attributable
#    collapse, and must name shared-capacity saturation.
pv10_json="$("$BIN" process-model --inject-fixture pv10-collapse --json 2>/dev/null | strip_banner)"
verdict_kind="$(printf '%s' "$pv10_json" | json_get verdict | python3 -c 'import json,sys; v=json.load(sys.stdin); print(list(v.keys())[0] if isinstance(v, dict) else v)' 2>/dev/null)"
if [ "$verdict_kind" = "MethodSpecificUnfairness" ]; then
    pass "PV10 field-evidence fixture classifies as MethodSpecificUnfairness"
else
    fail "PV10 field-evidence fixture classifies as MethodSpecificUnfairness" "got verdict kind '$verdict_kind'"
fi
detail="$(printf '%s' "$pv10_json" | json_get verdict.MethodSpecificUnfairness.detail)"
if printf '%s' "$detail" | grep -q "shared-capacity saturation"; then
    pass "PV10 verdict detail names shared-capacity saturation distinctly"
else
    fail "PV10 verdict detail names shared-capacity saturation distinctly" "detail: $detail"
fi
tcp_collapsed="$(printf '%s' "$pv10_json" | json_get paired_process.receive_path.tcp_rcv_collapsed.value)"
if [ "$tcp_collapsed" != "null" ] && [ -n "$tcp_collapsed" ]; then
    pass "paired-process trial carries an ingested TCPRcvCollapsed value in the PV10 fixture"
else
    fail "paired-process trial carries an ingested TCPRcvCollapsed value in the PV10 fixture" "value was null"
fi

# 2. reproduces fixture: collapse in both models is network-attributable.
repro_json="$("$BIN" process-model --inject-fixture reproduces --json 2>/dev/null | strip_banner)"
repro_kind="$(printf '%s' "$repro_json" | json_get verdict | python3 -c 'import json,sys; v=json.load(sys.stdin); print(list(v.keys())[0] if isinstance(v, dict) else v)' 2>/dev/null)"
if [ "$repro_kind" = "ReproducesAcrossProcessModels" ]; then
    pass "a collapse reproducing in both process models is classified network-attributable"
else
    fail "a collapse reproducing in both process models is classified network-attributable" "got verdict kind '$repro_kind'"
fi

# 3. balanced fixture: no collapse in either model.
bal_json="$("$BIN" process-model --inject-fixture balanced --json 2>/dev/null | strip_banner)"
bal_kind="$(printf '%s' "$bal_json" | json_get verdict)"
if [ "$bal_kind" = '"NoCollapseObserved"' ]; then
    pass "a balanced run in both models reports NoCollapseObserved"
else
    fail "a balanced run in both models reports NoCollapseObserved" "got '$bal_kind'"
fi

# 4. ingest round-trip via --native-receive-path-in / --paired-receive-path-in:
#    a field the operator JSON omits must stay platform-limited, not become
#    an invented zero.
telemetry_file="$WORK_DIR/gap069-external-telemetry.json"
cat > "$telemetry_file" <<'EOF'
{"tcp_rcv_collapsed": 91, "softnet_drops": null, "qdisc_drops": null}
EOF
ingest_json="$("$BIN" process-model --inject-fixture balanced --paired-receive-path-in "$telemetry_file" --json 2>/dev/null | strip_banner)"
ingested_collapsed="$(printf '%s' "$ingest_json" | json_get paired_process.receive_path.tcp_rcv_collapsed.value)"
ingested_softnet_obtainability="$(printf '%s' "$ingest_json" | json_get paired_process.receive_path.softnet_drops.obtainability)"
if [ "$ingested_collapsed" = "91" ]; then
    pass "ingested TCPRcvCollapsed value round-trips from operator JSON"
else
    fail "ingested TCPRcvCollapsed value round-trips from operator JSON" "got '$ingested_collapsed'"
fi
if [ "$ingested_softnet_obtainability" = '"PlatformLimited"' ]; then
    pass "a field absent from the ingested JSON stays platform-limited, not an invented zero"
else
    fail "a field absent from the ingested JSON stays platform-limited, not an invented zero" \
        "softnet_drops.obtainability was '$ingested_softnet_obtainability'"
fi
rm -f "$telemetry_file"

check_contains "process-model advertises --inject-fixture for offline exercise" "--inject-fixture" \
    "$BIN" process-model --help
check_contains "process-model requires --server (no hardcoded default endpoint)" "--server" \
    "$BIN" process-model --help
