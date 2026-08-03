#!/usr/bin/env bash
# GAP-028: multi-uplink ECMP/LAG hash and NAT-affinity diagnostic. Field
# evidence produced a *negative* result that mattered: a ten-bucket
# fixed-source-port sweep of a failing 350 Mbps bidirectional run did NOT
# split bimodally -- every bucket failed the same way, arguing against one
# bad ECMP member and toward shared queue/policer/WLAN behavior. This gate
# locks:
#   1. Absence of bimodality is reported as a finding (NoSplitDetected),
#      not folded into an inconclusive result.
#   2. A genuine bimodal split (one bucket differs from the rest) is
#      distinguishable from NoSplitDetected.
#   3. Mid-flow rebinding is distinguishable from a stable mapping, and
#      from "STUN was unreachable so this is unknown".
#   4. A tunnel interface produces a loud warning.

cargo_test() { cargo test --release --lib network_tests::ecmp_nat:: --manifest-path "$REPO_ROOT/Cargo.toml" "$@"; }

check_ok "cargo test covers bucket-outcome bimodality classification" cargo_test
check_contains "cargo test proves all-succeeding buckets report NoSplitDetected, not inconclusive" \
    "all_buckets_succeeding_reports_no_split_not_inconclusive" cargo_test
check_contains "cargo test proves all-failing buckets report NoSplitDetected -- the field evidence's own shape" \
    "all_buckets_failing_reports_no_split_not_inconclusive" cargo_test
check_contains "cargo test proves one failing bucket among successes is a bimodal split" \
    "one_failing_bucket_among_successes_is_a_bimodal_split" cargo_test
check_contains "cargo test proves fewer than two buckets refuses a split judgement" \
    "fewer_than_two_buckets_refuses_a_split_judgement" cargo_test
check_contains "cargo test proves mid-flow rebind is true only when mapped addresses actually differ" \
    "mid_flow_rebind_is_true_only_when_mapped_addresses_actually_differ" cargo_test
check_contains "cargo test proves mid-flow rebind is unavailable, not false, when STUN was unreachable" \
    "mid_flow_rebind_is_unavailable_not_false_when_stun_was_unreachable" cargo_test

check_contains "ecmp-nat advertises --ports/--stun-server/--transport" "--stun-server" \
    "$BIN" ecmp-nat --help

json_get() { python3 -c '
import json, sys
d = json.load(sys.stdin)
path = sys.argv[1]
cur = d
for part in path.split("."):
    if isinstance(cur, dict):
        cur = cur.get(part)
    elif isinstance(cur, list):
        try:
            cur = cur[int(part)]
        except (ValueError, IndexError):
            cur = None
    else:
        cur = None
print(json.dumps(cur))
' "$1" 2>/dev/null; }

# --- absence of bimodality is a first-class finding, not a shrug ---
all_ok_out="$("$BIN" ecmp-nat --inject-fixture all-ok --json 2>/dev/null | sed -n '/^{/,$p')"
all_ok_verdict="$(printf '%s' "$all_ok_out" | json_get bimodality)"
if [ "$all_ok_verdict" = '"NoSplitDetected"' ]; then
    pass "every bucket succeeding reports NoSplitDetected"
else
    fail "every bucket succeeding reports NoSplitDetected" "got: $all_ok_verdict"
fi

all_fail_out="$("$BIN" ecmp-nat --inject-fixture all-fail --json 2>/dev/null | sed -n '/^{/,$p')"
all_fail_verdict="$(printf '%s' "$all_fail_out" | json_get bimodality)"
if [ "$all_fail_verdict" = '"NoSplitDetected"' ]; then
    pass "every bucket failing (the field evidence's own shape) reports NoSplitDetected, not inconclusive"
else
    fail "every bucket failing reports NoSplitDetected" "got: $all_fail_verdict"
fi
check_contains "human output states NO SPLIT DETECTED argues against one bad ECMP member" \
    "argues AGAINST one bad ECMP member" \
    "$BIN" ecmp-nat --inject-fixture all-fail

# --- a genuine split is distinguishable from the no-split cases above ---
one_bad_out="$("$BIN" ecmp-nat --inject-fixture one-bad-bucket --json 2>/dev/null | sed -n '/^{/,$p')"
one_bad_verdict="$(printf '%s' "$one_bad_out" | json_get bimodality)"
if [ "$one_bad_verdict" = '"BimodalSplitDetected"' ]; then
    pass "one failing bucket among successes reports BimodalSplitDetected"
else
    fail "one failing bucket among successes reports BimodalSplitDetected" "got: $one_bad_verdict"
fi
check_contains "human output states BIMODAL SPLIT DETECTED for the mixed-outcome case" \
    "BIMODAL SPLIT DETECTED" \
    "$BIN" ecmp-nat --inject-fixture one-bad-bucket

# --- mid-flow rebinding is distinguishable from a stable mapping ---
rebind_out="$("$BIN" ecmp-nat --inject-fixture mid-flow-rebind --json 2>/dev/null | sed -n '/^{/,$p')"
rebind_bucket0="$(printf '%s' "$rebind_out" | json_get buckets.0.mid_flow_rebind_detected)"
rebind_bucket1="$(printf '%s' "$rebind_out" | json_get buckets.1.mid_flow_rebind_detected)"
if [ "$rebind_bucket0" = "true" ] && [ "$rebind_bucket1" = "false" ]; then
    pass "a rebinding bucket and a stable bucket report distinguishable mid_flow_rebind_detected values"
else
    fail "a rebinding bucket and a stable bucket report distinguishable mid_flow_rebind_detected values" \
        "bucket0=$rebind_bucket0 bucket1=$rebind_bucket1"
fi
check_contains "human output flags a mid-flow rebind distinctly from a stable mapping" \
    "mid_flow_rebind=YES" \
    "$BIN" ecmp-nat --inject-fixture mid-flow-rebind

# --- a bucket with no STUN bracket at all reports rebind as unavailable,
#     never false (silence must not read as "stable") ---
check_contains "a bucket run without a STUN bracket reports rebind as unavailable, not false" \
    "mid_flow_rebind=unavailable" \
    "$BIN" ecmp-nat --inject-fixture all-fail

# --- a tunnel interface produces a loud warning ---
check_contains "a tunnel interface produces a loud warning naming why the result is meaningless" \
    "masking any real ECMP/LAG/NAT behavior" \
    "$BIN" ecmp-nat --interface utun6 --inject-fixture all-ok
check_lacks "a non-tunnel interface produces no tunnel warning" \
    "masking any real ECMP/LAG/NAT behavior" \
    "$BIN" ecmp-nat --interface en0 --inject-fixture all-ok

# --- no output anywhere contains a MAC-shaped string (this command
#     touches no radio/BSSID data, but the policy is blanket) ---
mac_pattern='([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}'
combined="$all_ok_out$all_fail_out$one_bad_out$rebind_out"
if printf '%s' "$combined" | grep -Eq "$mac_pattern"; then
    fail "ecmp-nat JSON output carries no MAC-shaped string" "found a MAC-shaped token"
else
    pass "ecmp-nat JSON output carries no MAC-shaped string"
fi

# --- exactly one real end-to-end run against a public STUN server, tiny
#     payload, few buckets -- proves the mechanism without reproducing the
#     350 Mbps matrix from the incident ---
if net_guard; then
    real_out="$("$BIN" ecmp-nat --target 8.8.8.8:53 --ports 41001,41002,41003 --payload-bytes 32 --timeout-ms 800 --json 2>/dev/null | sed -n '/^{/,$p')"
    if [ -z "$real_out" ]; then
        skip "a real port-sweep run against 8.8.8.8:53 produces a bimodality verdict" "no output"
    else
        real_verdict="$(printf '%s' "$real_out" | json_get bimodality)"
        if [ "$real_verdict" != "null" ]; then
            pass "a real port-sweep run against 8.8.8.8:53 produces a bimodality verdict ($real_verdict)"
        else
            fail "a real port-sweep run produces a bimodality verdict" "got: $real_verdict"
        fi
    fi
else
    skip "a real port-sweep run against 8.8.8.8:53 produces a bimodality verdict" "FP_HARNESS_OFFLINE=1"
fi
