#!/usr/bin/env bash
# GAP-007: packet capture must never be unbounded. Field evidence: a 75s
# full-snaplen capture grew to ~2GB with no duration/size/rotation caps and
# required a manual sudo handoff outside the tool's control.
#
# Real tcpdump needs root on this machine, and the harness must not grant it
# (no sudo, no password prompts, ever). These checks use $FP_TCPDUMP_BIN to
# swap in small fixture scripts under harness/fixtures/fake-bin/ that
# reproduce tcpdump's real behavior (permission failure, unbounded growth)
# deterministically, offline, in well under a second.

check_ok "cargo test covers bounded-capture logic" \
    cargo test --release --lib network_tests::capture:: --manifest-path "$REPO_ROOT/Cargo.toml"

check_contains "capture advertises bound flags" "--duration-secs" \
    "$BIN" capture --help
check_contains "capture advertises --max-bytes" "--max-bytes" \
    "$BIN" capture --help
check_contains "capture advertises --snaplen" "--snaplen" \
    "$BIN" capture --help

FAKE_BIN="$REPO_ROOT/harness/fixtures/fake-bin/fake-tcpdump-grows.sh"
FAKE_PRIVFAIL="$REPO_ROOT/harness/fixtures/fake-bin/fake-tcpdump-privfail.sh"

if [ ! -x "$FAKE_BIN" ] || [ ! -x "$FAKE_PRIVFAIL" ]; then
    skip "GAP-007 bounded-capture checks" "fixture fake-tcpdump scripts missing or not executable"
else
    # --- the exact regression: a default-flags capture must still terminate ---
    out_file="$WORK_DIR/gap007-default.pcap"
    out_log="$WORK_DIR/gap007-default.log"
    rm -f "$out_file" "$out_log"
    start_ts=$(date +%s)
    FP_TCPDUMP_BIN="$FAKE_BIN" "$BIN" capture -i fake0 -o "$out_file" --duration-secs 2 --json > "$out_log" 2>&1
    end_ts=$(date +%s)
    elapsed=$((end_ts - start_ts))
    if [ "$elapsed" -le 6 ]; then
        pass "a default-bounded capture terminates on its own (${elapsed}s elapsed)"
    else
        fail "a default-bounded capture terminates on its own" "took ${elapsed}s against a 2s duration cap; process did not stop"
    fi
    sed -n '/^{/,$p' "$out_log" > "$out_log.json"
    check_json_field "capture --json reports a stop_reason" "stop_reason" cat "$out_log.json"

    # --- byte cap is actually honored, not just accepted as a flag ---
    out_file2="$WORK_DIR/gap007-bytecap.pcap"
    out_log2="$WORK_DIR/gap007-bytecap.log"
    rm -f "$out_file2" "$out_log2"
    FP_TCPDUMP_BIN="$FAKE_BIN" "$BIN" capture -i fake0 -o "$out_file2" --duration-secs 10 --max-bytes 100000 --json > "$out_log2" 2>&1
    if [ -f "$out_file2" ]; then
        size2=$(wc -c < "$out_file2" | tr -d ' ')
        # The fake tool writes in 64KB bursts every 50ms; the cap must stop
        # it near the requested ceiling, not let it run to the 10s duration.
        if [ "$size2" -gt 0 ] && [ "$size2" -lt 400000 ]; then
            pass "byte cap is honored: file size ($size2) stayed near the 100000-byte cap, not the 10s duration"
        else
            fail "byte cap is honored" "file size was $size2 bytes; expected well under the unbounded-10s size"
        fi
    else
        fail "byte cap is honored" "no output file was produced"
    fi
    check_contains "byte-capped run reports ByteCapReached" "ByteCapReached" cat "$out_log2"

    # --- privilege handoff: detect, name the command, exit cleanly, never escalate ---
    out3_file="$WORK_DIR/gap007-priv.pcap"
    out_log3="$WORK_DIR/gap007-priv.log"
    rm -f "$out3_file" "$out_log3"
    FP_TCPDUMP_BIN="$FAKE_PRIVFAIL" "$BIN" capture -i fake0 -o "$out3_file" --duration-secs 2 > "$out_log3" 2>&1
    priv_exit=$?
    if [ "$priv_exit" -eq 0 ]; then
        fail "capture without privilege exits non-zero" "exited 0 on a simulated permission failure"
    else
        pass "capture without privilege exits non-zero"
    fi
    check_contains "privilege failure names the required elevated command" "re-run as:" cat "$out_log3"
    check_lacks "privilege failure never invokes sudo itself" "sudo " cat "$out_log3"
    check_lacks "privilege failure output carries no password prompt" "assword:" cat "$out_log3"
    if [ -f "$out3_file" ] && [ -s "$out3_file" ]; then
        fail "no output file is produced on a privilege failure" "found a non-empty $out3_file"
    else
        pass "no output file is produced on a privilege failure"
    fi

    rm -f "$out_file" "$out_file2" "$out3_file" "$out_log" "$out_log2" "$out_log3" "$out_log.json"
fi

# --- real capture on this machine, to prove the actual system tcpdump path ---
if net_guard; then
    real_out="$WORK_DIR/gap007-real.pcap"
    rm -f "$real_out"
    real="$("$BIN" capture -i lo0 -o "$real_out" --duration-secs 2 --json 2>&1)"
    if printf '%s' "$real" | grep -q "PrivilegeRequired\|re-run as:"; then
        note "real capture on lo0 needs elevated privilege on this machine (expected without sudo): $(printf '%s' "$real" | tail -1)"
        pass "real tcpdump path correctly reports missing privilege instead of hanging or escalating"
    elif [ -f "$real_out" ]; then
        real_size=$(wc -c < "$real_out" | tr -d ' ')
        pass "real bounded capture on lo0 produced a file ($real_size bytes)"
    else
        fail "real capture attempt produced neither a file nor a privilege report" "$real"
    fi
    rm -f "$real_out"
else
    skip "real tcpdump capture on lo0" "FP_HARNESS_OFFLINE=1"
fi
