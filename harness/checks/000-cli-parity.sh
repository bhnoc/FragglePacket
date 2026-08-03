#!/usr/bin/env bash
# Locks the pre-existing CLI surface. Every subcommand that worked before the
# src/cli/ refactor must keep the exact same --help contract afterward.
# Golden files were captured from the v0.2.0 monolithic main.rs.
#
# Regenerate ONLY with an explicit, reviewed decision:
#   for c in <cmd>; do ./target/release/fraggle-packet $c --help > harness/golden/$c.help.txt 2>&1; done

check_ok "root --help exits 0" "$BIN" --help

for g in "$GOLDEN_DIR"/*.help.txt; do
    name="$(basename "$g" .help.txt)"
    if [ "$name" = "root" ]; then
        actual="$("$BIN" --help 2>&1)"
    else
        actual="$("$BIN" "$name" --help 2>&1)"
    fi
    # Golden may legitimately gain new options; it must never LOSE the
    # arguments/flags it had. Compare only lines that declare a flag or arg.
    expected_flags="$(grep -oE '(^|[[:space:]])(-{1,2}[a-z][a-z0-9-]*|<[A-Z_]+>)' "$g" | tr -d ' ' | sort -u)"
    actual_flags="$(printf '%s' "$actual" | grep -oE '(^|[[:space:]])(-{1,2}[a-z][a-z0-9-]*|<[A-Z_]+>)' | tr -d ' ' | sort -u)"
    lost="$(comm -23 <(printf '%s\n' "$expected_flags") <(printf '%s\n' "$actual_flags") | tr '\n' ' ')"
    if [ -n "${lost// /}" ]; then
        fail "parity: $name retains its flags" "lost:$lost"
    else
        pass "parity: $name retains its flags"
    fi
done

# The legacy global flags live on the root Args struct and must survive.
for flag in --min --max --timeout-ms --retries --target; do
    check_contains "parity: root advertises $flag" "$flag" "$BIN" --help
done
