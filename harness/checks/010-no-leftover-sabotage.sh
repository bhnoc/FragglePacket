#!/usr/bin/env bash
# Every locking check in this suite is proven by deliberately breaking the code,
# watching the check go red, then restoring. That workflow leaves a window where
# sabotage is sitting in the tree, and a restore that gets forgotten ships a
# disabled feature with a green-looking build.
#
# This already happened once: `let fake_radio = false; // BROKEN: args.fake_radio
# ignored` was left in src/cli/commands/load_guard.rs after a red/green proof and
# silently disabled the radio-injection flag.

sabotage_markers='BROKEN:|SABOTAGE|DO NOT COMMIT|DONOTCOMMIT|TEMPORARILY DISABLED|revert me|REVERTME'

hits="$(grep -rlnE "$sabotage_markers" "$REPO_ROOT/src" "$REPO_ROOT/main.rs" 2>/dev/null | tr '\n' ' ')"
if [ -n "${hits// /}" ]; then
    fail "no sabotage markers left in source" "$hits"
else
    pass "no sabotage markers left in source"
fi

# A red/green proof that stubs a bool to a literal is the specific shape that
# bit us. Catch an arg field being shadowed by a hardcoded literal.
stubbed="$(grep -rnE 'let +[a-z_]+ *= *(true|false); *//' "$REPO_ROOT/src" 2>/dev/null \
    | grep -viE 'default|intentional|always|placeholder' | tr '\n' ' ')"
if [ -n "${stubbed// /}" ]; then
    fail "no CLI arg is shadowed by a hardcoded literal" "$stubbed"
else
    pass "no CLI arg is shadowed by a hardcoded literal"
fi

# Sanity: this gate is worthless if the marker search itself is broken, so prove
# the pattern matches a known-bad string.
probe_file="$WORK_DIR/sabotage-selftest.txt"
printf 'let fake_radio = false; // BROKEN: args.fake_radio ignored\n' > "$probe_file"
if grep -qE "$sabotage_markers" "$probe_file"; then
    pass "sabotage pattern self-test matches a known-bad line"
else
    fail "sabotage pattern self-test matches a known-bad line" "pattern does not match its own example"
fi
rm -f "$probe_file"
