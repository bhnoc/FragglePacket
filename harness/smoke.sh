#!/usr/bin/env bash
# Fast plumbing check. Run before every unit of work to confirm a green baseline.
# Target: under 60 seconds. No network load, no privileged operations.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

section "build"
check_ok "cargo build --release" cargo build --release --manifest-path "$REPO_ROOT/Cargo.toml"
require_bin

section "dispatch reachability"
check_ok "binary runs --version" "$BIN" --version
check_ok "binary runs --help" "$BIN" --help

# Every subcommand advertised in root --help must answer --help.
# Catches a command registered in the enum but not wired into dispatch.
subcommands="$("$BIN" --help 2>&1 | awk '/^Commands:/{f=1;next} /^Options:/{f=0} f && NF && $1 !~ /^-/ {print $1}' | grep -v '^help$')"
if [ -z "$subcommands" ]; then
    fail "subcommand enumeration" "parsed zero subcommands from root --help"
else
    missing=""
    for c in $subcommands; do
        "$BIN" "$c" --help >/dev/null 2>&1 || missing="$missing $c"
    done
    if [ -n "$missing" ]; then
        fail "all subcommands answer --help" "no help for:$missing"
    else
        pass "all $(printf '%s\n' $subcommands | wc -l | tr -d ' ') subcommands answer --help"
    fi
fi

section "unit tests"
check_ok "cargo test --lib" cargo test --release --lib --manifest-path "$REPO_ROOT/Cargo.toml"

summary "smoke"
