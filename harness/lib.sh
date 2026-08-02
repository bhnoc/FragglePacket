#!/usr/bin/env bash
# Shared helpers for the smoke and acid harnesses.
# Sourced, never executed directly.

HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HARNESS_DIR/.." && pwd)"
BIN="$REPO_ROOT/target/release/fraggle-packet"
GOLDEN_DIR="$HARNESS_DIR/golden"
FIXTURE_DIR="$HARNESS_DIR/fixtures"
WORK_DIR="$REPO_ROOT/temp/harness"

CHECKS_RUN=0
CHECKS_FAILED=0
FAILED_NAMES=()

mkdir -p "$WORK_DIR"

_c_red=$'\033[31m'; _c_grn=$'\033[32m'; _c_yel=$'\033[33m'; _c_dim=$'\033[2m'; _c_off=$'\033[0m'
if [ ! -t 1 ]; then _c_red=; _c_grn=; _c_yel=; _c_dim=; _c_off=; fi

pass() { CHECKS_RUN=$((CHECKS_RUN+1)); printf '  %sPASS%s %s\n' "$_c_grn" "$_c_off" "$1"; }
fail() {
    CHECKS_RUN=$((CHECKS_RUN+1)); CHECKS_FAILED=$((CHECKS_FAILED+1)); FAILED_NAMES+=("$1")
    printf '  %sFAIL%s %s\n' "$_c_red" "$_c_off" "$1"
    [ -n "${2:-}" ] && printf '       %s%s%s\n' "$_c_dim" "$2" "$_c_off"
    return 0
}
skip() { printf '  %sSKIP%s %s %s(%s)%s\n' "$_c_yel" "$_c_off" "$1" "$_c_dim" "${2:-}" "$_c_off"; }
note() { printf '  %s- %s%s\n' "$_c_dim" "$1" "$_c_off"; }
section() { printf '\n%s\n' "$1"; }

# check_ok <name> <cmd...> : command must exit 0
check_ok() {
    local name="$1"; shift
    local out
    if out="$("$@" 2>&1)"; then pass "$name"; else fail "$name" "exit=$? :: $(printf '%s' "$out" | tail -3 | tr '\n' ' ')"; fi
}

# check_fails <name> <cmd...> : command must exit non-zero
check_fails() {
    local name="$1"; shift
    local out
    if out="$("$@" 2>&1)"; then fail "$name" "expected non-zero exit, got 0"; else pass "$name"; fi
}

# check_contains <name> <needle> <cmd...> : stdout+stderr must contain needle
check_contains() {
    local name="$1" needle="$2"; shift 2
    local out
    out="$("$@" 2>&1 || true)"
    if printf '%s' "$out" | grep -qF -- "$needle"; then
        pass "$name"
    else
        fail "$name" "missing '$needle' in output :: $(printf '%s' "$out" | tail -3 | tr '\n' ' ')"
    fi
}

# check_lacks <name> <needle> <cmd...> : stdout+stderr must NOT contain needle
check_lacks() {
    local name="$1" needle="$2"; shift 2
    local out
    out="$("$@" 2>&1 || true)"
    if printf '%s' "$out" | grep -qF -- "$needle"; then
        fail "$name" "found forbidden '$needle'"
    else
        pass "$name"
    fi
}

# check_json_field <name> <jq-ish python path> <cmd...>
# Validates stdout parses as JSON and the dotted field path exists and is non-null.
check_json_field() {
    local name="$1" path="$2"; shift 2
    local out
    out="$("$@" 2>/dev/null || true)"
    if printf '%s' "$out" | python3 -c '
import sys, json
path = sys.argv[1]
try:
    d = json.load(sys.stdin)
except Exception as e:
    print(f"not JSON: {e}", file=sys.stderr); sys.exit(1)
cur = d
for part in path.split("."):
    if isinstance(cur, list):
        try: cur = cur[int(part)]
        except Exception: print(f"no index {part}", file=sys.stderr); sys.exit(1)
    elif isinstance(cur, dict):
        if part not in cur: print(f"no key {part}", file=sys.stderr); sys.exit(1)
        cur = cur[part]
    else:
        print(f"scalar at {part}", file=sys.stderr); sys.exit(1)
if cur is None: print(f"{path} is null", file=sys.stderr); sys.exit(1)
' "$path" 2>/dev/null; then
        pass "$name"
    else
        fail "$name" "JSON field '$path' missing or unparseable"
    fi
}

summary() {
    printf '\n'
    if [ "$CHECKS_FAILED" -eq 0 ]; then
        printf '%s%s GREEN%s  %d checks passed\n' "$_c_grn" "${1:-harness}" "$_c_off" "$CHECKS_RUN"
        return 0
    fi
    printf '%s%s RED%s  %d/%d failed:\n' "$_c_red" "${1:-harness}" "$_c_off" "$CHECKS_FAILED" "$CHECKS_RUN"
    for n in "${FAILED_NAMES[@]}"; do printf '    %s\n' "$n"; done
    return 1
}

require_bin() {
    if [ ! -x "$BIN" ]; then
        printf '%sBinary missing at %s. Run: cargo build --release%s\n' "$_c_red" "$BIN" "$_c_off"
        exit 2
    fi
}

# Marks a check as needing live network. Set FP_HARNESS_OFFLINE=1 to skip these.
net_guard() {
    if [ "${FP_HARNESS_OFFLINE:-0}" = "1" ]; then return 1; fi
    return 0
}
