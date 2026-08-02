#!/usr/bin/env bash
# Full end-to-end validation. Ratchet: only grows, never shrinks.
# Runs every check file in harness/checks/*.sh. Each gap gets its own file so
# parallel work never collides on one script.
#
#   ./harness/acid.sh              run everything
#   ./harness/acid.sh 001 019      run only gap-001 and gap-019 checks
#   FP_HARNESS_OFFLINE=1 ...       skip checks that need live network
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require_bin
mkdir -p "$HARNESS_DIR/checks"

filters=("$@")
matches_filter() {
    [ ${#filters[@]} -eq 0 ] && return 0
    local base pat
    base="$(basename "$1")"
    for pat in "${filters[@]}"; do
        case "$base" in *"$pat"*) return 0 ;; esac
    done
    return 1
}

shopt -s nullglob
files=("$HARNESS_DIR"/checks/*.sh)
if [ ${#files[@]} -eq 0 ]; then
    printf 'No check files in harness/checks/. Nothing to validate.\n'
    exit 1
fi

# A gate is only worth having if it's cheap enough to run every round. Anything
# slower than this gets called out so it can be moved onto fixtures/synthetic
# state instead of paying real platform or network cost per assertion.
SLOW_CHECK_SECS="${FP_SLOW_CHECK_SECS:-25}"

ran_any=0
slow_files=()
for f in "${files[@]}"; do
    matches_filter "$f" || continue
    ran_any=1
    section "$(basename "$f" .sh)"
    _started=$SECONDS
    # shellcheck disable=SC1090
    source "$f"
    _elapsed=$((SECONDS - _started))
    if [ "$_elapsed" -gt "$SLOW_CHECK_SECS" ]; then
        slow_files+=("$(basename "$f") ${_elapsed}s")
        printf '  %s! %ss — over the %ss budget; move assertions onto fixtures%s\n' \
            "$_c_yel" "$_elapsed" "$SLOW_CHECK_SECS" "$_c_off"
    fi
done

if [ ${#slow_files[@]} -gt 0 ]; then
    printf '\n%sslow check files:%s\n' "$_c_yel" "$_c_off"
    for s in "${slow_files[@]}"; do printf '    %s\n' "$s"; done
fi

if [ "$ran_any" = 0 ]; then
    printf 'No check files matched filter: %s\n' "${filters[*]}"
    exit 1
fi

summary "acid"
