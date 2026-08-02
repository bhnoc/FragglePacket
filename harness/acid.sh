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

ran_any=0
for f in "${files[@]}"; do
    matches_filter "$f" || continue
    ran_any=1
    section "$(basename "$f" .sh)"
    # shellcheck disable=SC1090
    source "$f"
done

if [ "$ran_any" = 0 ]; then
    printf 'No check files matched filter: %s\n' "${filters[*]}"
    exit 1
fi

summary "acid"
