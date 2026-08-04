#!/usr/bin/env bash
# Documentation must enumerate every subcommand that actually exists.
#
# README.md listed 39 of 79 subcommands, docs/CLI.md documented 22, and
# docs/TESTS.md described only the 19 legacy NetworkTest impls while calling
# itself the catalog. A reader could not tell which capabilities shipped, and
# every new gap-closing command widened the gap silently.
#
# This gate makes the binary the source of truth: `--help` is authoritative, and
# a subcommand added without a doc entry fails the build. That is the only thing
# that keeps a 79-command surface documented, since nobody remembers to update
# three files by hand.

# The authoritative list, from the binary itself.
actual="$(mktemp)"; documented="$(mktemp)"; missing="$(mktemp)"
trap 'rm -f "$actual" "$documented" "$missing"' EXIT

"$BIN" --help 2>&1 \
    | awk '/^Commands:/{f=1;next} /^Options:/{f=0} f && NF && $1 !~ /^-/ {print $1}' \
    | grep -v '^help$' | sort -u > "$actual"

n_actual="$(wc -l < "$actual" | tr -d ' ')"
if [ "$n_actual" -lt 50 ]; then
    fail "the binary reports its subcommand list" "only $n_actual found; --help parsing likely broke"
else
    pass "the binary reports its subcommand list ($n_actual subcommands)"
fi

# Each doc must mention every subcommand in a backticked table cell. Matching on
# `name` rather than a table shape keeps this robust to formatting changes while
# still requiring the command be named.
for doc in README.md docs/CLI.md docs/TESTS.md; do
    path="$REPO_ROOT/$doc"
    if [ ! -f "$path" ]; then
        fail "$doc enumerates every subcommand" "file absent"
        continue
    fi
    grep -oE '`[a-z0-9][a-z0-9-]*`' "$path" | tr -d '`' | sort -u > "$documented"
    comm -23 "$actual" "$documented" > "$missing"
    n_missing="$(wc -l < "$missing" | tr -d ' ')"
    if [ "$n_missing" -eq 0 ]; then
        pass "$doc enumerates every subcommand ($n_actual)"
    else
        fail "$doc enumerates every subcommand" \
            "$n_missing undocumented: $(tr '\n' ' ' < "$missing")"
    fi
done

# --- the stated subcommand count must match reality ---
# A doc that says "79 subcommands" while 80 exist is worse than one that says
# nothing, because it reads as verified.
for doc in README.md docs/CLI.md docs/TESTS.md; do
    path="$REPO_ROOT/$doc"
    [ -f "$path" ] || continue
    claimed="$(grep -oE '[0-9]+ subcommands' "$path" | head -1 | grep -oE '[0-9]+' || true)"
    if [ -z "$claimed" ]; then
        skip "$doc's stated subcommand count is correct" "no count claimed"
    elif [ "$claimed" = "$n_actual" ]; then
        pass "$doc's stated subcommand count is correct ($claimed)"
    else
        fail "$doc's stated subcommand count is correct" \
            "claims $claimed, binary has $n_actual"
    fi
done

# --- every NetworkTest impl must appear in TESTS.md ---
impls="$(mktemp)"; doc_impls="$(mktemp)"
trap 'rm -f "$actual" "$documented" "$missing" "$impls" "$doc_impls"' EXIT
grep -rhoE 'impl NetworkTest for [A-Za-z0-9_]+' "$REPO_ROOT/src" 2>/dev/null \
    | sed 's/impl NetworkTest for //' | sort -u > "$impls"
grep -oE '\| [A-Z][A-Za-z0-9]+ \|' "$REPO_ROOT/docs/TESTS.md" 2>/dev/null \
    | tr -d '| ' | sort -u > "$doc_impls"
missing_impls="$(comm -23 "$impls" "$doc_impls" | tr '\n' ' ')"
if [ -z "${missing_impls// /}" ]; then
    pass "docs/TESTS.md catalogs every NetworkTest impl ($(wc -l < "$impls" | tr -d ' '))"
else
    fail "docs/TESTS.md catalogs every NetworkTest impl" "undocumented: $missing_impls"
fi

# --- TESTS.md must state the limits, not just the capabilities ---
# The whole point of the page is that a reader can tell what is NOT possible.
# Without this, "capability map" degrades back into a feature list.
check_contains "docs/TESTS.md documents what the tool cannot do" "cannot do" \
    cat "$REPO_ROOT/docs/TESTS.md"

for limit in "ingest-only" "Continuous monitoring" "credential" "Topology"; do
    if grep -qi "$limit" "$REPO_ROOT/docs/TESTS.md"; then
        pass "docs/TESTS.md names the '$limit' limitation"
    else
        fail "docs/TESTS.md names the '$limit' limitation" "not mentioned"
    fi
done

# --- no doc may reference a file that was removed ---
# Dangling links are how a reader concludes the docs are stale and stops trusting
# any of them.
dangling=""
for doc in "$REPO_ROOT/README.md" "$REPO_ROOT"/docs/*.md; do
    [ -f "$doc" ] || continue
    base="$(dirname "$doc")"
    for link in $(grep -ohE '\]\([^)]+\.md\)' "$doc" 2>/dev/null | sed 's/](//;s/)//'); do
        case "$link" in http*) continue;; esac
        target="$base/$link"
        [ -f "$target" ] || dangling="$dangling $(basename "$doc")->$link"
    done
done
if [ -z "${dangling// /}" ]; then
    pass "no documentation link points at a removed file"
else
    fail "no documentation link points at a removed file" "$dangling"
fi
