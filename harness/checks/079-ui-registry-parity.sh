#!/usr/bin/env bash
# The UI command registry must describe every subcommand the binary has.
#
# Both UIs used to hardcode the 19 NetworkTest impls, so 60 of 79 subcommands --
# every gap-closing command, i.e. most of the tool -- were unreachable, and
# nothing detected the drift as new commands landed. src/ui_bridge/registry.rs is
# now the single list both UIs render from, which only works if it cannot fall
# behind the binary.
#
# This gate makes `--help` authoritative: add a subcommand without registering
# it and the build fails, naming it.

check_ok "cargo test covers the CLI bridge and the command registry" \
    cargo test --release --lib ui_bridge --manifest-path "$REPO_ROOT/Cargo.toml"

# A refusal must stay a valid result. If this inverts, every UI starts showing
# "REFUSED: insufficient evidence" as a red error and users learn to ignore the
# most important output this tool produces.
check_ok "cargo test proves a refusal is a result, not a failure" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib ui_bridge::tests::a_refusal_payload_is_json_not_failure 2>&1 | grep -q '1 passed'"

check_ok "cargo test proves a missing binary reports NotRun, not a command failure" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib ui_bridge::tests::a_missing_binary_is_not_run_rather_than_failed 2>&1 | grep -q '1 passed'"

# --- every subcommand the binary reports must be registered ---
actual="$(mktemp)"; registered="$(mktemp)"
trap 'rm -f "$actual" "$registered"' EXIT

"$BIN" --help 2>&1 \
    | awk '/^Commands:/{f=1;next} /^Options:/{f=0} f && NF && $1 !~ /^-/ {print $1}' \
    | grep -v '^help$' | sort -u > "$actual"

grep -oE '^\s+Cmd \{ name: "[a-z0-9-]+"' "$REPO_ROOT/src/ui_bridge/registry.rs" \
    | grep -oE '"[a-z0-9-]+"' | tr -d '"' | sort -u > "$registered"

n_actual="$(wc -l < "$actual" | tr -d ' ')"
n_reg="$(wc -l < "$registered" | tr -d ' ')"

missing="$(comm -23 "$actual" "$registered" | tr '\n' ' ')"
if [ -z "${missing// /}" ]; then
    pass "every subcommand is in the UI registry ($n_actual)"
else
    fail "every subcommand is in the UI registry" \
        "unregistered: $missing -- add to src/ui_bridge/registry.rs"
fi

# A registry entry for a command that no longer exists is equally wrong: the UI
# would render a button that cannot run.
stale="$(comm -13 "$actual" "$registered" | tr '\n' ' ')"
if [ -z "${stale// /}" ]; then
    pass "the UI registry contains no removed subcommand"
else
    fail "the UI registry contains no removed subcommand" "stale entries: $stale"
fi

if [ "$n_actual" = "$n_reg" ]; then
    pass "registry and binary agree on the subcommand count ($n_actual)"
else
    fail "registry and binary agree on the subcommand count" "binary $n_actual, registry $n_reg"
fi

# --- the emits_json flag must match reality ---
# Appending --json to a command that has no JSON mode makes it fail on an unknown
# flag, so a wrong flag here breaks the UI at runtime for that command.
json_drift="$(
    python3 - "$REPO_ROOT" "$BIN" <<'PY'
import re, subprocess, sys, pathlib
root, binp = pathlib.Path(sys.argv[1]), sys.argv[2]
src = (root / "src" / "ui_bridge" / "registry.rs").read_text()
rows = re.findall(r'Cmd \{ name: "([a-z0-9-]+)".*?emits_json: (true|false)', src)
bad = []
for name, claimed in rows:
    h = subprocess.run([binp, name, "--help"], capture_output=True, text=True).stdout
    real = "--json" in h
    if real != (claimed == "true"):
        bad.append(f"{name}(registry={claimed},real={str(real).lower()})")
print(" ".join(bad))
PY
)"
if [ -z "${json_drift// /}" ]; then
    pass "every registry emits_json flag matches the binary"
else
    fail "every registry emits_json flag matches the binary" "$json_drift"
fi

# --- platform-limited commands must be declared, not silently offered ---
# A command whose live path reads macOS-only tooling must be either MacOsOnly or
# MacOsForLiveSampling. Left as AnyPlatform, a Linux user clicks it and gets a
# confident empty result -- the exact failure this codebase exists to prevent.
undeclared=""
for c in rf-survey bufferbloat radio-diagnostic ap-identity load-guard counter-deltas; do
    line="$(grep -oE "Cmd \{ name: \"$c\".*?platform: Platform::[A-Za-z]+" "$REPO_ROOT/src/ui_bridge/registry.rs" | head -1)"
    case "$line" in
        *MacOsOnly*|*MacOsForLiveSampling*) ;;
        *) undeclared="$undeclared $c" ;;
    esac
done
if [ -z "${undeclared// /}" ]; then
    pass "macOS-dependent commands declare their platform requirement"
else
    fail "macOS-dependent commands declare their platform requirement" \
        "declared AnyPlatform: $undeclared"
fi

# --- privileged commands must be declared ---
for c in replay capture probe; do
    if grep -qE "Cmd \{ name: \"$c\".*needs_privilege: true" "$REPO_ROOT/src/ui_bridge/registry.rs"; then
        pass "$c declares that it needs privilege"
    else
        fail "$c declares that it needs privilege" "needs root but registry says otherwise"
    fi
done

# --- every bucket must be non-empty ---
# An empty bucket renders as a dead tab in both UIs.
check_ok "cargo test proves no bucket is empty" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib ui_bridge::registry::tests::every_bucket_has_at_least_one_command 2>&1 | grep -q '1 passed'"

# --- both UIs must source their command list from the registry ---
# The original bug was two hardcoded lists drifting from the binary. If a UI
# stops reading the registry, it silently goes stale again.
for ui in "src/bin/tui/command_panel.rs" "src/bin/desktop/components/commands_panel/mod.rs"; do
    path="$REPO_ROOT/$ui"
    if [ ! -f "$path" ]; then
        fail "$(basename "$(dirname "$ui")")/$(basename "$ui") exists" "file absent"
    elif grep -q "ui_bridge::registry" "$path"; then
        pass "$ui reads the shared command registry"
    else
        fail "$ui reads the shared command registry" "no registry import: it has a hardcoded list"
    fi
done

# Both panels must be reachable, or the work is invisible to users.
if grep -q "AppMode::CommandPanel" "$REPO_ROOT/src/bin/tui/app.rs"; then
    pass "the TUI dispatches the registry command panel"
else
    fail "the TUI dispatches the registry command panel" "AppMode::CommandPanel never rendered"
fi

if grep -q "PanelId::Commands" "$REPO_ROOT/src/bin/desktop/state/mod.rs" \
    && grep -q "PanelId::Commands =>" "$REPO_ROOT/src/bin/desktop/app.rs"; then
    pass "the desktop registers and dispatches the Commands panel"
else
    fail "the desktop registers and dispatches the Commands panel" "PanelId::Commands not wired"
fi

# A blocked command must never render as runnable in either UI. Both panels
# assert this in their own tests; run them here so the gate owns the guarantee.
check_ok "cargo test proves the TUI marks every blocked command" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --bins tui_app::command_panel::tests::every_command_resolves_to_a_known_marker 2>&1 | grep -q '1 passed'"

check_ok "cargo test proves the desktop never badges a blocked command as ready" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --bins components::commands_panel::tests::a_blocked_command_never_renders_as_ready 2>&1 | grep -q '1 passed'"

# Every command must be reachable by navigation, not merely present in the data.
check_ok "cargo test proves every registered command is reachable in the TUI" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --bins tui_app::command_panel::tests::every_registered_command_is_reachable 2>&1 | grep -q '1 passed'"

# --- commands needing arguments must be runnable from the UIs, not just named ---
# Before input prompting, both UIs reported "needs TARGET; run from the CLI",
# which meant 30+ commands were listed but not usable. The guard that matters is
# that an empty or invalid value is refused BEFORE spawning, so a bad run never
# reaches the CLI as a confusing error.
check_ok "cargo test proves typed inputs line up with required_inputs" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib ui_bridge::registry::tests::typed_inputs_match_required_inputs_in_order 2>&1 | grep -q '1 passed'"

check_ok "cargo test proves an empty value is rejected for every input kind" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib ui_bridge::registry::tests::an_empty_value_is_rejected_for_every_kind 2>&1 | grep -q '1 passed'"

check_ok "cargo test proves a missing file is rejected before the run" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib ui_bridge::registry::tests::a_nonexistent_file_is_rejected_before_the_run 2>&1 | grep -q '1 passed'"

check_ok "cargo test proves file inputs prompt for a file, not free text" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib ui_bridge::registry::tests::file_inputs_are_classified_as_files_not_free_text 2>&1 | grep -q '1 passed'"

check_ok "cargo test proves the TUI completes a single-input command on one Enter" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --bins tui_app::command_panel::tests::a_single_input_command_completes_on_the_first_enter 2>&1 | grep -q '1 passed'"

check_ok "cargo test proves the TUI advances between fields on a two-input command" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --bins tui_app::command_panel::tests::a_two_input_command_advances_before_running 2>&1 | grep -q '1 passed'"

# Entered values must not leak between commands: a hostname typed for one command
# silently becoming another's interface name would be a wrong-argument bug the
# user cannot see.
check_ok "cargo test proves entered values are cleared when the selection changes" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --bins tui_app::command_panel::tests::changing_selection_clears_entered_values 2>&1 | grep -q '1 passed'"

check_ok "cargo test proves the desktop enables Run once values are valid" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --bins components::commands_panel::tests::a_command_needing_input_is_runnable_once_values_are_valid 2>&1 | grep -q '1 passed'"

check_ok "cargo test proves entered values precede the --json flag" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --bins components::commands_panel::tests::entered_values_precede_the_json_flag 2>&1 | grep -q '1 passed'"

# Only the 6 structurally-incapable commands may lack --json. If that count grows,
# a new command shipped without structured output and the UIs can only show text.
no_json="$(
    for c in $(cat "$actual"); do
        "$BIN" "$c" --help 2>&1 | grep -q -- "--json" || printf '%s ' "$c"
    done
)"
expected_no_json="dsl-demo fuzz probe replay serve tui"
if [ "$(echo $no_json | tr ' ' '\n' | sort | tr '\n' ' ')" = "$(echo $expected_no_json | tr ' ' '\n' | sort | tr '\n' ' ')" ]; then
    pass "only the 6 structurally text-only commands lack --json"
else
    fail "only the 6 structurally text-only commands lack --json" \
        "got: $no_json (expected: $expected_no_json)"
fi
