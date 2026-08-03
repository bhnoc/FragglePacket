#!/usr/bin/env bash
# GAP-020: generalized allowlist-extraction for privileged platform
# reports, lifted from load_guard::wdutil's WIFI-vs-BLUETOOTH pattern
# (that module is off-limits this sprint and already correct; this
# generalizes its mechanism as fraggle_packet::redact::SectionAllowlist).
# CENTRAL REGRESSION this locks: content from a non-allowlisted section
# never reaches the caller's field callback -- not filtered afterward,
# never buffered at all.

check_ok "cargo test covers SectionAllowlist's extraction logic" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib redact::section_allowlist_tests:: 2>&1 | grep -q 'test result: ok'"
check_ok "cargo test proves only allowed-section lines are extracted" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib redact::section_allowlist_tests::only_allowed_section_lines_are_extracted 2>&1 | grep -q '1 passed'"
check_ok "cargo test CENTRAL REGRESSION: disallowed-section content never reaches the field callback" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib redact::section_allowlist_tests::disallowed_section_content_never_reaches_the_callback 2>&1 | grep -q '1 passed'"
check_ok "cargo test proves an empty allowlist yields zero fields" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib redact::section_allowlist_tests::no_allowed_sections_yields_no_fields_at_all 2>&1 | grep -q '1 passed'"
check_ok "cargo test proves a resumed allowed section after a disallowed one still contributes" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib redact::section_allowlist_tests::resumed_allowed_section_after_a_disallowed_one_is_still_extracted 2>&1 | grep -q '1 passed'"

# --- source-level guarantee: SectionAllowlist has no method that returns
# or exposes a disallowed section's raw text, only the per-field callback ---
allowlist_impl="$(grep -E "^impl.*SectionAllowlist" -A 30 "$REPO_ROOT/src/redact.rs")"
if printf '%s' "$allowlist_impl" | grep -qE "pub fn raw_text|pub fn all_sections|pub fn full_text"; then
    fail "SectionAllowlist exposes no whole-text/raw-section accessor" "found a raw-text accessor"
else
    pass "SectionAllowlist exposes no whole-text/raw-section accessor"
fi

# --- audit: none of this agent's own commands shell out to a privileged
# platform report or a tool that returns sections beyond what they parse ---
counter_liveness_commands="$(grep -n "Command::new" "$REPO_ROOT/src/network_tests/counter_liveness.rs")"
if printf '%s' "$counter_liveness_commands" | grep -qE "system_profiler|wdutil|ioreg"; then
    fail "counter-liveness's netstat invocation requests no extra sections" "found a privileged-report tool"
else
    pass "counter-liveness's netstat invocation requests no extra sections"
fi
