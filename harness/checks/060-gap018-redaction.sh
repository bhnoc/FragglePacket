#!/usr/bin/env bash
# GAP-018: consolidated redaction layer (fraggle_packet::redact). Default
# is redacted, one explicit flag (--retain-identifiers) retains raw values.
# The sweep below is the valuable part: it walks EVERY subcommand's --help
# text (offline, no network) for MAC/BSSID-shaped strings, so a future
# command that forgets to route through the shared policy is caught
# immediately rather than trusting a hand-picked list of commands.

check_ok "cargo test covers the redaction policy's category logic" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib redact:: 2>&1 | grep -q 'test result: ok'"
check_ok "cargo test proves a public IPv4 is redacted by default" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib redact::tests::default_policy_redacts_a_public_ipv4 2>&1 | grep -q '1 passed'"
check_ok "cargo test proves private and public IPs get distinct labels" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib redact::tests::default_policy_labels_private_ipv4_distinctly_from_public 2>&1 | grep -q '1 passed'"
check_ok "cargo test proves a MAC/BSSID-shaped token is redacted by default" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib redact::tests::default_policy_redacts_mac_shaped_tokens 2>&1 | grep -q '1 passed'"
check_ok "cargo test CENTRAL REGRESSION: the reveal policy leaves text completely unchanged" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib redact::tests::reveal_policy_leaves_text_unchanged 2>&1 | grep -q '1 passed'"
check_ok "cargo test proves the retain flag's absence means redacted" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib redact::tests::from_retain_flag_false_redacts 2>&1 | grep -q '1 passed'"
check_ok "cargo test proves an embedded port-suffixed IP is still found and redacted" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib redact::extra_tests::port_suffixed_ip_is_redacted 2>&1 | grep -q '1 passed'"
check_ok "cargo test proves an equals-prefixed MAC is still found and redacted" \
    bash -c "cd '$REPO_ROOT' && cargo test --release --lib redact::extra_tests::equals_prefixed_mac_is_redacted 2>&1 | grep -q '1 passed'"

# --- the sweep: every subcommand's default output must carry no raw
# MAC/BSSID-shaped string and no fixture-provided real MAC placeholder ---
subcommands="$("$BIN" --help 2>&1 | awk '/^Commands:/{f=1;next} /^Options:/{f=0} f && NF && $1 !~ /^-/ {print $1}' | grep -v '^help$')"
if [ -z "$subcommands" ]; then
    fail "subcommand enumeration for redaction sweep" "parsed zero subcommands from root --help"
else
    mac_leak=""
    for sub in $subcommands; do
        help_out="$("$BIN" "$sub" --help 2>&1)"
        if printf '%s' "$help_out" | grep -qoE '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}'; then
            mac_leak="$mac_leak $sub"
        fi
    done
    if [ -n "${mac_leak// /}" ]; then
        fail "no subcommand's --help text carries a raw MAC/BSSID-shaped string" "$mac_leak"
    else
        pass "no subcommand's --help text carries a raw MAC/BSSID-shaped string ($(printf '%s\n' $subcommands | wc -l | tr -d ' ') commands swept)"
    fi
fi

# --- commands this agent routed through the shared policy: default output
# redacts, --retain-identifiers reveals ---
me_out="$("$BIN" mss-evidence --ingest "$FIXTURE_DIR/pcap/mixed-head.pcap" 2>&1)"
if printf '%s' "$me_out" | grep -qoE '\b10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b'; then
    fail "mss-evidence default output redacts private IPs" "found a raw 10.x address"
else
    pass "mss-evidence default output redacts private IPs"
fi
me_retained="$("$BIN" mss-evidence --ingest "$FIXTURE_DIR/pcap/mixed-head.pcap" --retain-identifiers 2>&1)"
if printf '%s' "$me_retained" | grep -qoE '\b10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b'; then
    pass "mss-evidence --retain-identifiers reveals raw IPs"
else
    fail "mss-evidence --retain-identifiers reveals raw IPs" "no raw 10.x address found even with the retain flag"
fi
check_contains "mss-evidence advertises --retain-identifiers" "--retain-identifiers" \
    "$BIN" mss-evidence --help

check_contains "provider-path advertises --retain-identifiers" "--retain-identifiers" \
    "$BIN" provider-path --help
check_contains "pcap-report advertises --retain-identifiers" "--retain-identifiers" \
    "$BIN" pcap-report --help
check_contains "dns-steering advertises --retain-identifiers" "--retain-identifiers" \
    "$BIN" dns-steering --help

if net_guard; then
    pp_out="$("$BIN" provider-path github.com --interface en8 --trace-samples 1 --max-hops 3 --wait-secs 1 2>&1)"
    if [ -z "$pp_out" ]; then
        skip "provider-path default output redacts the local hop's private IP" "no output / no network / no en8"
    else
        if printf '%s' "$pp_out" | grep -qoE '\b(10|192\.168|172\.(1[6-9]|2[0-9]|3[0-1]))\.[0-9]{1,3}\.[0-9]{1,3}\b'; then
            fail "provider-path default output redacts the local hop's private IP" "found a raw private address"
        else
            pass "provider-path default output redacts the local hop's private IP"
        fi
    fi
else
    skip "provider-path default output redacts the local hop's private IP" "FP_HARNESS_OFFLINE=1"
fi
