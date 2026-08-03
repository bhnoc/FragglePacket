//! GAP-018: shared redaction primitive for sensitive network identifiers.
//!
//! The discipline already exists scattered: `ap_identity.rs` salts BSSIDs,
//! `stun.rs` hides the mapped address behind `--reveal-mapped-address`,
//! `wdutil.rs` stops reading at the BLUETOOTH section, `dhcp_lifecycle.rs`
//! excludes `chaddr`, `multicast_isolation.rs` counts responders without
//! naming them, `policy_manifest.rs` has an attendee-facing mode. Each of
//! those enforces its own category by hand. This module gives every
//! command ONE function to route final display text through so a new
//! command gets the same default-redacted behavior for free, rather than
//! re-deriving the regexes.
//!
//! Categories: SSID (no reliable syntactic marker -- callers with a known
//! SSID string pass it explicitly via `extra_literals`), BSSID/MAC
//! (`xx:xx:xx:xx:xx:xx`), public egress IPv4 (RFC 1918/loopback/link-local
//! excluded), private IPv4 (RFC 1918 + loopback + link-local), and IPv6
//! equivalents. Hostname/resolver-identity redaction is intentionally NOT
//! pattern-based here -- a hostname has no syntactic marker distinguishing
//! it from any other word, so blanket redaction would gut every diagnostic
//! message. Callers with a known hostname/resolver string (the common
//! case: it's a CLI argument or a resolved value already in hand) redact
//! it explicitly via `extra_literals`, the same mechanism GAP-057 uses for
//! SSID literals.
//!
//! Default is redacted; callers pass `RedactionPolicy::reveal()` only when
//! the operator explicitly requested raw output (one flag, checked once,
//! not re-implemented per command).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedactionMode {
    Redacted,
    Retained,
}

#[derive(Debug, Clone)]
pub struct RedactionPolicy {
    mode: RedactionMode,
    /// Known sensitive literals (SSID text, a specific hostname, a
    /// resolver address) the caller wants masked even though they carry
    /// no syntactic marker a regex could find.
    extra_literals: Vec<String>,
}

impl RedactionPolicy {
    pub fn default_redacted() -> Self {
        RedactionPolicy { mode: RedactionMode::Redacted, extra_literals: Vec::new() }
    }

    pub fn reveal() -> Self {
        RedactionPolicy { mode: RedactionMode::Retained, extra_literals: Vec::new() }
    }

    /// Builds a policy from the presence of an operator-facing "retain"
    /// flag -- the one explicit-flag-to-retain gate GAP-018 requires.
    pub fn from_retain_flag(retain_raw_identifiers: bool) -> Self {
        if retain_raw_identifiers {
            Self::reveal()
        } else {
            Self::default_redacted()
        }
    }

    pub fn with_literal(mut self, literal: impl Into<String>) -> Self {
        self.extra_literals.push(literal.into());
        self
    }

    pub fn is_redacting(&self) -> bool {
        self.mode == RedactionMode::Redacted
    }

    /// Applies every category to `text` and returns the result. Idempotent
    /// -- redacting already-redacted text is a no-op, so callers can
    /// apply this to an assembled multi-line report without needing to
    /// track which substrings were already masked.
    pub fn apply(&self, text: &str) -> String {
        if self.mode == RedactionMode::Retained {
            return text.to_string();
        }
        let mut out = redact_mac_or_bssid(text);
        out = redact_ipv4(&out);
        out = redact_ipv6(&out);
        for literal in &self.extra_literals {
            if !literal.is_empty() {
                out = out.replace(literal.as_str(), "<redacted>");
            }
        }
        out
    }
}

/// Scans `text` for maximal runs of characters matching `is_candidate_char`
/// and passes each run to `try_redact`, which returns a replacement label
/// if the run matches the target shape. This -- not word-boundary
/// trimming -- is what lets a colon-adjacent port (`140.82.114.4:443`) or
/// an `=`-prefixed BSSID (`bssid=aa:bb:cc:dd:ee:ff`) still get found: the
/// candidate run is extracted from wherever it starts inside the token,
/// not just from a whole whitespace-delimited word.
fn scan_and_replace(text: &str, is_candidate_char: impl Fn(char) -> bool, try_redact: impl Fn(&str) -> Option<&'static str>) -> String {
    let mut out = String::with_capacity(text.len());
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if is_candidate_char(chars[i]) {
            let start = i;
            while i < chars.len() && is_candidate_char(chars[i]) {
                i += 1;
            }
            let run: String = chars[start..i].iter().collect();
            if let Some(label) = try_redact(&run) {
                out.push_str(label);
            } else {
                out.push_str(&run);
            }
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    out
}

/// `xx:xx:xx:xx:xx:xx` (BSSID/MAC) -- six colon-separated hex octets. This
/// is the same shape `harness/checks/001-fixture-privacy.sh` scans fixtures
/// for; the placeholder text used there, `02:00:00:00:00:01`, is not
/// special-cased here -- if a caller's own test data uses it, it will also
/// be redacted, which is the conservative default.
fn redact_mac_or_bssid(text: &str) -> String {
    scan_and_replace(
        text,
        |c| c.is_ascii_hexdigit() || c == ':',
        |run| {
            // A run can contain a MAC plus trailing/leading hex-shaped
            // noise from IPv6 groups sharing the ':' character; only an
            // EXACT 6-octet colon-separated hex shape counts.
            if is_mac_shaped(run) {
                Some("<redacted-mac>")
            } else {
                None
            }
        },
    )
}

fn is_mac_shaped(s: &str) -> bool {
    let parts: Vec<&str> = s.split(':').collect();
    parts.len() == 6 && parts.iter().all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()))
}

fn redact_ipv4(text: &str) -> String {
    scan_and_replace(text, |c| c.is_ascii_digit() || c == '.', |run| {
        run.parse::<Ipv4Addr>().ok().map(|addr| redaction_label_for(IpAddr::V4(addr)))
    })
}

fn redact_ipv6(text: &str) -> String {
    scan_and_replace(
        text,
        |c| c.is_ascii_hexdigit() || c == ':' || c == '%',
        |run| {
            if run.matches(':').count() < 2 {
                return None;
            }
            let candidate = run.split('%').next().unwrap_or(run);
            candidate.parse::<Ipv6Addr>().ok().map(|addr| redaction_label_for(IpAddr::V6(addr)))
        },
    )
}

/// Distinct labels for public vs private/loopback/link-local addresses --
/// a caller reading redacted output can still tell "this was someone's
/// public egress IP" from "this was an internal address", which matters
/// for diagnosing without ever seeing the real value.
fn redaction_label_for(addr: IpAddr) -> &'static str {
    if is_private_or_local(addr) {
        "<redacted-private-ip>"
    } else {
        "<redacted-public-ip>"
    }
}

fn is_private_or_local(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            v6.is_loopback() || (v6.segments()[0] & 0xffc0) == 0xfe80 || (v6.segments()[0] & 0xfe00) == 0xfc00
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_redacts_a_public_ipv4() {
        let policy = RedactionPolicy::default_redacted();
        let out = policy.apply("connect 140.82.114.4:443 -> ok");
        assert!(!out.contains("140.82.114.4"));
        assert!(out.contains("<redacted-public-ip>"));
    }

    #[test]
    fn default_policy_labels_private_ipv4_distinctly_from_public() {
        let policy = RedactionPolicy::default_redacted();
        let out = policy.apply("hop 1: 10.10.250.1");
        assert!(!out.contains("10.10.250.1"));
        assert!(out.contains("<redacted-private-ip>"));
        assert!(!out.contains("<redacted-public-ip>"));
    }

    #[test]
    fn default_policy_redacts_mac_shaped_tokens() {
        let policy = RedactionPolicy::default_redacted();
        let out = policy.apply("bssid=aa:bb:cc:dd:ee:ff seen");
        assert!(!out.contains("aa:bb:cc:dd:ee:ff"));
        assert!(out.contains("<redacted-mac>"));
    }

    #[test]
    fn reveal_policy_leaves_text_unchanged() {
        let policy = RedactionPolicy::reveal();
        let text = "hop 1: 10.10.250.1 mac=aa:bb:cc:dd:ee:ff";
        assert_eq!(policy.apply(text), text);
    }

    #[test]
    fn from_retain_flag_false_redacts() {
        let policy = RedactionPolicy::from_retain_flag(false);
        assert!(policy.is_redacting());
    }

    #[test]
    fn from_retain_flag_true_reveals() {
        let policy = RedactionPolicy::from_retain_flag(true);
        assert!(!policy.is_redacting());
    }

    #[test]
    fn extra_literal_masks_a_known_hostname_with_no_syntactic_marker() {
        let policy = RedactionPolicy::default_redacted().with_literal("internal-resolver.example.corp");
        let out = policy.apply("query sent to internal-resolver.example.corp");
        assert!(!out.contains("internal-resolver.example.corp"));
        assert!(out.contains("<redacted>"));
    }

    #[test]
    fn ipv6_loopback_and_link_local_are_labeled_private() {
        let policy = RedactionPolicy::default_redacted();
        let out = policy.apply("addr fe80::1 seen");
        assert!(out.contains("<redacted-private-ip>"));
    }

    #[test]
    fn idempotent_on_already_redacted_text() {
        let policy = RedactionPolicy::default_redacted();
        let once = policy.apply("10.10.250.1");
        let twice = policy.apply(&once);
        assert_eq!(once, twice);
    }
}

/// GAP-020: generalized allowlist-extraction for privileged platform
/// reports, lifted from `load_guard::wdutil::parse_wdutil_info`'s pattern
/// (section-header-delimited text, only one named section entered as a
/// parse state at all -- e.g. `wdutil info`'s `WIFI` section, never
/// `BLUETOOTH`). That module is off-limits this sprint and already
/// implements this correctly for its one case; this is the same mechanism
/// made reusable so the NEXT command that shells out to a privileged
/// report (a `system_profiler`/`ioreg`/similar tool with more sections
/// than it needs) does not need to hand-roll the same state machine.
///
/// Audit note: none of this agent's own commands (`counter-liveness`'s
/// `netstat -I <iface> -b`, `dns-steering`'s `dig`, `provider-path`'s
/// `traceroute`) are privileged platform reports or emit sections beyond
/// what they parse, so nothing here needed migration -- this primitive is
/// prepared for the next command that does.
pub struct SectionAllowlist<'a> {
    /// Section header names permitted to be entered as a parse state.
    /// Any other bare header (e.g. "BLUETOOTH") causes every line until
    /// the next header to be skipped entirely -- never buffered, never
    /// passed to a caller callback.
    allowed_sections: &'a [&'a str],
}

impl<'a> SectionAllowlist<'a> {
    pub fn new(allowed_sections: &'a [&'a str]) -> Self {
        SectionAllowlist { allowed_sections }
    }

    /// Walks `text` line by line, calling `on_field_line(line)` only for
    /// lines inside an allowed section. A line is a header when it starts
    /// at column 0 and contains no ':' -- the same heuristic
    /// `parse_wdutil_info` uses for `wdutil info`'s output shape.
    pub fn extract_fields(&self, text: &str, mut on_field_line: impl FnMut(&str)) {
        let mut current_allowed = false;
        for raw_line in text.lines() {
            let trimmed = raw_line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let is_header = !raw_line.starts_with(' ') && !trimmed.contains(':');
            if is_header {
                current_allowed = self.allowed_sections.contains(&trimmed);
                continue;
            }
            if current_allowed {
                on_field_line(trimmed);
            }
        }
    }
}

#[cfg(test)]
mod section_allowlist_tests {
    use super::*;

    const SAMPLE: &str = "WIFI\n  RSSI : -55\n  BSSID : aa:bb:cc:dd:ee:ff\nBLUETOOTH\n  Paired Device : James's MacBook\n  Address : 11:22:33:44:55:66\nWIFI\n  Noise : -90\n";

    #[test]
    fn only_allowed_section_lines_are_extracted() {
        let allowlist = SectionAllowlist::new(&["WIFI"]);
        let mut lines = Vec::new();
        allowlist.extract_fields(SAMPLE, |line| lines.push(line.to_string()));
        assert_eq!(lines, vec!["RSSI : -55", "BSSID : aa:bb:cc:dd:ee:ff", "Noise : -90"]);
    }

    #[test]
    fn disallowed_section_content_never_reaches_the_callback() {
        let allowlist = SectionAllowlist::new(&["WIFI"]);
        let mut saw_bluetooth_content = false;
        allowlist.extract_fields(SAMPLE, |line| {
            if line.contains("James") || line.contains("11:22:33:44:55:66") {
                saw_bluetooth_content = true;
            }
        });
        assert!(!saw_bluetooth_content, "BLUETOOTH section content must never reach the field callback");
    }

    #[test]
    fn no_allowed_sections_yields_no_fields_at_all() {
        let allowlist = SectionAllowlist::new(&[]);
        let mut count = 0;
        allowlist.extract_fields(SAMPLE, |_| count += 1);
        assert_eq!(count, 0);
    }

    #[test]
    fn resumed_allowed_section_after_a_disallowed_one_is_still_extracted() {
        // WIFI appears twice, separated by BLUETOOTH -- both WIFI runs
        // must contribute, proving the state machine isn't "first match
        // wins" but tracks current section on every header line.
        let allowlist = SectionAllowlist::new(&["WIFI"]);
        let mut lines = Vec::new();
        allowlist.extract_fields(SAMPLE, |line| lines.push(line.to_string()));
        assert!(lines.iter().any(|l| l.contains("Noise")));
    }
}

#[cfg(test)]
mod extra_tests {
    use super::*;

    #[test]
    fn port_suffixed_ip_is_redacted() {
        let policy = RedactionPolicy::default_redacted();
        let out = policy.apply("connect 140.82.114.4:443 -> ok");
        assert!(!out.contains("140.82.114.4"));
        assert!(out.contains(":443"));
    }

    #[test]
    fn equals_prefixed_mac_is_redacted() {
        let policy = RedactionPolicy::default_redacted();
        let out = policy.apply("bssid=aa:bb:cc:dd:ee:ff seen");
        assert!(!out.contains("aa:bb:cc:dd:ee:ff"));
    }
}
