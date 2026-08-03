//! GAP-016: shared privilege-failure classification, reused across every
//! elevated probe path (raw ICMP sockets, BPF-based capture, traceroute).
//!
//! Field bug this fixes: a TCP traceroute path failed with an EMPTY
//! `pcap_activate()` message when BPF access was unavailable -- the tool's
//! own text carried no content at all, so the opaque failure gave the
//! operator nothing to act on beyond "it didn't work". That is two
//! separate problems wearing one symptom: text-based tools (tcpdump,
//! traceroute) sometimes DO name the permission problem in stderr, but a
//! caller holding a raw syscall result (`std::io::Error` from opening a raw
//! socket) has the OS errno directly and should never fall back to an
//! empty string when that's available. `classify_privilege_failure` checks
//! both signals and, when neither is available, says so explicitly rather
//! than returning a status that looks like "no problem occurred".

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PrivilegeStatus {
    /// The privileged path was not attempted, or it succeeded.
    NotRequiredOrGranted,
    /// The privileged path failed for a permission reason. `detail` is the
    /// underlying signal preserved verbatim; `required_command` is the
    /// exact, copy-pasteable command to re-run elevated.
    Denied { detail: String, required_command: String },
}

impl PrivilegeStatus {
    pub fn is_denied(&self) -> bool {
        matches!(self, PrivilegeStatus::Denied { .. })
    }
}

/// True when `stderr` names a permission problem via wording actually
/// emitted by the common capture/trace tools on macOS and Linux. Does NOT
/// match on emptiness -- an empty string never satisfies this, by design,
/// so callers with no text signal are forced to fall back to
/// `classify_privilege_failure`'s errno path instead of silently matching
/// nothing.
pub fn stderr_names_a_permission_problem(stderr: &str) -> bool {
    let lower = stderr.to_lowercase();
    lower.contains("permission denied")
        || lower.contains("operation not permitted")
        || lower.contains("you don't have permission to capture")
        || lower.contains("socket: uid")
}

/// True for the two raw-socket errno values every privileged probe path in
/// this codebase can hit: `EPERM` (no `CAP_NET_RAW`/root) and `EACCES`
/// (blocked by a sandbox/MAC policy rather than a bare capability check).
pub fn errno_is_privilege_denial(e: &std::io::Error) -> bool {
    matches!(e.raw_os_error(), Some(code) if code == libc::EPERM || code == libc::EACCES)
}

/// Classifies a failure from either a subprocess (`stderr_text`) or a
/// direct syscall (`os_error`) into a `PrivilegeStatus`. When stderr names
/// the problem, that text is preserved as `detail`. When stderr is empty
/// but the syscall errno is a privilege denial -- the exact
/// `pcap_activate()` field bug, generalized -- `detail` states plainly
/// that the underlying tool produced no message and names the errno
/// instead, rather than passing an empty string through as if it were
/// informative.
pub fn classify_privilege_failure(
    stderr_text: &str,
    os_error: Option<&std::io::Error>,
    required_command: String,
) -> Option<PrivilegeStatus> {
    let trimmed = stderr_text.trim();
    if stderr_names_a_permission_problem(trimmed) {
        return Some(PrivilegeStatus::Denied { detail: trimmed.to_string(), required_command });
    }
    if let Some(e) = os_error {
        if errno_is_privilege_denial(e) {
            let detail = if trimmed.is_empty() {
                format!(
                    "permission denied (errno {}); the underlying tool produced no message text",
                    e.raw_os_error().unwrap_or(0)
                )
            } else {
                trimmed.to_string()
            };
            return Some(PrivilegeStatus::Denied { detail, required_command });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worded_stderr_is_preserved_verbatim() {
        let status = classify_privilege_failure(
            "socket: Operation not permitted",
            None,
            "sudo fraggle-packet trace 1.1.1.1".to_string(),
        );
        assert_eq!(
            status,
            Some(PrivilegeStatus::Denied {
                detail: "socket: Operation not permitted".to_string(),
                required_command: "sudo fraggle-packet trace 1.1.1.1".to_string(),
            })
        );
    }

    #[test]
    fn empty_stderr_with_eperm_errno_never_reports_an_empty_message() {
        // Reproduces the field bug: pcap_activate() gave nothing in text,
        // but the syscall-level signal (EPERM here) was available.
        let e = std::io::Error::from_raw_os_error(libc::EPERM);
        let status = classify_privilege_failure("", Some(&e), "sudo fraggle-packet trace 1.1.1.1".to_string());
        match status {
            Some(PrivilegeStatus::Denied { detail, .. }) => {
                assert!(!detail.is_empty());
                assert!(detail.contains("no message text"));
            }
            other => panic!("expected Denied with a non-empty detail, got {other:?}"),
        }
    }

    #[test]
    fn empty_stderr_with_no_errno_signal_is_not_misclassified_as_denied() {
        // No wording, no errno -- there is genuinely no privilege signal
        // here, so this must not be reported as a denial.
        assert_eq!(classify_privilege_failure("", None, "sudo x".to_string()), None);
    }

    #[test]
    fn eacces_is_also_a_privilege_denial() {
        let e = std::io::Error::from_raw_os_error(libc::EACCES);
        assert!(errno_is_privilege_denial(&e));
    }

    #[test]
    fn a_non_privilege_errno_is_not_flagged() {
        let e = std::io::Error::from_raw_os_error(libc::ENOENT);
        assert!(!errno_is_privilege_denial(&e));
        assert_eq!(classify_privilege_failure("", Some(&e), "sudo x".to_string()), None);
    }

    #[test]
    fn unrelated_stderr_text_is_not_misclassified() {
        assert!(!stderr_names_a_permission_problem("no such device: bogus0"));
    }
}

/// Inventory of the privileged operations this project performs, each paired
/// with the unprivileged path that still yields something useful.
///
/// GAP-016 asks not only that a denial be actionable but that the run
/// "continue with unprivileged alternatives". Declaring them in one place means
/// a new privileged call site has an obvious slot to name its fallback, rather
/// than each site deciding independently whether to degrade or refuse.
pub struct PrivilegedOp {
    pub what: &'static str,
    pub required_command: &'static str,
    pub unprivileged_alternative: Option<&'static str>,
}

pub const BPF_CAPTURE: PrivilegedOp = PrivilegedOp {
    what: "live packet capture (BPF device)",
    required_command: "sudo /usr/sbin/tcpdump -i <iface> -s <snaplen> -w <out.pcap>",
    unprivileged_alternative: Some("fraggle-packet pcap-report <existing.pcap>"),
};

pub const TCP_TRACEROUTE: PrivilegedOp = PrivilegedOp {
    what: "TCP traceroute (raw socket)",
    required_command: "sudo traceroute -T -p 443 <target>",
    unprivileged_alternative: Some(
        "fraggle-packet provider-path, which uses unprivileged TCP connect timing",
    ),
};

pub const RA_LISTEN: PrivilegedOp = PrivilegedOp {
    what: "router-advertisement capture (raw ICMPv6)",
    required_command: "sudo tcpdump -i <iface> -n 'icmp6 && ip6[40] == 134'",
    unprivileged_alternative: Some(
        "fraggle-packet ipv6-validate, which infers RA presence from a configured SLAAC address",
    ),
};

pub const WDUTIL_INFO: PrivilegedOp = PrivilegedOp {
    what: "full Wi-Fi radio state (wdutil)",
    required_command: "sudo wdutil info",
    unprivileged_alternative: Some(
        "fraggle-packet radio-diagnostic via system_profiler, which omits retry and WMM counters",
    ),
};

pub fn all_ops() -> Vec<&'static PrivilegedOp> {
    vec![&BPF_CAPTURE, &TCP_TRACEROUTE, &RA_LISTEN, &WDUTIL_INFO]
}

#[cfg(test)]
mod op_inventory_tests {
    use super::*;

    #[test]
    fn every_declared_op_names_a_command_and_an_unprivileged_path() {
        for op in all_ops() {
            assert!(!op.required_command.is_empty(), "{} has no command", op.what);
            assert!(
                op.unprivileged_alternative.is_some(),
                "{} offers no unprivileged path, so a denial would leave the operator stuck",
                op.what
            );
        }
    }
}
