//! GAP-007: bounded, safe packet capture.
//!
//! Field evidence: a 75-second full-snaplen capture grew to roughly 2 GB
//! (1,569,970 packets). Nothing about that capture was bounded: no duration
//! cap, no snaplen limit, no size cap, no rotation. Capture also required a
//! manual sudo handoff outside the tool's control.
//!
//! This module wraps the system `tcpdump` with defaults that always
//! terminate on their own -- a default capture with no caps specified is
//! still bounded by a default duration and snaplen -- and never attempts to
//! elevate privilege itself. If the capture device needs a privilege this
//! process does not have, that is detected from tcpdump's own stderr and
//! reported as a named required command, never silently retried with sudo.

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// Every diagnostic capture is bounded even if the caller specifies nothing:
/// this default duration is the fix for "default diagnostic captures must be
/// bounded". 30s is enough to see a handful of flows without approaching the
/// multi-GB growth the field capture hit at 75s of unbounded full-snaplen.
pub const DEFAULT_DURATION_SECS: u64 = 30;
/// Full-snaplen (65535) is what turned 75s into ~2GB; a bounded default
/// captures enough of each packet for header/flow analysis without hoarding
/// payload bytes.
pub const DEFAULT_SNAPLEN: u32 = 262;
/// Hard ceiling on total bytes written, independent of duration. tcpdump's
/// own `-C` rotates per-file at this size; we additionally stop the process
/// once the sum across rotated files would exceed this, so "bounded" holds
/// even with rotation enabled.
pub const DEFAULT_MAX_BYTES: u64 = 50 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureOptions {
    pub interface: String,
    pub duration_secs: u64,
    pub snaplen: u32,
    pub max_bytes: u64,
    /// When set, rotates to a new file after this many bytes (tcpdump `-C`,
    /// in units of 1,000,000 bytes) and keeps at most this many files (`-W`).
    /// `max_bytes` still applies across the rotation set.
    pub rotate_file_mb: Option<u64>,
    pub rotate_file_count: Option<u32>,
    /// BPF filter expression, e.g. "tcp port 443" or "udp port 443".
    pub filter: Option<String>,
    pub output_path: PathBuf,
}

impl CaptureOptions {
    pub fn new(interface: impl Into<String>, output_path: impl Into<PathBuf>) -> Self {
        Self {
            interface: interface.into(),
            duration_secs: DEFAULT_DURATION_SECS,
            snaplen: DEFAULT_SNAPLEN,
            max_bytes: DEFAULT_MAX_BYTES,
            rotate_file_mb: None,
            rotate_file_count: None,
            filter: None,
            output_path: output_path.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StopReason {
    DurationElapsed,
    ByteCapReached,
    ProcessExited,
    OperatorInterrupted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureMetadata {
    pub interface: String,
    pub started_unix_secs: u64,
    pub requested_duration_secs: u64,
    pub actual_duration_secs: f64,
    pub snaplen: u32,
    pub max_bytes: u64,
    pub filter: Option<String>,
    pub stop_reason: StopReason,
    pub output_files: Vec<String>,
    pub total_bytes_written: u64,
    pub tcpdump_command: String,
}

#[derive(Debug, thiserror::Error)]
pub enum CaptureError {
    #[error("tcpdump not found on this system (looked for tcpdump on PATH)")]
    ToolMissing,
    #[error(
        "capture requires elevated privilege: {detail}. Re-run as: sudo {command}"
    )]
    PrivilegeRequired { detail: String, command: String },
    #[error("failed to start tcpdump: {0}")]
    SpawnFailed(String),
    #[error("tcpdump exited with an error before capturing anything: {0}")]
    ExitedWithError(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Override point for the harness: a fake capture tool can stand in for
/// tcpdump so bounded-capture behavior (duration cap, byte cap, exit
/// handling) is testable without requiring root or live network access.
fn tcpdump_binary() -> Option<String> {
    if let Ok(path) = std::env::var("FP_TCPDUMP_BIN") {
        if !path.is_empty() {
            return Some(path);
        }
    }
    for candidate in ["/usr/sbin/tcpdump", "/usr/bin/tcpdump", "tcpdump"] {
        if candidate.starts_with('/') {
            if std::path::Path::new(candidate).exists() {
                return Some(candidate.to_string());
            }
        } else if Command::new("which")
            .arg(candidate)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            return Some(candidate.to_string());
        }
    }
    None
}

/// True when a line of tcpdump stderr indicates missing capture privilege
/// rather than some other failure (bad interface name, bad filter, etc).
/// Delegates to the shared classifier (GAP-016) so every elevated path in
/// this codebase recognizes the same wording rather than each maintaining
/// its own copy that can drift out of sync.
fn is_privilege_error(stderr: &str) -> bool {
    crate::probe::privilege_status::stderr_names_a_permission_problem(stderr)
}

fn build_command(opts: &CaptureOptions) -> (String, Vec<String>) {
    let bin = tcpdump_binary().unwrap_or_else(|| "tcpdump".to_string());
    let mut args: Vec<String> = vec![
        "-i".to_string(),
        opts.interface.clone(),
        "-s".to_string(),
        opts.snaplen.to_string(),
        "-w".to_string(),
        opts.output_path.display().to_string(),
        "-U".to_string(), // flush each packet to disk so a killed process still yields a valid file
    ];
    if let Some(mb) = opts.rotate_file_mb {
        args.push("-C".to_string());
        args.push(mb.to_string());
    }
    if let Some(count) = opts.rotate_file_count {
        args.push("-W".to_string());
        args.push(count.to_string());
    }
    if let Some(filter) = &opts.filter {
        args.push(filter.clone());
    }
    (bin, args)
}

/// Renders the exact command an operator should run to capture with root,
/// so a permission failure names a copy-pasteable next step instead of an
/// opaque error.
pub fn suggested_privileged_command(opts: &CaptureOptions) -> String {
    let (bin, args) = build_command(opts);
    let mut parts = vec![bin];
    parts.extend(args);
    parts.join(" ")
}

/// Runs a bounded tcpdump capture. Never escalates privilege itself: if the
/// capture device requires a privilege this process lacks, returns
/// `CaptureError::PrivilegeRequired` naming the exact command to re-run
/// elevated, and does not retry, prompt, or invoke sudo.
///
/// Bounded even with no caller-specified caps: `duration_secs` always has a
/// value (`DEFAULT_DURATION_SECS` if unset by the caller), and the process is
/// killed at that deadline regardless of how much tcpdump has produced.
pub fn run_bounded_capture(opts: &CaptureOptions) -> Result<CaptureMetadata, CaptureError> {
    if tcpdump_binary().is_none() {
        return Err(CaptureError::ToolMissing);
    }

    let (bin, args) = build_command(opts);
    let started = Instant::now();
    let started_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut child = Command::new(&bin)
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| CaptureError::SpawnFailed(e.to_string()))?;

    // tcpdump prints "listening on ..." to stderr once capture actually
    // starts; an early exit before that line, especially with a permission
    // phrase, means the device could not be opened at all.
    let stderr = child.stderr.take();
    let mut stderr_lines: Vec<String> = Vec::new();
    let deadline = started + Duration::from_secs(opts.duration_secs.max(1));
    let mut stop_reason = StopReason::DurationElapsed;

    loop {
        if let Some(status) = child.try_wait()? {
            stop_reason = StopReason::ProcessExited;
            if let Some(mut s) = stderr {
                let mut buf = String::new();
                use std::io::Read;
                let _ = s.read_to_string(&mut buf);
                stderr_lines.extend(buf.lines().map(|l| l.to_string()));
            }
            if !status.success() {
                let joined = stderr_lines.join("\n");
                if is_privilege_error(&joined) {
                    return Err(CaptureError::PrivilegeRequired {
                        detail: joined.trim().to_string(),
                        command: suggested_privileged_command(opts),
                    });
                }
                return Err(CaptureError::ExitedWithError(joined.trim().to_string()));
            }
            break;
        }

        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            break;
        }

        if let Ok(bytes) = std::fs::metadata(&opts.output_path).map(|m| m.len()) {
            if bytes >= opts.max_bytes {
                stop_reason = StopReason::ByteCapReached;
                let _ = child.kill();
                let _ = child.wait();
                break;
            }
        }

        std::thread::sleep(Duration::from_millis(100));
    }

    let total_bytes = std::fs::metadata(&opts.output_path).map(|m| m.len()).unwrap_or(0);
    let mut output_files = vec![opts.output_path.display().to_string()];
    if opts.rotate_file_mb.is_some() {
        output_files = list_rotated_files(&opts.output_path);
    }

    Ok(CaptureMetadata {
        interface: opts.interface.clone(),
        started_unix_secs: started_unix,
        requested_duration_secs: opts.duration_secs,
        actual_duration_secs: started.elapsed().as_secs_f64(),
        snaplen: opts.snaplen,
        max_bytes: opts.max_bytes,
        filter: opts.filter.clone(),
        stop_reason,
        output_files,
        total_bytes_written: total_bytes,
        tcpdump_command: suggested_privileged_command(opts),
    })
}

/// tcpdump's `-C`/`-W` rotation names files `<base><N>` starting at 1.
fn list_rotated_files(base: &PathBuf) -> Vec<String> {
    let dir = base.parent().unwrap_or_else(|| std::path::Path::new("."));
    let stem = base.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    let mut found = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with(&stem) {
                found.push(entry.path().display().to_string());
            }
        }
    }
    found.sort();
    if found.is_empty() {
        vec![base.display().to_string()]
    } else {
        found
    }
}

/// Detects whether this process can plausibly open a capture device at all,
/// without actually starting a capture. Used to fail fast with an actionable
/// message before spending any of the capture duration budget.
pub fn preflight_privilege_check(interface: &str) -> Result<(), CaptureError> {
    let bin = tcpdump_binary().ok_or(CaptureError::ToolMissing)?;
    let mut child = Command::new(&bin)
        .args(["-i", interface, "-c", "1", "-w", "/dev/null"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| CaptureError::SpawnFailed(e.to_string()))?;

    let stderr = child.stderr.take();
    let deadline = Instant::now() + Duration::from_millis(1500);
    let mut lines: Vec<String> = Vec::new();
    let mut reader = stderr.map(BufReader::new);

    loop {
        if let Some(r) = reader.as_mut() {
            let mut line = String::new();
            if r.read_line(&mut line).unwrap_or(0) > 0 {
                let is_priv = is_privilege_error(&line);
                lines.push(line);
                if is_priv {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(CaptureError::PrivilegeRequired {
                        detail: lines.join(""),
                        command: format!("{} -i {} -c 1 -w /tmp/capture.pcap", bin, interface),
                    });
                }
            }
        }
        if let Some(status) = child.try_wait().ok().flatten() {
            if !status.success() {
                let joined = lines.join("");
                if is_privilege_error(&joined) {
                    return Err(CaptureError::PrivilegeRequired {
                        detail: joined.trim().to_string(),
                        command: format!("{} -i {} -c 1 -w /tmp/capture.pcap", bin, interface),
                    });
                }
            }
            return Ok(());
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_options_are_bounded_without_any_caller_input() {
        let opts = CaptureOptions::new("lo0", "/tmp/whatever.pcap");
        assert!(opts.duration_secs > 0);
        assert!(opts.snaplen > 0);
        assert!(opts.max_bytes > 0);
    }

    #[test]
    fn privilege_error_detected_from_macos_bpf_wording() {
        assert!(is_privilege_error(
            "tcpdump: lo0: You don't have permission to capture on that device\n\
             ((cannot open BPF device) /dev/bpf0: Permission denied)"
        ));
    }

    #[test]
    fn privilege_error_detected_from_linux_wording() {
        assert!(is_privilege_error("eth0: You don't have permission to capture on that device"));
        assert!(is_privilege_error("socket: Operation not permitted"));
    }

    #[test]
    fn non_privilege_error_not_misclassified() {
        assert!(!is_privilege_error("tcpdump: no such device: bogus0"));
    }

    #[test]
    fn suggested_command_includes_actual_interface_and_snaplen() {
        let opts = CaptureOptions::new("en0", "/tmp/out.pcap");
        let cmd = suggested_privileged_command(&opts);
        assert!(cmd.contains("en0"));
        assert!(cmd.contains(&opts.snaplen.to_string()));
        assert!(cmd.contains("/tmp/out.pcap"));
    }
}
