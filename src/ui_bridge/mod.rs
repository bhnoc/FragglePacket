//! Shared bridge letting the TUI and desktop app run any CLI subcommand and
//! render its structured output.
//!
//! Both UIs previously exposed only the 19 `NetworkTest` trait impls, leaving 60
//! of 79 subcommands unreachable -- including every gap-closing command, which is
//! most of what this tool actually does. Porting those into the trait was
//! rejected: the trait's one-target/pass-fail shape cannot express a command that
//! *refuses* a verdict for want of evidence, and flattening a refusal into a
//! green check would destroy the discipline the commands exist to enforce.
//!
//! So the UIs invoke the CLI and parse its `--json`. The CLI stays the single
//! owner of every evidence contract; the UIs are renderers. 58 of 79 subcommands
//! emit JSON today.
//!
//! Two properties matter for correctness here:
//!
//! * **A refusal is not an error.** `wired-edge` printing
//!   "REFUSED: no wired-edge conclusion" exits 0, because refusing to conclude
//!   from missing evidence is the correct behaviour. Only a genuine failure
//!   (bad path, unparseable input) exits non-zero. Collapsing those two into
//!   "it failed" would teach users to ignore refusals.
//! * **Output is banner-then-payload.** Every run prints a version banner before
//!   any JSON, so the payload starts at the first line beginning with `{` or `[`.
//!   This mirrors the `sed -n '/^{/,$p'` the harness has always used.

use std::path::{Path, PathBuf};
use std::process::Command;

/// What happened when a subcommand ran.
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    /// Ran, exited 0, and produced parseable JSON. This includes a command that
    /// deliberately refused to reach a verdict -- the refusal is *in* the JSON,
    /// and the UI must render it as a finding rather than an error.
    Json(serde_json::Value),
    /// Ran and exited 0 but emitted no JSON payload. Either the subcommand has
    /// no `--json` mode (21 of 79) or it printed only human text.
    TextOnly(String),
    /// Ran and exited non-zero: a real failure, not a refusal.
    Failed { exit_code: Option<i32>, stderr: String },
    /// Never launched. The CLI binary could not be found or could not be
    /// executed -- a bridge problem, distinct from the command failing.
    NotRun(String),
}

impl Outcome {
    /// True only for a run that produced usable structured output.
    pub fn is_json(&self) -> bool {
        matches!(self, Outcome::Json(_))
    }

    /// True when the command itself did not complete successfully. A refusal is
    /// deliberately NOT a failure.
    pub fn is_failure(&self) -> bool {
        matches!(self, Outcome::Failed { .. } | Outcome::NotRun(_))
    }
}

/// Splits the CLI's banner preamble from its JSON payload.
///
/// Returns the payload starting at the first line that begins with `{` or `[`,
/// or `None` when the output carries no JSON at all. Anchoring on the line start
/// matters: a `{` inside banner prose must not be mistaken for the payload.
pub fn extract_json_payload(stdout: &str) -> Option<&str> {
    let mut offset = 0usize;
    for line in stdout.split_inclusive('\n') {
        let trimmed = line.trim_start_matches(['\u{feff}', ' ', '\t']);
        if trimmed.starts_with('{') || trimmed.starts_with('[') {
            return Some(&stdout[offset + (line.len() - trimmed.len())..]);
        }
        offset += line.len();
    }
    None
}

/// Locates the `fraggle-packet` binary.
///
/// Looks beside the currently running executable first, so a desktop app
/// launched from `target/release/` finds the CLI shipped next to it, then falls
/// back to `PATH`. Never guesses a path that does not exist -- an absent binary
/// must surface as `NotRun` with the reason, not as a mysterious command
/// failure.
pub fn find_cli_binary() -> Result<PathBuf, String> {
    let exe_name = if cfg!(windows) { "fraggle-packet.exe" } else { "fraggle-packet" };

    if let Ok(current) = std::env::current_exe() {
        if let Some(dir) = current.parent() {
            let candidate = dir.join(exe_name);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }

    // PATH fallback, so a system-installed binary works too.
    if let Ok(path) = std::env::var("PATH") {
        let sep = if cfg!(windows) { ';' } else { ':' };
        for dir in path.split(sep) {
            if dir.is_empty() {
                continue;
            }
            let candidate = Path::new(dir).join(exe_name);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }

    Err(format!(
        "could not locate `{exe_name}` beside this executable or on PATH; build it with `cargo build --release`"
    ))
}

/// Runs a subcommand and classifies the result.
///
/// `args` are passed through verbatim; the caller decides whether to include
/// `--json`, because 21 subcommands have no JSON mode and asking for one would
/// make them fail on an unknown flag.
pub fn run_subcommand(subcommand: &str, args: &[String]) -> Outcome {
    let bin = match find_cli_binary() {
        Ok(b) => b,
        Err(e) => return Outcome::NotRun(e),
    };
    run_subcommand_with(&bin, subcommand, args)
}

/// Same as [`run_subcommand`] but against an explicit binary path, so tests can
/// exercise the parsing and classification without depending on discovery.
pub fn run_subcommand_with(bin: &Path, subcommand: &str, args: &[String]) -> Outcome {
    let output = match Command::new(bin).arg(subcommand).args(args).output() {
        Ok(o) => o,
        Err(e) => return Outcome::NotRun(format!("failed to execute {}: {e}", bin.display())),
    };

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

    if !output.status.success() {
        // A non-zero exit is a real failure. Prefer stderr for the reason, but
        // fall back to stdout so the user is never shown an empty explanation.
        let reason = if stderr.trim().is_empty() { stdout.trim().to_string() } else { stderr };
        return Outcome::Failed { exit_code: output.status.code(), stderr: reason };
    }

    match extract_json_payload(&stdout) {
        Some(payload) => match serde_json::from_str::<serde_json::Value>(payload) {
            Ok(v) => Outcome::Json(v),
            // Exited 0 with something JSON-shaped that will not parse. Surfaced
            // as text rather than silently dropped, so the UI shows what the
            // command actually said.
            Err(_) => Outcome::TextOnly(stdout),
        },
        None => Outcome::TextOnly(stdout),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_is_found_after_the_version_banner() {
        let out = "============\n FragglePacket v0.2 \n============\n\n{\n  \"a\": 1\n}\n";
        let p = extract_json_payload(out).expect("payload follows the banner");
        assert!(p.starts_with('{'), "got {p:?}");
        let v: serde_json::Value = serde_json::from_str(p).expect("parses");
        assert_eq!(v["a"], 1);
    }

    /// Several commands emit a top-level array, not an object.
    #[test]
    fn an_array_payload_is_found_too() {
        let out = "banner\n\n[\n  {\"x\": 2}\n]\n";
        let p = extract_json_payload(out).expect("array payload");
        assert!(p.starts_with('['), "got {p:?}");
        let v: serde_json::Value = serde_json::from_str(p).expect("parses");
        assert_eq!(v[0]["x"], 2);
    }

    /// A brace inside banner prose must not be mistaken for the payload start.
    #[test]
    fn a_brace_mid_line_is_not_treated_as_the_payload() {
        let out = "note: use {json} mode for machine output\n{\"real\": true}\n";
        let p = extract_json_payload(out).expect("payload");
        let v: serde_json::Value = serde_json::from_str(p).expect("parses");
        assert_eq!(v["real"], true, "picked the wrong line: {p:?}");
    }

    #[test]
    fn human_only_output_yields_no_payload() {
        assert!(extract_json_payload("== Wired Edge Health ==\n  REFUSED\n").is_none());
        assert!(extract_json_payload("").is_none());
    }

    /// The load-bearing distinction: a command refusing to conclude is a
    /// successful run whose JSON carries the refusal. It must never classify as
    /// a failure, or the UI will teach users that refusals are bugs.
    #[test]
    fn a_refusal_payload_is_json_not_failure() {
        let refusal = serde_json::json!({
            "verdict": "InsufficientCells",
            "missing": ["the same AP/radio in AX mode"]
        });
        let o = Outcome::Json(refusal);
        assert!(o.is_json());
        assert!(!o.is_failure(), "a refusal is a valid result, not a failure");
    }

    #[test]
    fn a_nonzero_exit_is_a_failure() {
        let o = Outcome::Failed { exit_code: Some(1), stderr: "no such file".into() };
        assert!(o.is_failure());
        assert!(!o.is_json());
    }

    #[test]
    fn a_missing_binary_is_not_run_rather_than_failed() {
        let o = run_subcommand_with(Path::new("/nonexistent/fraggle-packet"), "endpoints", &[]);
        match o {
            Outcome::NotRun(reason) => assert!(reason.contains("failed to execute"), "{reason}"),
            other => panic!("expected NotRun, got {other:?}"),
        }
    }

    /// End-to-end against the real binary when it has been built. Skipped
    /// rather than failed when absent, so a fresh clone's `cargo test` is green
    /// before the first release build.
    #[test]
    fn a_real_subcommand_round_trips_to_json() {
        let bin = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target/release/fraggle-packet");
        if !bin.is_file() {
            eprintln!("skipping: {} not built", bin.display());
            return;
        }
        match run_subcommand_with(&bin, "endpoints", &["--json".to_string()]) {
            Outcome::Json(v) => {
                assert!(v.get("providers").is_some(), "expected the endpoint registry: {v}");
            }
            other => panic!("expected Json, got {other:?}"),
        }
    }

    /// A real failure from the real binary must classify as Failed, not as an
    /// empty success.
    #[test]
    fn a_real_failure_classifies_as_failed() {
        let bin = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target/release/fraggle-packet");
        if !bin.is_file() {
            return;
        }
        let o = run_subcommand_with(
            &bin,
            "wired-edge",
            &["--bracket".to_string(), "/nonexistent-bracket.json".to_string()],
        );
        assert!(o.is_failure(), "expected a failure for a missing bracket file, got {o:?}");
    }
}
