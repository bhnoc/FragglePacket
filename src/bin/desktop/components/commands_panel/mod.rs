//! Registry-driven command browser for the desktop app.
//!
//! The desktop's twelve panels were wired to the in-process `NetworkTest`
//! framework, so 60 of 79 subcommands -- every gap-closing command, i.e. most of
//! the tool -- were unreachable. This panel renders the same registry the TUI
//! uses, so both UIs show one capability surface and a newly added command
//! appears in both without touching either.
//!
//! Availability is declared, never discovered by failing. A command whose live
//! sampling needs macOS renders as ingest-only with the reason; one with no
//! alternative renders disabled. Clicking something that cannot work here wastes
//! a run and, worse, can return a hollow result that looks like a measurement.

use dioxus::prelude::*;

use crate::state::{AppState, PanelId};
use crate::window_manager::DetachButton;
use fraggle_packet::ui_bridge::registry::{self, Availability, Bucket, Cmd};
use fraggle_packet::ui_bridge::{run_subcommand, Outcome};

/// Availability rendered for the UI: a short badge, a CSS class, and the reason.
fn badge(cmd: &Cmd) -> (&'static str, &'static str, String) {
    match cmd.availability() {
        Availability::Unavailable(reason) => ("unavailable", "badge-error", reason.to_string()),
        Availability::IngestOnly(reason) => ("ingest only", "badge-warn", reason.to_string()),
        Availability::Available if cmd.needs_privilege => (
            "needs root",
            "badge-warn",
            "raw sockets require root or capabilities".to_string(),
        ),
        Availability::Available => ("ready", "badge-ok", String::new()),
    }
}

/// Renders one run's outcome. A refusal arrives as `Json` and must read as a
/// result: re-deriving a verdict here is how "REFUSED: insufficient evidence"
/// turns into a false green.
fn render_outcome(outcome: &Outcome) -> (String, String) {
    match outcome {
        Outcome::Json(v) => (
            "result".to_string(),
            serde_json::to_string_pretty(v).unwrap_or_else(|_| v.to_string()),
        ),
        Outcome::TextOnly(t) => ("output".to_string(), t.clone()),
        Outcome::Failed { exit_code, stderr } => (
            "failed".to_string(),
            format!("exit {exit_code:?}\n\n{}", stderr.trim()),
        ),
        Outcome::NotRun(why) => ("not run".to_string(), why.clone()),
    }
}

#[component]
pub fn CommandsPanel(state: Signal<AppState>, panel: PanelId) -> Element {
    let mut selected_bucket = use_signal(|| Bucket::WifiRf);
    let mut selected_cmd = use_signal(|| None::<&'static str>);
    let mut output = use_signal(String::new);
    let mut output_kind = use_signal(String::new);
    let mut running = use_signal(|| false);
    let _ = state;

    let bucket = *selected_bucket.read();
    let cmds = registry::in_bucket(bucket);
    let current: Option<&'static Cmd> = selected_cmd.read().and_then(registry::find);

    rsx! {
        div { class: "commands-panel",
            div { class: "panel",
                div { class: "panel-header",
                    span { class: "panel-title",
                        "Commands ({registry::COMMANDS.len()} subcommands)"
                    }
                    DetachButton { panel: panel }
                }
            }

            div { style: "display: grid; grid-template-columns: 220px 300px 1fr; gap: 16px; height: calc(100vh - 200px);",

                // Areas
                div { class: "panel", style: "overflow-y: auto;",
                    div { class: "panel-header", span { class: "panel-title", "Areas" } }
                    for b in Bucket::ALL.iter().copied() {
                        button {
                            key: "{b:?}",
                            class: if b == bucket { "btn active" } else { "btn" },
                            style: "display: block; width: 100%; text-align: left; margin-bottom: 4px;",
                            onclick: move |_| {
                                selected_bucket.set(b);
                                selected_cmd.set(None);
                            },
                            "{b.label()} ({registry::in_bucket(b).len()})"
                        }
                    }
                }

                // Commands in the selected area
                div { class: "panel", style: "overflow-y: auto;",
                    div { class: "panel-header",
                        span { class: "panel-title", "{bucket.label()}" }
                    }
                    for c in cmds.iter().copied() {
                        {
                            let (label, cls, _) = badge(c);
                            let is_sel = *selected_cmd.read() == Some(c.name);
                            rsx! {
                                div {
                                    key: "{c.name}",
                                    class: if is_sel { "list-item selected" } else { "list-item" },
                                    style: "cursor: pointer; padding: 6px;",
                                    onclick: move |_| selected_cmd.set(Some(c.name)),
                                    div { style: "display: flex; justify-content: space-between; gap: 8px;",
                                        span { style: "font-family: monospace;", "{c.name}" }
                                        span { class: "{cls}", "{label}" }
                                    }
                                    if let Some(g) = c.gaps {
                                        div { style: "font-size: 11px; opacity: 0.6;", "{g}" }
                                    }
                                }
                            }
                        }
                    }
                }

                // Detail + run
                div { class: "panel", style: "overflow-y: auto;",
                    match current {
                        None => rsx! {
                            div { class: "panel-header", span { class: "panel-title", "Select a command" } }
                            div { style: "padding: 12px; opacity: 0.7;",
                                "Every subcommand is listed by area. Availability is shown before you run anything: a command whose live sampling needs macOS is marked ingest only, and one that cannot work on this host at all is disabled."
                            }
                        },
                        Some(c) => {
                            let (blabel, bcls, reason) = badge(c);
                            let blocked = c.availability().is_blocked();
                            let needs_input = !c.required_inputs.is_empty();
                            let inputs = c.required_inputs.join(", ");
                            rsx! {
                                div { class: "panel-header",
                                    span { class: "panel-title", "{c.name}" }
                                    span { class: "{bcls}", "{blabel}" }
                                }
                                div { style: "padding: 12px;",
                                    p { "{c.summary}" }
                                    if !reason.is_empty() {
                                        p { style: "opacity: 0.8;", "{reason}" }
                                    }
                                    if needs_input {
                                        p { style: "opacity: 0.8;",
                                            "Requires {inputs}. Run this from the CLI with those arguments."
                                        }
                                    }
                                    p { style: "font-size: 11px; opacity: 0.6;",
                                        if c.emits_json { "structured JSON output" } else { "text output only" }
                                    }

                                    button {
                                        class: "btn primary",
                                        // Disabled rather than allowed-to-fail: the registry
                                        // already knows this cannot produce a result here.
                                        disabled: blocked || needs_input || *running.read(),
                                        onclick: move |_| {
                                            running.set(true);
                                            let args = c.invocation(&[]);
                                            let o = run_subcommand(c.name, &args);
                                            let (kind, text) = render_outcome(&o);
                                            output_kind.set(kind);
                                            output.set(text);
                                            running.set(false);
                                        },
                                        if *running.read() { "Running..." } else { "Run" }
                                    }

                                    if !output.read().is_empty() {
                                        div { style: "margin-top: 12px;",
                                            div { class: "panel-header",
                                                span { class: "panel-title", "{output_kind}" }
                                            }
                                            pre {
                                                style: "max-height: 40vh; overflow: auto; font-size: 11px; white-space: pre-wrap;",
                                                "{output}"
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The badge must reflect availability, not merely exist. Asserted through
    /// the registry so a blocked command can never render as "ready".
    #[test]
    fn a_blocked_command_never_renders_as_ready() {
        for c in registry::COMMANDS {
            let (label, cls, reason) = badge(c);
            if c.availability().is_blocked() {
                assert_eq!(label, "unavailable", "{} is blocked but badged {label}", c.name);
                assert_eq!(cls, "badge-error");
                assert!(!reason.is_empty(), "{} blocked with no reason", c.name);
            }
        }
    }

    #[test]
    fn privileged_commands_are_badged_as_needing_root() {
        let c = registry::find("capture").unwrap();
        if c.availability().is_available() {
            assert_eq!(badge(c).0, "needs root");
        }
    }

    #[test]
    fn a_plain_command_is_badged_ready_with_no_reason() {
        let c = registry::find("endpoints").unwrap();
        let (label, cls, reason) = badge(c);
        assert_eq!(label, "ready");
        assert_eq!(cls, "badge-ok");
        assert!(reason.is_empty());
    }

    /// A refusal must render as a result, never as a failure.
    #[test]
    fn a_refusal_renders_as_a_result_not_a_failure() {
        let refusal = serde_json::json!({ "verdict": "InsufficientCells" });
        let (kind, text) = render_outcome(&Outcome::Json(refusal));
        assert_eq!(kind, "result");
        assert!(text.contains("InsufficientCells"), "{text}");
    }

    #[test]
    fn a_failure_renders_as_failed_with_its_reason() {
        let (kind, text) = render_outcome(&Outcome::Failed {
            exit_code: Some(1),
            stderr: "no such file".into(),
        });
        assert_eq!(kind, "failed");
        assert!(text.contains("no such file"), "{text}");
    }

    #[test]
    fn every_bucket_has_commands_to_render() {
        for b in Bucket::ALL {
            assert!(!registry::in_bucket(*b).is_empty(), "{b:?} would render empty");
        }
    }
}
