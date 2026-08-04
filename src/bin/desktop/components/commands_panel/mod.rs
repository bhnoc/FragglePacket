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
    // Values for the selected command's required inputs, in order. Cleared when
    // the selection changes so one command's hostname cannot become another's
    // interface name.
    let mut inputs = use_signal(Vec::<String>::new);
    let mut input_errors = use_signal(Vec::<String>::new);
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
                                    onclick: move |_| {
                                selected_cmd.set(Some(c.name));
                                inputs.set(vec![String::new(); c.required_inputs.len()]);
                                input_errors.set(Vec::new());
                                output.set(String::new());
                            },
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
                                        div { style: "margin: 8px 0;",
                                            for (i, (name, kind)) in c.typed_inputs().into_iter().enumerate() {
                                                div { key: "{name}", style: "margin-bottom: 6px;",
                                                    label { style: "display: block; font-size: 11px; opacity: 0.75;", "{name}" }
                                                    input {
                                                        r#type: "text",
                                                        placeholder: "{kind.hint()}",
                                                        value: "{inputs.read().get(i).cloned().unwrap_or_default()}",
                                                        oninput: move |e| {
                                                            let mut v = inputs.read().clone();
                                                            if v.len() <= i { v.resize(i + 1, String::new()); }
                                                            v[i] = e.value();
                                                            inputs.set(v);
                                                        },
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    if !input_errors.read().is_empty() {
                                        div { style: "margin: 8px 0;",
                                            for err in input_errors.read().iter() {
                                                div { class: "badge-error", style: "display: block; margin-bottom: 4px;", "{err}" }
                                            }
                                        }
                                    }
                                    p { style: "font-size: 11px; opacity: 0.6;",
                                        if c.emits_json { "structured JSON output" } else { "text output only" }
                                    }

                                    button {
                                        class: "btn primary",
                                        // Disabled rather than allowed-to-fail: the registry
                                        // already knows this cannot produce a result here.
                                        disabled: blocked || *running.read(),
                                        onclick: move |_| {
                                            let values = inputs.read().clone();
                                            // Validate before spawning: an empty field or a
                                            // missing file is caught here, not as a confusing
                                            // CLI error the user has to decode.
                                            if let Err(errs) = c.validate_inputs(&values) {
                                                input_errors.set(errs);
                                                return;
                                            }
                                            input_errors.set(Vec::new());
                                            running.set(true);
                                            let args = c.invocation(&values);
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
    /// The Run button is gated on validate_inputs, so a command needing input is
    /// no longer permanently disabled -- it is disabled only until the values are
    /// valid. Asserting the validation itself, since the button state is derived
    /// from it.
    #[test]
    fn a_command_needing_input_is_runnable_once_values_are_valid() {
        let c = registry::find("quick").expect("quick is registered");
        assert!(!c.required_inputs.is_empty(), "quick needs a target");
        assert!(c.validate_inputs(&[]).is_err(), "must not run with nothing entered");
        assert!(
            c.validate_inputs(&["1.1.1.1".to_string()]).is_ok(),
            "a valid target must permit the run"
        );
    }

    #[test]
    fn an_empty_field_blocks_the_run_with_a_named_error() {
        let c = registry::find("quick").unwrap();
        let errs = c.validate_inputs(&[String::new()]).unwrap_err();
        assert!(!errs.is_empty());
        assert!(
            errs.iter().any(|e| e.contains("TARGET")),
            "error must name the field: {errs:?}"
        );
    }

    /// A file input must be rejected before the run when the path does not exist,
    /// rather than surfacing as a CLI error the user has to decode.
    #[test]
    fn a_missing_file_input_blocks_the_run() {
        let c = registry::find("wired-edge").expect("wired-edge is registered");
        if !c.required_inputs.is_empty() {
            let errs = c.validate_inputs(&["/nonexistent/bracket.json".to_string()]).unwrap_err();
            assert!(errs.iter().any(|e| e.contains("no file at")), "{errs:?}");
        }
    }

    /// Values are passed positionally ahead of --json, so the command sees its
    /// arguments in the right order.
    #[test]
    fn entered_values_precede_the_json_flag() {
        let c = registry::find("quick").unwrap();
        let inv = c.invocation(&["1.1.1.1".to_string()]);
        assert_eq!(inv[0], "1.1.1.1");
        if c.emits_json {
            assert_eq!(inv.last().unwrap(), "--json");
        }
    }

}
