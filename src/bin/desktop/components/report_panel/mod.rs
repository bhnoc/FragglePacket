//! Report Panel - Unified README_FIRST-style diagnosis

use crate::components::target_input::TargetInput;
use crate::state::{AppState, LogLevel, PanelId};
use crate::window_manager::DetachButton;
use dioxus::prelude::*;
use fraggle_packet::diagnosis::{render_unified_report, DiagnosisEngine, DiagnosisEvidence};
use fraggle_packet::framework::NetworkTest;
use fraggle_packet::network_tests::{
    https::HttpsTest, Raw9100BulkTest, SshDataPathTest, UploadSizeSweepTest,
};

#[component]
pub fn ReportPanel(state: Signal<AppState>, panel: PanelId) -> Element {
    let current_target = state.read().current_target.read().clone();
    let testing = *state.read().testing.read();
    let report_text = state.read().last_report.read().clone();

    rsx! {
        div { class: "probes-panel",
            div { class: "panel",
                div { class: "panel-header",
                    span { class: "panel-title", "Unified Blackhole Report" }
                    DetachButton { panel: panel }
                }
                p { style: "color: var(--term-green-dim); font-size: 12px; margin: 4px 0 12px;",
                    "Runs HTTPS, upload sweep, SSH data-path, and raw 9100 probes, then renders a README_FIRST-style diagnosis with aggregated blackhole score."
                }
                TargetInput { state: state, disabled: testing }
                div { style: "margin-top: 12px;",
                    button {
                        class: "btn primary",
                        disabled: testing || current_target.is_empty(),
                        onclick: move |_| {
                            let target = state.read().current_target.read().clone();
                            state.write().log(LogLevel::Info, format!("Generating unified report for {}", target));
                            state.write().testing.set(true);
                            spawn(async move {
                                let report = tokio::task::spawn_blocking(move || {
                                    generate_unified_report(&target)
                                }).await.unwrap_or_else(|e| format!("join error: {}", e));
                                state.write().last_report.set(report);
                                state.write().testing.set(false);
                                state.write().log(LogLevel::Success, "Report generated");
                            });
                        },
                        "Generate Unified Report"
                    }
                }
            }
            div { class: "panel",
                div { class: "panel-header",
                    span { class: "panel-title", "README_FIRST Output" }
                }
                if report_text.is_empty() {
                    p { style: "color: var(--term-green-dim);",
                        "No report generated yet. Set a target and click the button above."
                    }
                } else {
                    pre {
                        style: "white-space: pre-wrap; font-family: monospace; background: var(--term-bg); color: var(--term-green); padding: 12px; border: 1px solid var(--term-green-dim); max-height: 600px; overflow: auto;",
                        "{report_text}"
                    }
                }
            }
        }
    }
}

fn generate_unified_report(target: &str) -> String {
    let mut ev = DiagnosisEvidence::default();
    let mut lines = Vec::new();

    lines.push(format!("--- HTTPS probe against {} ---", target));
    if let Ok(r) = HttpsTest::new().run(target) {
        ev.tcp_connect_success = r
            .metrics
            .get("tls_success")
            .map(|v| *v > 0.5);
        lines.push(format!("  status: {:?}", r.status));
        for (k, v) in &r.metrics {
            lines.push(format!("  metric {} = {}", k, v));
        }
    }

    lines.push(format!("--- Upload sweep against {} ---", target));
    if let Ok(r) = UploadSizeSweepTest::new().run(target) {
        let fails = r.metadata.get("upload_fail_sizes").cloned().unwrap_or_default();
        ev.upload_fail_sizes = fails
            .split(',')
            .filter_map(|s| s.trim().parse().ok())
            .collect();
        lines.push(format!("  status: {:?}", r.status));
        lines.push(format!("  fail_sizes: {}", fails));
    }

    lines.push(format!("--- SSH banner/echo against {} ---", target));
    if let Ok(r) = SshDataPathTest::new().run(target) {
        ev.ssh_banner_ok = r.metadata.get("ssh_banner_ok").and_then(|v| v.parse().ok());
        ev.ssh_exec_ok = r.metadata.get("ssh_exec_ok").and_then(|v| v.parse().ok());
        lines.push(format!("  banner_ok: {:?}", ev.ssh_banner_ok));
        lines.push(format!("  exec_ok: {:?}", ev.ssh_exec_ok));
    }

    lines.push(format!("--- Raw 9100 against {} ---", target));
    if let Ok(r) = Raw9100BulkTest::new().run(target) {
        let fails = r.metadata.get("printer_fail_sizes").cloned().unwrap_or_default();
        ev.printer_fail_sizes = fails
            .split(',')
            .filter_map(|s| s.trim().parse().ok())
            .collect();
        lines.push(format!("  status: {:?}", r.status));
        lines.push(format!("  fail_sizes: {}", fails));
    }

    let engine = DiagnosisEngine::new();
    let diagnoses = engine.diagnose(&ev);
    let mut out = String::new();
    out.push_str(&lines.join("\n"));
    out.push_str("\n\n");
    out.push_str(&render_unified_report(&diagnoses, &ev));
    out
}
