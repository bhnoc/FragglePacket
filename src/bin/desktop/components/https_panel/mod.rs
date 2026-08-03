//! HTTPS Panel - Stage-by-stage HTTPS testing with waterfall visualization

use crate::state::test_runner::TestUpdate;
use crate::state::{AppState, PanelId};
use crate::window_manager::DetachButton;
use dioxus::prelude::*;
use fraggle_packet::framework::TestCategory;

/// HTTPS testing panel with waterfall chart
#[component]
pub fn HttpsPanel(
    state: Signal<AppState>,
    update_tx: Coroutine<TestUpdate>,
    panel: PanelId,
) -> Element {
    let current_target = state.read().current_target.read().clone();
    let testing = *state.read().testing.read();
    let progress = *state.read().progress.read();

    // Get HTTPS results for current target
    let https_results = state
        .read()
        .get_category_results(&current_target, TestCategory::HTTPS);
    let latest_result = https_results.last();

    // Extract waterfall data from latest result
    let stages: Vec<(&str, f64, bool)> = if let Some(result) = latest_result {
        vec![
            (
                "DNS",
                result.metrics.get("dns_time_ms").copied().unwrap_or(0.0),
                true,
            ),
            (
                "TCP Connect",
                result
                    .metrics
                    .get("tcp_connect_time_ms")
                    .copied()
                    .unwrap_or(0.0),
                result
                    .metadata
                    .get("tcp_success")
                    .map(|s| s == "true")
                    .unwrap_or(false),
            ),
            (
                "TLS Handshake",
                result
                    .metrics
                    .get("tls_handshake_time_ms")
                    .copied()
                    .unwrap_or(0.0),
                result
                    .metadata
                    .get("tls_success")
                    .map(|s| s == "true")
                    .unwrap_or(false),
            ),
            (
                "TTFB",
                result.metrics.get("ttfb_ms").copied().unwrap_or(0.0),
                true,
            ),
            (
                "Total",
                result.metrics.get("total_time_ms").copied().unwrap_or(0.0),
                true,
            ),
        ]
    } else {
        vec![
            ("DNS", 0.0, false),
            ("TCP Connect", 0.0, false),
            ("TLS Handshake", 0.0, false),
            ("TTFB", 0.0, false),
            ("Total", 0.0, false),
        ]
    };

    let max_time = stages
        .iter()
        .map(|(_, t, _)| *t)
        .fold(0.0_f64, f64::max)
        .max(1.0);

    // Extract diagnosis info
    let diagnosis_text = latest_result
        .and_then(|r| r.diagnoses.first())
        .map(|d| (d.title.clone(), d.description.clone(), d.severity))
        .unwrap_or_else(|| {
            (
                "No test run".to_string(),
                "Run HTTPS test to see diagnosis".to_string(),
                fraggle_packet::framework::DiagnosisSeverity::Info,
            )
        });

    rsx! {
        div { class: "https-panel",
            // Target input
            div { class: "panel",
                div { class: "panel-header",
                    span { class: "panel-title", "HTTPS Stage-by-Stage Test" }
                    DetachButton { panel: panel }
                }
                div { class: "target-input", style: "display: flex; gap: 8px;",
                    input {
                        r#type: "text",
                        placeholder: "Enter HTTPS target (e.g., google.com)",
                        value: "{current_target}",
                        style: "flex: 1;",
                        disabled: testing,
                        oninput: move |evt| {
                            state.write().current_target.set(evt.value().clone());
                        }
                    }
                    button {
                        class: "btn primary",
                        disabled: testing,
                        onclick: move |_| {
                            let target = state.read().current_target.read().clone();
                            let runner = state.read().test_runner.clone();
                            let (tx, mut rx) = crate::state::test_runner::TestRunner::create_channel();

                            runner.run_category(target.clone(), TestCategory::HTTPS, tx);

                            spawn(async move {
                                while let Some(update) = rx.recv().await {
                                    update_tx.send(update);
                                }
                            });
                        },
                        if testing { "Testing..." } else { "Run HTTPS Test" }
                    }
                }
                if testing {
                    div { class: "progress-bar", style: "margin-top: 8px;",
                        div {
                            class: "fill",
                            style: "width: {(progress * 100.0) as u32}%;"
                        }
                    }
                }
            }

            // Waterfall chart
            div { class: "panel",
                div { class: "panel-header",
                    span { class: "panel-title", "Connection Waterfall" }
                    if let Some(result) = latest_result {
                        span { style: "color: var(--term-green-dim);",
                            "HTTP {result.metadata.get(\"http_status\").unwrap_or(&\"---\".to_string())}"
                        }
                    }
                }
                div { class: "waterfall",
                    for (stage, time, success) in stages {
                        {
                            let width_pct = if max_time > 0.0 { (time / max_time * 100.0) as u32 } else { 0 };
                            let bar_class = if success { "waterfall-fill" } else { "waterfall-fill error" };
                            let min_width = if time > 0.0 { "40px" } else { "0" };
                            let time_text = if time > 0.0 { format!("{:.0}ms", time) } else { String::new() };
                            rsx! {
                                div { class: "waterfall-stage",
                                    div { class: "waterfall-label", "{stage}" }
                                    div { class: "waterfall-bar",
                                        div {
                                            class: "{bar_class}",
                                            style: "width: {width_pct}%; min-width: {min_width};",
                                            "{time_text}"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Diagnosis panel
            div { class: "panel",
                div { class: "panel-header",
                    span { class: "panel-title", "Diagnosis" }
                }
                div { class: "diagnosis",
                    {
                        let severity_class = match diagnosis_text.2 {
                            fraggle_packet::framework::DiagnosisSeverity::Info => "status-success",
                            fraggle_packet::framework::DiagnosisSeverity::Warning => "status-warning",
                            fraggle_packet::framework::DiagnosisSeverity::Error => "status-error",
                            fraggle_packet::framework::DiagnosisSeverity::Critical => "status-error",
                        };
                        rsx! {
                            p { class: "{severity_class}", "{diagnosis_text.0}" }
                            p { "{diagnosis_text.1}" }
                        }
                    }
                    if let Some(result) = latest_result {
                        for diagnosis in result.diagnoses.iter() {
                            if !diagnosis.recommendations.is_empty() {
                                div { class: "recommendations", style: "margin-top: 12px;",
                                    strong { "Recommendations:" }
                                    ul {
                                        for rec in diagnosis.recommendations.iter() {
                                            li { "{rec}" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // History
            if https_results.len() > 1 {
                div { class: "panel",
                    div { class: "panel-header",
                        span { class: "panel-title", "Test History" }
                        span { style: "color: var(--term-green-dim);", "{https_results.len()} tests" }
                    }
                    table { class: "table",
                        thead {
                            tr {
                                th { "Time" }
                                th { "DNS" }
                                th { "TCP" }
                                th { "TLS" }
                                th { "Total" }
                                th { "Status" }
                            }
                        }
                        tbody {
                            for result in https_results.iter().rev().take(5) {
                                {
                                    let status_class = match result.status {
                                        fraggle_packet::framework::TestStatus::Success => "status-success",
                                        fraggle_packet::framework::TestStatus::Warning => "status-warning",
                                        _ => "status-error",
                                    };
                                    rsx! {
                                        tr {
                                            td { "{result.duration.as_millis()}ms ago" }
                                            td { "{result.metrics.get(\"dns_time_ms\").unwrap_or(&0.0):.0}ms" }
                                            td { "{result.metrics.get(\"tcp_connect_time_ms\").unwrap_or(&0.0):.0}ms" }
                                            td { "{result.metrics.get(\"tls_handshake_time_ms\").unwrap_or(&0.0):.0}ms" }
                                            td { "{result.metrics.get(\"total_time_ms\").unwrap_or(&0.0):.0}ms" }
                                            td { class: "{status_class}", "{result.status:?}" }
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
