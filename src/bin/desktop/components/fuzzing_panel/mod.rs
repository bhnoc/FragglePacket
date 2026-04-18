//! Fuzzing Panel - Packet fuzzing controls

use dioxus::prelude::*;
use crate::state::AppState;
use crate::state::test_runner::TestUpdate;
use fraggle_packet::framework::TestCategory;

/// Fuzzing panel with mode selection and PCAP output
#[component]
pub fn FuzzingPanel(
    state: Signal<AppState>,
    update_tx: Coroutine<TestUpdate>,
) -> Element {
    let current_target = state.read().current_target.read().clone();
    let mut selected_mode = use_signal(|| "all".to_string());
    let mut output_path = use_signal(|| "reports/fuzz.pcap".to_string());
    let testing = *state.read().testing.read();
    let progress = *state.read().progress.read();

    // Get fuzzing results
    let fuzz_results = state.read().get_category_results(&current_target, TestCategory::Fuzzing);
    let latest_result = fuzz_results.last();

    let modes = vec![
        ("segment-size", "Segment Size", "Test TCP segment size handling"),
        ("length-mismatch", "Length Mismatch", "Test IP/TCP length field mismatches"),
        ("tcp-options", "TCP Options", "Test malformed TCP options"),
        ("fragmentation", "Fragmentation", "Test IP fragmentation handling"),
        ("checksum", "Checksum", "Test invalid checksum handling"),
        ("all", "All Modes", "Run all fuzzing modes"),
    ];

    rsx! {
        div { class: "fuzzing-panel",
            // Target input
            div { class: "panel",
                div { class: "panel-header",
                    span { class: "panel-title", "Packet Fuzzing" }
                }
                div { class: "target-input", style: "display: flex; gap: 8px;",
                    input {
                        r#type: "text",
                        placeholder: "Target IP or hostname",
                        value: "{current_target}",
                        style: "flex: 1;",
                        disabled: testing,
                        oninput: move |evt| {
                            state.write().current_target.set(evt.value().clone());
                        }
                    }
                }
            }

            // Mode selection
            div { class: "panel",
                div { class: "panel-header",
                    span { class: "panel-title", "Fuzzing Mode" }
                }
                div { class: "category-grid", style: "grid-template-columns: repeat(3, 1fr);",
                    for (mode, label, desc) in modes {
                        {
                            let mode_str = mode.to_string();
                            let is_selected = *selected_mode.read() == mode;
                            rsx! {
                                button {
                                    class: if is_selected { "category-btn selected" } else { "category-btn" },
                                    disabled: testing,
                                    onclick: move |_| {
                                        selected_mode.set(mode_str.clone());
                                    },
                                    span { class: "label", "{label}" }
                                    span { style: "font-size: 10px; color: var(--term-green-dim);", "{desc}" }
                                }
                            }
                        }
                    }
                }
            }

            // Output configuration
            div { class: "panel",
                div { class: "panel-header",
                    span { class: "panel-title", "Output" }
                }
                div { class: "output-config", style: "display: flex; gap: 8px; align-items: center;",
                    label { "PCAP Output:" }
                    input {
                        r#type: "text",
                        value: "{output_path}",
                        style: "flex: 1;",
                        disabled: testing,
                        oninput: move |evt| {
                            output_path.set(evt.value().clone());
                        }
                    }
                    button {
                        class: "btn",
                        disabled: testing,
                        onclick: move |_| {
                            spawn(async move {
                                if let Some(path) = rfd::AsyncFileDialog::new()
                                    .add_filter("PCAP Files", &["pcap"])
                                    .set_file_name("fuzz.pcap")
                                    .set_title("Save PCAP File")
                                    .save_file()
                                    .await
                                {
                                    output_path.set(path.path().to_string_lossy().to_string());
                                }
                            });
                        },
                        "Browse..."
                    }
                }
            }

            // Run button and progress
            div { class: "panel", style: "display: flex; gap: 8px; align-items: center;",
                button {
                    class: "btn primary",
                    disabled: testing,
                    onclick: move |_| {
                        let target = state.read().current_target.read().clone();
                        let runner = state.read().test_runner.clone();
                        let (tx, mut rx) = crate::state::test_runner::TestRunner::create_channel();

                        // Run fuzzing test
                        runner.run_category(target.clone(), TestCategory::Fuzzing, tx);

                        spawn(async move {
                            while let Some(update) = rx.recv().await {
                                update_tx.send(update);
                            }
                        });
                    },
                    if testing { "Generating..." } else { "Generate Fuzz Packets" }
                }
                if testing {
                    div { class: "progress-bar", style: "flex: 1;",
                        div {
                            class: "fill",
                            style: "width: {(progress * 100.0) as u32}%;"
                        }
                    }
                }
            }

            // Results
            if let Some(result) = latest_result {
                div { class: "panel",
                    div { class: "panel-header",
                        span { class: "panel-title", "Last Fuzzing Result" }
                    }
                    div { class: "fuzz-results",
                        div { class: "result-row",
                            span { "Mode:" }
                            span { class: "status-success", "{result.metadata.get(\"mode\").unwrap_or(&\"Unknown\".to_string())}" }
                        }
                        div { class: "result-row",
                            span { "Packets Generated:" }
                            span { class: "status-success", "{result.metrics.get(\"packets_generated\").unwrap_or(&0.0):.0}" }
                        }
                        div { class: "result-row",
                            span { "Output File:" }
                            span { "{result.metadata.get(\"output_file\").unwrap_or(&\"N/A\".to_string())}" }
                        }
                        div { class: "result-row",
                            span { "Target IP:" }
                            span { "{result.metadata.get(\"target_ip\").unwrap_or(&\"N/A\".to_string())}" }
                        }
                        div { class: "result-row",
                            span { "Duration:" }
                            span { "{result.duration.as_millis()}ms" }
                        }
                    }
                    if !result.diagnoses.is_empty() {
                        div { class: "recommendations", style: "margin-top: 12px;",
                            strong { "Next Steps:" }
                            ul {
                                for diagnosis in result.diagnoses.iter() {
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
    }
}
