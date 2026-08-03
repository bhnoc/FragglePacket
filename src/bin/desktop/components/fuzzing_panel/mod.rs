//! Fuzzing Panel - Packet fuzzing controls

use crate::state::test_runner::TestUpdate;
use crate::state::LogLevel;
use crate::state::{AppState, PanelId};
use crate::window_manager::DetachButton;
use dioxus::prelude::*;
use fraggle_packet::framework::TestCategory;

/// Fuzzing panel with mode selection and PCAP output
#[component]
pub fn FuzzingPanel(
    state: Signal<AppState>,
    update_tx: Coroutine<TestUpdate>,
    panel: PanelId,
) -> Element {
    let current_target = state.read().current_target.read().clone();
    let mut selected_mode = use_signal(|| "all".to_string());
    let mut output_path = use_signal(|| "reports/fuzz.pcap".to_string());
    let testing = *state.read().testing.read();
    let progress = *state.read().progress.read();

    // Track if we're actively generating fuzz packets (local to this panel)
    let mut is_generating = use_signal(|| false);

    // Get fuzzing results
    let fuzz_results = state
        .read()
        .get_category_results(&current_target, TestCategory::Fuzzing);
    let latest_result = fuzz_results.last();

    // Extract packets count and output file from latest result for status display
    let packets_from_result = latest_result
        .and_then(|r| r.metrics.get("packets_generated"))
        .map(|v| *v as u64)
        .unwrap_or(0);
    let output_from_result = latest_result
        .and_then(|r| r.metadata.get("output_file"))
        .cloned()
        .unwrap_or_default();

    let modes = vec![
        (
            "segment-size",
            "Segment Size",
            "Test TCP segment size handling",
        ),
        (
            "length-mismatch",
            "Length Mismatch",
            "Test IP/TCP length field mismatches",
        ),
        ("tcp-options", "TCP Options", "Test malformed TCP options"),
        (
            "fragmentation",
            "Fragmentation",
            "Test IP fragmentation handling",
        ),
        ("checksum", "Checksum", "Test invalid checksum handling"),
        ("all", "All Modes", "Run all fuzzing modes"),
    ];

    rsx! {
        div { class: "fuzzing-panel",
            // Target input
            div { class: "panel",
                div { class: "panel-header",
                    span { class: "panel-title", "Packet Fuzzing" }
                    DetachButton { panel: panel }
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
            div { class: "panel",
                div { class: "fuzz-controls", style: "display: flex; gap: 8px; align-items: center; margin-bottom: 12px;",
                    button {
                        class: "btn primary",
                        disabled: *is_generating.read(),
                        onclick: move |_| {
                            let target = state.read().current_target.read().clone();
                            let runner = state.read().test_runner.clone();
                            let (tx, mut rx) = crate::state::test_runner::TestRunner::create_channel();

                            // Reset state and start generating
                            is_generating.set(true);
                            state.write().reset_cancel();

                            // Run fuzzing test
                            runner.run_category(target.clone(), TestCategory::Fuzzing, tx);

                            spawn(async move {
                                while let Some(update) = rx.recv().await {
                                    // Check for cancellation
                                    if state.read().is_cancelled() {
                                        is_generating.set(false);
                                        break;
                                    }
                                    update_tx.send(update);
                                }
                                is_generating.set(false);
                            });
                        },
                        if *is_generating.read() { "Generating..." } else { "Generate" }
                    }
                    if *is_generating.read() {
                        button {
                            class: "btn danger",
                            onclick: move |_| {
                                state.read().cancel_tests();
                                state.write().log(LogLevel::Warning, "Fuzzing cancelled by user");
                                is_generating.set(false);
                            },
                            "Stop"
                        }
                    }
                    if !output_from_result.is_empty() && !*is_generating.read() {
                        {
                            let output_path_for_open = output_from_result.clone();
                            rsx! {
                                button {
                                    class: "btn",
                                    onclick: move |_| {
                                        let path = output_path_for_open.clone();
                                        // Get the parent directory of the output file
                                        if let Some(parent) = std::path::Path::new(&path).parent() {
                                            let parent_str = parent.to_string_lossy().to_string();
                                            #[cfg(target_os = "macos")]
                                            {
                                                let _ = std::process::Command::new("open")
                                                    .arg(&parent_str)
                                                    .spawn();
                                            }
                                            #[cfg(target_os = "linux")]
                                            {
                                                let _ = std::process::Command::new("xdg-open")
                                                    .arg(&parent_str)
                                                    .spawn();
                                            }
                                            #[cfg(target_os = "windows")]
                                            {
                                                let _ = std::process::Command::new("explorer")
                                                    .arg(&parent_str)
                                                    .spawn();
                                            }
                                        }
                                    },
                                    "Open Folder"
                                }
                            }
                        }
                    }
                    if *is_generating.read() {
                        div { class: "progress-bar", style: "flex: 1;",
                            div {
                                class: "fill",
                                style: "width: {(progress * 100.0) as u32}%;"
                            }
                        }
                    }
                }

                // Status display
                if *is_generating.read() || packets_from_result > 0 || !output_from_result.is_empty() {
                    div { class: "fuzz-status",
                        if *is_generating.read() {
                            div { class: "status-row",
                                span { class: "status-label", "Status:" }
                                span { class: "status-value status-warning", "Generating packets..." }
                            }
                        }
                        if packets_from_result > 0 {
                            div { class: "status-row",
                                span { class: "status-label", "Packets:" }
                                span { class: "status-value status-success", "{packets_from_result}" }
                            }
                        }
                        if !output_from_result.is_empty() {
                            div { class: "status-row",
                                span { class: "status-label", "Output:" }
                                span { class: "status-value", "{output_from_result}" }
                            }
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
