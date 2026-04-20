//! Logs panel - Live test output viewer with expandable details

use dioxus::prelude::*;
use std::collections::HashSet;
use crate::state::{AppState, LogLevel, PanelId};
use crate::window_manager::DetachButton;

/// Logs panel showing live test output
#[component]
pub fn LogsPanel(state: Signal<AppState>, panel: PanelId) -> Element {
    let logs = state.read().logs.read().clone();
    let testing = *state.read().testing.read();
    let current_test = state.read().current_test_name.read().clone();
    let progress = *state.read().progress.read();

    // Track which log entries are expanded (by index)
    let mut expanded_entries: Signal<HashSet<usize>> = use_signal(HashSet::new);

    rsx! {
        div { class: "logs-panel",
            // Header with status and controls
            div { class: "panel",
                div { class: "panel-header",
                    span { class: "panel-title", "Test Execution Log" }
                    div { style: "display: flex; gap: 8px; align-items: center;",
                        if testing {
                            button {
                                class: "btn danger",
                                onclick: move |_| {
                                    state.read().cancel_tests();
                                    state.write().log(LogLevel::Warning, "Cancellation requested...");
                                },
                                "Stop Tests"
                            }
                        }
                        button {
                            class: "btn",
                            onclick: move |_| {
                                state.write().clear_logs();
                                expanded_entries.set(HashSet::new());
                            },
                            "Clear Log"
                        }
                        DetachButton { panel: panel }
                    }
                }

                // Current status
                if testing {
                    div { class: "current-status", style: "margin-bottom: 16px;",
                        div { style: "display: flex; align-items: center; gap: 12px; margin-bottom: 8px;",
                            span { class: "status-indicator running" }
                            span { class: "status-running",
                                if current_test.is_empty() {
                                    "Starting tests..."
                                } else {
                                    "Running: {current_test}"
                                }
                            }
                        }
                        div { class: "progress-bar",
                            div {
                                class: "fill",
                                style: "width: {(progress * 100.0) as u32}%;"
                            }
                        }
                        div { style: "font-size: 12px; color: var(--term-green-dim); margin-top: 4px;",
                            "{(progress * 100.0) as u32}% complete"
                        }
                    }
                }
            }

            // Log entries
            div { class: "panel log-container",
                div { class: "panel-header",
                    span { class: "panel-title", "Output ({logs.len()} entries)" }
                    button {
                        class: "btn",
                        style: "font-size: 11px; padding: 4px 8px;",
                        onclick: move |_| {
                            // Toggle all
                            let current = expanded_entries.read().clone();
                            if current.is_empty() {
                                // Expand all
                                let all: HashSet<usize> = (0..logs.len()).collect();
                                expanded_entries.set(all);
                            } else {
                                // Collapse all
                                expanded_entries.set(HashSet::new());
                            }
                        },
                        if expanded_entries.read().is_empty() { "Expand All" } else { "Collapse All" }
                    }
                }
                div { class: "log-entries",
                    if logs.is_empty() {
                        div { class: "no-logs",
                            "No log entries yet. Run a test to see output here."
                        }
                    } else {
                        for (i, entry) in logs.iter().rev().enumerate() {
                            {
                                let idx = logs.len() - 1 - i; // Actual index in the logs vec
                                let is_expanded = expanded_entries.read().contains(&idx);
                                let has_details = entry.cli_command.is_some() || entry.details.is_some() || !entry.metrics.is_empty();

                                let level_class = match entry.level {
                                    LogLevel::Info => "log-info",
                                    LogLevel::Running => "log-running",
                                    LogLevel::Success => "log-success",
                                    LogLevel::Warning => "log-warning",
                                    LogLevel::Error => "log-error",
                                };
                                let level_icon = match entry.level {
                                    LogLevel::Info => "[i]",
                                    LogLevel::Running => "[>]",
                                    LogLevel::Success => "[+]",
                                    LogLevel::Warning => "[!]",
                                    LogLevel::Error => "[x]",
                                };
                                let time = entry.timestamp.format("%H:%M:%S").to_string();
                                let message = entry.message.clone();
                                let cli_cmd = entry.cli_command.clone();
                                let details = entry.details.clone();
                                let metrics: Vec<_> = entry.metrics.clone();

                                rsx! {
                                    div {
                                        key: "{idx}",
                                        class: "log-entry-container",
                                        // Main log line
                                        div {
                                            class: "log-entry {level_class}",
                                            style: if has_details { "cursor: pointer;" } else { "" },
                                            onclick: move |_| {
                                                if has_details {
                                                    let mut current = expanded_entries.write();
                                                    if current.contains(&idx) {
                                                        current.remove(&idx);
                                                    } else {
                                                        current.insert(idx);
                                                    }
                                                }
                                            },
                                            // Expand/collapse indicator
                                            if has_details {
                                                span { class: "log-expand",
                                                    if is_expanded { "[-]" } else { "[+]" }
                                                }
                                            } else {
                                                span { class: "log-expand", "   " }
                                            }
                                            span { class: "log-time", "{time}" }
                                            span { class: "log-level", "{level_icon}" }
                                            span { class: "log-message", "{message}" }
                                        }

                                        // Expanded details
                                        if is_expanded && has_details {
                                            div { class: "log-details",
                                                // CLI command
                                                if let Some(cmd) = cli_cmd {
                                                    div { class: "log-detail-section",
                                                        span { class: "log-detail-label", "CLI Command:" }
                                                        code { class: "log-detail-code", "{cmd}" }
                                                    }
                                                }

                                                // Metrics
                                                if !metrics.is_empty() {
                                                    div { class: "log-detail-section",
                                                        span { class: "log-detail-label", "Results:" }
                                                        div { class: "log-metrics-grid",
                                                            for (key, value) in metrics.iter() {
                                                                div { class: "log-metric",
                                                                    span { class: "log-metric-key", "{key}:" }
                                                                    span { class: "log-metric-value", "{value}" }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }

                                                // Details/output
                                                if let Some(det) = details {
                                                    div { class: "log-detail-section",
                                                        span { class: "log-detail-label", "Output:" }
                                                        pre { class: "log-detail-output", "{det}" }
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
    }
}
