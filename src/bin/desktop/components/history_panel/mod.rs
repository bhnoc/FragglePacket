//! History panel - Previous test results

use crate::components::results_display::ResultsDisplay;
use crate::state::{AppState, PanelId};
use crate::window_manager::DetachButton;
use dioxus::prelude::*;
use fraggle_packet::framework::TestStatus;

/// History panel showing previous test runs
#[component]
pub fn HistoryPanel(state: Signal<AppState>, panel: PanelId) -> Element {
    let history = state.read().history.read().clone();
    let mut selected_history = use_signal(|| None::<u64>);

    // Get selected entry
    let selected_entry = selected_history
        .read()
        .and_then(|id| history.iter().find(|e| e.id == id).cloned());

    rsx! {
        div { class: "history-panel",
            // Header
            div { class: "panel",
                div { class: "panel-header",
                    span { class: "panel-title", "Test History ({history.len()} runs)" }
                    div { style: "display: flex; gap: 8px; align-items: center;",
                        button {
                            class: "btn danger",
                            disabled: history.is_empty(),
                            onclick: move |_| {
                                state.write().clear_history();
                                selected_history.set(None);
                            },
                            "Clear History"
                        }
                        DetachButton { panel: panel }
                    }
                }
            }

            div { style: "display: grid; grid-template-columns: 350px 1fr; gap: 16px; height: calc(100vh - 200px);",
                // History list
                div { class: "panel", style: "overflow-y: auto;",
                    div { class: "panel-header",
                        span { class: "panel-title", "Previous Runs" }
                    }
                    if history.is_empty() {
                        div { class: "no-history",
                            style: "padding: 24px; text-align: center; color: var(--term-green-dim);",
                            "No test history yet."
                            br {}
                            "Run some tests to build history."
                        }
                    } else {
                        div { class: "history-list",
                            for entry in &history {
                                {
                                    let id = entry.id;
                                    let is_selected = *selected_history.read() == Some(id);
                                    let success_count = entry.results.iter()
                                        .filter(|r| r.status == TestStatus::Success)
                                        .count();
                                    let total = entry.results.len();
                                    let time_str = entry.timestamp.format("%Y-%m-%d %H:%M:%S").to_string();
                                    let category_str = if entry.categories.is_empty() {
                                        "All Tests".to_string()
                                    } else if entry.categories.len() == 1 {
                                        entry.categories.iter().next().unwrap().as_str().to_string()
                                    } else {
                                        format!("{} categories", entry.categories.len())
                                    };

                                    rsx! {
                                        div {
                                            key: "{id}",
                                            class: if is_selected { "history-item selected" } else { "history-item" },
                                            onclick: move |_| {
                                                selected_history.set(Some(id));
                                            },
                                            div { class: "history-item-header",
                                                span { class: "history-target", "{entry.target}" }
                                                span { class: "history-category", "{category_str}" }
                                            }
                                            div { class: "history-item-meta",
                                                span { class: "history-time", "{time_str}" }
                                                span { class: "history-duration", "{entry.duration_secs}s" }
                                            }
                                            div { class: "history-item-stats",
                                                span { class: "status-success", "{success_count}" }
                                                span { " / {total} passed" }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Selected entry details
                div { class: "panel", style: "overflow-y: auto;",
                    div { class: "panel-header",
                        span { class: "panel-title", "Results Detail" }
                    }
                    if let Some(entry) = selected_entry {
                        div { class: "history-detail",
                            div { style: "margin-bottom: 16px; padding-bottom: 8px; border-bottom: 1px solid var(--term-green-dark);",
                                h3 { style: "margin: 0 0 8px 0;", "{entry.target}" }
                                p { style: "margin: 0; font-size: 12px; color: var(--term-green-dim);",
                                    "Ran {entry.results.len()} tests in {entry.duration_secs} seconds"
                                }
                            }
                            {ResultsDisplay::render(&entry.results)}
                        }
                    } else {
                        div { class: "no-selection",
                            style: "padding: 48px; text-align: center; color: var(--term-green-dim);",
                            "Select a history entry to view details"
                        }
                    }
                }
            }
        }
    }
}
