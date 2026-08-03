//! Test Panel - Category selection and test execution

use crate::components::results_display::ResultsDisplay;
use crate::components::target_input::TargetInput;
use crate::state::test_runner::TestUpdate;
use crate::state::{AppState, PanelId};
use crate::window_manager::DetachButton;
use dioxus::prelude::*;
use fraggle_packet::framework::TestCategory;
use std::collections::HashSet;

/// Test panel component with category grid (multi-select)
#[component]
pub fn TestPanel(
    state: Signal<AppState>,
    update_tx: Coroutine<TestUpdate>,
    panel: PanelId,
) -> Element {
    let selected_categories = state.read().selected_categories.read().clone();
    let selected_count = selected_categories.len();
    let current_target = state.read().current_target.read().clone();
    let testing = *state.read().testing.read();
    let progress = *state.read().progress.read();
    let results = state.read().results.read().clone();

    // Get results filtered by selected categories
    let filtered_results: Vec<_> = if selected_categories.is_empty() {
        results.get(&current_target).cloned().unwrap_or_default()
    } else {
        state
            .read()
            .get_categories_results(&current_target, &selected_categories)
    };

    let categories = vec![
        (TestCategory::DNS, "DNS", "Resolution, EDNS0"),
        (TestCategory::MTU, "MTU", "ICMP, TCP, UDP, QUIC"),
        (TestCategory::HTTPS, "HTTPS", "5-stage waterfall"),
        (TestCategory::TCPHealth, "TCP Health", "Handshake, window"),
        (TestCategory::RTT, "RTT", "Latency, jitter"),
        (TestCategory::PacketLoss, "Pkt Loss", "Loss rate, patterns"),
        (TestCategory::PathAnalysis, "Path", "Traceroute + MTU"),
        (TestCategory::IPv6, "IPv6", "v4/v6 comparison"),
        (TestCategory::Application, "App", "HTTP/2, HTTP/3, WS"),
        (TestCategory::Fuzzing, "Fuzzing", "Packet crafting"),
    ];

    // Clone for use in Select All button
    let all_categories: HashSet<TestCategory> = categories.iter().map(|(c, _, _)| *c).collect();

    rsx! {
        div { class: "test-panel",
            // Target input
            div { class: "panel",
                div { class: "panel-header",
                    span { class: "panel-title", "Target" }
                    DetachButton { panel: panel }
                }
                TargetInput { state: state, disabled: testing }
            }

            // Category grid
            div { class: "panel",
                div { class: "panel-header",
                    span { class: "panel-title", "Test Categories" }
                    span { style: "color: var(--term-green-dim); font-size: 12px;",
                        "Click to toggle selection (multi-select enabled)"
                    }
                }
                div { class: "category-grid",
                    for (category, label, desc) in categories.clone() {
                        {
                            let is_selected = selected_categories.contains(&category);
                            rsx! {
                                button {
                                    class: if is_selected { "category-btn selected" } else { "category-btn" },
                                    disabled: testing,
                                    onclick: move |_| {
                                        let mut cats = state.read().selected_categories.read().clone();
                                        if cats.contains(&category) {
                                            cats.remove(&category);
                                        } else {
                                            cats.insert(category);
                                        }
                                        state.write().selected_categories.set(cats);
                                    },
                                    span { class: "label", "{label}" }
                                    span { style: "font-size: 10px; color: var(--term-green-dim);", "{desc}" }
                                }
                            }
                        }
                    }
                }

                // Select All / Clear Selection buttons
                div { style: "display: flex; gap: 8px; margin-top: 8px; padding: 0 4px;",
                    button {
                        class: "btn",
                        style: "font-size: 12px; padding: 4px 8px;",
                        disabled: testing,
                        onclick: move |_| {
                            state.write().selected_categories.set(all_categories.clone());
                        },
                        "Select All"
                    }
                    button {
                        class: "btn",
                        style: "font-size: 12px; padding: 4px 8px;",
                        disabled: testing || selected_count == 0,
                        onclick: move |_| {
                            state.write().selected_categories.set(HashSet::new());
                        },
                        "Clear Selection"
                    }
                    if selected_count > 0 {
                        span { style: "color: var(--term-green); font-size: 12px; align-self: center; margin-left: auto;",
                            "{selected_count} selected"
                        }
                    }
                }
            }

            // Action buttons
            div { class: "panel", style: "display: flex; gap: 8px; align-items: center;",
                button {
                    class: "btn primary",
                    disabled: testing || selected_count == 0,
                    onclick: move |_| {
                        let cats = state.read().selected_categories.read().clone();
                        if !cats.is_empty() {
                            let target = state.read().current_target.read().clone();
                            let runner = state.read().test_runner.clone();
                            let (tx, mut rx) = crate::state::test_runner::TestRunner::create_channel();

                            runner.run_categories(target.clone(), cats, tx);

                            spawn(async move {
                                while let Some(update) = rx.recv().await {
                                    update_tx.send(update);
                                }
                            });
                        }
                    },
                    if testing {
                        "Testing..."
                    } else if selected_count > 0 {
                        "Run Selected ({selected_count})"
                    } else {
                        "Run Selected"
                    }
                }
                button {
                    class: "btn",
                    disabled: testing,
                    onclick: move |_| {
                        let target = state.read().current_target.read().clone();
                        let runner = state.read().test_runner.clone();
                        let (tx, mut rx) = crate::state::test_runner::TestRunner::create_channel();

                        runner.run_all(target.clone(), tx);

                        spawn(async move {
                            while let Some(update) = rx.recv().await {
                                update_tx.send(update);
                            }
                        });
                    },
                    "Run All"
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

            // Results area
            div { class: "panel",
                div { class: "panel-header",
                    span { class: "panel-title",
                        if selected_count == 0 {
                            "All Results"
                        } else if selected_count == 1 {
                            {
                                let cat = selected_categories.iter().next().unwrap();
                                format!("{} Results", cat.as_str())
                            }
                        } else {
                            "Selected Categories Results"
                        }
                    }
                    if !filtered_results.is_empty() {
                        span { style: "color: var(--term-green-dim);",
                            "{filtered_results.len()} result(s)"
                        }
                    }
                }
                {ResultsDisplay::render(&filtered_results)}
            }
        }
    }
}
