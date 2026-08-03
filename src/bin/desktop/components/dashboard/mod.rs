//! Dashboard panel - Overview of test results

use crate::components::results_display::ResultsDisplay;
use crate::components::target_input::TargetInput;
use crate::state::test_runner::TestUpdate;
use crate::state::{AppState, PanelId};
use crate::window_manager::DetachButton;
use dioxus::prelude::*;

/// Dashboard component showing test results overview
#[component]
pub fn Dashboard(
    state: Signal<AppState>,
    update_tx: Coroutine<TestUpdate>,
    panel: PanelId,
) -> Element {
    let targets = state.read().targets.read().clone();
    let results = state.read().results.read().clone();
    let current_target = state.read().current_target.read().clone();
    let testing = *state.read().testing.read();
    let progress = *state.read().progress.read();

    // Get all results for the current target
    let current_results: Vec<_> = results.get(&current_target).cloned().unwrap_or_default();

    let success_count = state.read().success_count();
    let total_tests = state.read().total_tests();

    rsx! {
        div { class: "dashboard",
            // Quick stats panel
            div { class: "panel",
                div { class: "panel-header",
                    span { class: "panel-title", "Overview" }
                    DetachButton { panel: panel }
                }
                div { class: "stats-grid",
                    style: "display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px;",
                    div { class: "stat",
                        div { class: "stat-value", "{targets.len()}" }
                        div { class: "stat-label", "Targets" }
                    }
                    div { class: "stat",
                        div { class: "stat-value", "{results.len()}" }
                        div { class: "stat-label", "Tested" }
                    }
                    div { class: "stat",
                        div { class: "stat-value status-success", "{success_count}" }
                        div { class: "stat-label", "Passed" }
                    }
                    div { class: "stat",
                        div { class: "stat-value", "{total_tests}" }
                        div { class: "stat-label", "Total Tests" }
                    }
                }
            }

            // Target input and quick test
            div { class: "panel",
                div { class: "panel-header",
                    span { class: "panel-title", "Quick Test" }
                }
                div { style: "display: flex; gap: 8px; align-items: flex-start;",
                    TargetInput { state: state, disabled: testing }
                    button {
                        class: "btn primary",
                        disabled: testing,
                        onclick: move |_| {
                            let target = state.read().current_target.read().clone();
                            let runner = state.read().test_runner.clone();
                            let (tx, mut rx) = crate::state::test_runner::TestRunner::create_channel();

                            // Start test execution
                            runner.run_all(target.clone(), tx);

                            // Forward updates to the coroutine
                            spawn(async move {
                                while let Some(update) = rx.recv().await {
                                    update_tx.send(update);
                                }
                            });
                        },
                        if testing { "Testing..." } else { "Run All Tests" }
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

            // Results for current target
            if !current_results.is_empty() {
                div { class: "panel",
                    div { class: "panel-header",
                        span { class: "panel-title", "Results for {current_target}" }
                        button {
                            class: "btn",
                            onclick: move |_| {
                                state.write().clear_results();
                            },
                            "Clear"
                        }
                    }
                    {ResultsDisplay::render(&current_results)}
                }
            }
        }
    }
}
