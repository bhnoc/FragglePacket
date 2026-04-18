//! Dashboard panel - Overview of test results

use dioxus::prelude::*;
use crate::state::AppState;
use crate::state::test_runner::TestUpdate;
use crate::components::results_display::ResultsDisplay;

/// Dashboard component showing test results overview
#[component]
pub fn Dashboard(
    state: Signal<AppState>,
    update_tx: Coroutine<TestUpdate>,
) -> Element {
    let targets = state.read().targets.read().clone();
    let results = state.read().results.read().clone();
    let current_target = state.read().current_target.read().clone();
    let testing = *state.read().testing.read();
    let progress = *state.read().progress.read();

    // Get all results for the current target
    let current_results: Vec<_> = results
        .get(&current_target)
        .cloned()
        .unwrap_or_default();

    let success_count = state.read().success_count();
    let total_tests = state.read().total_tests();

    rsx! {
        div { class: "dashboard",
            // Quick stats panel
            div { class: "panel",
                div { class: "panel-header",
                    span { class: "panel-title", "Overview" }
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
                div { class: "target-input", style: "display: flex; gap: 8px; align-items: center;",
                    input {
                        r#type: "text",
                        placeholder: "Enter target (e.g., github.com)",
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

            // Targets table
            div { class: "panel",
                div { class: "panel-header",
                    span { class: "panel-title", "Configured Targets" }
                }
                table { class: "table",
                    thead {
                        tr {
                            th { "Target" }
                            th { "Description" }
                            th { "Port" }
                            th { "Status" }
                            th { "Actions" }
                        }
                    }
                    tbody {
                        for target in targets {
                            {
                                let host = target.host.clone();
                                let port_display = if target.port == 0 { "ICMP".to_string() } else { target.port.to_string() };
                                let is_tested = results.contains_key(&target.host);
                                let status_class = if is_tested { "status-success" } else { "status-pending" };
                                let status_text = if is_tested { "Tested" } else { "Pending" };
                                let host_for_select = host.clone();
                                let host_for_test = host.clone();

                                rsx! {
                                    tr {
                                        td { "{host}" }
                                        td { "{target.description}" }
                                        td { "{port_display}" }
                                        td { class: "{status_class}", "{status_text}" }
                                        td {
                                            button {
                                                class: "btn",
                                                style: "padding: 4px 8px; font-size: 12px;",
                                                disabled: testing,
                                                onclick: move |_| {
                                                    state.write().current_target.set(host_for_select.clone());
                                                },
                                                "Select"
                                            }
                                            button {
                                                class: "btn primary",
                                                style: "padding: 4px 8px; font-size: 12px; margin-left: 4px;",
                                                disabled: testing,
                                                onclick: move |_| {
                                                    let target = host_for_test.clone();
                                                    let runner = state.read().test_runner.clone();
                                                    let (tx, mut rx) = crate::state::test_runner::TestRunner::create_channel();

                                                    runner.run_all(target.clone(), tx);

                                                    spawn(async move {
                                                        while let Some(update) = rx.recv().await {
                                                            update_tx.send(update);
                                                        }
                                                    });
                                                },
                                                "Test"
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
