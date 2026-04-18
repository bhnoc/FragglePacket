//! Test Panel - Category selection and test execution

use dioxus::prelude::*;
use crate::state::AppState;
use crate::state::test_runner::TestUpdate;
use crate::components::results_display::ResultsDisplay;
use fraggle_packet::framework::TestCategory;

/// Test panel component with category grid
#[component]
pub fn TestPanel(
    state: Signal<AppState>,
    update_tx: Coroutine<TestUpdate>,
) -> Element {
    let selected = *state.read().selected_category.read();
    let current_target = state.read().current_target.read().clone();
    let testing = *state.read().testing.read();
    let progress = *state.read().progress.read();
    let results = state.read().results.read().clone();

    // Get results filtered by selected category
    let filtered_results: Vec<_> = if let Some(cat) = selected {
        state.read().get_category_results(&current_target, cat)
    } else {
        results.get(&current_target).cloned().unwrap_or_default()
    };

    let categories = vec![
        (TestCategory::DNS, "1", "DNS", "Resolution, EDNS0"),
        (TestCategory::MTU, "2", "MTU", "ICMP, TCP, UDP, QUIC"),
        (TestCategory::HTTPS, "3", "HTTPS", "5-stage waterfall"),
        (TestCategory::TCPHealth, "4", "TCP Health", "Handshake, window"),
        (TestCategory::RTT, "5", "RTT", "Latency, jitter"),
        (TestCategory::PacketLoss, "6", "Pkt Loss", "Loss rate, patterns"),
        (TestCategory::PathAnalysis, "7", "Path", "Traceroute + MTU"),
        (TestCategory::IPv6, "8", "IPv6", "v4/v6 comparison"),
        (TestCategory::Application, "9", "App", "HTTP/2, HTTP/3, WS"),
        (TestCategory::Fuzzing, "0", "Fuzzing", "Packet crafting"),
    ];

    rsx! {
        div { class: "test-panel",
            // Target input
            div { class: "panel",
                div { class: "panel-header",
                    span { class: "panel-title", "Target" }
                }
                div { class: "target-input", style: "display: flex; gap: 8px;",
                    input {
                        r#type: "text",
                        placeholder: "Enter target",
                        value: "{current_target}",
                        style: "flex: 1;",
                        disabled: testing,
                        oninput: move |evt| {
                            state.write().current_target.set(evt.value().clone());
                        }
                    }
                }
            }

            // Category grid
            div { class: "panel",
                div { class: "panel-header",
                    span { class: "panel-title", "Test Categories" }
                    span { style: "color: var(--term-green-dim); font-size: 12px;",
                        "Press 1-0 to select, Enter to run"
                    }
                }
                div { class: "category-grid",
                    for (category, key, label, desc) in categories {
                        {
                            let is_selected = selected == Some(category);
                            rsx! {
                                button {
                                    class: if is_selected { "category-btn selected" } else { "category-btn" },
                                    disabled: testing,
                                    onclick: move |_| {
                                        if selected == Some(category) {
                                            state.write().selected_category.set(None);
                                        } else {
                                            state.write().selected_category.set(Some(category));
                                        }
                                    },
                                    span { class: "key", "{key}" }
                                    span { class: "label", "{label}" }
                                    span { style: "font-size: 10px; color: var(--term-green-dim);", "{desc}" }
                                }
                            }
                        }
                    }
                }
            }

            // Action buttons
            div { class: "panel", style: "display: flex; gap: 8px; align-items: center;",
                button {
                    class: "btn primary",
                    disabled: testing || selected.is_none(),
                    onclick: move |_| {
                        if let Some(cat) = selected {
                            let target = state.read().current_target.read().clone();
                            let runner = state.read().test_runner.clone();
                            let (tx, mut rx) = crate::state::test_runner::TestRunner::create_channel();

                            runner.run_category(target.clone(), cat, tx);

                            spawn(async move {
                                while let Some(update) = rx.recv().await {
                                    update_tx.send(update);
                                }
                            });
                        }
                    },
                    if testing { "Testing..." } else { "Run Selected" }
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
                        if let Some(cat) = selected {
                            "{cat.as_str()} Results"
                        } else {
                            "All Results"
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
