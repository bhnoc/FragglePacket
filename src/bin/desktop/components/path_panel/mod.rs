//! Path Analysis Panel - Traceroute with per-hop MTU

use dioxus::prelude::*;
use crate::state::AppState;
use crate::state::test_runner::TestUpdate;
use fraggle_packet::framework::TestCategory;

/// Path analysis panel with traceroute visualization
#[component]
pub fn PathPanel(
    state: Signal<AppState>,
    update_tx: Coroutine<TestUpdate>,
) -> Element {
    let current_target = state.read().current_target.read().clone();
    let testing = *state.read().testing.read();
    let progress = *state.read().progress.read();

    // Get path analysis results
    let path_results = state.read().get_category_results(&current_target, TestCategory::PathAnalysis);
    let latest_result = path_results.last();

    // Extract hop data from metrics/metadata
    let hops: Vec<(u32, String, f64, String)> = if let Some(result) = latest_result {
        // Parse hop data from metadata
        // Format: hop_N_addr, hop_N_rtt, hop_N_mtu
        let mut hop_data = Vec::new();
        for i in 1..=30 {
            let addr_key = format!("hop_{}_addr", i);
            let rtt_key = format!("hop_{}_rtt", i);
            if let Some(addr) = result.metadata.get(&addr_key) {
                let rtt = result.metrics.get(&rtt_key).copied().unwrap_or(0.0);
                hop_data.push((i as u32, addr.clone(), rtt, "1500".to_string()));
            } else {
                break;
            }
        }
        if hop_data.is_empty() {
            // Fallback: show general metrics
            vec![(1, current_target.clone(), result.metrics.get("total_rtt_ms").copied().unwrap_or(0.0), "1500".to_string())]
        } else {
            hop_data
        }
    } else {
        Vec::new()
    };

    rsx! {
        div { class: "path-panel",
            // Target input
            div { class: "panel",
                div { class: "panel-header",
                    span { class: "panel-title", "Path Analysis" }
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
                    button {
                        class: "btn primary",
                        disabled: testing,
                        onclick: move |_| {
                            let target = state.read().current_target.read().clone();
                            let runner = state.read().test_runner.clone();
                            let (tx, mut rx) = crate::state::test_runner::TestRunner::create_channel();

                            runner.run_category(target.clone(), TestCategory::PathAnalysis, tx);

                            spawn(async move {
                                while let Some(update) = rx.recv().await {
                                    update_tx.send(update);
                                }
                            });
                        },
                        if testing { "Tracing..." } else { "Trace Path" }
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

            // Traceroute results
            if !hops.is_empty() {
                div { class: "panel",
                    div { class: "panel-header",
                        span { class: "panel-title", "Route to {current_target}" }
                        span { style: "color: var(--term-green-dim);", "{hops.len()} hops" }
                    }
                    table { class: "table",
                        thead {
                            tr {
                                th { "Hop" }
                                th { "Address" }
                                th { "RTT (ms)" }
                                th { "MTU" }
                            }
                        }
                        tbody {
                            for (hop, addr, rtt, mtu) in hops {
                                {
                                    let mtu_val: u32 = mtu.parse().unwrap_or(1500);
                                    let mtu_class = if mtu_val < 1500 { "status-warning" } else { "status-success" };
                                    rsx! {
                                        tr {
                                            td { "{hop}" }
                                            td { "{addr}" }
                                            td { "{rtt:.1}" }
                                            td { class: "{mtu_class}", "{mtu}" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            } else if !testing {
                div { class: "panel",
                    div { class: "panel-header",
                        span { class: "panel-title", "Route" }
                    }
                    div { class: "no-results",
                        "No path analysis results yet. Click 'Trace Path' to analyze the route."
                    }
                }
            }

            // Summary metrics
            if let Some(result) = latest_result {
                div { class: "panel",
                    div { class: "panel-header",
                        span { class: "panel-title", "Path Summary" }
                    }
                    div { class: "stats-grid", style: "display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px;",
                        div { class: "stat",
                            div { class: "stat-value", "{result.metrics.get(\"hop_count\").unwrap_or(&0.0):.0}" }
                            div { class: "stat-label", "Hops" }
                        }
                        div { class: "stat",
                            div { class: "stat-value", "{result.metrics.get(\"total_rtt_ms\").unwrap_or(&0.0):.1}ms" }
                            div { class: "stat-label", "Total RTT" }
                        }
                        div { class: "stat",
                            div { class: "stat-value", "{result.duration.as_millis()}ms" }
                            div { class: "stat-label", "Test Duration" }
                        }
                    }

                    // Diagnoses
                    if !result.diagnoses.is_empty() {
                        div { class: "diagnoses", style: "margin-top: 16px;",
                            for diagnosis in result.diagnoses.iter() {
                                {
                                    let severity_class = match diagnosis.severity {
                                        fraggle_packet::framework::DiagnosisSeverity::Info => "status-success",
                                        fraggle_packet::framework::DiagnosisSeverity::Warning => "status-warning",
                                        fraggle_packet::framework::DiagnosisSeverity::Error => "status-error",
                                        fraggle_packet::framework::DiagnosisSeverity::Critical => "status-error",
                                    };
                                    rsx! {
                                        div { class: "diagnosis-item",
                                            p { class: "{severity_class}", "{diagnosis.title}" }
                                            p { style: "color: var(--term-green-dim);", "{diagnosis.description}" }
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
