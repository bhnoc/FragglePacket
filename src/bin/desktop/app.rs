//! Main application component

use dioxus::prelude::*;
use futures_util::StreamExt;
use crate::state::{AppState, PanelId, ToastType, LogLevel};
use crate::state::test_runner::TestUpdate;
use crate::components::{Dashboard, TestPanel, HttpsPanel, FuzzingPanel, PathPanel, Simulator, LogsPanel, HistoryPanel};
use crate::window_manager::reattach_panel;

/// Main App component
#[component]
pub fn App() -> Element {
    // Initialize application state
    let mut state = use_signal(AppState::new);

    // Set up test update processing
    let process_updates = use_coroutine(move |mut rx: UnboundedReceiver<TestUpdate>| async move {
        while let Some(update) = rx.next().await {
            match update {
                TestUpdate::Started { target, category } => {
                    state.write().testing.set(true);
                    state.write().progress.set(0.0);
                    state.write().reset_cancel();
                    state.write().test_start_time.set(Some(std::time::Instant::now()));
                    let msg = match category {
                        Some(cat) => format!("Running {} test on {}...", cat.as_str(), target),
                        None => format!("Running all tests on {}...", target),
                    };
                    state.write().status_message.set(msg.clone());
                    state.write().log(LogLevel::Info, format!("=== {} ===", msg));
                    state.write().current_test_name.set(String::new());
                }
                TestUpdate::Result { result, .. } => {
                    let target = result.target.clone();
                    let test_name = result.name.clone();
                    let status = result.status;

                    // Log the result with details
                    let level = match status {
                        fraggle_packet::framework::TestStatus::Success => LogLevel::Success,
                        fraggle_packet::framework::TestStatus::Warning => LogLevel::Warning,
                        fraggle_packet::framework::TestStatus::Failed => LogLevel::Error,
                        fraggle_packet::framework::TestStatus::Skipped => LogLevel::Info,
                        fraggle_packet::framework::TestStatus::Pending => LogLevel::Info,
                        fraggle_packet::framework::TestStatus::Running => LogLevel::Running,
                    };

                    // Extract CLI command from metadata
                    let cli_command = result.metadata.get("cli_command").cloned();

                    // Build metrics list
                    let metrics: Vec<(String, String)> = result.metrics.iter()
                        .map(|(k, v)| (k.clone(), format!("{:.2}", v)))
                        .collect();

                    // Build details from metadata (excluding cli_command)
                    let details: Option<String> = {
                        let other_meta: Vec<String> = result.metadata.iter()
                            .filter(|(k, _)| !k.starts_with("cli_"))
                            .map(|(k, v)| format!("{}: {}", k, v))
                            .collect();
                        if other_meta.is_empty() {
                            None
                        } else {
                            Some(other_meta.join("\n"))
                        }
                    };

                    // Create detailed log entry
                    let mut entry = crate::state::LogEntry::new(level, format!("{}: {:?}", test_name, status));
                    if let Some(cmd) = cli_command {
                        entry = entry.with_cli_command(cmd);
                    }
                    if !metrics.is_empty() {
                        entry = entry.with_metrics(metrics);
                    }
                    if let Some(det) = details {
                        entry = entry.with_details(det);
                    }

                    state.write().log_detailed(entry);
                    state.write().current_test_name.set(test_name);
                    state.write().store_result(&target, result);
                }
                TestUpdate::Progress { progress, .. } => {
                    state.write().progress.set(progress);
                }
                TestUpdate::Completed { target } => {
                    // Save to history before clearing testing state
                    let categories = state.read().selected_categories.read().clone();
                    state.write().save_to_history(&target, categories);

                    state.write().testing.set(false);
                    state.write().progress.set(1.0);
                    state.write().current_test_name.set(String::new());
                    state.write().status_message.set(format!("Tests completed for {}", target));
                    state.write().log(LogLevel::Success, format!("=== Completed: {} ===", target));
                    state.write().add_toast(
                        format!("Tests completed for {}", target),
                        ToastType::Success
                    );
                }
                TestUpdate::Failed { target, error } => {
                    state.write().testing.set(false);
                    state.write().current_test_name.set(String::new());
                    state.write().status_message.set(format!("Test failed: {}", error));
                    state.write().log(LogLevel::Error, format!("FAILED: {} - {}", target, error));
                    state.write().add_toast(
                        format!("Test failed for {}: {}", target, error),
                        ToastType::Error
                    );
                }
            }
        }
    });

    rsx! {
        div { class: "app-container",
            // Header
            Header { state: state }

            // Tab bar (only shows attached panels)
            TabBar { state: state }

            // Content area - render active panel
            div { class: "content",
                {render_active_panel(state, process_updates)}
            }

            // Toast container
            ToastContainer { state: state }
        }
    }
}

/// Render the currently active panel with detach button
fn render_active_panel(
    state: Signal<AppState>,
    update_tx: Coroutine<TestUpdate>,
) -> Element {
    let active = *state.read().active_panel.read();

    // Read the global signal DIRECTLY to create reactive dependency
    // This ensures the content area re-renders when panels are detached/reattached
    let detached = crate::window_manager::DETACHED_PANELS.read();
    let is_active_detached = detached.contains(&active);

    // If this panel is detached, show a placeholder
    if is_active_detached {
        return rsx! {
            div { class: "panel-detached-message",
                p { "This panel is open in a separate window." }
                button {
                    class: "btn",
                    onclick: move |_| {
                        reattach_panel(active);
                    },
                    "Bring Back Here"
                }
            }
        };
    }

    rsx! {
        div { class: "panel-container",
            // Panel content - each panel includes its own detach button in header
            match active {
                PanelId::Dashboard => rsx! { Dashboard { state: state, update_tx: update_tx, panel: active } },
                PanelId::Tests => rsx! { TestPanel { state: state, update_tx: update_tx, panel: active } },
                PanelId::Https => rsx! { HttpsPanel { state: state, update_tx: update_tx, panel: active } },
                PanelId::Fuzzing => rsx! { FuzzingPanel { state: state, update_tx: update_tx, panel: active } },
                PanelId::Path => rsx! { PathPanel { state: state, update_tx: update_tx, panel: active } },
                PanelId::Simulator => rsx! { Simulator { state: state, panel: active } },
                PanelId::VpnCalculator => rsx! { Simulator { state: state, panel: active } },
                PanelId::Targets => rsx! { Dashboard { state: state, update_tx: update_tx, panel: active } },
                PanelId::Logs => rsx! { LogsPanel { state: state, panel: active } },
                PanelId::History => rsx! { HistoryPanel { state: state, panel: active } },
            }
        }
    }
}

/// Header component
#[component]
fn Header(state: Signal<AppState>) -> Element {
    let status = state.read().status_message.read().clone();
    let testing = *state.read().testing.read();
    let progress = *state.read().progress.read();

    rsx! {
        header { class: "header",
            h1 { "FragglePacket" }
            div { class: "header-right",
                if testing {
                    div { class: "progress-container",
                        div { class: "progress-bar",
                            div {
                                class: "fill",
                                style: "width: {(progress * 100.0) as u32}%;"
                            }
                        }
                    }
                }
                div { class: "status",
                    if testing {
                        span { class: "status-pending", "Testing... " }
                    }
                    "{status}"
                }
            }
        }
    }
}

/// Tab bar component - only shows attached panels
#[component]
fn TabBar(state: Signal<AppState>) -> Element {
    let active = *state.read().active_panel.read();

    // Read the global signal DIRECTLY in the component to create reactive dependency
    // This ensures the component re-renders when panels are detached/reattached
    let detached = crate::window_manager::DETACHED_PANELS.read();
    let attached: Vec<PanelId> = PanelId::all()
        .into_iter()
        .filter(|p| !detached.contains(p))
        .collect();
    let num_detached = detached.len();

    rsx! {
        nav { class: "tabs",
            for panel in attached {
                button {
                    class: if panel == active { "tab active" } else { "tab" },
                    onclick: move |_| {
                        state.write().active_panel.set(panel);
                    },
                    {panel.label()}
                }
            }
            // Show indicator for detached panels
            if num_detached > 0 {
                span { class: "detached-indicator",
                    "{num_detached} detached"
                }
            }
        }
    }
}

/// Toast container component
#[component]
fn ToastContainer(state: Signal<AppState>) -> Element {
    let toasts = state.read().toasts.read().clone();

    // Auto-remove toasts after 5 seconds
    use_effect(move || {
        let toasts = state.read().toasts.read().clone();
        for toast in toasts {
            let toast_id = toast.id;
            spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                state.write().remove_toast(toast_id);
            });
        }
    });

    rsx! {
        div { class: "toast-container",
            for toast in toasts {
                div {
                    key: "{toast.id}",
                    class: match toast.toast_type {
                        ToastType::Success => "toast success",
                        ToastType::Warning => "toast warning",
                        ToastType::Error => "toast error",
                        ToastType::Info => "toast",
                    },
                    onclick: move |_| {
                        state.write().remove_toast(toast.id);
                    },
                    "{toast.message}"
                }
            }
        }
    }
}
