//! Main application component

use dioxus::prelude::*;
use futures_util::StreamExt;
use crate::state::{AppState, PanelId, ToastType};
use crate::state::test_runner::TestUpdate;
use crate::components::{Dashboard, TestPanel, HttpsPanel, FuzzingPanel, PathPanel, Simulator};
use crate::window_manager::{DetachButton, get_attached_panels, is_panel_detached, detached_count, reattach_panel};

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
                    let msg = match category {
                        Some(cat) => format!("Running {} test on {}...", cat.as_str(), target),
                        None => format!("Running all tests on {}...", target),
                    };
                    state.write().status_message.set(msg);
                }
                TestUpdate::Result { result, .. } => {
                    let target = result.target.clone();
                    state.write().store_result(&target, result);
                }
                TestUpdate::Progress { progress, .. } => {
                    state.write().progress.set(progress);
                }
                TestUpdate::Completed { target } => {
                    state.write().testing.set(false);
                    state.write().progress.set(1.0);
                    state.write().status_message.set(format!("Tests completed for {}", target));
                    state.write().add_toast(
                        format!("Tests completed for {}", target),
                        ToastType::Success
                    );
                }
                TestUpdate::Failed { target, error } => {
                    state.write().testing.set(false);
                    state.write().status_message.set(format!("Test failed: {}", error));
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

    // If this panel is detached, show a placeholder
    if is_panel_detached(active) {
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
            // Detach button in corner
            div { class: "panel-detach-corner",
                DetachButton { panel: active }
            }

            // Panel content
            match active {
                PanelId::Dashboard => rsx! { Dashboard { state: state, update_tx: update_tx } },
                PanelId::Tests => rsx! { TestPanel { state: state, update_tx: update_tx } },
                PanelId::Https => rsx! { HttpsPanel { state: state, update_tx: update_tx } },
                PanelId::Fuzzing => rsx! { FuzzingPanel { state: state, update_tx: update_tx } },
                PanelId::Path => rsx! { PathPanel { state: state, update_tx: update_tx } },
                PanelId::Simulator => rsx! { Simulator { state: state } },
                PanelId::VpnCalculator => rsx! { Simulator { state: state } },
                PanelId::Targets => rsx! { Dashboard { state: state, update_tx: update_tx } },
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
    let attached = get_attached_panels();
    let num_detached = detached_count();

    rsx! {
        nav { class: "tabs",
            for panel in attached {
                button {
                    class: if panel == active { "tab active" } else { "tab" },
                    onclick: move |_| {
                        state.write().active_panel.set(panel);
                    },
                    "{panel.label()}"
                    if let Some(shortcut) = panel.shortcut() {
                        span { class: "shortcut", "[{shortcut}]" }
                    }
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
