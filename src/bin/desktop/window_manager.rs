//! Multi-window manager for detachable panels
//!
//! Implements true multi-window support using Dioxus Desktop's native window API.
//! Detached panels open in separate OS-level windows and share state via GlobalSignal.

use std::collections::HashSet;
use dioxus::prelude::*;
use dioxus::desktop::{use_window, Config, WindowBuilder, LogicalSize};
use crate::state::PanelId;

// ============================================================================
// Global State - Shared across all windows
// ============================================================================

/// Global signal tracking which panels are currently detached
pub static DETACHED_PANELS: GlobalSignal<HashSet<PanelId>> = Signal::global(|| HashSet::new());

/// Check if a panel is detached
pub fn is_panel_detached(panel: PanelId) -> bool {
    DETACHED_PANELS.read().contains(&panel)
}

/// Mark a panel as detached
pub fn detach_panel(panel: PanelId) {
    DETACHED_PANELS.write().insert(panel);
}

/// Mark a panel as reattached (remove from detached set)
pub fn reattach_panel(panel: PanelId) {
    DETACHED_PANELS.write().remove(&panel);
}

/// Get list of currently attached panels (for main window tab bar)
pub fn get_attached_panels() -> Vec<PanelId> {
    let detached = DETACHED_PANELS.read();
    PanelId::all()
        .into_iter()
        .filter(|p| !detached.contains(p))
        .collect()
}

/// Get count of detached panels
pub fn detached_count() -> usize {
    DETACHED_PANELS.read().len()
}

// ============================================================================
// Detach Button Component
// ============================================================================

/// Button to detach a panel into its own window
#[component]
pub fn DetachButton(panel: PanelId) -> Element {
    let window = use_window();
    let is_detached = is_panel_detached(panel);

    if is_detached {
        // This button appears in the detached window - clicking closes the window
        rsx! {
            button {
                class: "detach-btn reattach",
                title: "Close and reattach to main window",
                onclick: move |_| {
                    // Reattach the panel
                    reattach_panel(panel);
                    // Close this window
                    window.close();
                },
                "× Close & Reattach"
            }
        }
    } else {
        // This button appears in the main window - clicking opens new window
        rsx! {
            button {
                class: "detach-btn",
                title: "Open in separate window",
                onclick: move |_| {
                    // Mark panel as detached
                    detach_panel(panel);

                    // Spawn new window asynchronously
                    let window_clone = window.clone();
                    spawn(async move {
                        spawn_panel_window(window_clone, panel).await;
                    });
                },
                "⬚ Detach"
            }
        }
    }
}

// ============================================================================
// Window Spawning
// ============================================================================

/// Spawn a new window for a detached panel
async fn spawn_panel_window(window: dioxus::desktop::DesktopContext, panel: PanelId) {
    use crate::theme;

    // Create the VirtualDom for the new window
    // We use a wrapper component that knows which panel to render
    let dom = VirtualDom::new_with_props(
        DetachedPanelWindow,
        DetachedPanelWindowProps { panel },
    );

    // Configure the new window
    let config = Config::default()
        .with_window(
            WindowBuilder::new()
                .with_title(format!("FragglePacket - {}", panel.label()))
                .with_inner_size(LogicalSize::new(900.0, 700.0))
                .with_min_inner_size(LogicalSize::new(600.0, 400.0))
        )
        .with_custom_head(format!(r#"<style>{}</style>"#, theme::get_css()));

    // Create the new window
    // In Dioxus 0.6, new_window is synchronous and returns immediately
    let _ = window.new_window(dom, config);
}

// ============================================================================
// Detached Panel Window Component
// ============================================================================

#[derive(Props, Clone, PartialEq)]
pub struct DetachedPanelWindowProps {
    panel: PanelId,
}

/// Component that renders inside a detached panel window
#[component]
pub fn DetachedPanelWindow(props: DetachedPanelWindowProps) -> Element {
    let panel = props.panel;

    // When this window unmounts (closes), reattach the panel
    use_drop(move || {
        reattach_panel(panel);
    });

    rsx! {
        div { class: "app-container detached-window",
            // Header with panel name and close button
            header { class: "header",
                h1 { "{panel.label()}" }
                DetachButton { panel: panel }
            }

            // Panel content
            div { class: "content",
                DetachedPanelContent { panel: panel }
            }
        }
    }
}

/// Renders the actual panel content in a detached window
#[component]
fn DetachedPanelContent(panel: PanelId) -> Element {
    use crate::components::{Dashboard, TestPanel, HttpsPanel, FuzzingPanel, PathPanel, Simulator};
    use crate::state::AppState;
    use crate::state::test_runner::TestUpdate;
    use futures_util::StreamExt;

    // Get the shared app state
    let mut state = use_signal(AppState::new);

    // Set up test update processing for this window
    let update_tx = use_coroutine({
        let mut state = state;
        move |mut rx: UnboundedReceiver<TestUpdate>| async move {
            while let Some(update) = rx.next().await {
                match update {
                    TestUpdate::Started { target, category } => {
                        state.write().testing.set(true);
                        state.write().progress.set(0.0);
                        let msg = match category {
                            Some(cat) => format!("Running {} on {}...", cat.as_str(), target),
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
                        state.write().status_message.set(format!("Completed: {}", target));
                    }
                    TestUpdate::Failed { error, .. } => {
                        state.write().testing.set(false);
                        state.write().status_message.set(format!("Failed: {}", error));
                    }
                }
            }
        }
    });

    match panel {
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
