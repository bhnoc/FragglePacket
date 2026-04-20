//! Multi-window manager for detachable panels
//!
//! Uses VirtualDom::new_with_props to pass panel ID directly,
//! avoiding race conditions. Uses tao/wry event handlers to detect window close.

use std::collections::HashSet;
use dioxus::prelude::*;
use dioxus::desktop::{use_window, Config, WindowBuilder, LogicalSize, tao};
use tao::event::{Event, WindowEvent};
use crate::state::PanelId;

// ============================================================================
// Global State
// ============================================================================

/// Tracks which panels are currently in detached windows
pub static DETACHED_PANELS: GlobalSignal<HashSet<PanelId>> = Signal::global(|| HashSet::new());

/// Context for child components to know they're in a detached window
#[derive(Clone, Copy, PartialEq)]
pub struct DetachedWindowContext {
    pub panel: PanelId,
}

// ============================================================================
// Public API
// ============================================================================

/// Mark a panel as reattached
pub fn reattach_panel(panel: PanelId) {
    DETACHED_PANELS.write().remove(&panel);
}

// ============================================================================
// Detach Button Component
// ============================================================================

#[component]
pub fn DetachButton(panel: PanelId) -> Element {
    let window = use_window();

    // Check if we're inside a detached window
    let in_detached = try_use_context::<DetachedWindowContext>();

    // Read detached state for reactivity
    let detached = DETACHED_PANELS.read();
    let is_this_detached = detached.contains(&panel);

    match in_detached {
        Some(ctx) if ctx.panel == panel => {
            // Header of this detached window - show Reattach
            rsx! {
                button {
                    class: "detach-btn reattach",
                    onclick: move |_| {
                        // Update state - panel reappears in main window
                        reattach_panel(panel);
                        // User closes window with X, or leaves it open (harmless)
                    },
                    "Reattach"
                }
            }
        }
        Some(_) => {
            // Sub-component in detached window - no button
            rsx! {}
        }
        None if is_this_detached => {
            // Panel is detached, we're in main window - no button
            rsx! {}
        }
        None => {
            // Normal case - show Detach button
            rsx! {
                button {
                    class: "detach-btn",
                    onclick: move |_| {
                        // Mark as detached in global state
                        DETACHED_PANELS.write().insert(panel);

                        // Create new window with this panel
                        spawn_detached_window(window.clone(), panel);
                    },
                    "Detach"
                }
            }
        }
    }
}

// ============================================================================
// Window Spawning
// ============================================================================

fn spawn_detached_window(window: dioxus::desktop::DesktopContext, panel: PanelId) {
    use crate::theme;

    // Create VirtualDom with props - the panel ID is passed directly, no race conditions
    // #[component] macro generates DetachedWindowComponentProps automatically
    let dom = VirtualDom::new_with_props(
        DetachedWindowComponent,
        DetachedWindowComponentProps { panel },
    );

    let config = Config::default()
        .with_window(
            WindowBuilder::new()
                .with_title(format!("FragglePacket - {}", panel.label()))
                .with_inner_size(LogicalSize::new(900.0, 700.0))
                .with_min_inner_size(LogicalSize::new(600.0, 400.0))
        )
        .with_custom_head(format!(r#"<style>{}</style>"#, theme::get_css()));

    window.new_window(dom, config);
}

/// Root component for detached windows - receives panel via props
#[component]
fn DetachedWindowComponent(panel: PanelId) -> Element {
    let window = use_window();

    // Provide context for children
    use_context_provider(|| DetachedWindowContext { panel });

    // Register event handler to detect when THIS window is being closed (X button)
    use_hook(|| {
        let window_id = window.id();
        window.create_wry_event_handler(move |event, _target| {
            if let Event::WindowEvent { window_id: evt_window_id, event: WindowEvent::CloseRequested, .. } = event {
                if *evt_window_id == window_id {
                    // Window is closing - reattach the panel
                    reattach_panel(panel);
                }
            }
        });
    });

    rsx! {
        div { class: "app-container detached-window",
            header { class: "header",
                h1 { "{panel.label()}" }
                DetachButton { panel }
            }
            div { class: "content",
                PanelContent { panel }
            }
        }
    }
}

/// Renders panel content
#[component]
fn PanelContent(panel: PanelId) -> Element {
    use crate::components::{Dashboard, TestPanel, FuzzingPanel, Simulator, LogsPanel, HistoryPanel};
    use crate::state::AppState;
    use crate::state::test_runner::TestUpdate;
    use futures_util::StreamExt;

    let state = use_signal(AppState::new);

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
                            None => format!("Running tests on {}...", target),
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
        PanelId::Dashboard => rsx! { Dashboard { state, update_tx, panel } },
        PanelId::Tests => rsx! { TestPanel { state, update_tx, panel } },
        PanelId::Fuzzing => rsx! { FuzzingPanel { state, update_tx, panel } },
        PanelId::Simulator => rsx! { Simulator { state, panel } },
        PanelId::Logs => rsx! { LogsPanel { state, panel } },
        PanelId::History => rsx! { HistoryPanel { state, panel } },
        _ => rsx! { Dashboard { state, update_tx, panel: PanelId::Dashboard } },
    }
}
