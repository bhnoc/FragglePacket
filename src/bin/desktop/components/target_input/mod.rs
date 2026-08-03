//! Target input component with dropdown presets

use dioxus::prelude::*;
use crate::state::{AppState, TargetCategory, Target, get_preset_targets};

/// Combined text input + dropdown for target selection
#[component]
pub fn TargetInput(
    state: Signal<AppState>,
    disabled: bool,
) -> Element {
    let mut show_dropdown = use_signal(|| false);
    let current_target = state.read().current_target.read().clone();
    let selected_tests = state.read().selected_categories.read().clone();
    let presets = get_preset_targets();
    let categories = TargetCategory::all();

    // Read dropdown state once for this render
    let is_open = *show_dropdown.read();

    // Count compatible targets for header (supports all selected test categories)
    let compatible_count: usize = if selected_tests.is_empty() {
        presets.len()
    } else {
        presets.iter().filter(|t| {
            selected_tests.iter().all(|test_cat| t.supports_test(*test_cat))
        }).count()
    };

    rsx! {
        div { class: "target-input-container",
            // Text input with dropdown toggle
            div { class: "target-input-row",
                input {
                    r#type: "text",
                    class: "target-text-input",
                    placeholder: "Enter target or select from list",
                    value: "{current_target}",
                    disabled: disabled,
                    onfocus: move |_| {
                        show_dropdown.set(true);
                    },
                    oninput: move |evt| {
                        state.write().current_target.set(evt.value().clone());
                    },
                    onkeydown: move |evt| {
                        if evt.key() == Key::Escape {
                            show_dropdown.set(false);
                        }
                    }
                }
                button {
                    class: "dropdown-toggle",
                    disabled: disabled,
                    onclick: move |_| {
                        let current = *show_dropdown.read();
                        show_dropdown.set(!current);
                    },
                    if is_open { "[^]" } else { "[v]" }
                }
            }

            // Dropdown panel
            if is_open && !disabled {
                div { class: "target-dropdown",
                    // Header with filter info
                    div { class: "dropdown-header",
                        span {
                            if selected_tests.is_empty() {
                                "All Targets ({compatible_count})"
                            } else if selected_tests.len() == 1 {
                                {
                                    let test_cat = selected_tests.iter().next().unwrap();
                                    format!("Targets for {} ({})", test_cat.as_str(), compatible_count)
                                }
                            } else {
                                "Targets for selected tests ({compatible_count})"
                            }
                        }
                        button {
                            class: "dropdown-close",
                            onclick: move |_| {
                                show_dropdown.set(false);
                            },
                            "x"
                        }
                    }

                    // Categories with targets
                    div { class: "dropdown-content",
                        for category in &categories {
                            {
                                let cat_targets: Vec<_> = presets.iter()
                                    .filter(|t| t.category == *category)
                                    .cloned()
                                    .collect();

                                if !cat_targets.is_empty() {
                                    // Split into compatible and incompatible based on selected test categories
                                    let selected_tests_clone = selected_tests.clone();
                                    let (compatible, incompatible): (Vec<_>, Vec<_>) = if !selected_tests_clone.is_empty() {
                                        cat_targets.iter().cloned().partition(|t| {
                                            selected_tests_clone.iter().all(|test_cat| t.supports_test(*test_cat))
                                        })
                                    } else {
                                        (cat_targets.clone(), vec![])
                                    };

                                    let compat_count = compatible.len();

                                    rsx! {
                                        div { class: "dropdown-category",
                                            div { class: "category-header",
                                                "{category.label()}"
                                                if !selected_tests.is_empty() && compat_count > 0 {
                                                    span { class: "category-count", " ({compat_count})" }
                                                }
                                            }
                                            // Compatible targets (full color)
                                            for target in compatible {
                                                {render_item(&target, state, show_dropdown, false)}
                                            }
                                            // Incompatible targets (dimmed)
                                            for target in incompatible {
                                                {render_item(&target, state, show_dropdown, true)}
                                            }
                                        }
                                    }
                                } else {
                                    rsx! {}
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Render a single target item
fn render_item(
    target: &Target,
    mut state: Signal<AppState>,
    mut show_dropdown: Signal<bool>,
    dimmed: bool,
) -> Element {
    let host = target.host.clone();
    let desc = target.description.clone();
    let port = target.port;
    let port_display = if port == 0 { "ICMP".to_string() } else { format!(":{}", port) };
    let host_for_click = host.clone();
    let item_class = if dimmed { "dropdown-item dimmed" } else { "dropdown-item" };

    rsx! {
        div {
            class: "{item_class}",
            title: if dimmed { "May not respond to selected test type" } else { "" },
            onclick: move |_| {
                state.write().current_target.set(host_for_click.clone());
                show_dropdown.set(false);
            },
            span { class: "item-host", "{host}" }
            span { class: "item-desc", "{desc}" }
            span { class: "item-port", "{port_display}" }
        }
    }
}
