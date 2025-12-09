//! TUI Event Handling

use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use std::io;
use std::time::Duration;

use fraggle_packet::framework::test_trait::TestCategory;

use super::types::{App, AppMode, ViewMode};
use super::colors::*;

pub fn handle_events(app: &mut App) -> io::Result<bool> {
    let poll_duration = if app.tracepath_running {
        Duration::from_millis(10)
    } else {
        Duration::from_millis(100)
    };
    
    if event::poll(poll_duration)? {
        if let Event::Key(key) = event::read()? {
            if key.kind != KeyEventKind::Press {
                return Ok(false);
            }
            
            match key.code {
                KeyCode::Char('q') => app.should_quit = true,
                KeyCode::Char('?') | KeyCode::Char('h') => app.mode = AppMode::Help,
                KeyCode::Char('1') => {
                    if matches!(app.mode, AppMode::TestPanel) {
                        app.selected_category = Some(0);
                    } else {
                        app.mode = AppMode::Dashboard;
                    }
                }
                KeyCode::Char('2') => {
                    if matches!(app.mode, AppMode::TestPanel) {
                        app.selected_category = Some(1);
                    }
                }
                KeyCode::Char('3') => {
                    if matches!(app.mode, AppMode::TestPanel) {
                        app.selected_category = Some(2);
                    } else {
                        app.mode = AppMode::Simulator;
                    }
                }
                KeyCode::Char('4') => {
                    if matches!(app.mode, AppMode::TestPanel) {
                        app.selected_category = Some(3);
                    }
                }
                KeyCode::Char('5') => {
                    if matches!(app.mode, AppMode::TestPanel) {
                        app.selected_category = Some(4);
                    }
                }
                KeyCode::Char('6') => {
                    if matches!(app.mode, AppMode::TestPanel) {
                        app.selected_category = Some(5);
                    }
                }
                KeyCode::Char('7') => {
                    if matches!(app.mode, AppMode::TestPanel) {
                        app.selected_category = Some(6);
                    }
                }
                KeyCode::Char('8') => {
                    if matches!(app.mode, AppMode::TestPanel) {
                        app.selected_category = Some(7);
                    }
                }
                KeyCode::Char('9') => {
                    if matches!(app.mode, AppMode::TestPanel) {
                        app.selected_category = Some(8);
                    }
                }
                KeyCode::Char('0') => {
                    if matches!(app.mode, AppMode::TestPanel) {
                        app.selected_category = Some(9);
                    }
                }
                KeyCode::Char('f') | KeyCode::Char('F') => app.mode = AppMode::FuzzingPanel,
                KeyCode::Char('T') => app.mode = AppMode::TestPanel,
                KeyCode::Char('H') => app.mode = AppMode::HttpsPanel,
                KeyCode::Esc => {
                    match app.mode {
                        AppMode::FuzzingPanel | AppMode::HttpsPanel | AppMode::TestPanel => {
                            app.mode = AppMode::Dashboard
                        },
                        _ => app.mode = AppMode::Dashboard,
                    }
                }
                KeyCode::Enter => handle_enter(app),
                KeyCode::Char('a') | KeyCode::Char('A') => handle_run_all(app),
                KeyCode::Up | KeyCode::Char('k') => handle_up(app),
                KeyCode::Down | KeyCode::Char('j') => handle_down(app),
                KeyCode::Char('[') => handle_left_bracket(app),
                KeyCode::Char(']') => handle_right_bracket(app),
                KeyCode::Char('t') => handle_tracepath(app),
                KeyCode::Char('r') => handle_retest_single(app),
                KeyCode::Char('R') => handle_retest_all(app),
                KeyCode::Char('s') => handle_save(app),
                KeyCode::Char('c') => handle_collapse_toggle(app),  // NEW - toggle collapse
                _ => {}
            }
        }
    }
    
    Ok(false)
}

fn handle_enter(app: &mut App) {
    if matches!(app.mode, AppMode::Dashboard) {
        app.mode = AppMode::TargetDetail;
    } else if matches!(app.mode, AppMode::FuzzingPanel) {
        app.run_selected_fuzzer();
    } else if matches!(app.mode, AppMode::HttpsPanel) {
        let target = {
            let state = app.state.lock().unwrap();
            state.results.get(app.selected_https_target)
                .map(|r| r.target.clone())
                .unwrap_or_else(|| "example.com".to_string())
        };
        app.run_https_test(&target);
    } else if matches!(app.mode, AppMode::TestPanel) {
        if let Some(category_idx) = app.selected_category {
            let category = match category_idx {
                0 => TestCategory::DNS,
                1 => TestCategory::MTU,
                2 => TestCategory::HTTPS,
                3 => TestCategory::TCPHealth,
                4 => TestCategory::RTT,
                5 => TestCategory::PacketLoss,
                6 => TestCategory::PathAnalysis,
                7 => TestCategory::IPv6,
                8 => TestCategory::Application,
                9 => TestCategory::Fuzzing,
                _ => TestCategory::DNS,
            };
            
            if matches!(app.view_mode, ViewMode::Dashboard) {
                app.run_category(category);
            } else {
                app.run_category_on_all_targets(category);
            }
        }
    }
}

fn handle_run_all(app: &mut App) {
    if matches!(app.mode, AppMode::TestPanel) {
        if matches!(app.view_mode, ViewMode::Dashboard) {
            app.run_all_tests_on_current_target();
        } else {
            app.popup_message = "Press Shift+A again to run ALL tests on ALL targets (this will take a while!)".to_string();
            app.show_popup = true;
        }
    }
}

fn handle_up(app: &mut App) {
    if app.show_popup && (app.tracepath_running || !app.tracepath_output.is_empty()) {
        app.popup_scroll = app.popup_scroll.saturating_sub(1);
    } else if matches!(app.mode, AppMode::FuzzingPanel) {
        app.prev_fuzz_mode();
    } else if matches!(app.mode, AppMode::HttpsPanel) {
        app.prev_https_target();
    } else if matches!(app.mode, AppMode::TargetDetail) {
        if app.selected_hop > 0 {
            app.selected_hop -= 1;
            app.hop_list_state.select(Some(app.selected_hop));
        }
    } else {
        if app.selected_target > 0 {
            app.selected_target -= 1;
            app.table_state.select(Some(app.selected_target));
        }
    }
}

fn handle_down(app: &mut App) {
    if app.show_popup && (app.tracepath_running || !app.tracepath_output.is_empty()) {
        app.popup_scroll += 1;
        if app.popup_scroll > app.tracepath_output.len().saturating_sub(10) {
            app.popup_scroll = app.tracepath_output.len().saturating_sub(10);
        }
    } else if matches!(app.mode, AppMode::FuzzingPanel) {
        app.next_fuzz_mode();
    } else if matches!(app.mode, AppMode::HttpsPanel) {
        app.next_https_target();
    } else if matches!(app.mode, AppMode::TargetDetail) {
        let state = app.state.lock().unwrap();
        if app.selected_hop < state.hops.len().saturating_sub(1) {
            app.selected_hop += 1;
            app.hop_list_state.select(Some(app.selected_hop));
        }
    } else {
        let state = app.state.lock().unwrap();
        if app.selected_target < state.results.len().saturating_sub(1) {
            app.selected_target += 1;
            app.table_state.select(Some(app.selected_target));
        }
    }
}

fn handle_left_bracket(app: &mut App) {
    if matches!(app.mode, AppMode::Simulator) {
        app.adjust_simulated_mtu(-8);
    }
}

fn handle_right_bracket(app: &mut App) {
    if matches!(app.mode, AppMode::Simulator) {
        app.adjust_simulated_mtu(8);
    }
}

fn handle_tracepath(app: &mut App) {
    app.run_tracepath(app.selected_target);
}

fn handle_retest_single(app: &mut App) {
    let state = app.state.lock().unwrap();
    if let Some(result) = state.results.get(app.selected_target) {
        app.log_messages.push(format!("[RETEST] {}", result.target));
    }
}

fn handle_retest_all(app: &mut App) {
    app.start_testing(576, 9000, 500, 3);
}

fn handle_save(app: &mut App) {
    use std::fs;
    let state = app.state.lock().unwrap();
    let json = serde_json::to_string_pretty(&*state).unwrap_or_else(|_| "{}".to_string());
    let _ = fs::write("fraggle-results.json", json);
    app.popup_message = "Results saved to fraggle-results.json".to_string();
    app.show_popup = true;
}

fn handle_collapse_toggle(app: &mut App) {
    // Toggle collapse for current panel/section
    if matches!(app.mode, AppMode::TargetDetail) {
        let key = format!("detail_{}", app.selected_target);
        let current = app.collapsed_panels.get(&key).copied().unwrap_or(false);
        app.collapsed_panels.insert(key, !current);
    }
}

