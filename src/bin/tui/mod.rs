//! TUI modules

pub mod app;
pub mod fuzzing_panel;

pub use app::{App, AppState, run_tui};
pub use fuzzing_panel::render_fuzzing_panel;

