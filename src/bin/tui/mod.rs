//! TUI Module - FragglePacket Terminal User Interface

pub mod types;
pub mod colors;
pub mod events;
pub mod dashboard;
pub mod test_panel;
pub mod test_registration;
pub mod fuzzing_panel;
pub mod https_panel;

// Re-exports
pub use types::{App, AppState, AppMode, ViewMode, TestStatus, TargetResult, HopInfo, Verdict, FuzzingResult, FuzzingStatus, TestUpdate};
pub use colors::*;
pub use events::handle_events;
pub use dashboard::render_dashboard;

use crossterm::{
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    event::{DisableMouseCapture, EnableMouseCapture},
};
use ratatui::{
    backend::CrosstermBackend,
    Terminal,
};
use std::io;

pub fn run_tui() -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    
    let state = std::sync::Arc::new(std::sync::Mutex::new(AppState::default()));
    let mut app = App::new(state);
    
    loop {
        terminal.draw(|f| {
            crate::bin::tui::app::render(f, &mut app);
        })?;
        
        if handle_events(&mut app)? || app.should_quit {
            break;
        }
    }
    
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        crossterm::terminal::LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;
    
    Ok(())
}
