//! TUI Module - FragglePacket Terminal User Interface

pub mod app;
pub mod colors;
pub mod fuzzing_panel;
pub mod https_panel;
pub mod test_panel;
pub mod test_registration;

// Re-exports from app module (which has everything)
pub use app::{App, AppState, AppMode, render};

use crossterm::{
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen},
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
            render(f, &mut app);
        })?;
        
        if app::handle_events(&mut app)? || app.should_quit {
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
