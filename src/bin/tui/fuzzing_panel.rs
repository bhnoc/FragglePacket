//! Fuzzing Panel UI for TUI
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, BorderType, Cell, List, ListItem, Paragraph, Row, Table},
    Frame,
};

use super::app::{App, FuzzingStatus, TERM_BLACK, TERM_GREEN, TERM_GREEN_DIM, TERM_GREEN_DARK, TERM_AMBER, TERM_RED, TERM_CYAN};

pub fn render_fuzzing_panel(frame: &mut Frame, area: Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(7),   // Fuzzing modes selector
            Constraint::Min(10),     // Results table
            Constraint::Length(5),   // Controls
        ])
        .split(area);
    
    // Fuzzing modes selector
    let modes = vec![
        "Segment Size Fuzzing",
        "Length Mismatch",
        "TCP Options Corruption",
        "IP Fragmentation",
        "Checksum Validation",
    ];
    
    let mut items: Vec<ListItem> = vec![];
    for (i, mode) in modes.iter().enumerate() {
        let style = if i == app.selected_fuzz_mode {
            Style::default().fg(TERM_BLACK).bg(TERM_GREEN)
        } else {
            Style::default().fg(TERM_GREEN)
        };
        items.push(ListItem::new(*mode).style(style));
    }
    
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(TERM_GREEN))
                .title(" Fuzzing Modes ")
                .title_style(Style::default().fg(TERM_CYAN).add_modifier(Modifier::BOLD))
        );
    frame.render_widget(list, chunks[0]);
    
    // Results table
    let state = app.state.lock().unwrap();
    let mut rows = vec![];
    
    for (mode, result) in &state.fuzzing_results {
        let status_str = match &result.status {
            FuzzingStatus::Pending => "PENDING",
            FuzzingStatus::Running => "RUNNING",
            FuzzingStatus::Complete => "COMPLETE",
            FuzzingStatus::Failed(msg) => msg.as_str(),
        };
        
        let status_style = match &result.status {
            FuzzingStatus::Pending => Style::default().fg(TERM_GREEN_DIM),
            FuzzingStatus::Running => Style::default().fg(TERM_AMBER),
            FuzzingStatus::Complete => Style::default().fg(TERM_GREEN),
            FuzzingStatus::Failed(_) => Style::default().fg(TERM_RED),
        };
        
        rows.push(Row::new(vec![
            Cell::from(mode.as_str()).style(Style::default().fg(TERM_GREEN)),
            Cell::from(result.packets_generated.to_string()).style(Style::default().fg(TERM_CYAN)),
            Cell::from(format!("{}KB", result.file_size_bytes / 1024)).style(Style::default().fg(TERM_GREEN)),
            Cell::from(format!("{}ms", result.duration_ms)).style(Style::default().fg(TERM_GREEN_DIM)),
            Cell::from(status_str).style(status_style),
        ]));
    }
    
    let table = Table::new(
        rows,
        [
            Constraint::Percentage(30),
            Constraint::Percentage(15),
            Constraint::Percentage(15),
            Constraint::Percentage(15),
            Constraint::Percentage(25),
        ],
    )
    .header(
        Row::new(vec!["Mode", "Packets", "Size", "Time", "Status"])
            .style(Style::default().fg(TERM_CYAN).add_modifier(Modifier::BOLD))
            .bottom_margin(1),
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(TERM_GREEN))
            .title(" Fuzzing Results ")
            .title_style(Style::default().fg(TERM_CYAN).add_modifier(Modifier::BOLD))
    )
    .highlight_style(Style::default().fg(TERM_BLACK).bg(TERM_GREEN));
    
    frame.render_widget(table, chunks[1]);
    
    // Controls
    let controls = vec![
        Line::from(vec![
            Span::styled("[ENTER]", Style::default().fg(TERM_CYAN)),
            Span::raw(" Run Fuzzer  "),
            Span::styled("[↑/↓]", Style::default().fg(TERM_CYAN)),
            Span::raw(" Select  "),
            Span::styled("[A]", Style::default().fg(TERM_CYAN)),
            Span::raw(" Run All  "),
            Span::styled("[ESC]", Style::default().fg(TERM_CYAN)),
            Span::raw(" Back"),
        ]),
    ];
    
    let controls_para = Paragraph::new(controls)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(TERM_GREEN))
                .title(" Controls ")
                .title_style(Style::default().fg(TERM_GREEN_DIM))
        )
        .alignment(Alignment::Center);
    
    frame.render_widget(controls_para, chunks[2]);
}

