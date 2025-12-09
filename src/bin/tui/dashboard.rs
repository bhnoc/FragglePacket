//! Dashboard View - Main results table and summary

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, BorderType, Cell, Gauge, Row, Sparkline, Table, Paragraph, Wrap},
    Frame,
};

use super::types::{App, TestStatus};
use super::colors::*;

pub fn render_dashboard(frame: &mut Frame, area: Rect, app: &mut App) {
    let state = app.state.lock().unwrap();
    
    // Split into left (results table) and right (summary + sparkline)
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
        .split(area);
    
    // Left: Results table
    let header_cells = ["TARGET", "ICMP", "TCP", "UDP", "QUIC", "MSS", "STATUS"]
        .iter()
        .map(|h| Cell::from(*h).style(Style::default().fg(TERM_CYAN).add_modifier(Modifier::BOLD)));
    let header = Row::new(header_cells)
        .style(Style::default().bg(TERM_BLACK))
        .height(1);
    
    let rows = state.results.iter().map(|r| {
        let status_style = match r.status {
            TestStatus::Complete => Style::default().fg(TERM_GREEN),
            TestStatus::Testing => Style::default().fg(TERM_AMBER).add_modifier(Modifier::SLOW_BLINK),
            TestStatus::Failed => Style::default().fg(TERM_RED),
            TestStatus::Pending => Style::default().fg(TERM_GREEN_DIM),
        };
        
        let format_mtu = |m: Option<usize>| -> (String, Style) {
            match m {
                Some(v) if v >= 1500 => (v.to_string(), Style::default().fg(TERM_GREEN)),
                Some(v) if v >= 1400 => (v.to_string(), Style::default().fg(TERM_AMBER)),
                Some(v) => (v.to_string(), Style::default().fg(TERM_RED)),
                None => ("---".to_string(), Style::default().fg(TERM_GREEN_DIM)),
            }
        };
        
        let (icmp, icmp_style) = format_mtu(r.icmp_mtu);
        let (tcp, tcp_style) = format_mtu(r.tcp_mtu);
        let (udp, udp_style) = format_mtu(r.udp_mtu);
        let (quic, quic_style) = format_mtu(r.quic_mtu);
        let (mss, mss_style) = format_mtu(r.tcp_mss);
        
        let status_text = match r.status {
            TestStatus::Complete => "OK",
            TestStatus::Testing => "...",
            TestStatus::Failed => "FAIL",
            TestStatus::Pending => "WAIT",
        };
        
        Row::new(vec![
            Cell::from(r.desc.chars().take(18).collect::<String>()).style(Style::default().fg(TERM_GREEN)),
            Cell::from(icmp).style(icmp_style),
            Cell::from(tcp).style(tcp_style),
            Cell::from(udp).style(udp_style),
            Cell::from(quic).style(quic_style),
            Cell::from(mss).style(mss_style),
            Cell::from(status_text).style(status_style),
        ])
        .height(1)
    });
    
    let table = Table::new(
        rows,
        [
            Constraint::Length(20),
            Constraint::Length(6),
            Constraint::Length(6),
            Constraint::Length(6),
            Constraint::Length(6),
            Constraint::Length(6),
            Constraint::Length(6),
        ],
    )
    .header(header)
    .block(Block::default()
        .title(" ▶ RESULTS ")
        .title_style(Style::default().fg(TERM_GREEN).add_modifier(Modifier::BOLD))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(TERM_GREEN_DIM))
        .border_type(BorderType::Rounded)
        .style(Style::default().bg(TERM_BLACK)))
    .row_highlight_style(Style::default().bg(TERM_GREEN_DARK).add_modifier(Modifier::BOLD))
    .highlight_symbol("▶ ");
    
    drop(state);
    frame.render_stateful_widget(table, chunks[0], &mut app.table_state);
    
    // Right panel: Summary and progress
    let state = app.state.lock().unwrap();
    let right_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(8),
            Constraint::Length(5),
            Constraint::Min(5),
        ])
        .split(chunks[1]);
    
    // Verdict box
    let verdict_text = if let Some(v) = &state.verdict {
        let status_style = if v.status == "PASS" {
            Style::default().fg(TERM_GREEN).add_modifier(Modifier::BOLD)
        } else if v.status == "ACTION_NEEDED" {
            Style::default().fg(TERM_RED).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(TERM_AMBER).add_modifier(Modifier::BOLD)
        };
        
        vec![
            Line::from(vec![
                Span::styled("STATUS: ", Style::default().fg(TERM_GREEN_DIM)),
                Span::styled(&v.status, status_style),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("Median MTU: ", Style::default().fg(TERM_GREEN_DIM)),
                Span::styled(v.median_mtu.to_string(), Style::default().fg(TERM_GREEN)),
            ]),
            Line::from(vec![
                Span::styled("Success:    ", Style::default().fg(TERM_GREEN_DIM)),
                Span::styled(format!("{:.1}%", v.percent_ok), Style::default().fg(TERM_GREEN)),
            ]),
            if let Some(mtu) = v.recommended_mtu {
                Line::from(vec![
                    Span::styled("Set MTU:    ", Style::default().fg(TERM_AMBER)),
                    Span::styled(mtu.to_string(), Style::default().fg(TERM_AMBER).add_modifier(Modifier::BOLD)),
                ])
            } else {
                Line::from(vec![
                    Span::styled("No changes needed", Style::default().fg(TERM_GREEN)),
                ])
            },
        ]
    } else {
        vec![
            Line::from(Span::styled("Awaiting scan...", Style::default().fg(TERM_GREEN_DIM))),
        ]
    };
    
    let verdict_widget = Paragraph::new(verdict_text)
        .block(Block::default()
            .title(" ▶ VERDICT ")
            .title_style(Style::default().fg(TERM_GREEN).add_modifier(Modifier::BOLD))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(TERM_GREEN_DIM))
            .border_type(BorderType::Rounded)
            .style(Style::default().bg(TERM_BLACK)))
        .wrap(Wrap { trim: true });
    
    frame.render_widget(verdict_widget, right_chunks[0]);
    
    // Progress bar
    let progress_pct = (state.progress * 100.0) as u16;
    let progress_label = if state.testing {
        format!("{}% - {}", progress_pct, state.current_target)
    } else {
        format!("{}%", progress_pct)
    };
    
    let progress = Gauge::default()
        .block(Block::default()
            .title(" ▶ PROGRESS ")
            .title_style(Style::default().fg(TERM_GREEN).add_modifier(Modifier::BOLD))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(TERM_GREEN_DIM))
            .border_type(BorderType::Rounded)
            .style(Style::default().bg(TERM_BLACK)))
        .gauge_style(Style::default().fg(TERM_GREEN).bg(TERM_BLACK))
        .percent(progress_pct)
        .label(progress_label);
    
    frame.render_widget(progress, right_chunks[1]);
    
    // MTU Sparkline
    let sparkline = Sparkline::default()
        .block(Block::default()
            .title(" ▶ MTU TREND ")
            .title_style(Style::default().fg(TERM_GREEN).add_modifier(Modifier::BOLD))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(TERM_GREEN_DIM))
            .border_type(BorderType::Rounded)
            .style(Style::default().bg(TERM_BLACK)))
        .data(&state.mtu_history.iter().map(|&v| v as u64).collect::<Vec<_>>())
        .max(1600)
        .style(Style::default().fg(TERM_GREEN));
    
    frame.render_widget(sparkline, right_chunks[2]);
}

