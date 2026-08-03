//! HTTPS Panel UI for TUI - Stage-by-stage HTTPS testing with diagnosis
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Cell, List, ListItem, Paragraph, Row, Table},
    Frame,
};

use super::app::{
    App, TERM_AMBER, TERM_BLACK, TERM_CYAN, TERM_GREEN, TERM_GREEN_DIM, TERM_RED,
};
use fraggle_packet::network_tests::HttpsDiagnosis;

pub fn render_https_panel(frame: &mut Frame, area: Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(9), // Target selector
            Constraint::Min(10),   // Results table
            Constraint::Length(6), // Diagnosis summary
            Constraint::Length(4), // Controls
        ])
        .split(area);

    // Target selector
    let state = app.state.lock().unwrap();
    let mut target_items: Vec<ListItem> = vec![];

    for (i, result) in state.results.iter().enumerate() {
        let style = if i == app.selected_https_target {
            Style::default().fg(TERM_BLACK).bg(TERM_GREEN)
        } else {
            Style::default().fg(TERM_GREEN)
        };

        let status_icon = if state.https_results.contains_key(&result.target) {
            "✓"
        } else {
            "○"
        };

        let item_text = format!("{} {}", status_icon, result.target);
        target_items.push(ListItem::new(item_text).style(style));
    }

    let target_list = List::new(target_items).block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(TERM_GREEN))
            .title(" Select Target for HTTPS Test ")
            .title_style(Style::default().fg(TERM_CYAN).add_modifier(Modifier::BOLD)),
    );
    frame.render_widget(target_list, chunks[0]);

    // Results table
    let mut rows = vec![];

    for (target, result) in &state.https_results {
        let dns_status = if result.dns_time_ms.is_some() {
            format!("✓ {}ms", result.dns_time_ms.unwrap())
        } else {
            "✗".to_string()
        };

        let tcp_status = if result.tcp_success {
            format!("✓ {}ms", result.tcp_connect_time_ms.unwrap_or(0))
        } else {
            "✗".to_string()
        };

        let tls_status = if result.tls_success {
            format!("✓ {}ms", result.tls_handshake_time_ms.unwrap_or(0))
        } else if result.tcp_success {
            "⚠ TIMEOUT".to_string() // MTU blackhole indicator
        } else {
            "✗".to_string()
        };

        let http_status = if result.status_code.is_some() {
            format!("✓ {}", result.status_code.unwrap())
        } else {
            "✗".to_string()
        };

        let diagnosis_str = match &result.diagnosis {
            HttpsDiagnosis::Success => "OK",
            HttpsDiagnosis::TlsTimeout => "MTU BLACKHOLE",
            HttpsDiagnosis::DnsFailure => "DNS FAIL",
            HttpsDiagnosis::TcpConnectFailed => "TCP FAIL",
            HttpsDiagnosis::TlsHandshakeFailed => "TLS FAIL",
            _ => "ERROR",
        };

        let diagnosis_style = match &result.diagnosis {
            HttpsDiagnosis::Success => Style::default().fg(TERM_GREEN),
            HttpsDiagnosis::TlsTimeout | HttpsDiagnosis::MtuBlackhole => {
                Style::default().fg(TERM_RED).add_modifier(Modifier::BOLD)
            }
            _ => Style::default().fg(TERM_AMBER),
        };

        rows.push(Row::new(vec![
            Cell::from(target.as_str()).style(Style::default().fg(TERM_GREEN)),
            Cell::from(dns_status).style(Style::default().fg(TERM_CYAN)),
            Cell::from(tcp_status).style(Style::default().fg(TERM_CYAN)),
            Cell::from(tls_status).style(Style::default().fg(TERM_CYAN)),
            Cell::from(http_status).style(Style::default().fg(TERM_CYAN)),
            Cell::from(format!("{}ms", result.total_time_ms))
                .style(Style::default().fg(TERM_GREEN_DIM)),
            Cell::from(diagnosis_str).style(diagnosis_style),
        ]));
    }

    let results_table = Table::new(
        rows,
        [
            Constraint::Percentage(20),
            Constraint::Percentage(12),
            Constraint::Percentage(12),
            Constraint::Percentage(15),
            Constraint::Percentage(12),
            Constraint::Percentage(10),
            Constraint::Percentage(19),
        ],
    )
    .header(
        Row::new(vec![
            "Target",
            "DNS",
            "TCP",
            "TLS",
            "HTTP",
            "Total",
            "Diagnosis",
        ])
        .style(Style::default().fg(TERM_CYAN).add_modifier(Modifier::BOLD))
        .bottom_margin(1),
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(TERM_GREEN))
            .title(" HTTPS Test Results ")
            .title_style(Style::default().fg(TERM_CYAN).add_modifier(Modifier::BOLD)),
    );

    frame.render_widget(results_table, chunks[1]);

    // Diagnosis summary
    let mut diagnosis_lines = vec![];

    if state.diagnoses.is_empty() {
        diagnosis_lines.push(Line::from(Span::styled(
            "No issues detected",
            Style::default().fg(TERM_GREEN),
        )));
    } else {
        for (i, diag) in state.diagnoses.iter().take(3).enumerate() {
            let severity_color = match diag.severity {
                fraggle_packet::diagnosis::Severity::Critical => TERM_RED,
                fraggle_packet::diagnosis::Severity::High => TERM_AMBER,
                _ => TERM_GREEN_DIM,
            };

            diagnosis_lines.push(Line::from(vec![
                Span::styled(format!("{}. ", i + 1), Style::default().fg(TERM_CYAN)),
                Span::styled(
                    format!("{:?}: ", diag.issue),
                    Style::default()
                        .fg(severity_color)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    &diag.description[..diag.description.len().min(80)],
                    Style::default().fg(TERM_GREEN_DIM),
                ),
            ]));
        }
    }

    let diagnosis_para = Paragraph::new(diagnosis_lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(TERM_GREEN))
                .title(" Diagnosis ")
                .title_style(Style::default().fg(TERM_AMBER).add_modifier(Modifier::BOLD)),
        )
        .wrap(ratatui::widgets::Wrap { trim: true });

    frame.render_widget(diagnosis_para, chunks[2]);

    // Controls
    let controls = vec![Line::from(vec![
        Span::styled("[ENTER]", Style::default().fg(TERM_CYAN)),
        Span::raw(" Test Selected  "),
        Span::styled("[↑/↓]", Style::default().fg(TERM_CYAN)),
        Span::raw(" Navigate  "),
        Span::styled("[A]", Style::default().fg(TERM_CYAN)),
        Span::raw(" Test All  "),
        Span::styled("[ESC]", Style::default().fg(TERM_CYAN)),
        Span::raw(" Back"),
    ])];

    let controls_para = Paragraph::new(controls)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(TERM_GREEN))
                .title(" Controls ")
                .title_style(Style::default().fg(TERM_GREEN_DIM)),
        )
        .alignment(Alignment::Center);

    frame.render_widget(controls_para, chunks[3]);
}
