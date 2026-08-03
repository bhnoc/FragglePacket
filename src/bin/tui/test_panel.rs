//! Test Panel - displays test framework results

use fraggle_packet::framework::test_trait::TestCategory as FrameworkCategory;
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, List, ListItem, Paragraph},
    Frame,
};

use super::app::{
    App, TERM_AMBER, TERM_BLACK, TERM_CYAN, TERM_GREEN, TERM_GREEN_DARK, TERM_GREEN_DIM, TERM_RED,
};

const CATEGORIES: &[(&str, usize)] = &[
    ("DNS", 1),
    ("MTU", 2),
    ("HTTPS", 3),
    ("TCP Health", 4),
    ("RTT", 5),
    ("Loss", 6),
    ("Path", 7),
    ("IPv6", 8),
    ("App Proto", 9),
    ("Fuzzing", 10),
];

pub fn render_test_panel(f: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5), // Category buttons
            Constraint::Min(10),   // Test results
            Constraint::Length(3), // Status bar
        ])
        .split(area);

    // Category selection buttons
    render_category_buttons(f, app, chunks[0]);

    // Test results
    render_test_results(f, app, chunks[1]);

    // Status bar
    render_status_bar(f, app, chunks[2]);
}

fn render_category_buttons(f: &mut Frame, app: &App, area: Rect) {
    let mut button_text = vec![
        Line::from(vec![Span::styled(
            "  Test Categories  ",
            Style::default().fg(TERM_CYAN).add_modifier(Modifier::BOLD),
        )]),
        Line::from(""),
    ];

    // First row (1-5)
    let mut first_row = vec![];
    for (name, num) in &CATEGORIES[0..5] {
        let selected = app.selected_category == Some(num - 1);
        let style = if selected {
            Style::default()
                .fg(TERM_BLACK)
                .bg(TERM_GREEN)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(TERM_GREEN)
        };
        first_row.push(Span::styled(format!(" [{}] {} ", num, name), style));
        first_row.push(Span::raw(" "));
    }
    button_text.push(Line::from(first_row));

    // Second row (6-10)
    let mut second_row = vec![];
    for (name, num) in &CATEGORIES[5..10] {
        let selected = app.selected_category == Some(num - 1);
        let style = if selected {
            Style::default()
                .fg(TERM_BLACK)
                .bg(TERM_GREEN)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(TERM_GREEN)
        };
        second_row.push(Span::styled(format!(" [{}] {} ", num, name), style));
        second_row.push(Span::raw(" "));
    }
    button_text.push(Line::from(second_row));

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Double)
        .border_style(Style::default().fg(TERM_GREEN))
        .style(Style::default().bg(TERM_BLACK));

    let paragraph = Paragraph::new(button_text)
        .block(block)
        .alignment(Alignment::Left);

    f.render_widget(paragraph, area);
}

fn render_test_results(f: &mut Frame, app: &App, area: Rect) {
    let state = app.state.lock().unwrap();

    let target = if !state.results.is_empty() && app.selected_target < state.results.len() {
        state.results[app.selected_target].target.clone()
    } else {
        "No target selected".to_string()
    };

    drop(state);

    // Get framework results for this target
    let results = app.framework_results.get(&target);

    let mut items = vec![];

    if let Some(category_idx) = app.selected_category {
        // Show detailed results for selected category
        items.push(ListItem::new(Line::from(vec![Span::styled(
            format!("Results for: {}", CATEGORIES[category_idx].0),
            Style::default().fg(TERM_CYAN).add_modifier(Modifier::BOLD),
        )])));
        items.push(ListItem::new(Line::from("")));

        if let Some(results) = results {
            for result in results {
                // Filter by category
                let cat_matches = match category_idx {
                    0 => matches!(result.category, FrameworkCategory::DNS),
                    1 => matches!(result.category, FrameworkCategory::MTU),
                    2 => matches!(result.category, FrameworkCategory::HTTPS),
                    3 => matches!(result.category, FrameworkCategory::TCPHealth),
                    4 => matches!(result.category, FrameworkCategory::RTT),
                    5 => matches!(result.category, FrameworkCategory::PacketLoss),
                    6 => matches!(result.category, FrameworkCategory::PathAnalysis),
                    7 => matches!(result.category, FrameworkCategory::IPv6),
                    8 => matches!(result.category, FrameworkCategory::Application),
                    9 => matches!(result.category, FrameworkCategory::Fuzzing),
                    _ => false,
                };

                if cat_matches {
                    let status_color = match result.status {
                        fraggle_packet::framework::TestStatus::Success => TERM_GREEN,
                        fraggle_packet::framework::TestStatus::Warning => TERM_AMBER,
                        fraggle_packet::framework::TestStatus::Failed => TERM_RED,
                        _ => TERM_GREEN_DIM,
                    };

                    items.push(ListItem::new(Line::from(vec![
                        Span::styled(
                            format!(" {} ", result.name),
                            Style::default().fg(TERM_GREEN).add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(
                            format!("{:?}", result.status),
                            Style::default().fg(status_color),
                        ),
                    ])));

                    // Show key metrics
                    for (key, value) in result.metrics.iter().take(3) {
                        items.push(ListItem::new(Line::from(vec![
                            Span::raw("   "),
                            Span::styled(
                                format!("{}: {:.1}", key, value),
                                Style::default().fg(TERM_GREEN_DIM),
                            ),
                        ])));
                    }

                    // Show diagnoses
                    for diag in &result.diagnoses {
                        items.push(ListItem::new(Line::from(vec![
                            Span::raw("   "),
                            Span::styled(
                                format!("[{:?}] {}", diag.severity, diag.title),
                                Style::default().fg(TERM_AMBER),
                            ),
                        ])));
                    }

                    items.push(ListItem::new(Line::from("")));
                }
            }
        } else {
            items.push(ListItem::new(Line::from(vec![Span::styled(
                "  No results yet. Press ENTER to run test.",
                Style::default().fg(TERM_GREEN_DIM),
            )])));
        }
    } else {
        // Show overview of all categories
        items.push(ListItem::new(Line::from(vec![Span::styled(
            "All Test Categories",
            Style::default().fg(TERM_CYAN).add_modifier(Modifier::BOLD),
        )])));
        items.push(ListItem::new(Line::from("")));

        if let Some(results) = results {
            for (name, _) in CATEGORIES {
                let count = results
                    .iter()
                    .filter(|r| {
                        format!("{:?}", r.category).contains(name.replace(" ", "").as_str())
                    })
                    .count();

                items.push(ListItem::new(Line::from(vec![
                    Span::styled(format!(" {} ", name), Style::default().fg(TERM_GREEN)),
                    Span::styled(
                        format!("{} test(s)", count),
                        Style::default().fg(TERM_GREEN_DIM),
                    ),
                ])));
            }
        } else {
            items.push(ListItem::new(Line::from(vec![Span::styled(
                "  No tests run yet. Select category (1-10) and press ENTER.",
                Style::default().fg(TERM_GREEN_DIM),
            )])));
        }
    }

    let list = List::new(items)
        .block(
            Block::default()
                .title(format!(" Test Results: {} ", target))
                .title_style(Style::default().fg(TERM_CYAN).add_modifier(Modifier::BOLD))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(TERM_GREEN)),
        )
        .style(Style::default().bg(TERM_BLACK).fg(TERM_GREEN));

    f.render_widget(list, area);
}

fn render_status_bar(f: &mut Frame, app: &App, area: Rect) {
    let status_text = if let Some(cat) = app.selected_category {
        format!(
            " Category: {} | ENTER=Run | ESC=Back | TAB=Switch View ",
            CATEGORIES[cat].0
        )
    } else {
        " Select Category (1-10) | ENTER=Run All | ESC=Back | TAB=Switch View ".to_string()
    };

    let paragraph = Paragraph::new(status_text)
        .style(
            Style::default()
                .bg(TERM_GREEN_DARK)
                .fg(TERM_GREEN)
                .add_modifier(Modifier::BOLD),
        )
        .alignment(Alignment::Center);

    f.render_widget(paragraph, area);
}
