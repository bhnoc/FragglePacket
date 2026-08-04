//! Registry-driven command browser: every CLI subcommand, grouped by bucket.
//!
//! Replaces a panel that hardcoded ten `NetworkTest` categories behind ten
//! number-key handlers. That shape could not grow past ten entries, so 60 of 79
//! subcommands had no way to be reached from the TUI at all.
//!
//! Buckets are selected on the left, commands listed on the right. Availability
//! comes from the registry rather than from trying and failing: a command whose
//! live sampling needs macOS is shown as ingest-only with the reason, and one
//! with no alternative is shown blocked. The user learns why before spending a
//! run on it.

use fraggle_packet::ui_bridge::registry::{self, Availability, Bucket, Cmd};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, List, ListItem, Paragraph, Wrap},
    Frame,
};

use super::app::{App, TERM_AMBER, TERM_BLACK, TERM_CYAN, TERM_GREEN, TERM_GREEN_DARK, TERM_GREEN_DIM, TERM_RED};

/// Which pane has focus. Commands-per-bucket means two lists, and without an
/// explicit focus the arrow keys would be ambiguous.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    Buckets,
    Commands,
}

/// Panel state. Kept here rather than on `App` so the panel owns its own
/// navigation and `app.rs` does not grow another dozen fields.
#[derive(Debug, Clone)]
pub struct CommandPanelState {
    pub focus: Focus,
    pub selected_bucket: usize,
    pub selected_command: usize,
    /// Result of the last run, rendered verbatim. Not parsed into a verdict
    /// here: the CLI already decided, and re-interpreting it in the UI is how a
    /// refusal turns into a false green.
    pub last_output: Option<String>,
    pub last_command: Option<String>,
    pub running: bool,
    /// Values typed for the selected command's required inputs, one per
    /// placeholder in order. Empty until the user starts entering them.
    pub input_values: Vec<String>,
    /// Which required input is being edited, when in input mode.
    pub editing_input: Option<usize>,
}

impl Default for CommandPanelState {
    fn default() -> Self {
        CommandPanelState {
            focus: Focus::Buckets,
            selected_bucket: 0,
            selected_command: 0,
            last_output: None,
            last_command: None,
            running: false,
            input_values: Vec::new(),
            editing_input: None,
        }
    }
}

impl CommandPanelState {
    pub fn current_bucket(&self) -> Bucket {
        Bucket::ALL[self.selected_bucket.min(Bucket::ALL.len() - 1)]
    }

    pub fn commands(&self) -> Vec<&'static Cmd> {
        registry::in_bucket(self.current_bucket())
    }

    /// The highlighted command, or `None` when the bucket is empty. Clamped
    /// rather than indexed blindly, since switching buckets can leave the index
    /// past the end of a shorter list.
    pub fn current_command(&self) -> Option<&'static Cmd> {
        let cmds = self.commands();
        if cmds.is_empty() {
            return None;
        }
        Some(cmds[self.selected_command.min(cmds.len() - 1)])
    }

    pub fn next_bucket(&mut self) {
        self.selected_bucket = (self.selected_bucket + 1) % Bucket::ALL.len();
        self.selected_command = 0;
        self.input_values.clear();
        self.editing_input = None;
    }

    pub fn prev_bucket(&mut self) {
        self.selected_bucket = if self.selected_bucket == 0 {
            Bucket::ALL.len() - 1
        } else {
            self.selected_bucket - 1
        };
        self.selected_command = 0;
        self.input_values.clear();
        self.editing_input = None;
    }

    pub fn next_command(&mut self) {
        self.input_values.clear();
        self.editing_input = None;
        let n = self.commands().len();
        if n > 0 {
            self.selected_command = (self.selected_command + 1) % n;
        }
    }

    pub fn prev_command(&mut self) {
        self.input_values.clear();
        self.editing_input = None;
        let n = self.commands().len();
        if n > 0 {
            self.selected_command = if self.selected_command == 0 { n - 1 } else { self.selected_command - 1 };
        }
    }

    /// Begins entering values for the selected command, sizing the buffer to its
    /// required inputs. Called instead of running when a command needs input.
    pub fn begin_input(&mut self) {
        if let Some(c) = self.current_command() {
            if c.required_inputs.is_empty() {
                return;
            }
            if self.input_values.len() != c.required_inputs.len() {
                self.input_values = vec![String::new(); c.required_inputs.len()];
            }
            self.editing_input = Some(0);
        }
    }

    pub fn cancel_input(&mut self) {
        self.editing_input = None;
    }

    /// Moves to the next field, or returns true when the last field is done and
    /// the caller should attempt the run.
    pub fn advance_input(&mut self) -> bool {
        let Some(i) = self.editing_input else { return false };
        let n = self.input_values.len();
        if i + 1 < n {
            self.editing_input = Some(i + 1);
            false
        } else {
            self.editing_input = None;
            true
        }
    }

    pub fn push_char(&mut self, ch: char) {
        if let Some(i) = self.editing_input {
            if let Some(v) = self.input_values.get_mut(i) {
                v.push(ch);
            }
        }
    }

    pub fn pop_char(&mut self) {
        if let Some(i) = self.editing_input {
            if let Some(v) = self.input_values.get_mut(i) {
                v.pop();
            }
        }
    }

    pub fn is_editing(&self) -> bool {
        self.editing_input.is_some()
    }

    pub fn toggle_focus(&mut self) {
        self.focus = match self.focus {
            Focus::Buckets => Focus::Commands,
            Focus::Commands => Focus::Buckets,
        };
    }
}

/// Short availability marker shown beside each command name.
fn availability_marker(cmd: &Cmd) -> (&'static str, ratatui::style::Color) {
    marker_for(&cmd.availability(), cmd.needs_privilege)
}

/// Marker for an availability/privilege pair. Split out from
/// [`availability_marker`] so the mapping is testable on every platform rather
/// than only on whichever OS the test happens to run on.
fn marker_for(a: &Availability, needs_privilege: bool) -> (&'static str, ratatui::style::Color) {
    match a {
        Availability::Unavailable(_) => ("n/a", TERM_RED),
        Availability::IngestOnly(_) => ("ingest", TERM_AMBER),
        Availability::Available if needs_privilege => ("root", TERM_AMBER),
        Availability::Available => ("", TERM_GREEN),
    }
}

pub fn render_command_panel(f: &mut Frame, app: &mut App, area: Rect) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(10), Constraint::Length(9)])
        .split(area);

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(26), Constraint::Min(30)])
        .split(rows[0]);

    render_buckets(f, app, cols[0]);
    render_commands(f, app, cols[1]);
    render_detail(f, app, rows[1]);
}

fn render_buckets(f: &mut Frame, app: &App, area: Rect) {
    let st = &app.command_panel;
    let items: Vec<ListItem> = Bucket::ALL
        .iter()
        .enumerate()
        .map(|(i, b)| {
            let n = registry::in_bucket(*b).len();
            let selected = i == st.selected_bucket;
            let style = if selected {
                Style::default().fg(TERM_BLACK).bg(TERM_GREEN).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(TERM_GREEN_DIM)
            };
            ListItem::new(Line::from(vec![
                Span::styled(format!(" {:<20}", b.label()), style),
                Span::styled(format!("{n:>2} "), Style::default().fg(TERM_GREEN_DARK)),
            ]))
        })
        .collect();

    let focused = st.focus == Focus::Buckets;
    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(if focused { TERM_CYAN } else { TERM_GREEN_DARK }))
            .title(Span::styled(" Areas ", Style::default().fg(TERM_CYAN).add_modifier(Modifier::BOLD))),
    );
    f.render_widget(list, area);
}

fn render_commands(f: &mut Frame, app: &App, area: Rect) {
    let st = &app.command_panel;
    let cmds = st.commands();

    let items: Vec<ListItem> = cmds
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let selected = i == st.selected_command && st.focus == Focus::Commands;
            let (marker, marker_color) = availability_marker(c);
            let name_style = if selected {
                Style::default().fg(TERM_BLACK).bg(TERM_GREEN).add_modifier(Modifier::BOLD)
            } else if c.availability().is_blocked() {
                Style::default().fg(TERM_GREEN_DARK)
            } else {
                Style::default().fg(TERM_GREEN)
            };
            let mut spans = vec![Span::styled(format!(" {:<24}", c.name), name_style)];
            if !marker.is_empty() {
                spans.push(Span::styled(format!("[{marker}] "), Style::default().fg(marker_color)));
            }
            if let Some(g) = c.gaps {
                spans.push(Span::styled(g.to_string(), Style::default().fg(TERM_GREEN_DARK)));
            }
            ListItem::new(Line::from(spans))
        })
        .collect();

    let focused = st.focus == Focus::Commands;
    let title = format!(" {} ({}) ", st.current_bucket().label(), cmds.len());
    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(if focused { TERM_CYAN } else { TERM_GREEN_DARK }))
            .title(Span::styled(title, Style::default().fg(TERM_CYAN).add_modifier(Modifier::BOLD))),
    );
    f.render_widget(list, area);
}

fn render_detail(f: &mut Frame, app: &App, area: Rect) {
    let st = &app.command_panel;
    let mut lines: Vec<Line> = Vec::new();

    match st.current_command() {
        None => lines.push(Line::from(Span::styled(
            "  no commands in this area",
            Style::default().fg(TERM_GREEN_DARK),
        ))),
        Some(c) => {
            lines.push(Line::from(vec![
                Span::styled("  ", Style::default()),
                Span::styled(c.name, Style::default().fg(TERM_CYAN).add_modifier(Modifier::BOLD)),
                Span::styled(
                    if c.emits_json { "  (json)" } else { "  (text output)" },
                    Style::default().fg(TERM_GREEN_DARK),
                ),
            ]));
            lines.push(Line::from(Span::styled(
                format!("  {}", c.summary),
                Style::default().fg(TERM_GREEN_DIM),
            )));

            // Availability is stated before the user spends a run finding out.
            match c.availability() {
                Availability::Available => {
                    if c.needs_privilege {
                        lines.push(Line::from(Span::styled(
                            "  needs root: raw sockets",
                            Style::default().fg(TERM_AMBER),
                        )));
                    }
                }
                Availability::IngestOnly(reason) => lines.push(Line::from(Span::styled(
                    format!("  ingest only here: {reason}"),
                    Style::default().fg(TERM_AMBER),
                ))),
                Availability::Unavailable(reason) => lines.push(Line::from(Span::styled(
                    format!("  unavailable here: {reason}"),
                    Style::default().fg(TERM_RED),
                ))),
            }

            if !c.required_inputs.is_empty() {
                if st.is_editing() || !st.input_values.is_empty() {
                    // Show one line per field so the user can see what has been
                    // entered and which field is active.
                    for (i, (name, kind)) in c.typed_inputs().iter().enumerate() {
                        let val = st.input_values.get(i).cloned().unwrap_or_default();
                        let active = st.editing_input == Some(i);
                        let shown = if val.is_empty() { kind.hint().to_string() } else { val };
                        lines.push(Line::from(vec![
                            Span::styled(
                                format!("  {} {name}: ", if active { ">" } else { " " }),
                                Style::default().fg(if active { TERM_CYAN } else { TERM_GREEN_DARK }),
                            ),
                            Span::styled(
                                shown,
                                Style::default().fg(if active { TERM_GREEN } else { TERM_GREEN_DIM }),
                            ),
                        ]));
                    }
                    if st.is_editing() {
                        lines.push(Line::from(Span::styled(
                            "  [Enter] next field  [ESC] cancel",
                            Style::default().fg(TERM_GREEN_DARK),
                        )));
                    }
                } else {
                    lines.push(Line::from(Span::styled(
                        format!("  requires: {} -- press [i] to enter", c.required_inputs.join(", ")),
                        Style::default().fg(TERM_AMBER),
                    )));
                }
            }
        }
    }

    if st.running {
        lines.push(Line::from(Span::styled("  running...", Style::default().fg(TERM_CYAN))));
    } else if let (Some(cmd), Some(out)) = (&st.last_command, &st.last_output) {
        lines.push(Line::from(Span::styled(
            format!("  last: {cmd}"),
            Style::default().fg(TERM_GREEN_DARK),
        )));
        for l in out.lines().take(2) {
            lines.push(Line::from(Span::styled(
                format!("  {l}"),
                Style::default().fg(TERM_GREEN_DIM),
            )));
        }
    }

    let p = Paragraph::new(lines)
        .wrap(Wrap { trim: true })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(TERM_GREEN_DARK))
                .title(Span::styled(
                    " Detail  [Tab]switch [Enter]run [ESC]back ",
                    Style::default().fg(TERM_CYAN),
                )),
        );
    f.render_widget(p, area);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_bucket_is_reachable_by_cycling() {
        let mut st = CommandPanelState::default();
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..Bucket::ALL.len() {
            seen.insert(st.current_bucket());
            st.next_bucket();
        }
        assert_eq!(seen.len(), Bucket::ALL.len(), "cycling must visit every bucket");
    }

    #[test]
    fn bucket_cycling_wraps_both_ways() {
        let mut st = CommandPanelState::default();
        st.prev_bucket();
        assert_eq!(st.selected_bucket, Bucket::ALL.len() - 1);
        st.next_bucket();
        assert_eq!(st.selected_bucket, 0);
    }

    /// Switching to a shorter bucket must not leave the command index dangling.
    #[test]
    fn changing_bucket_resets_the_command_index() {
        let mut st = CommandPanelState::default();
        st.focus = Focus::Commands;
        for _ in 0..5 {
            st.next_command();
        }
        st.next_bucket();
        assert_eq!(st.selected_command, 0);
        assert!(st.current_command().is_some(), "a reset index must resolve");
    }

    /// Every command in every bucket must be selectable -- this is the whole
    /// point, since 60 of 79 were previously unreachable.
    #[test]
    fn every_registered_command_is_reachable() {
        let mut reachable = std::collections::BTreeSet::new();
        let mut st = CommandPanelState::default();
        for _ in 0..Bucket::ALL.len() {
            let n = st.commands().len();
            for _ in 0..n {
                if let Some(c) = st.current_command() {
                    reachable.insert(c.name);
                }
                st.next_command();
            }
            st.next_bucket();
        }
        assert_eq!(
            reachable.len(),
            registry::COMMANDS.len(),
            "unreachable: {:?}",
            registry::COMMANDS
                .iter()
                .map(|c| c.name)
                .filter(|n| !reachable.contains(n))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn current_command_is_clamped_not_panicking() {
        let mut st = CommandPanelState::default();
        st.selected_command = 9999;
        assert!(st.current_command().is_some(), "an out-of-range index must clamp");
    }

    #[test]
    fn focus_toggles_between_the_two_panes() {
        let mut st = CommandPanelState::default();
        assert_eq!(st.focus, Focus::Buckets);
        st.toggle_focus();
        assert_eq!(st.focus, Focus::Commands);
        st.toggle_focus();
        assert_eq!(st.focus, Focus::Buckets);
    }

    /// A blocked command must be visibly marked, not silently offered.
    #[test]
    fn availability_markers_distinguish_the_three_states() {
        // Marker text is derived from Availability, so assert the mapping
        // directly rather than through cfg!(target_os). An earlier version of
        // this test allowed an empty marker for every case, which meant it
        // passed on macOS no matter how the non-macOS path behaved.
        assert_eq!(marker_for(&Availability::Available, false).0, "");
        assert_eq!(marker_for(&Availability::Available, true).0, "root");
        assert_eq!(marker_for(&Availability::IngestOnly("x"), false).0, "ingest");
        assert_eq!(marker_for(&Availability::Unavailable("x"), false).0, "n/a");
        // A blocked command must stay blocked even if it also needs privilege:
        // "n/a" is the more important fact.
        assert_eq!(marker_for(&Availability::Unavailable("x"), true).0, "n/a");
    }

    /// Every command resolves to exactly one of the three markers on this host,
    /// so no entry can render blank-and-clickable when it is actually blocked.
    #[test]
    fn every_command_resolves_to_a_known_marker() {
        for c in registry::COMMANDS {
            let m = availability_marker(c).0;
            assert!(
                m.is_empty() || m == "root" || m == "ingest" || m == "n/a",
                "{} produced unknown marker {m:?}",
                c.name
            );
            if c.availability().is_blocked() {
                assert_eq!(m, "n/a", "{} is blocked but not marked", c.name);
            }
        }
    }
    /// Entering values for a single-input command must complete on the first
    /// Enter, and for a two-input command only on the second. The pty test that
    /// first exercised this landed on burst-analysis (INTERFACE + TARGET) and
    /// advanced instead of running, which was correct behaviour but looked like a
    /// bug -- so the sequencing is asserted here rather than through the terminal.
    #[test]
    fn a_single_input_command_completes_on_the_first_enter() {
        let mut st = CommandPanelState::default();
        // Find a command needing exactly one input.
        let (bi, ci) = find_command_with_inputs(1).expect("some command needs one input");
        st.selected_bucket = bi;
        st.selected_command = ci;
        st.begin_input();
        assert_eq!(st.editing_input, Some(0));
        for ch in "1.1.1.1".chars() {
            st.push_char(ch);
        }
        assert_eq!(st.input_values[0], "1.1.1.1");
        assert!(st.advance_input(), "one field means Enter should run");
        assert!(!st.is_editing());
    }

    #[test]
    fn a_two_input_command_advances_before_running() {
        let mut st = CommandPanelState::default();
        let (bi, ci) = find_command_with_inputs(2).expect("some command needs two inputs");
        st.selected_bucket = bi;
        st.selected_command = ci;
        st.begin_input();
        for ch in "en0".chars() {
            st.push_char(ch);
        }
        assert!(!st.advance_input(), "first of two fields must not run");
        assert_eq!(st.editing_input, Some(1));
        for ch in "1.1.1.1".chars() {
            st.push_char(ch);
        }
        assert!(st.advance_input(), "second field completes");
        assert_eq!(st.input_values, vec!["en0".to_string(), "1.1.1.1".to_string()]);
    }

    fn find_command_with_inputs(n: usize) -> Option<(usize, usize)> {
        for (bi, b) in Bucket::ALL.iter().enumerate() {
            for (ci, c) in registry::in_bucket(*b).iter().enumerate() {
                if c.required_inputs.len() == n {
                    return Some((bi, ci));
                }
            }
        }
        None
    }

    /// A command needing no input must not enter edit mode at all, or Enter would
    /// silently do nothing instead of running.
    #[test]
    fn begin_input_is_a_noop_for_a_command_needing_nothing() {
        let mut st = CommandPanelState::default();
        let (bi, ci) = find_command_with_inputs(0).expect("some command needs nothing");
        st.selected_bucket = bi;
        st.selected_command = ci;
        st.begin_input();
        assert!(!st.is_editing(), "must not prompt for a command with no inputs");
    }

    /// Values must not leak between commands: typing a hostname for one command
    /// and then moving the selection must not silently reuse it as another
    /// command's interface name.
    #[test]
    fn changing_selection_clears_entered_values() {
        let mut st = CommandPanelState::default();
        let (bi, ci) = find_command_with_inputs(1).expect("one-input command");
        st.selected_bucket = bi;
        st.selected_command = ci;
        st.begin_input();
        st.push_char('x');
        st.next_command();
        assert!(st.input_values.is_empty(), "stale value survived a selection change");
        assert!(!st.is_editing());
    }

    #[test]
    fn backspace_removes_the_last_character() {
        let mut st = CommandPanelState::default();
        let (bi, ci) = find_command_with_inputs(1).expect("one-input command");
        st.selected_bucket = bi;
        st.selected_command = ci;
        st.begin_input();
        for ch in "abc".chars() {
            st.push_char(ch);
        }
        st.pop_char();
        assert_eq!(st.input_values[0], "ab");
    }

    #[test]
    fn cancel_leaves_edit_mode_without_running() {
        let mut st = CommandPanelState::default();
        let (bi, ci) = find_command_with_inputs(1).expect("one-input command");
        st.selected_bucket = bi;
        st.selected_command = ci;
        st.begin_input();
        st.cancel_input();
        assert!(!st.is_editing());
    }

}
