# Terminal UI

Binary `fraggle-packet tui` backed by ratatui and crossterm. Render loop lives in `src/bin/tui/app.rs`. Panels split out into `dashboard.rs`, `test_panel.rs`, `fuzzing_panel.rs`, and `https_panel.rs`.

Launch either way:

```bash
./start.sh --tui
./target/release/fraggle-packet tui
```

## Modes

`AppMode` variants cycle through these screens:

| Mode | Screen |
| --- | --- |
| Dashboard | Target list with MTU columns and a sparkline |
| TargetDetail | Per-target detail including hops |
| TestPanel | Framework tests with ten category slots |
| HttpsPanel | HTTPS staged timings plus diagnosis |
| FuzzingPanel | FuzzMode selector and output path |
| Simulator | MTU what-if calculator |
| Help | Keybinding reference |

## Keybindings

Bindings are global unless noted. Mode prefix appears in brackets.

| Key | Effect |
| --- | --- |
| q | Quit |
| ? | Toggle help screen |
| T | Open Test Panel |
| H | Open HTTPS Panel |
| F or f | Open Fuzzing Panel |
| 1 to 9, 0 | TestPanel: select category 1 through 10 (1 DNS, 2 MTU, ...). Dashboard: 1 and 2 jump to test panel and detail, 3 opens Simulator |
| Tab | TestPanel: toggle category inclusion in the batch |
| Enter | Dashboard: open target detail. TestPanel: run selected. HttpsPanel and FuzzingPanel: run highlighted entry |
| A or a | Run all on the current target in the active panel (TestPanel, FuzzingPanel, HttpsPanel) |
| Up, k | Move selection up |
| Down, j | Move selection down |
| PageUp, PageDown | Scroll lists or popup text |
| Left, Right | Simulator: adjust MTU by 10 |
| r | Re-run a single target test |
| R | Re-run all |
| s | Stop running tests |
| t | Run tracepath for the selected target |
| c | Collapse and expand detail panels |
| Esc | Return to Dashboard from any subpanel |

## Tracepath behavior

Pressing `t` shells out to `sudo tracepath -n <target>`. Output streams line by line into the popup. Linux distributions with passwordless sudo run silently. Other setups prompt on the controlling terminal; crossterm raw mode is temporarily relaxed while sudo is in foreground. There is no prior privilege check, so without sudo the command fails and the popup shows the error text.

## Test registration

`src/bin/tui/test_registration.rs` registers the full NetworkTest set, equivalent to the desktop registration. The TUI builds its own `TestOrchestrator` per panel action rather than reusing one across sessions.

## Theme

The retro phosphor palette in `colors.rs` defines `TERM_GREEN`, `TERM_GREEN_DIM`, `TERM_AMBER`, `TERM_RED`, `TERM_BLACK`, `TERM_CYAN`. Widgets use these directly; there is no theme switcher.
