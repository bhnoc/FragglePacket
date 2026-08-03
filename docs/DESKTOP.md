# Desktop GUI

Binary `fraggle-desktop` built from `src/bin/desktop/main.rs`. Framework is Dioxus 0.6 desktop with Tokio for async tasks. Launch through `./start.sh`, `./start.sh --desktop`, or the binary directly.

## Panel map

`PanelId::all()` lists the tabs shown in the main tab bar:

| Panel | Role |
| --- | --- |
| Dashboard | Target picker, summary cards, quick runs |
| Tests | Runs NetworkTest categories, renders HTTPS and Path results inline |
| Probes | DSL Demo, PCAP Replay, Active PMTU Probe, Scenario Runner, Prometheus Metrics |
| Report | README_FIRST-style unified report rendered from `DiagnosisEngine` |
| Fuzzing | FuzzMode selector and PCAP output controls |
| Simulator | What-if MTU math plus VPN overhead calculator |
| Logs | Live log stream with levels and CLI command hints |
| History | Past results keyed by target |

Additional `PanelId` values exist but are not on the main tab bar:

* HTTPS, Path, VPN Calculator, Targets: integrated into the tabs above.

## Dashboard

Pulls from `AppState.targets`, categorised by `TargetCategory` (DNS, Cloud Providers, Microsoft 365, Collaboration, Dev Tools, CDN, Custom). Users can queue a single target or run all selected tests.

## Tests panel

Shows the registered tests from `test_registration::register_all_tests`. Each run spawns a Tokio blocking task that consumes a `TestOrchestrator`. Updates arrive over a coroutine channel:

| Update | Effect |
| --- | --- |
| Started | Toggles the testing flag, logs the start banner |
| Result | Stores a `TestResult`, surfaces metrics and diagnoses, adds log entry with optional `cli_command` |
| Progress | Drives the progress bar |
| Completed | Clears the testing flag |
| Failed | Adds an error log and toast |

## Probes panel

`src/bin/desktop/components/probes_panel/mod.rs` contains five cards:

| Card | Action |
| --- | --- |
| DSL Demo | Renders a summary and hexdump using `fuzzing::dsl` |
| PCAP Replay | Calls `fuzzing::replay::replay_pcap`; disabled when not privileged |
| Active PMTU Probe | Calls `fuzzing::probe::active_pmtu_probe`; disabled when not privileged |
| Scenario Runner | Parses the text area via `Scenario::parse` and runs each step |
| Prometheus Metrics | Starts `framework::metrics::serve` on a user-supplied bind address |

Privilege-gated cards replace their primary button with a toast hint instead of silently failing.

## Report panel

Calls the same path as the `fraggle-packet report` subcommand: runs HTTPS, upload sweep, SSH, and printer tests, feeds results into `DiagnosisEngine`, and displays the `render_unified_report` output.

## Fuzzing panel

Lets the user pick a FuzzMode and PCAP path, then invokes the NetworkTest wrapper. Output file name and packet count surface back via the log panel.

## Simulator and VPN calculator

Pure numeric tools over the VPN overhead constants defined in `main.rs`. No network traffic.

## Logs and History

* Logs capture every `AppState::log()` call. Entries carry `LogLevel`, timestamp, optional CLI command, metrics, and freeform details.
* History buckets results per target and per test for quick comparison.

## Detach and reattach

`window_manager.rs` uses a `GlobalSignal<HashSet<PanelId>>` named `DETACHED_PANELS`.

* Each header shows a detach button outside detached context.
* Clicking detach inserts the PanelId into `DETACHED_PANELS`, spawns a fresh Dioxus desktop window sharing the same global state, and hides the panel from the main window.
* The detached window header shows a reattach button. Clicking it clears the PanelId from `DETACHED_PANELS` via the mpsc reattach channel, letting the main window re-render the panel.
* Closing a detached window sends the same reattach signal automatically.

## Privileges banner

`state::mod::detect_privileged()` calls `fuzzing::is_root` once on startup. Results populate:

| Field | Default when privileged | Default otherwise |
| --- | --- | --- |
| `is_privileged` | true | false |
| `disabled_features` | empty | `["PCAP Replay", "Active PMTU Probe", "Packet Capture"]` |

A startup hook logs the warning and fires a toast. The header renders a ROOT badge when privileged, USER otherwise. A dismissible banner below the tab bar lists disabled features and prints the platform-specific relaunch hint:

| OS | Hint |
| --- | --- |
| Linux | `sudo setcap cap_net_raw,cap_net_admin+eip ./target/release/fraggle-desktop` |
| macOS | `sudo ./target/release/fraggle-desktop` |
| Other | Relaunch the application as administrator |

## Keyboard behavior

Dioxus desktop hands keyboard events to the native OS webview. The app does not install global shortcuts. Focus lives in the active input or button, so Tab navigates inputs, Enter activates buttons, and Escape is handled by the OS. Detached windows inherit OS-level close shortcuts (Command-W on macOS, Alt-F4 on Linux).
