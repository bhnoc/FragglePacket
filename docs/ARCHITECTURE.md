# Architecture

## Crate shape

Two binaries share one library crate.

| Artifact | Path | Purpose |
| --- | --- | --- |
| `fraggle-packet` | `main.rs` | CLI plus ratatui TUI |
| `fraggle-desktop` | `src/bin/desktop/main.rs` | Dioxus 0.6 desktop GUI |
| `fraggle_packet` library | `src/lib.rs` | Framework, fuzzing, diagnosis, network_tests |

## Module map

```
src/
├── lib.rs
├── framework/
│   ├── test_trait.rs      NetworkTest trait, TestCategory enum
│   ├── result.rs          TestResult, TestStatus, Diagnosis
│   ├── orchestrator.rs    TestOrchestrator, run_single/run_all/run_category
│   └── metrics.rs         MetricsRegistry + serve (HTTP/1.1 Prometheus text)
├── network_tests/         NetworkTest implementations, scenario parser
├── fuzzing/
│   ├── context.rs         PacketContext (src/dst + baseline layers)
│   ├── builder.rs         etherparse builder helpers
│   ├── writer.rs          PcapWriter wrapping pcap-file
│   ├── fuzzers/           per-mode fuzz generators
│   ├── dsl.rs             Scapy-style layer DSL (Ether/Ip/Tcp/Udp/Icmp/Raw)
│   ├── capture.rs         AF_PACKET and BPF capture with FilterFn
│   ├── replay.rs          PCAP wire replay via AF_PACKET / IP_HDRINCL
│   ├── probe.rs           send_and_wait + active_pmtu_probe
│   └── cli.rs             CLI helpers for the fuzz subcommand
├── diagnosis/mod.rs       Rules, engine, render_unified_report
└── bin/
    ├── cli/               fuzzing.rs, test_cmd.rs, helpers used by main.rs
    ├── tui/               Ratatui panels, test_registration.rs
    └── desktop/           Dioxus app, panels, state, window_manager
```

## Framework traits

### NetworkTest

```rust
pub trait NetworkTest: Send + Sync {
    fn name(&self) -> &str;
    fn category(&self) -> TestCategory;
    fn run(&self, target: &str) -> Result<TestResult, Box<dyn Error>>;
    fn requires_root(&self) -> bool { false }
    fn estimated_duration(&self) -> u64 { 5 }
}
```

Implementations live in `src/network_tests/*`. Each returns a populated `TestResult`. None of the current impls opt into `requires_root = true`; raw-socket work sits inside the fuzzing engine instead.

### TestCategory

```rust
pub enum TestCategory {
    MTU, RTT, PacketLoss, PathAnalysis, TCPHealth,
    DNS, HTTPS, IPv6, Application, Fuzzing,
}
```

Ten variants. `TestCategory::all()` returns them in declaration order. `as_str()` provides display labels used across CLI, TUI, and desktop UIs. Serde impls round-trip using the string form.

### TestResult

```rust
pub struct TestResult {
    pub name: String,
    pub category: TestCategory,
    pub target: String,
    pub status: TestStatus,
    pub metrics: HashMap<String, f64>,
    pub metadata: HashMap<String, String>,
    pub diagnoses: Vec<Diagnosis>,
    pub duration: Duration,
    pub timestamp: u64,
}
```

Metadata carries free-form strings, including `cli_command` hints that the desktop UI surfaces in its log view. Metrics are numeric. `Diagnosis` entries hang off `diagnoses` so rule-based findings travel with the result.

### TestStatus

`Pending`, `Running`, `Success`, `Warning`, `Failed`, `Skipped`.

### Diagnosis

```rust
pub struct Diagnosis {
    pub severity: DiagnosisSeverity, // Info, Warning, Error, Critical
    pub title: String,
    pub description: String,
    pub recommendations: Vec<String>,
    pub related_tests: Vec<String>,
}
```

Separate from the diagnosis engine in `src/diagnosis/mod.rs`, which defines its own `Diagnosis`, `Severity`, and `DiagnosisEvidence` types oriented around cross-test correlation. Both coexist today.

## TestOrchestrator flow

`TestOrchestrator` holds `Vec<Box<dyn NetworkTest>>` and `HashMap<target, HashMap<TestCategory, TestResult>>` behind a `Mutex`.

Execution path for `run_single`:

1. Measure `Instant::now`
2. If `test.requires_root()` and `geteuid != 0`, record a Skipped result with `metadata.skip_reason`
3. Otherwise call `test.run(target)`; on `Err`, build a Failed result with `metadata.error`
4. Stamp `result.duration`, store into the results map, return a clone

`run_all` and `run_category` iterate through the registered tests, calling `run_single` for each. Both return `Vec<TestResult>`.

Results are keyed by target then category, so storing a second result in the same category overwrites the first. This intentionally treats re-runs as refresh.

## Result flow from orchestrator to UI

### CLI

`fraggle-packet test <target>` builds a fresh orchestrator, registers per-category tests from `--categories`, calls `run_all`, then prints colored blocks per result plus a summary. Upload, SSH, printer, TCP options, QUIC, and DNS-secure subcommands instantiate the test struct directly and feed it through `print_test_result`, without touching the orchestrator.

### TUI

`src/bin/tui/test_panel.rs` runs tests in a worker thread, sends results back through an `mpsc::Sender<TestUpdate>`. The render loop reads the latest state and paints ratatui widgets. Framework results are cached in `App.framework_results: HashMap<String, Vec<TestResult>>`.

### Desktop

`src/bin/desktop/state/test_runner.rs` runs tests in a Tokio blocking task. Each status change emits a `TestUpdate` variant over a Dioxus coroutine channel:

| Variant | Carries |
| --- | --- |
| `Started` | target, optional category |
| `Result` | `TestResult` (stored into `AppState.results`) |
| `Progress` | f64 0 to 1 |
| `Completed` | target |
| `Failed` | target, error string |

The main `App` component consumes updates in `use_coroutine`, writes state signals, adds log entries, and pushes toasts. Panels subscribe to the state signal and re-render. Detached windows spawn fresh VirtualDoms that observe the same global `DETACHED_PANELS` signal.

## Scenario runner

`src/network_tests/scenario.rs` parses the declarative format, maps each step `kind` to a `NetworkTest` constructor, calls `run`, and returns `Vec<(name, Result<TestResult, String>)>`. Syntax details in [SCENARIOS.md](SCENARIOS.md).

## Diagnosis engine

`DiagnosisEngine::new()` pre-registers eight rules. `diagnose(&DiagnosisEvidence)` runs each rule, collects `Some(Diagnosis)` returns, sorts by severity descending. `render_unified_report` produces the shell-parity `README_FIRST` text output including `LIKELY_MTU_OR_MSS_BLACKHOLE`, `SUGGESTED_BASE_MSS_IPV4`, and `SUGGESTED_CONSERVATIVE_CLAMP` lines.

## Metrics exporter

`MetricsRegistry` stores `HashMap<String, f64>` gauges plus an optional `HashMap<String, String>` of `# HELP` texts. `serve(registry, addr)` binds a `TcpListener`, answers any request with a full snapshot in Prometheus 0.0.4 text format. Intended for scraping with curl or Prometheus; not a full server.

## Native packet engine

The replay, capture, and active-probe modules sit below the test framework.

* `fuzzing::dsl` defines `Layer`, `Packet`, and `Div` operator so `Ether::new() / Ip::new().df() / Tcp::new().syn() / Raw::of_size(32, b'X')` yields a `Packet` serializable with `build()` and printable with `summary()` and `hexdump()`.
* `fuzzing::replay::replay_pcap` reads a PCAP, optionally rewrites MAC or IPv4 source/destination, and writes via a per-platform `RawSender`.
* `fuzzing::capture::start_capture` opens AF_PACKET (Linux) or BPF (macOS) and pushes matching frames through an mpsc channel using a userspace `FilterFn`.
* `fuzzing::probe::send_and_wait` pairs capture with replay to yield scapy `sr1()` semantics.
* `fuzzing::probe::active_pmtu_probe` binary-searches DF pings at the DSL level and watches for ICMP type 3 code 4.

## Dependencies worth knowing

| Crate | Role |
| --- | --- |
| `clap` | CLI parsing |
| `rayon` | Parallel kitchen-sink tests |
| `tokio`, `quinn`, `rustls`, `rcgen` | QUIC PMTU probing |
| `etherparse` | Packet build and parse |
| `pcap-file` 3.0.0-rc1 | PCAP read and write |
| `libc` | Raw socket syscalls |
| `ratatui`, `crossterm` | TUI |
| `dioxus` 0.6 desktop | Desktop GUI |
| `rfd` | Native file dialogs |
| `native-tls` | HTTPS TLS client |
| `thiserror` | Error enums in fuzzing |
