# FragglePacket

FragglePacket is a Rust network diagnostics suite that combines active path probing, packet fuzzing, PCAP replay, staged HTTPS analysis, and a rule-based diagnosis engine behind a CLI, a terminal UI, and a Dioxus desktop GUI.

**79 subcommands**, 56 of which close a specific gap found during real network investigations. **1032 harness checks** gate the behaviour.

The design rule everything else follows: *a figure that cannot be substantiated is withheld, not printed with a caveat.* A silent probe is missing evidence, never a passing result; two sources that disagree produce a finding rather than a winner; and a figure derived from a stale input is not reported as current. See [docs/TESTS.md](docs/TESTS.md) for the full capability map, including [what this tool deliberately cannot do](docs/TESTS.md#what-this-tool-deliberately-cannot-do).

## Features

### Network tests

Ten test categories drive the legacy in-process framework (`fraggle-packet test`). Each category holds one or more `NetworkTest` implementations. The gap-closing subcommands listed in [docs/TESTS.md](docs/TESTS.md) are separate from and larger than this set.

| Category | What it covers |
| --- | --- |
| MTU | ICMP and TCP MSS discovery, QUIC PMTU, tunnel MSS clamping analysis |
| RTT | Round-trip latency sampling via ping with min/avg/max/stddev parsing |
| PacketLoss | Loss percentage from fast-interval pings, burst detection |
| PathAnalysis | Traceroute style per-hop latency and MTU inspection |
| TCPHealth | Handshake timing, TCP options echo, segmentation detection |
| DNS | Plain resolution, DoH and DoT comparison against UDP |
| HTTPS | Staged DNS, TCP, TLS, HTTP request, TTFB probe with blackhole detection |
| IPv6 | AAAA lookup and IPv6 reachability comparison |
| Application | ALPN detection, HTTP/2 vs HTTP/3, raw JetDirect bulk sweep, SSH data-path |
| Fuzzing | PCAP campaigns driven by the RustPacketFuzz engine |

Full catalog in [docs/TESTS.md](docs/TESTS.md).

### Packet fuzzing modes

Five modes emit PCAP files for offline replay, IDS testing, or wire replay.

| Mode | Focus |
| --- | --- |
| SegmentSize | TCP segment sizes across the 0 to 65535 range |
| LengthMismatch | Heartbleed-style header length lies |
| TcpOptions | Malformed MSS, SACK, and window-scale options |
| Fragmentation | Edge-case IPv4 fragment offsets, overlaps, DF combos |
| Checksum | Valid and corrupt IP, TCP, UDP checksums |

### Active probes, PCAP replay, capture

Native engine built on `etherparse` and `pcap-file`. No `tcpreplay`, `hping3`, or `nping` required.

* Packet DSL composes layers with `/` in scapy style
* PCAP replay sends on the wire using AF_PACKET on Linux, IP_HDRINCL raw sockets on macOS and FreeBSD
* Passive capture reads from AF_PACKET with userspace filter callbacks
* Active PMTU probe binary-searches DF pings and watches for ICMP fragmentation-needed

Details in [docs/FUZZING.md](docs/FUZZING.md).

### Scenario runner

Declarative key-value step format. Each step names a `kind` (https, upload_sweep, ssh, printer, quic, dns_secure, tcp_options) and a target. Runs sequentially through the same `NetworkTest` trait. See [docs/SCENARIOS.md](docs/SCENARIOS.md).

### Prometheus metrics exporter

Hand-rolled HTTP/1.1 server exposes a `/metrics` endpoint using the 0.0.4 text format. Default bind is `127.0.0.1:9464`. The `serve` subcommand can seed the registry from a single upload-sweep run. See [docs/METRICS.md](docs/METRICS.md).

### Diagnosis engine

Eight rules correlate evidence and produce severity-ranked `Diagnosis` records.

| Rule | Signal |
| --- | --- |
| MtuBlackholeRule | TCP ok, TLS timeout, interface MTU 1500 |
| PathMtuMismatchRule | ICMP path MTU lower than interface by more than 50 |
| PortBlockingRule | Ping ok, TCP connect fails |
| DnsIssuesRule | DNS failure or resolution over 1000 ms |
| TcpSegmentationLimitRule | Negotiated segment under 1000 bytes |
| HighPacketLossRule | Loss at or above 1 percent |
| HighLatencyRule | RTT over 200 ms |
| BlackholeScoreRule | Aggregated heuristic score across probes |

Engine and evidence schema live in `src/diagnosis/mod.rs`.

### Terminal UI

Ratatui-based retro phosphor-green dashboard. Panels cover Dashboard, Tests, HTTPS stage view, Fuzzing, and Help. Keybindings in [docs/TUI.md](docs/TUI.md).

### Desktop GUI

Dioxus 0.6 desktop app with detachable panels. Dashboard, Tests, Probes, Report, Fuzzing, Simulator, Logs, History tabs. The app detects missing root at launch and banners any disabled raw-socket features. Layout and behavior in [docs/DESKTOP.md](docs/DESKTOP.md).

## Supported platforms

| Platform | Status |
| --- | --- |
| Ubuntu 22.04 or newer | Supported |
| Debian 12 or newer | Supported |
| macOS (recent) | Supported |
| Older Ubuntu or Debian | Not supported |
| Windows | Best effort, raw socket features unavailable |

The `setup.sh` dependency list targets the newer `libwebkit2gtk-4.1-dev` and `libayatana-appindicator3-dev` packages. Older LTS releases ship the 4.0 webkit and appindicator3 packages which will not satisfy the build.

See [docs/PLATFORMS.md](docs/PLATFORMS.md) for per-OS feature matrix.

## Quickstart

```bash
./setup.sh       # install deps, build release binaries
./start.sh       # launches the desktop GUI by default
./start.sh --tui # launches the terminal UI
```

`start.sh` rebuilds release binaries when Rust sources are newer, and falls back
to the TUI if the desktop binary is missing.

## start.sh flags

| Flag | Action |
| --- | --- |
| (no args) | Launch desktop GUI (falls back to TUI if missing) |
| `-d`, `--desktop` | Launch desktop GUI |
| `-t`, `--tui` | Launch terminal UI |
| `-1`, `--quick [TARGET]` | Quick ICMP test, default 8.8.8.8 |
| `-2`, `--diagnose [TARGET]` | Full diagnostic, default github.com |
| `-3`, `--multi [TARGETS]` | Multi-target comparison, comma separated |
| `-4`, `--vpn [TYPE]` | VPN/SASE MTU calculator, default zscaler |
| `-5`, `--tcp [HOST:PORT]` | TCP-only MTU discovery |
| `-6`, `--test [CATEGORY] [TARGET]` | Run a single test category |
| `-7`, `--test-all [TARGET]` | Run all registered tests |
| `-8`, `--https [TARGET]` | HTTPS stage-by-stage analysis |
| `-9`, `--list-vpn` | List supported VPN types |
| `-10`, `--kitchen-sink` | Run the comprehensive MTU sweep |
| `-11`, `--json` | Kitchen-sink with timestamped JSON in reports/ |
| `-f`, `--fuzz [MODE] [OUTPUT]` | Run a fuzzing campaign |
| `-h`, `--help` | Show help |

## fraggle-packet CLI subcommands

79 subcommands. Names and one-line purposes below come straight from
`fraggle-packet --help`; per-flag detail is in [docs/CLI.md](docs/CLI.md) and each
subcommand's own `--help`.

### Core and utility (23)

| Subcommand | Purpose |
| --- | --- |
| `diagnose` | Full diagnostic against a hostname (DNS, TCP, HTTP, ICMP comparison) |
| `dns-secure` | DoH/DoT vs plain DNS comparison |
| `dsl-demo` | Print a hexdump of a packet described by our DSL (demo helper) |
| `endpoints` | Known iperf3 endpoints and the ports recorded as failing, so a known-bad endpoint is never retried or scored as zero throughput |
| `fuzz` | Packet fuzzing for security testing |
| `https` | Test HTTPS connectivity with stage-by-stage analysis (MTU blackhole detection) |
| `kitchen-sink` | Run all tests against common targets and give final verdict |
| `multi` | Test multiple targets and compare path MTUs |
| `printer-raw` | Raw JetDirect port 9100 PJL + bulk size sweep |
| `probe` | Active MTU probe using the native DSL + send-and-capture engine |
| `quic` | QUIC/UDP PMTUD probe |
| `quick` | Quick ICMP-only MTU test |
| `replay` | Replay a PCAP file onto the wire (requires root) |
| `report` | Render a unified README_FIRST-style diagnosis of a target |
| `scenario` | Run a declarative scenario from a file or stdin |
| `serve` | Expose a Prometheus metrics scrape endpoint |
| `ssh-path` | SSH banner + optional authenticated echo data-path test |
| `tcp` | TCP-based MTU discovery (no ICMP required) |
| `tcp-options` | Query actual negotiated TCP MSS and detect middlebox rewriting |
| `test` | Run test framework tests (DNS, HTTPS, TCP, RTT, Loss) |
| `tui` | Launch interactive TUI |
| `upload-sweep` | HTTP(S) upload size sweep (detects data-stall blackholes) |
| `vpn` | Calculate safe MTU for VPN/SASE/Zero-Trust usage |

### Gap-closing (56)

Each closes a numbered gap from a real investigation and carries that gap's
acceptance criteria as its contract. Grouped by area; the gap number in each
description is the authoritative reference.

| Subcommand | Purpose |
| --- | --- |
| `admission-fanout` | Barrier-synchronized public-listener admission fanout: never reports a listener that never admitted as zero throughput (GAP-045) |
| `ap-compat-matrix` | AP-generation/radio-mode/client-capability compatibility matrix; refuses a verdict until required comparison cells are present (GAP-037) |
| `ap-identity` | Stable, privacy-safe salted AP/radio identity derived from BSSID without storing or displaying it (GAP-024) |
| `auth-portal` | Authentication/captive-portal/policy-assignment workflow: separately timed phases, portal detection without login automation (GAP-049) |
| `bufferbloat` | Idle/upload-loaded/download-loaded/simultaneous latency via networkQuality (GAP-002) |
| `burst-analysis` | Bounded burst-loss/reordering/duplication/jitter probe with queue-delay correlation (GAP-066) |
| `capacity-knee` | Capacity/latency-knee discovery: distinguishes a capacity plateau from directional unfairness and withholds an established claim without cross-method reproduction (GAP-070) |
| `capture` | Bounded packet capture with duration/size caps and safe privilege handoff (GAP-007) |
| `circuit-compare` | Compare WAN A-only, B-only, and dual-active phases from an operator manifest; never changes routing (GAP-029) |
| `clock-guard` | Synchronized clock verification: NTP offset with uncertainty, gated against a configured skew threshold, before permitting a one-way delay claim (GAP-064) |
| `counter-deltas` | Normalized, qualified per-phase interface-counter deltas (GAP-031) |
| `counter-liveness` | Bracket a known packet stimulus to prove a counter is live, and refuse a zero-drop verdict without corroboration (GAP-043) |
| `dependency-health` | Infrastructure dependency health bundle: DNS/NTP/cert/OCSP/controller checks distinguishing blocked-by-policy from unhealthy (GAP-059) |
| `dhcp-lifecycle` | DHCP address-lifecycle and pool-capacity test: safe existing-lease read by default, authorization-gated fresh-lease test (GAP-048) |
| `dns-steering` | Compare A/AAAA/HTTPS/SVCB answers across resolvers to detect steering divergence (GAP-014) |
| `ecmp-nat` | Multi-uplink ECMP/LAG hash and NAT-affinity diagnostic via fixed-5-tuple port sweeps (GAP-028) |
| `ecn-aqm` | ECN/AQM capability and CE-mark counting with classic-ECN-vs-L4S distinction (GAP-023) |
| `first-hop` | First-hop gateway isolation with non-ICMP fallback when echo is suppressed (GAP-022) |
| `fleet-orchestrator` | Distributed wireless-probe fleet orchestrator: management/test-node separation, redacted labels, bounded fanout (GAP-038) |
| `flow-dscp-matrix` | Constant-aggregate flow-count sweep with DSCP marking-survival qualification (GAP-034) |
| `gateway-bracket` | Pair idle/upload/download/simultaneous load phases with a first-hop gateway RTT/loss bracket (GAP-044) |
| `independent-rates` | Independently rate-controlled, time-aligned simultaneous upload/download sweep (GAP-032) |
| `iperf-analyze` | Version/direction-aware iperf3 JSON parsing and explicit-allowlist endpoint capability discovery (GAP-039/GAP-036) |
| `ipv6-validate` | Decomposed IPv6/NAT64/DNS64 validation with separate IPv4 and IPv6 verdicts, plus Happy Eyeballs timing (GAP-056/GAP-015) |
| `listener-lease` | Authorized-only listener leasing with per-transport capacity/duration qualification and endpoint loss-floor declaration (GAP-040) |
| `load-guard` | Run a budget-guarded, radio-monitored load phase (GAP-027/GAP-047) |
| `media-quality` | Synthetic RTP/WebRTC media-quality probe: setup/ICE, burst-derived concealment/freeze risk, MOS-style estimate (GAP-052) |
| `mss-evidence` | SYN/SYN-ACK MSS evidence (local/peer/middlebox) and multi-destination MSS clustering vs route MTU (GAP-010/GAP-026) |
| `multicast-isolation` | Discovery/multicast/peer-isolation policy diagnostic: declared expected-reachable/expected-blocked verdicts, name-free responder tallies (GAP-057) |
| `multiclient-fairness` | Coordinated multi-client capacity/fairness: refuses a cross-client verdict until both role descriptors exist and their phase windows overlap (GAP-051/GAP-072) |
| `nat-capacity` | Firewall/NAT/session-state capacity matrix: authorization-gated disruptive probing, safe-by-default idle-mapping observation (GAP-054) |
| `pcap-report` | Analyze a PCAP/pcapng capture: vantage point, capture health, qualified MTU/loss verdicts (GAP-019) |
| `phy-normalized` | PHY-normalized fleet comparison: offered load as a fraction of each client's own PHY capacity (GAP-042) |
| `platform-matrix` | Privacy-safe cross-platform/power-save capability matrix with confound-aware attribution (GAP-063) |
| `policy-manifest` | Expected-policy and service-reachability manifest: probes only allowlisted targets and flags drift from declared allow/deny policy (GAP-065) |
| `preflight` | Preflight ALPN/Alt-Svc + real handshake capability across endpoints (GAP-025) |
| `privilege-status` | Privileged-operation inventory and failure classification: preserve the error, name the exact command, offer an unprivileged path (GAP-016) |
| `probe-preflight` | Remote probe health/dependency preflight: quarantines broken binaries, timeouts, and changed SSH host keys with no auto-accept path (GAP-041) |
| `probe-rate` | Detect ICMP rate-limiting/batching artifacts by comparing normal vs elevated probe cadence (GAP-021) |
| `process-model` | Process-model equivalence and receive-path artifact guard: withholds a directional-collapse verdict unless it reproduces across native-bidir and paired-process methods (GAP-069) |
| `protocol-compare` | Controlled H1/H2/H3 comparison with directional vs simultaneous isolation (GAP-003/GAP-004) |
| `provider-path` | Provider/geography/path-stability comparison with non-response distinguished from loss (GAP-061) |
| `radio-diagnostic` | Wi-Fi radio/retry diagnostic with safe elevation and explicit platform-limitation reporting (GAP-011) |
| `reference-endpoint` | Reference-endpoint calibration and client-result acceptance: the endpoint can invalidate a client's measurement (GAP-053) |
| `resilience` | Controlled resilience/failover validation: observes and labels an operator-performed component change, never initiates one (GAP-062) |
| `rf-survey` | Bounded time-series RF survey with platform-limited metric qualification and change-point correlation (GAP-055) |
| `roaming` | Controlled roaming/session-continuity test: privacy-safe AP transitions, handoff duration, and VLAN/public-identity continuity (GAP-050) |
| `second-network` | Second-network control workflow: save/compare a connection fingerprint and test bundle across a network switch (GAP-013) |
| `site-ab` | Affected-site vs known-good-control A/B workflow: forced protocol, IP pinning, repeated samples, redirect-aware verdict (GAP-012) |
| `size-rate-matrix` | Datagram-size/packet-rate pressure matrix distinguishing packet-rate ceilings from byte-rate policing (GAP-033) |
| `stun-turn` | Repeated STUN binding requests with validation/RTT, mapped-address change detection, and TURN allocation checks (GAP-005) |
| `tcp-vs-udp` | Controlled TCP-versus-UDP throughput/loss comparison against a user-supplied endpoint (GAP-006) |
| `throughput-tuner` | Version-aware maximum-throughput tuner: randomized trials, duration validation, synthetic-max vs representative-application split (GAP-046) |
| `vpn-matrix` | VPN/encapsulation compatibility matrix: credential-free protocol reachability and real effective MTU/MSS measurement (GAP-060) |
| `wired-control` | Matched wired-versus-Wi-Fi fault-domain control: withholds WLAN attribution when the two paths' public egress identities differ (GAP-030) |
| `wired-edge` | Wired edge/AP-uplink/LLDP/PoE health bundle: read-only ingest, refuses a conclusion without telemetry (GAP-058) |

Shared top-level flags apply to the legacy MTU commands: `--target`, `--min`, `--max`, `--timeout-ms`, `--retries`. Full flag table in [docs/CLI.md](docs/CLI.md).

## Privileges

Most tests run unprivileged. A small set of features require raw sockets and therefore root or an equivalent capability on Linux.

| Feature | Root needed | Why |
| --- | --- | --- |
| Framework tests (DNS, HTTPS, RTT, Loss, TCP health, MSS, App, IPv6) | No | Use standard sockets or shell out to ping |
| `ping`-based ICMP paths | No | `iputils-ping` is typically setuid |
| `tracepath` in TUI | Yes (spawns sudo) | TUI shells out to `sudo tracepath` |
| PCAP replay (`replay`) | Yes | AF_PACKET on Linux, IP_HDRINCL on BSD/macOS |
| Active PMTU probe (`probe`) | Yes | Raw capture plus raw send |
| Passive capture (probe engine) | Yes | AF_PACKET socket open |

The desktop app detects elevation at startup by checking `geteuid` and displays a banner listing disabled features. On Linux you can grant capabilities once instead of running as root:

```bash
sudo setcap cap_net_raw,cap_net_admin+eip ./target/release/fraggle-desktop
```

The same approach works for the CLI binary.

## Project layout

```
.
├── Cargo.toml
├── main.rs                     # fraggle-packet CLI + TUI entry
├── setup.sh                    # Install deps and build
├── start.sh                    # Launcher (desktop default, --tui for TUI)
├── targets.txt                 # Default targets for kitchen-sink
├── src/
│   ├── lib.rs
│   ├── framework/              # NetworkTest trait, orchestrator, result, metrics
│   ├── network_tests/          # All NetworkTest impls
│   ├── fuzzing/                # Fuzzers, DSL, replay, capture, probe, writer
│   ├── diagnosis/              # Rules and report rendering
│   └── bin/
│       ├── cli/                # CLI subcommand helpers
│       ├── tui/                # Ratatui terminal UI
│       └── desktop/            # Dioxus desktop GUI
├── tests/                      # Integration tests
└── docs/                       # Documentation, see below
```

## Build, test, run

```bash
cargo build --release --bin fraggle-packet
cargo build --release --bin fraggle-desktop
cargo test
./target/release/fraggle-packet test github.com
./target/release/fraggle-desktop
```

## Continuous integration and test coverage

Automated test coverage and verification run in GitHub Actions on every pull request targeting `main` and on pushes to `main` via `.github/workflows/test.yml`. The workflow builds the release binaries, runs the 628-test suite, the `harness/smoke.sh` baseline checks, and the full offline `harness/acid.sh` ratchet, then generates LCOV coverage reports via `cargo-llvm-cov`. Formatting is advisory; tests, smoke, and acid all fail the build. See [docs/SETUP.md](docs/SETUP.md) for which steps gate and why.

## Documentation

| Page | Covers |
| --- | --- |
| [docs/INDEX.md](docs/INDEX.md) | Table of contents |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Modules, data flow, framework traits |
| [docs/TESTS.md](docs/TESTS.md) | Every NetworkTest impl, category, root needs |
| [docs/FUZZING.md](docs/FUZZING.md) | FuzzMode, DSL, PCAP writer, replay, capture, probe |
| [docs/CLI.md](docs/CLI.md) | Full CLI reference |
| [docs/DESKTOP.md](docs/DESKTOP.md) | Desktop panel map and behavior |
| [docs/TUI.md](docs/TUI.md) | TUI keybindings and panels |
| [docs/SETUP.md](docs/SETUP.md) | setup.sh per distro, verification, setcap |
| [docs/PLATFORMS.md](docs/PLATFORMS.md) | OS feature matrix |
| [docs/SCENARIOS.md](docs/SCENARIOS.md) | Scenario DSL syntax |
| [docs/METRICS.md](docs/METRICS.md) | Prometheus exporter |
