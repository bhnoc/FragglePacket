# FragglePacket

FragglePacket is a Rust network diagnostics suite that combines active path probing, packet fuzzing, PCAP replay, staged HTTPS analysis, and a rule-based diagnosis engine behind a CLI, a terminal UI, and a Dioxus desktop GUI.

## Features

### Network tests

Ten test categories drive the framework. Each category holds one or more `NetworkTest` implementations.

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

| Subcommand | Purpose |
| --- | --- |
| `tui` | Launch the terminal UI (also default when no subcommand given) |
| `diagnose <target> [-p PORT]` | Six-step DNS, ICMP, TCP, MTU, HTTPS diagnostic |
| `https <target> [-T SECS] [-d]` | Staged HTTPS probe, optional diagnosis engine output |
| `multi <targets>` | Comma-separated MTU comparison |
| `vpn <type> [-b MTU]` | Tunnel MTU calculator; `vpn list` prints the catalog |
| `quick <target>` | ICMP-only MTU with stability check |
| `fuzz <target> [-o OUTPUT] [-m MODE]` | Write a fuzzing PCAP |
| `test <target> [-c CATEGORIES] [-n COUNT] [-v]` | Run framework tests |
| `tcp <host:port>` | TCP-based MTU discovery |
| `kitchen-sink [--max N] [--json] [--output FILE]` | Comprehensive sweep across targets.txt |
| `upload-sweep <target> [-p PORT]` | HTTP(S) upload size sweep |
| `ssh-path <target> [-p PORT] [-u USER]` | SSH banner plus optional exec data-path |
| `printer-raw <target> [-p PORT]` | JetDirect PJL and bulk sweep on port 9100 |
| `tcp-options <target> [-p PORT]` | Negotiated MSS and middlebox rewrite detection |
| `quic <target> [-p PORT]` | QUIC PMTU probe |
| `dns-secure <target>` | UDP vs DoH vs DoT comparison |
| `report <target>` | README_FIRST style unified report |
| `replay <pcap> [--iface I] [--pps N] [--loop-count N] [--rewrite-dst-ip IP] [--rewrite-src-ip IP]` | PCAP wire replay |
| `probe <target> --iface I [--min N] [--max N]` | Active DSL-driven PMTU probe |
| `scenario <file>` | Run a scenario file or stdin with `-` |
| `serve [-b ADDR] [-t TARGET]` | Prometheus scrape endpoint |
| `dsl-demo [-d IP] [-p PORT] [--size N]` | Hexdump a DSL-built packet |

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
| [docs/CANARY.md](docs/CANARY.md) | Peer-impact companion TUI (`scripts/canary`) |
