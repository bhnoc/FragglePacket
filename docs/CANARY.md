# Canary — peer-impact companion monitor

Canary is a curses TUI that runs the same UDP→TCP iperf3 load matrix as
[`scripts/bhusa-peer-impact-test.zsh`](../scripts/bhusa-peer-impact-test.zsh) on a
second client, so two machines can load an AP (or path) **at the same time** and
compare results side-by-side.

It calibrates on quiet gateway pings, waits for one ENTER to start, then runs
the suite immediately (no “wait until companion is done” gate). UDP and TCP are
scored separately so the mid-suite transport switch cannot skew a single
baseline.

## Requirements

| Need | Notes |
| --- | --- |
| macOS | Uses `/usr/sbin/ipconfig` and Apple `ping` flags |
| Interactive terminal | TUI requires a real TTY (≥80×24 recommended) |
| `iperf3` | On `PATH` |
| `python3` | 3.10+ recommended |
| Reachable iperf3 listeners | Separate upload + download ports |

## Quick start

```bash
# Terminal A — primary load client (existing harness)
IFACE=en0 SERVER=speedtest.example.com \
  MODE=load ./scripts/bhusa-peer-impact-test.zsh

# Terminal B — canary companion (this tool)
./scripts/canary --iface en0 --server speedtest.example.com
```

Flow on canary:

1. **Calibrate** (~60s) — gateway RTT baseline, metrics quiet afterward  
2. **ENTER** — start the peer-impact suite **now** (run alongside the companion)  
3. **Report** — tables on screen + `summary.txt` under a temp results dir  
4. **q** / Ctrl+C — quit (summary also prints to the terminal)

## Configuration

`--server` (or `SERVER`) is **required**. Ping defaults to the interface
**gateway**. Ports default to classic iperf3 `5201` / `5202`.

| Flag | Env | Default | Purpose |
| --- | --- | --- | --- |
| `--server` | `SERVER` | *(required)* | iperf3 host/IP |
| `--upload-port` | `UPLOAD_PORT` | `5201` | Forward/upload listener |
| `--download-port` | `DOWNLOAD_PORT` | `5202` | Reverse/download listener |
| `--iface` | `IFACE` | `en0` | Bind/source interface |
| `--ping-target` | `PING_TARGET` | iface gateway | Latency probe target |
| `--rate` | `RATE` | `350M` | UDP bitrate / aggregate intent |
| `--calibrate-seconds` | `CALIBRATE_SECONDS` | `60` | Quiet ping baseline |
| `--directional-seconds` | `DIRECTIONAL_SECONDS` | `7` | Upload-only / download-only |
| `--simultaneous-seconds` | `SIMULTANEOUS_SECONDS` | `12` | Bidirectional runs |
| `--tcp-parallel` | `TCP_PARALLEL` | `4` | TCP streams |
| `--tcp-rate-per-stream` | `TCP_RATE_PER_STREAM` | `87.5M` | Per-stream TCP pace |
| `--protoevidence` | — | off | Preset `test.protoevidence.com:443/444` |

Examples:

```bash
# Wired iface, custom listeners, ping stays on gateway
./scripts/canary --iface en19 --server 10.10.199.201 \
  --upload-port 5233 --download-port 5234

# Override ping target (still binds iperf to --iface)
./scripts/canary --iface en0 --server speedtest.example.com \
  --ping-target 1.1.1.1

# Env-style (matches peer-impact script conventions)
IFACE=en0 SERVER=speedtest.example.com UPLOAD_PORT=5201 DOWNLOAD_PORT=5202 \
  ./scripts/canary
```

Upload and download ports **must differ** so simultaneous up+down does not hit
one single-client iperf3 listener twice.

## What the TUI shows

| Panel | Meaning |
| --- | --- |
| Bird / status | Lifecycle: calibrate → armed → test → report |
| Ping graph | Live RTT to `--ping-target` (gateway by default) |
| 5s avg trend | ▲ red rising · ▶ yellow steady · ▼ green falling |
| iperf chart | Protocol-scoped throughput (UDP then TCP) |
| Packet loss counter | Per-run lost packets + % after each UDP/gateway step; cumulative `lostΣ` |
| This-is-fine dog | Appears under the bird when latency >50 ms, UDP loss >10%, or throughput <50 Mbps |
| Results panel | Full peer-impact tables when the suite finishes |

Evidence is written under a temp directory (`/tmp/bhusa-canary-r…`) including
`summary.txt`, per-phase JSON/stderr, and `timeline.tsv`.

## Pairing with `bhusa-peer-impact-test.zsh`

Recommended coordinated run:

1. Agree on the same iperf **server** and two **distinct** port pairs if both
   clients load the same listeners (one port pair per client), **or** use
   separate listener farms.
2. Start canary first; let it finish calibration so ENTER is ready.
3. Start the peer harness (`MODE=load` or `MODE=observe` as designed).
4. Hit **ENTER** on canary so both suites overlap in time.
5. Compare `summary.txt` outputs / report tables.

Canary always runs the **load** matrix (not observe-only). Use it when you want
a second aggressor with a live dashboard, not a silent observer.

## Security notes

- No lab server is hardcoded; you must name the iperf target.
- Host, interface, port, and rate strings are validated before subprocess use.
- Subprocesses use argv lists (`shell=False`).
- Temporary result directories are created via `tempfile.mkdtemp` with secure
  `0700` permissions so network evidence stays private to the local user.
- The tool generates real network load — only point it at listeners you own or
  are authorized to test.

## Tests

Offline unit/regression (no TUI, no live network):

```bash
python3 scripts/test_canary.py
```

## Files

| Path | Role |
| --- | --- |
| `scripts/canary.py` | TUI + suite implementation |
| `scripts/canary` | Thin launcher |
| `scripts/test_canary.py` | Config/parser/trend regression tests |
| `scripts/bhusa-peer-impact-test.zsh` | Original peer-impact harness (parity target) |
