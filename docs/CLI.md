# fraggle-packet CLI Reference

Enumeration matches the clap derive in `main.rs`. Global flags appear on the root `Args` struct and apply whenever a legacy ICMP/TCP subcommand consumes them. Running the binary with no subcommand launches the TUI.

## Global flags

| Flag | Default | Purpose |
| --- | --- | --- |
| `-t, --target <IP>` | none | Legacy quick-test target |
| `--min <N>` | 576 | Starting minimum MTU for binary search |
| `--max <N>` | 1500 | Starting maximum MTU (set 9000 for jumbo) |
| `-T, --timeout-ms <N>` | 2000 | Per-probe timeout in milliseconds |
| `-r, --retries <N>` | 2 | Retries per probe |

## Subcommands

### tui

Launches the ratatui interface. Same as running the binary with no args.

### diagnose

Full six-stage diagnostic against a hostname.

| Arg | Default | Notes |
| --- | --- | --- |
| `<TARGET>` | required | Hostname or IP |
| `-p, --port <N>` | 443 | TCP port to probe |

### https

HTTPS stage-by-stage analysis using the internal staged client.

| Arg | Default | Notes |
| --- | --- | --- |
| `<TARGET>` | required | Hostname |
| `-T, --timeout <SEC>` | 10 | Per-stage timeout seconds |
| `-d, --diagnose` | false | Run the diagnosis engine over the HTTPS result |

### multi

Compare PMTU across multiple comma-separated targets.

| Arg | Notes |
| --- | --- |
| `<TARGETS>` | Comma-separated hostnames or IPs |

### vpn

VPN and SASE overhead calculator. Pass `list` as the `vpn_type` to print all supported strings.

| Arg | Default | Notes |
| --- | --- | --- |
| `<VPN_TYPE>` | required | wireguard, openvpn-udp, ipsec, ikev2, zscaler, cloudflare, globalprotect, anyconnect, fortinet, gre, vxlan, geneve, plus `list` |
| `-b, --base-mtu <N>` | auto | Base MTU for the calculation; auto probes 8.8.8.8 |

### quick

Minimal ICMP-only MTU discovery.

| Arg | Notes |
| --- | --- |
| `<TARGET>` | IP address or hostname |

### fuzz

Runs a packet fuzzing campaign.

| Arg | Default | Notes |
| --- | --- | --- |
| `<TARGET>` | required | Hostname or IP |
| `-o, --output <PATH>` | `reports/fuzz.pcap` | PCAP output |
| `-m, --mode <MODE>` | `segment-size` | segment-size, length-mismatch, tcp-options, fragmentation, checksum |

### test

Runs the NetworkTest framework.

| Arg | Default | Notes |
| --- | --- | --- |
| `<TARGET>` | required | Hostname or IP |
| `-c, --categories <CSV>` | `all` | Comma-separated. Recognized: dns, https, tcp, rtt, loss, upload, ssh, printer, tcp_opts, quic, dns_secure, all |
| `-n, --count <N>` | 20 | Packet count for RTT and loss tests |
| `-v, --verbose` | false | Show all metrics and durations |

### tcp

TCP-only binary-search PMTU when ICMP is unavailable.

| Arg | Notes |
| --- | --- |
| `<TARGET>` | host:port |

### kitchen-sink

Parallel test sweep across targets from `targets.txt` (or built-in defaults), followed by tracepath, stats, and a verdict.

| Flag | Default | Notes |
| --- | --- | --- |
| `--max <N>` | 1500 | Max MTU to search |
| `--json` | false | Emit a JSON report to stdout |
| `--output <PATH>` | none | Write JSON report to file |

### upload-sweep

Direct invocation of `UploadSizeSweepTest`.

| Arg | Default | Notes |
| --- | --- | --- |
| `<TARGET>` | required | Hostname |
| `-p, --port <N>` | 443 | HTTPS port |

### ssh-path

Direct invocation of `SshDataPathTest`.

| Arg | Default | Notes |
| --- | --- | --- |
| `<TARGET>` | required | Hostname or IP |
| `-p, --port <N>` | 22 | SSH port |
| `-u, --user <USER>` | none | Supplying this enables the exec echo stage |

### printer-raw

Direct invocation of `Raw9100BulkTest`.

| Arg | Default | Notes |
| --- | --- | --- |
| `<TARGET>` | required | Hostname or IP |
| `-p, --port <N>` | 9100 | JetDirect port |

### tcp-options

Direct invocation of `TcpOptionsEchoTest`.

| Arg | Default | Notes |
| --- | --- | --- |
| `<TARGET>` | required | Hostname or IP |
| `-p, --port <N>` | 443 | Target TCP port |

### quic

Direct invocation of `QuicPmtudTest`.

| Arg | Default | Notes |
| --- | --- | --- |
| `<TARGET>` | required | Hostname or IP |
| `-p, --port <N>` | 443 | UDP port |

### dns-secure

Direct invocation of `DnsSecureCompareTest`.

| Arg | Notes |
| --- | --- |
| `<TARGET>` | Hostname to resolve |

### report

Renders a README_FIRST-style unified diagnosis by running HTTPS, upload sweep, SSH, and printer sweep tests, then feeding results into `DiagnosisEngine`.

| Arg | Notes |
| --- | --- |
| `<TARGET>` | Hostname |

### replay

Replays a PCAP file to the wire. Requires root on Linux and BSD/macOS.

| Arg | Default | Notes |
| --- | --- | --- |
| `<PCAP>` | required | Input PCAP path |
| `-i, --iface <NAME>` | none | Required on Linux |
| `--pps <N>` | none | Packets per second rate limit |
| `--loop-count <N>` | 1 | Number of iterations |
| `--rewrite-dst-ip <IPV4>` | none | Overwrite destination IP before send |
| `--rewrite-src-ip <IPV4>` | none | Overwrite source IP before send |

### probe

Active MTU probe using the DSL and send-and-capture engine. Requires root.

| Arg | Default | Notes |
| --- | --- | --- |
| `<TARGET>` | required | IPv4 address |
| `-i, --iface <NAME>` | required | Interface to send and capture on |
| `--min <N>` | 576 | Min probe size |
| `--max <N>` | 1500 | Max probe size |

### scenario

Executes a declarative scenario from a file or stdin. See [SCENARIOS.md](SCENARIOS.md).

| Arg | Notes |
| --- | --- |
| `<FILE>` | Path to scenario, or `-` for stdin |

### serve

Runs the Prometheus metrics HTTP endpoint. See [METRICS.md](METRICS.md).

| Flag | Default | Notes |
| --- | --- | --- |
| `-b, --bind <ADDR>` | `127.0.0.1:9464` | Bind address for the exporter |
| `-t, --target <HOST>` | none | Optional target to seed gauges by running an upload sweep once at startup |

### dsl-demo

Prints a summary and hexdump of a DSL-described packet without touching the wire.

| Flag | Default | Notes |
| --- | --- | --- |
| `-d, --dst <IPV4>` | 1.1.1.1 | Destination IPv4 |
| `-p, --port <N>` | 443 | Destination port |
| `--size <N>` | 32 | Payload bytes, filled with `X` |
