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

## Complete subcommand index

All 79 subcommands, generated from `fraggle-packet --help` and each
subcommand's own `--help`, so this table cannot drift from the binary. The
`### ` sections below cover the legacy MTU commands in flag-level detail; the
GAP-numbered commands carry their full contract in `--help` and in the
module doc comment named by the GAP.

Regenerate after adding a subcommand:

```
fraggle-packet --help    # authoritative list
fraggle-packet <cmd> --help
```

| Subcommand | Usage | Purpose |
| --- | --- | --- |
| `admission-fanout` | `admission-fanout [OPTIONS] --target <TARGET>...` | Barrier-synchronized public-listener admission fanout: never reports a listener that never admitted as zero throughput (GAP-045) |
| `ap-compat-matrix` | `ap-compat-matrix [OPTIONS]` | AP-generation/radio-mode/client-capability compatibility matrix; refuses a verdict until required comparison cells are present (GAP-037) |
| `ap-identity` | `ap-identity [OPTIONS]` | Stable, privacy-safe salted AP/radio identity derived from BSSID without storing or displaying it (GAP-024) |
| `auth-portal` | `auth-portal [OPTIONS]` | Authentication/captive-portal/policy-assignment workflow: separately timed phases, portal detection without login automation (GAP-049) |
| `bufferbloat` | `bufferbloat [OPTIONS]` | Idle/upload-loaded/download-loaded/simultaneous latency via networkQuality (GAP-002) |
| `burst-analysis` | `burst-analysis [OPTIONS] --interface <INTERFACE> --target <TARGET>` | Bounded burst-loss/reordering/duplication/jitter probe with queue-delay correlation (GAP-066) |
| `capacity-knee` | `capacity-knee [OPTIONS] --interface <INTERFACE>` | Capacity/latency-knee discovery: distinguishes a capacity plateau from directional unfairness and withholds an established claim without cross-method reproduction (GAP-070) |
| `capture` | `capture [OPTIONS] --interface <INTERFACE>` | Bounded packet capture with duration/size caps and safe privilege handoff (GAP-007) |
| `circuit-compare` | `circuit-compare [OPTIONS] --manifest <MANIFEST>` | Compare WAN A-only, B-only, and dual-active phases from an operator manifest; never changes routing (GAP-029) |
| `clock-guard` | `clock-guard [OPTIONS]` | Synchronized clock verification: NTP offset with uncertainty, gated against a configured skew threshold, before permitting a one-way delay claim (GAP-064) |
| `counter-deltas` | `counter-deltas [OPTIONS]` | Normalized, qualified per-phase interface-counter deltas (GAP-031) |
| `counter-liveness` | `counter-liveness [OPTIONS]` | Bracket a known packet stimulus to prove a counter is live, and refuse a zero-drop verdict without corroboration (GAP-043) |
| `dependency-health` | `dependency-health [OPTIONS]` | Infrastructure dependency health bundle: DNS/NTP/cert/OCSP/controller checks distinguishing blocked-by-policy from unhealthy (GAP-059) |
| `dhcp-lifecycle` | `dhcp-lifecycle [OPTIONS] --interface <INTERFACE>` | DHCP address-lifecycle and pool-capacity test: safe existing-lease read by default, authorization-gated fresh-lease test (GAP-048) |
| `diagnose` [↓](#diagnose) | `diagnose [OPTIONS] <TARGET>` | Full diagnostic against a hostname (DNS, TCP, HTTP, ICMP comparison) |
| `dns-secure` [↓](#dns-secure) | `dns-secure [OPTIONS] <TARGET>` | DoH/DoT vs plain DNS comparison |
| `dns-steering` | `dns-steering [OPTIONS] --resolver <RESOLVERS> <NAME>` | Compare A/AAAA/HTTPS/SVCB answers across resolvers to detect steering divergence (GAP-014) |
| `dsl-demo` [↓](#dsl-demo) | `dsl-demo [OPTIONS]` | Print a hexdump of a packet described by our DSL (demo helper) |
| `ecmp-nat` | `ecmp-nat [OPTIONS]` | Multi-uplink ECMP/LAG hash and NAT-affinity diagnostic via fixed-5-tuple port sweeps (GAP-028) |
| `ecn-aqm` | `ecn-aqm [OPTIONS]` | ECN/AQM capability and CE-mark counting with classic-ECN-vs-L4S distinction (GAP-023) |
| `endpoints` | `endpoints [OPTIONS]` | Known iperf3 endpoints and the ports recorded as failing, so a known-bad endpoint is never retried or scored as zero throughput |
| `first-hop` | `first-hop [OPTIONS]` | First-hop gateway isolation with non-ICMP fallback when echo is suppressed (GAP-022) |
| `fleet-orchestrator` | `fleet-orchestrator [OPTIONS]` | Distributed wireless-probe fleet orchestrator: management/test-node separation, redacted labels, bounded fanout (GAP-038) |
| `flow-dscp-matrix` | `flow-dscp-matrix [OPTIONS] --interface <INTERFACE> --target <TARGET>` | Constant-aggregate flow-count sweep with DSCP marking-survival qualification (GAP-034) |
| `fuzz` [↓](#fuzz) | `fuzz [OPTIONS] <TARGET>` | Packet fuzzing for security testing |
| `gateway-bracket` | `gateway-bracket [OPTIONS]` | Pair idle/upload/download/simultaneous load phases with a first-hop gateway RTT/loss bracket (GAP-044) |
| `https` [↓](#https) | `https [OPTIONS] <TARGET>` | Test HTTPS connectivity with stage-by-stage analysis (MTU blackhole detection) |
| `independent-rates` | `independent-rates [OPTIONS]` | Independently rate-controlled, time-aligned simultaneous upload/download sweep (GAP-032) |
| `iperf-analyze` | `iperf-analyze [OPTIONS]` | Version/direction-aware iperf3 JSON parsing and explicit-allowlist endpoint capability discovery (GAP-039/GAP-036) |
| `ipv6-validate` | `ipv6-validate [OPTIONS] --interface <INTERFACE>` | Decomposed IPv6/NAT64/DNS64 validation with separate IPv4 and IPv6 verdicts, plus Happy Eyeballs timing (GAP-056/GAP-015) |
| `kitchen-sink` [↓](#kitchen-sink) | `kitchen-sink [OPTIONS]` | Run all tests against common targets and give final verdict |
| `listener-lease` | `listener-lease [OPTIONS] --allow <ALLOW>... --use-listener <USE_LISTENER>` | Authorized-only listener leasing with per-transport capacity/duration qualification and endpoint loss-floor declaration (GAP-040) |
| `load-guard` | `load-guard [OPTIONS]` | Run a budget-guarded, radio-monitored load phase (GAP-027/GAP-047) |
| `media-quality` | `media-quality [OPTIONS] --interface <INTERFACE> --target <TARGET>` | Synthetic RTP/WebRTC media-quality probe: setup/ICE, burst-derived concealment/freeze risk, MOS-style estimate (GAP-052) |
| `mss-evidence` | `mss-evidence [OPTIONS]` | SYN/SYN-ACK MSS evidence (local/peer/middlebox) and multi-destination MSS clustering vs route MTU (GAP-010/GAP-026) |
| `multi` [↓](#multi) | `multi [OPTIONS] <TARGETS>` | Test multiple targets and compare path MTUs |
| `multicast-isolation` | `multicast-isolation [OPTIONS]` | Discovery/multicast/peer-isolation policy diagnostic: declared expected-reachable/expected-blocked verdicts, name-free responder tallies (GAP-057) |
| `multiclient-fairness` | `multiclient-fairness [OPTIONS]` | Coordinated multi-client capacity/fairness: refuses a cross-client verdict until both role descriptors exist and their phase windows overlap (GAP-051/GAP-072) |
| `nat-capacity` | `nat-capacity [OPTIONS] --target <TARGET>` | Firewall/NAT/session-state capacity matrix: authorization-gated disruptive probing, safe-by-default idle-mapping observation (GAP-054) |
| `pcap-report` | `pcap-report [OPTIONS] <FILES>...` | Analyze a PCAP/pcapng capture: vantage point, capture health, qualified MTU/loss verdicts (GAP-019) |
| `phy-normalized` | `phy-normalized [OPTIONS] --measurements-file <MEASUREMENTS_FILE>` | PHY-normalized fleet comparison: offered load as a fraction of each client's own PHY capacity (GAP-042) |
| `platform-matrix` | `platform-matrix [OPTIONS]` | Privacy-safe cross-platform/power-save capability matrix with confound-aware attribution (GAP-063) |
| `policy-manifest` | `policy-manifest [OPTIONS] --manifest-file <MANIFEST_FILE>` | Expected-policy and service-reachability manifest: probes only allowlisted targets and flags drift from declared allow/deny policy (GAP-065) |
| `preflight` | `preflight [OPTIONS]` | Preflight ALPN/Alt-Svc + real handshake capability across endpoints (GAP-025) |
| `printer-raw` [↓](#printer-raw) | `printer-raw [OPTIONS] <TARGET>` | Raw JetDirect port 9100 PJL + bulk size sweep |
| `privilege-status` | `privilege-status [OPTIONS]` | Privileged-operation inventory and failure classification: preserve the error, name the exact command, offer an unprivileged path (GAP-016) |
| `probe` [↓](#probe) | `probe [OPTIONS] --iface <IFACE> <TARGET>` | Active MTU probe using the native DSL + send-and-capture engine |
| `probe-preflight` | `probe-preflight [OPTIONS]` | Remote probe health/dependency preflight: quarantines broken binaries, timeouts, and changed SSH host keys with no auto-accept path (GAP-041) |
| `probe-rate` | `probe-rate [OPTIONS] --gateway <GATEWAY> --remote <REMOTE>` | Detect ICMP rate-limiting/batching artifacts by comparing normal vs elevated probe cadence (GAP-021) |
| `process-model` | `process-model [OPTIONS]` | Process-model equivalence and receive-path artifact guard: withholds a directional-collapse verdict unless it reproduces across native-bidir and paired-process methods (GAP-069) |
| `protocol-compare` | `protocol-compare [OPTIONS] <HOST>` | Controlled H1/H2/H3 comparison with directional vs simultaneous isolation (GAP-003/GAP-004) |
| `provider-path` | `provider-path [OPTIONS] <TARGET>` | Provider/geography/path-stability comparison with non-response distinguished from loss (GAP-061) |
| `quic` [↓](#quic) | `quic [OPTIONS] <TARGET>` | QUIC/UDP PMTUD probe |
| `quick` [↓](#quick) | `quick [OPTIONS] <TARGET>` | Quick ICMP-only MTU test |
| `radio-diagnostic` | `radio-diagnostic [OPTIONS]` | Wi-Fi radio/retry diagnostic with safe elevation and explicit platform-limitation reporting (GAP-011) |
| `reference-endpoint` | `reference-endpoint [OPTIONS]` | Reference-endpoint calibration and client-result acceptance: the endpoint can invalidate a client's measurement (GAP-053) |
| `replay` [↓](#replay) | `replay [OPTIONS] <PCAP>` | Replay a PCAP file onto the wire (requires root) |
| `report` [↓](#report) | `report [OPTIONS] <TARGET>` | Render a unified README_FIRST-style diagnosis of a target |
| `resilience` | `resilience [OPTIONS] --run <RUN>` | Controlled resilience/failover validation: observes and labels an operator-performed component change, never initiates one (GAP-062) |
| `rf-survey` | `rf-survey [OPTIONS]` | Bounded time-series RF survey with platform-limited metric qualification and change-point correlation (GAP-055) |
| `roaming` | `roaming [OPTIONS]` | Controlled roaming/session-continuity test: privacy-safe AP transitions, handoff duration, and VLAN/public-identity continuity (GAP-050) |
| `scenario` [↓](#scenario) | `scenario [OPTIONS] <FILE>` | Run a declarative scenario from a file or stdin |
| `second-network` | `second-network [OPTIONS]` | Second-network control workflow: save/compare a connection fingerprint and test bundle across a network switch (GAP-013) |
| `serve` [↓](#serve) | `serve [OPTIONS]` | Expose a Prometheus metrics scrape endpoint |
| `site-ab` | `site-ab [OPTIONS] --affected-host <AFFECTED_HOST> --control-host <CONTROL_HOST>` | Affected-site vs known-good-control A/B workflow: forced protocol, IP pinning, repeated samples, redirect-aware verdict (GAP-012) |
| `size-rate-matrix` | `size-rate-matrix [OPTIONS] --interface <INTERFACE> --target <TARGET>` | Datagram-size/packet-rate pressure matrix distinguishing packet-rate ceilings from byte-rate policing (GAP-033) |
| `ssh-path` [↓](#ssh-path) | `ssh-path [OPTIONS] <TARGET>` | SSH banner + optional authenticated echo data-path test |
| `stun-turn` | `stun-turn [OPTIONS]` | Repeated STUN binding requests with validation/RTT, mapped-address change detection, and TURN allocation checks (GAP-005) |
| `tcp` [↓](#tcp) | `tcp [OPTIONS] <TARGET>` | TCP-based MTU discovery (no ICMP required) |
| `tcp-options` [↓](#tcp-options) | `tcp-options [OPTIONS] <TARGET>` | Query actual negotiated TCP MSS and detect middlebox rewriting |
| `tcp-vs-udp` | `tcp-vs-udp [OPTIONS]` | Controlled TCP-versus-UDP throughput/loss comparison against a user-supplied endpoint (GAP-006) |
| `test` [↓](#test) | `test [OPTIONS] <TARGET>` | Run test framework tests (DNS, HTTPS, TCP, RTT, Loss) |
| `throughput-tuner` | `throughput-tuner [OPTIONS] --host <HOST> --port <PORT>` | Version-aware maximum-throughput tuner: randomized trials, duration validation, synthetic-max vs representative-application split (GAP-046) |
| `tui` [↓](#tui) | `tui` | Launch interactive TUI |
| `upload-sweep` [↓](#upload-sweep) | `upload-sweep [OPTIONS] <TARGET>` | HTTP(S) upload size sweep (detects data-stall blackholes) |
| `vpn` [↓](#vpn) | `vpn [OPTIONS] <VPN_TYPE>` | Calculate safe MTU for VPN/SASE/Zero-Trust usage |
| `vpn-matrix` | `vpn-matrix [OPTIONS] --target <TARGET>` | VPN/encapsulation compatibility matrix: credential-free protocol reachability and real effective MTU/MSS measurement (GAP-060) |
| `wired-control` | `wired-control [OPTIONS]` | Matched wired-versus-Wi-Fi fault-domain control: withholds WLAN attribution when the two paths' public egress identities differ (GAP-030) |
| `wired-edge` | `wired-edge [OPTIONS] --bracket <BRACKET>` | Wired edge/AP-uplink/LLDP/PoE health bundle: read-only ingest, refuses a conclusion without telemetry (GAP-058) |

## Detailed reference: legacy MTU commands

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

The test compares the established socket's `TCP_MAXSEG` with the MSS implied by
the active route MTU. A warning means the reduction is larger than normal TCP
option overhead; confirming an in-flight rewrite still requires a SYN/SYN-ACK
packet capture.

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
