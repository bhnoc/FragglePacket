# Capability and Test Catalog

Three separate things ship in this binary, and conflating them is how a reader
concludes a capability exists when it does not:

1. **79 subcommands** — the real capability surface. 56 of them close a
   specific numbered gap from the field investigation and carry that gap's
   acceptance criteria in their `--help` and module doc comment.
2. **19 `NetworkTest` trait impls** — the older in-process framework driven by
   `fraggle-packet test`, the TUI Test Panel, and the desktop Tests panel.
   Both UIs additionally expose **all 79 subcommands** through a registry-driven
   command browser (TUI `[C]`, desktop **Commands** tab), grouped by the same
   buckets used above. Availability is declared per command, so one whose live
   sampling needs macOS shows as ingest-only and one that cannot run on this host
   is disabled with the reason rather than failing when clicked.
3. **1053 harness checks** (`harness/acid.sh`) — the ratchet that proves the
   above behave as documented. Only grows, never shrinks.

Full flag-level reference for every subcommand is in [CLI.md](CLI.md). This page
is the capability map: what is covered, and what is deliberately out of reach.

## Gap-closing subcommands

Each row is a capability that did not exist until a real investigation needed it.
The gap number is the contract: the command refuses to produce a verdict its
evidence cannot support, rather than printing a plausible number.

| Gap | Subcommand | Capability |
| --- | --- | --- |
| GAP-002 | `bufferbloat` | Idle/upload-loaded/download-loaded/simultaneous latency via networkQuality |
| GAP-003, GAP-004 | `protocol-compare` | Controlled H1/H2/H3 comparison with directional vs simultaneous isolation |
| GAP-005 | `stun-turn` | Repeated STUN binding requests with validation/RTT, mapped-address change detection, and TURN allocation checks |
| GAP-006 | `tcp-vs-udp` | Controlled TCP-versus-UDP throughput/loss comparison against a user-supplied endpoint |
| GAP-007 | `capture` | Bounded packet capture with duration/size caps and safe privilege handoff |
| GAP-010, GAP-026 | `mss-evidence` | SYN/SYN-ACK MSS evidence (local/peer/middlebox) and multi-destination MSS clustering vs route MTU |
| GAP-011 | `radio-diagnostic` | Wi-Fi radio/retry diagnostic with safe elevation and explicit platform-limitation reporting |
| GAP-012 | `site-ab` | Affected-site vs known-good-control A/B workflow: forced protocol, IP pinning, repeated samples, redirect-aware verdict |
| GAP-013 | `second-network` | Second-network control workflow: save/compare a connection fingerprint and test bundle across a network switch |
| GAP-014 | `dns-steering` | Compare A/AAAA/HTTPS/SVCB answers across resolvers to detect steering divergence |
| GAP-015, GAP-056 | `ipv6-validate` | Decomposed IPv6/NAT64/DNS64 validation with separate IPv4 and IPv6 verdicts, plus Happy Eyeballs timing |
| GAP-016 | `privilege-status` | Privileged-operation inventory and failure classification: preserve the error, name the exact command, offer an unprivileged path |
| GAP-019 | `pcap-report` | Analyze a PCAP/pcapng capture: vantage point, capture health, qualified MTU/loss verdicts |
| GAP-021 | `probe-rate` | Detect ICMP rate-limiting/batching artifacts by comparing normal vs elevated probe cadence |
| GAP-022 | `first-hop` | First-hop gateway isolation with non-ICMP fallback when echo is suppressed |
| GAP-023 | `ecn-aqm` | ECN/AQM capability and CE-mark counting with classic-ECN-vs-L4S distinction |
| GAP-024 | `ap-identity` | Stable, privacy-safe salted AP/radio identity derived from BSSID without storing or displaying it |
| GAP-025 | `preflight` | Preflight ALPN/Alt-Svc + real handshake capability across endpoints |
| GAP-027, GAP-047 | `load-guard` | Run a budget-guarded, radio-monitored load phase |
| GAP-028 | `ecmp-nat` | Multi-uplink ECMP/LAG hash and NAT-affinity diagnostic via fixed-5-tuple port sweeps |
| GAP-029 | `circuit-compare` | Compare WAN A-only, B-only, and dual-active phases from an operator manifest; never changes routing |
| GAP-030 | `wired-control` | Matched wired-versus-Wi-Fi fault-domain control: withholds WLAN attribution when the two paths' public egress identities differ |
| GAP-031 | `counter-deltas` | Normalized, qualified per-phase interface-counter deltas |
| GAP-032 | `independent-rates` | Independently rate-controlled, time-aligned simultaneous upload/download sweep |
| GAP-033 | `size-rate-matrix` | Datagram-size/packet-rate pressure matrix distinguishing packet-rate ceilings from byte-rate policing |
| GAP-034 | `flow-dscp-matrix` | Constant-aggregate flow-count sweep with DSCP marking-survival qualification |
| GAP-036, GAP-039 | `iperf-analyze` | Version/direction-aware iperf3 JSON parsing and explicit-allowlist endpoint capability discovery |
| GAP-037 | `ap-compat-matrix` | AP-generation/radio-mode/client-capability compatibility matrix; refuses a verdict until required comparison cells are present |
| GAP-038 | `fleet-orchestrator` | Distributed wireless-probe fleet orchestrator: management/test-node separation, redacted labels, bounded fanout |
| GAP-040 | `listener-lease` | Authorized-only listener leasing with per-transport capacity/duration qualification and endpoint loss-floor declaration |
| GAP-041 | `probe-preflight` | Remote probe health/dependency preflight: quarantines broken binaries, timeouts, and changed SSH host keys with no auto-accept path |
| GAP-042 | `phy-normalized` | PHY-normalized fleet comparison: offered load as a fraction of each client's own PHY capacity |
| GAP-043 | `counter-liveness` | Bracket a known packet stimulus to prove a counter is live, and refuse a zero-drop verdict without corroboration |
| GAP-044 | `gateway-bracket` | Pair idle/upload/download/simultaneous load phases with a first-hop gateway RTT/loss bracket |
| GAP-045 | `admission-fanout` | Barrier-synchronized public-listener admission fanout: never reports a listener that never admitted as zero throughput |
| GAP-046 | `throughput-tuner` | Version-aware maximum-throughput tuner: randomized trials, duration validation, synthetic-max vs representative-application split |
| GAP-048 | `dhcp-lifecycle` | DHCP address-lifecycle and pool-capacity test: safe existing-lease read by default, authorization-gated fresh-lease test |
| GAP-049 | `auth-portal` | Authentication/captive-portal/policy-assignment workflow: separately timed phases, portal detection without login automation |
| GAP-050 | `roaming` | Controlled roaming/session-continuity test: privacy-safe AP transitions, handoff duration, and VLAN/public-identity continuity |
| GAP-051, GAP-072 | `multiclient-fairness` | Coordinated multi-client capacity/fairness: refuses a cross-client verdict until both role descriptors exist and their phase windows overlap |
| GAP-052 | `media-quality` | Synthetic RTP/WebRTC media-quality probe: setup/ICE, burst-derived concealment/freeze risk, MOS-style estimate |
| GAP-053 | `reference-endpoint` | Reference-endpoint calibration and client-result acceptance: the endpoint can invalidate a client's measurement |
| GAP-054 | `nat-capacity` | Firewall/NAT/session-state capacity matrix: authorization-gated disruptive probing, safe-by-default idle-mapping observation |
| GAP-055 | `rf-survey` | Bounded time-series RF survey with platform-limited metric qualification and change-point correlation |
| GAP-057 | `multicast-isolation` | Discovery/multicast/peer-isolation policy diagnostic: declared expected-reachable/expected-blocked verdicts, name-free responder tallies |
| GAP-058 | `wired-edge` | Wired edge/AP-uplink/LLDP/PoE health bundle: read-only ingest, refuses a conclusion without telemetry |
| GAP-059 | `dependency-health` | Infrastructure dependency health bundle: DNS/NTP/cert/OCSP/controller checks distinguishing blocked-by-policy from unhealthy |
| GAP-060 | `vpn-matrix` | VPN/encapsulation compatibility matrix: credential-free protocol reachability and real effective MTU/MSS measurement |
| GAP-061 | `provider-path` | Provider/geography/path-stability comparison with non-response distinguished from loss |
| GAP-062 | `resilience` | Controlled resilience/failover validation: observes and labels an operator-performed component change, never initiates one |
| GAP-063 | `platform-matrix` | Privacy-safe cross-platform/power-save capability matrix with confound-aware attribution |
| GAP-064 | `clock-guard` | Synchronized clock verification: NTP offset with uncertainty, gated against a configured skew threshold, before permitting a one-way delay claim |
| GAP-065 | `policy-manifest` | Expected-policy and service-reachability manifest: probes only allowlisted targets and flags drift from declared allow/deny policy |
| GAP-066 | `burst-analysis` | Bounded burst-loss/reordering/duplication/jitter probe with queue-delay correlation |
| GAP-069 | `process-model` | Process-model equivalence and receive-path artifact guard: withholds a directional-collapse verdict unless it reproduces across native-bidir and paired-process methods |
| GAP-070 | `capacity-knee` | Capacity/latency-knee discovery: distinguishes a capacity plateau from directional unfairness and withholds an established claim without cross-method reproduction |

## Legacy and utility subcommands

Predate the gap list or serve the tooling itself. Useful, but without the
gap-numbered evidence contracts above.

| Subcommand | Purpose |
| --- | --- |
| `tui` | Launch the terminal UI (default with no subcommand) |
| `diagnose` | Six-stage DNS/ICMP/TCP/MTU/HTTPS diagnostic against one host |
| `https` | Staged HTTPS probe: DNS, connect, TLS, request, TTFB |
| `multi` | Path-MTU comparison across several targets |
| `vpn` | Tunnel MTU/overhead calculator (`vpn list` prints the catalog) |
| `quick` | ICMP-only MTU with a stability check |
| `tcp` | TCP-based MTU discovery where ICMP is filtered |
| `tcp-options` | Negotiated MSS and middlebox-rewrite detection |
| `quic` | QUIC/UDP PMTUD probe |
| `dns-secure` | Plain UDP DNS vs DoH vs DoT comparison |
| `upload-sweep` | HTTP(S) upload size sweep for data-stall blackholes |
| `ssh-path` | SSH banner plus optional authenticated echo data path |
| `printer-raw` | JetDirect port 9100 PJL and bulk size sweep |
| `kitchen-sink` | Broad sweep over a target list, coverage-gated verdict (GAP-073) |
| `report` | Unified README_FIRST-style diagnosis for one target |
| `test` | Runs the `NetworkTest` framework impls catalogued below |
| `fuzz` | Write a fuzzing PCAP (see [FUZZING.md](FUZZING.md)) |
| `replay` | Replay a PCAP onto the wire (root) |
| `probe` | Active DSL-driven PMTU probe with send-and-capture |
| `scenario` | Run a declarative scenario file or stdin |
| `serve` | Prometheus scrape endpoint (see [METRICS.md](METRICS.md)) |
| `dsl-demo` | Hexdump a DSL-described packet without touching the wire |
| `endpoints` | Known public iperf3 endpoints and the ports recorded as failing |

## What this tool deliberately cannot do

Not a roadmap. These are structural limits, and every one of them exists because
the alternative is a confident wrong answer.

| Limit | Why | What to use instead |
| --- | --- | --- |
| **Read another device's counters** | A client cannot read a switch or AP. `wired-edge`, `ap-compat-matrix`, `resilience`, `circuit-compare`, and `phy-normalized` are ingest-only: they accept operator-supplied JSON and refuse a conclusion without it. There is no live-query mode by design. | Export from your own controller/switch and pass it in |
| **Vendor controller APIs** | Dropped as out of scope: coupling a general-purpose diagnostic to one vendor's HTTP API is the wrong architecture. Telemetry is ingested as vendor-neutral optional fields instead. | Your vendor's own tooling, then ingest the export |
| **Continuous monitoring, alerting, history** | This is a point-in-time diagnostic with no database and no daemon. It cannot trend, correlate across time, or page anyone. | A real NMS/OSS; `serve` exposes Prometheus gauges to feed one |
| **Topology discovery** | No LLDP/CDP crawl and no persistent inventory, so no root-cause correlation across devices. | An NMS with a topology graph |
| **Spatial-stream (NSS) and MLO state on macOS** | Not exposed by any known unprivileged or privileged macOS Wi-Fi CLI path. Reported as `None` with the limitation named, never guessed from MCS index. | Operator-supplied AP telemetry via `ap-compat-matrix` |
| **Interface counters on Linux** | `load_guard::counters` shells `netstat -I <iface> -b`, which is BSD/Darwin syntax. `counter-deltas` on Linux cannot sample, and check 026 skips rather than reporting a fabricated clean result. | Run counter work on macOS until a `/proc/net/dev` reader exists |
| **Change infrastructure to test it** | `resilience` and `circuit-compare` observe and label an operator-performed change; they never initiate a failover or touch routing. `wired-edge` never writes switch config. | Perform the change yourself, then let the tool bracket it |
| **Automate a captive-portal login** | `auth-portal` detects a portal and times the phases but performs no HTTP POST and holds no credential field. | Log in by hand, then re-run |
| **Capture or require credentials** | No command has a `--password`/`--secret`/`--private-key` flag; gate 045 and 051 assert their absence, and `vpn-matrix` states inline that it never reads a VPN credential. | Credential-free reachability probes are what is offered |
| **Disruptive probing without consent** | `nat-capacity`, `dhcp-lifecycle`, `fleet-orchestrator`, and `listener-lease` gate their disruptive paths behind explicit authorization flags and refuse by default. | Pass the authorization flag when you own the network |
| **Claim a verdict from insufficient evidence** | The recurring rule: `kitchen-sink` refuses below 70% target coverage (GAP-073), `ap-compat-matrix` refuses without all required comparison cells, `capacity-knee` refuses without cross-method reproduction, contested properties yield no value (GAP-074), and a figure derived from a stale input is withheld (GAP-075). | Supply the missing controls the refusal names |

## NetworkTest trait impls

| Struct | File | Name | Category | Requires root | One-line description |
| --- | --- | --- | --- | --- | --- |
| IcmpMtuTest | mtu.rs | ICMP MTU Discovery | MTU | No | Binary-searches path MTU with DF-bit ICMP echoes (Linux uses IP_MTU_DISCOVER, macOS stub returns skip) |
| TcpMtuTest | mtu.rs | TCP MSS Discovery | MTU | No | Reads `TCP_MAXSEG` from a live connection on Linux, falls back to `ss -ti` parsing |
| QuicPmtudTest | quic_pmtud.rs | QUIC PMTU Probe | MTU | No | Opens a quinn client to the target, reads `max_datagram_size` after handshake |
| TunnelMssClampingTest | tunnel_mss.rs | Tunnel MSS Clamping Analysis | MTU | No | Cross-checks interface MTU, observed MSS, and common tunnel overheads to flag misconfigurations |
| RttTest | rtt.rs | RTT/Latency Test | RTT | No | Shells `ping -c N`, parses rtt min/avg/max/mdev |
| PacketLossTest | packet_loss.rs | Packet Loss Analysis | PacketLoss | No | Longer ping sweep, reports loss percent and jitter indicators |
| PathAnalysisTest | path_analysis.rs | Path Analysis (Traceroute) | PathAnalysis | No | Runs `tracepath` or `traceroute`, collects per-hop RTT and pmtu lines |
| TcpHealthTest | tcp_health.rs | TCP Health Analysis | TCPHealth | No | Connect latency, retransmit hints, connection stability |
| TcpSegmentationTest | tcp_segmentation.rs | TCP Segmentation Detection | TCPHealth | No | Compares negotiated MSS with interface MTU, flags segmentation surprises |
| TcpOptionsEchoTest | tcp_options_echo.rs | TCP Options Echo | TCPHealth | No | Compares live TCP_MAXSEG with the active route MTU and flags only reductions beyond normal TCP-option allowance |
| DnsTest | dns.rs | DNS Resolution | DNS | No | Multi-resolver A query via `dig`, timing and answer comparison |
| DnsSecureCompareTest | dns_secure.rs | DNS Secure Comparison | DNS | No | Compares plain UDP DNS, DoH (`https://cloudflare-dns.com/dns-query`), and DoT responses |
| HttpsTest | https.rs | HTTPS Stage-by-Stage | HTTPS | No | Splits DNS, TCP connect, TLS handshake, request, TTFB into discrete timings |
| UploadSizeSweepTest | upload_sweep.rs | HTTP Upload Size Sweep | HTTPS | No | POSTs escalating body sizes over HTTPS to locate data-stall blackholes |
| Ipv6Test | ipv6.rs | IPv6 Connectivity | IPv6 | No | AAAA lookup plus ping6 reachability |
| ApplicationTest | application.rs | Application Protocol Detection | Application | No | Probes common app-layer banners (HTTP, SSH, TLS, SMTP) |
| SshDataPathTest | ssh_path.rs | SSH Data-Path | Application | No | Grabs SSH banner, optionally runs an authenticated exec echo stage |
| Raw9100BulkTest | printer_raw.rs | Raw 9100 Bulk Sweep | Application | No | JetDirect port 9100 PJL sweep with escalating payload sizes |
| FuzzingTest | fuzzing.rs | Fuzzing variants | Fuzzing | No | Wraps the fuzzers to emit PCAPs (see [FUZZING.md](FUZZING.md)) |

Notes:

* No current impl returns `requires_root = true`. Raw-socket operations live outside this trait in `fuzzing::replay`, `fuzzing::capture`, and `fuzzing::probe`, so the orchestrator never auto-skips them.
* `IcmpMtuTest` short-circuits on macOS because `IP_MTU_DISCOVER` is Linux-only; it emits a Skipped status with metadata explaining the limitation.
* Tests read `result.metadata["cli_command"]` when present so the desktop UI can surface a reproducible command line per test.
* Registration lists live in three places:
  * `src/bin/cli/test_cmd.rs` drives the `fraggle-packet test` subcommand.
  * `src/bin/tui/test_registration.rs` drives the TUI Test Panel.
  * `src/bin/desktop/test_registration.rs` drives the desktop Tests panel.
