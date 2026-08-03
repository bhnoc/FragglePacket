# NetworkTest Catalog

Each implementation of `fraggle_packet::framework::NetworkTest` ships with a name, category, and `requires_root` flag. The table below enumerates every impl currently in `src/network_tests/`.

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
