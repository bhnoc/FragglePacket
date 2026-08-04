# Harness fixtures

Real captured platform output, used so parsers are tested against what the
tools actually emit rather than what we assume they emit. Several gaps in
the field investigation notes exist specifically because a parser was written against one
platform's format and silently produced zeros on another.

Every fixture here is scrubbed of SSID, BSSID, MAC, and hostname identifiers
before it is committed. `harness/checks/001-fixture-privacy.sh` enforces that.

## ping/

Captured on Darwin 25.5.0 (macOS), `/sbin/ping`.

| File | What it proves |
| --- | --- |
| `darwin-ping-ok.txt` | Darwin's summary line is `round-trip min/avg/max/stddev`, not Linux's `rtt min/avg/max/mdev`. This is the direct cause of GAP-009: `src/network_tests/rtt.rs` matched only the Linux spelling and reported 0.0 latency for every successful Darwin run. |
| `darwin-ping-timeout.txt` | Total loss produces `Request timeout for icmp_seq N` and NO round-trip line at all. A parser must mark latency unavailable here, never zero. |
| `darwin-ping-df-toobig.txt` | Darwin prints `ping: sendto: Message too long` to stderr and still emits a normal-looking statistics block. Treating the block as authoritative would score an oversize DF probe as ordinary loss instead of a fragmentation-needed signal. |

## wifi/

| File | What it proves |
| --- | --- |
| `system_profiler-airport.txt` | Unprivileged Wi-Fi state available on macOS: PHY mode, channel + band + width, signal/noise, transmit rate, MCS index. Enough for the GAP-035 per-phase radio guard without sudo. Note it exposes MAC address and neighbouring SSIDs, which is why GAP-018/GAP-020 require allowlisted extraction. MAC here is replaced with `02:00:00:00:00:01`. |

`wdutil info` needs root and additionally dumps Bluetooth device names, which is
the GAP-020 complaint. Do not add a raw `wdutil` fixture; capture only
allowlisted fields.

## pcap/

Synthetic. Generated with `re-cap-inator` from the campaign specs below, then
post-processed to carry the specific artifacts the checks assert on. Addresses
are RFC 5737 documentation ranges (`192.0.2.10`, `198.51.100.20`) or generic
RFC 1918 (`10.1.1.10`); MACs are locally-administered placeholders.

These replaced carves of a real host capture. A capture of someone else's
network is not ours to publish, and encrypted payloads do not make the
metadata safe to redistribute.

| File | What it proves |
| --- | --- |
| `mixed-head.pcap` | A 1,510-byte Ethernet frame (IP total_len 1,496) at MTU 1500 is legal, never oversize — the GAP-019 false positive. Also snaplen-truncated (96 bytes) so payload-dependent verdicts must be suppressed, and carries one single-direction TCP flow that GAP-010 must label `confidence=Insufficient`. Client is `10.1.1.10` so GAP-018's `--retain-identifiers` has a private address to reveal. |
| `tcp-anomalies.pcap` | Contains a genuine retransmission (a data-bearing segment repeated, so `seq_end <= prev_max`) for the GAP-008 anomaly counters. TCP-heavy, no QUIC. |
| `quic-443.pcap` | QUIC-candidate traffic on UDP/443 for the GAP-008 comparison and GAP-023 ECN classification. |

Regenerate with a local `re-cap-inator` (`./start.sh`, then POST the spec to
`/api/v1/generate`). Do not replace these with a real capture.

## iperf/

Captured live against `speedtest.xmission.com:5201`. Local IP rewritten to
`192.0.2.10` and the server to `198.51.100.20` (RFC 5737 documentation ranges).

| File | What it proves |
| --- | --- |
| `iperf-version-local.txt` | Local client is iperf 3.21. GAP-039 concerns 3.9 vs 3.16 vs 3.21 JSON divergence, so version detection cannot be skipped. |
| `tcp-forward-3.21.json` | Baseline shape: `end.sum_sent` and `end.sum_received`, no `end.sum`. |
| `tcp-reverse-3.21.json` | Same shape in reverse. The received rate is the achieved one. |
| `tcp-bidir-3.21.json` | Adds `sum_sent_bidir_reverse` and `sum_received_bidir_reverse`. A parser reading only `sum_sent`/`sum_received` silently reports one direction of a bidirectional test. |
| `udp-reverse-3.21.json` | **The GAP-039 trap.** Carries `sum`, `sum_sent`, and `sum_received` at once. `sum_sent` reports `packets: 0` while `sum` reports 489 packets and `sum_received` reports 460 at a different `bits_per_second`. Reading `sum_sent.lost_percent` yields 0% loss from a field that counted zero packets, which is exactly the "never turn missing fields into zero-loss results" clause. |
| `error-refused.json` | A refused connection still produces `start`, `intervals`, and `end` alongside a top-level `error` key. The error must be checked first or figures get read from an aborted run. |
