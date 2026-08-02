# Harness fixtures

Real captured platform output, used so parsers are tested against what the
tools actually emit rather than what we assume they emit. Several gaps in
`docs/GAP_LIST.md` exist specifically because a parser was written against one
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

Carved from `reports/bhusa26/protocol-comparison-20260801-234815.pcap`, the
2.1 GB / 1,569,970-packet host-side capture taken during the Black Hat
investigation. That file is gitignored for size; these carves are not.

## iperf/

| File | What it proves |
| --- | --- |
| `iperf-version-local.txt` | Local client is iperf 3.21. GAP-039 concerns 3.9 vs 3.16 vs 3.21 JSON divergence, so version detection cannot be skipped. |
