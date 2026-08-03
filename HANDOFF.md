# FragglePacket gap-closure handoff

Building out the open capabilities in `docs/GAP_LIST.md` as CLI features. No
UI or TUI work in scope. Sprint loop: build, test, commit, push, next sprint.

## Current state (2026-08-02)

| Sprint | Scope | State |
| --- | --- | --- |
| 0 | smoke/acid harnesses, `src/cli/` refactor | **done, pushed** (0daf3c4). main.rs 2551→21 lines |
| 1 | P0 gaps 001, 019, 025, 027, 047 | **done, pushed** (ed856bb) |
| 2 | measurement primitives 002, 003, 004, 009, 021, 022, 044 | **done, pushed** (fdb6c96) |
| 3 | capture/PCAP/MSS 007, 008, 010, 026, 066 | **done, pushed** (1edc17c) |
| 4 | iperf3 load matrix 006, 031-034, 036, 039, 040, 045, 046 | **done, pushed** (fdb6c96) |
| 5 | Wi-Fi radio 011, 024, 035, 037, 042, 043, 055, 063 | **done, pushed** (11c7a5d) |
| 6 | STUN/NAT/ECN/media 005, 023, 028, 052, 054, 060 | **done, pushed** (267e0ee) |
| 7 | DNS/IPv6/DHCP/auth 014, 015, 048, 049, 056, 057, 059, 061 | **done, pushed** (d50fe8b) |
| 8 | fleet orchestration 029, 038, 041, 053, 064, 065 | **done, pushed** (a16114f) |
| 9 | workflows/redaction/reporting 012, 013, 016-018, 020, 030, 050, 051, 058, 062 | **done** |

## Where this stands

**Every gap in `docs/GAP_LIST.md` is closed.** GAP-001 through GAP-066, plus
GAP-069, GAP-070, and GAP-072. The acid suite is at 1048 checks over 570 unit
tests, and every check was proven to fail against the broken state before being
trusted.

GAP-067, GAP-068, and GAP-071 were **dropped as out of scope**, not implemented.
They required a CV-CUE/Arista connector inside the tool: 1Password credential
retrieval, `launchpad.wifi.arista.com` tenant discovery, `/wifi/api/*` routes,
and vendor `Version` headers. FragglePacket is vendor-agnostic and must stay
that way. The `arista-ops` skill already owns that access, and `wired_edge.rs`
and `ap_compat_matrix.rs` already ingest operator-supplied AP and switch
telemetry as vendor-neutral `Option` fields, so the diagnosis-shaped parts were
covered without the coupling. See the "Resolved" table in the gap list.

The two P0s closed last were both about distrusting our own measurements:

- **GAP-069** found that the paired two-process harness can manufacture a
  directional collapse that looks like a network fault. On PV10, native
  `--bidir` stayed balanced with zero receive-collapse events while the paired
  method went severely asymmetric with 70-102 collapses, at similar combined
  throughput. `independent-rates` is a paired-process design, so part of the
  investigation's headline directional collapse may be harness artifact.
  `process-model` now withholds a verdict unless a collapse reproduces across
  both models.
- **GAP-070** separates a capacity plateau from directional unfairness and
  refuses to call a knee established unless a second method reproduces it and
  the endpoint did not drift underneath the sweep.

## Endpoint registry

`harness/fixtures/endpoints/public-iperf.json` records the iperf3 endpoints the
investigation actually used, including the ports that **failed**:
`speedtest.xmission.com:5201` admitted upload, `iperf.soute.xmission.com:5201`
admitted reverse download, port 5200 refused, and 5202-5206 failed admission or
sat at zero intervals until the safety timeout. Recording the failures is the
point: that is the GAP-045 shape where eight of twenty-one probes never
established a connection after port-open checks passed, and scoring them zero
would have implicated nine working clients.

It also carries the caveats a consumer needs: the two directions traverse
different public paths, each listener accepts one test at a time, old-client
reverse UDP has a 0.6-1.0% endpoint loss floor, a Colorado endpoint returned a
duration-inconsistent summary, and opening-to-closing baseline drift was severe.
Client source ports 40010-40019 are recorded as explicitly **not** listeners;
they held 5-tuples stable across ECMP hash buckets.

Still unwired: no command reads that registry yet. Operators pass endpoints by
hand, so the known-bad ports are not automatically avoided.

## The recurring failure mode: a number with no referent

Nearly every gap in this list is one bug wearing different clothes. Something
cannot be measured, and instead of saying so the code emits a plausible number.
Observed forms so far:

- GAP-009: an unparsed ping summary became `0.0 ms` latency.
- GAP-001: a successful `send_to()` became a confirmed 8,972-byte path MTU.
- GAP-019: frame length compared against a bare 1500 became phantom oversize
  frames, and host-side retransmissions became network fault counts.
- GAP-027: a run that roamed mid-phase still produced a capacity retention ratio.
- GAP-025: one endpoint's missing QUIC support became "the network blocks QUIC".
- `--fake-radio`: fabricated RSSI/MCS values emitted with no marker, so a faked
  report was byte-identical to a real measurement.
- `gateway-bracket`: a synthetic generator undershooting its own budget became
  `throughput_loss_pct: 96.7%` in a report stamped `data_source: live`.

The last two arrived through *test affordances*, not parsers, which is why gate
`020` exists. When reviewing any new capability, ask of every number: what would
this read as if the underlying measurement silently failed? If the answer is "a
normal-looking value", the type is wrong. Use `Option`, withhold derived figures
whose inputs are invalid, and state provenance in the artifact rather than
relying on the operator remembering which flags they passed.

## Ranked gotcha list, most likely to bite first

1. **The default route on this machine is a VPN tunnel (`utun6`, MTU 1412), not
   Wi-Fi.** `route -n get default` to confirm before interpreting any MTU, PMTU,
   or throughput result. Load tests and MTU probes must bind explicitly to the
   interface under test or the numbers describe the tunnel. This silently
   invalidates results rather than erroring.
2. **`harness/golden/*.help.txt` is the frozen pre-refactor CLI spec.** Never
   edit it to make a parity check pass. If a check fails, the code lost a flag.
   Adding new flags is fine; the gate only fails on loss.
3. **DF is now set correctly via `probe::pmtu_evidence::set_dont_fragment`**
   (Darwin `IP_DONTFRAG`, Linux `IP_MTU_DISCOVER`), and it checks the setsockopt
   result. Use it rather than writing a new DF path; the old `set_df` was a
   silent no-op off Linux and every macOS probe measured fragmented delivery.
4. **`*.json` is gitignored repo-wide.** `!/harness/fixtures/**` re-includes
   fixture JSON. New JSON test data outside that path will vanish from commits.
5. **`reports/bhusa26/protocol-comparison-*.pcap` is 2.1 GB and gitignored.**
   Read it with `tshark -c N` and carve with `editcap -s 128`; `tshark -s` does
   not truncate on file reads, only on live capture.
6. **`capinfos` prints "60 k" style rounded counts.** Do not parse that field
   for exact packet counts.
7. **`wdutil info` requires root and dumps Bluetooth device names** (that is
   GAP-020). Unprivileged `system_profiler SPAirPortDataType` gives PHY mode,
   channel/band/width, signal/noise, transmit rate, and MCS with SSIDs already
   redacted; prefer it.
8. macOS `ping` writes `ping: sendto: Message too long` to stderr and *still*
   prints a normal statistics block. Do not treat the block as authoritative.

## Corrections made to the gap list itself

- **GAP-019's oversize evidence was wrong.** The 1,569,970-packet capture holds
  zero frames above 1,514 bytes. The 170,663 flagged frames are 1,510 bytes
  carrying IP length 1,496, which is legal at MTU 1500. Frame-size verdicts must
  compare against link MTU plus L2 encapsulation, not a bare 1500 constant. The
  retransmission inflation in that gap is real (13,269 retransmissions per
  300,000-packet sample) and stays in scope.

## Verified reproductions

Both of these are now FIXED; kept as the record of what the bug looked like.

- **GAP-001** reported `[PASS] largest_udp_payload_sent = 8972` because a
  successful `send_to` counted as success. Now requires the peer to acknowledge
  stream data carried in datagrams pinned to the tested size, and reports 1300
  confirmed against this host's 1412-byte tunnel. Note a QUIC handshake alone is
  NOT sufficient evidence: Initial packets pad only to 1200 bytes, so a
  handshake completes on any path carrying 1200 regardless of the configured
  maximum. That mistake produced a false 8972 confirmation mid-fix.
- **GAP-009** reported 0.0 ms for every successful macOS run because
  `rtt.rs` matched only Linux's `rtt min/avg/max/mdev`. Darwin emits
  `round-trip min/avg/max/stddev`. Now `Option<f64>` across both platforms.

## Skills available for the infrastructure-dependent gaps

Two project skills exist that cover access this build otherwise cannot reach.
Read them before writing anything that needs remote probes or AP telemetry;
they likely already encode the access pattern, so don't reinvent it.

- **`precog-ops`** — operating the Black Hat Precog wireless probes through the
  wired bastion. Directly relevant to GAP-038 (distributed probe orchestrator),
  GAP-041 (remote probe health preflight), GAP-042, GAP-045, GAP-051.
- **`arista-ops`** — read-only Arista CV-CUE operations. Relevant to GAP-037
  (AP generation/radio-mode matrix), GAP-043 (telemetry counter liveness),
  GAP-051, GAP-055 (RF survey), GAP-058 (wired edge/LLDP/PoE).

## Local tooling confirmed present

`iperf3` 3.21, `tshark`, `capinfos`, `editcap`, `tcpdump`, `networkQuality`,
`wdutil` (root only), `dig`, `nc`. Most gaps are live-testable on this machine.

## Resume checklist

1. `git log --oneline -8` and read this file.
2. `./harness/smoke.sh` then `./harness/acid.sh`. Both must be green before new
   work. A red acid halts new work until fixed or reverted.
3. `route -n get default` to see which interface you are actually measuring.
4. Pick the lowest-numbered incomplete sprint from the table above.
