# FragglePacket gap-closure handoff

Building out all 66 open capabilities in `docs/GAP_LIST.md` as CLI features. No
UI or TUI work in scope. Sprint loop: build, test, commit, push, next sprint.

## Current state (2026-08-02)

| Sprint | Scope | State |
| --- | --- | --- |
| 0 | smoke/acid harnesses, `src/cli/` refactor | harnesses done and committed; refactor in progress |
| 1 | P0 gaps 001, 019, 025, 027, 047 | not started |
| 2 | measurement primitives 002, 003, 004, 009, 021, 022, 044 | not started |
| 3 | capture/PCAP/MSS 007, 008, 010, 026, 066 | not started |
| 4 | iperf3 load matrix 006, 031-034, 036, 039, 040, 045, 046 | not started |
| 5 | Wi-Fi radio 011, 024, 035, 037, 042, 043, 055, 063 | not started |
| 6 | STUN/NAT/ECN/media 005, 023, 028, 052, 054, 060 | not started |
| 7 | DNS/IPv6/DHCP/auth 014, 015, 048, 049, 056, 057, 059, 061 | not started |
| 8 | fleet orchestration 029, 038, 041, 053, 064, 065 | not started |
| 9 | workflows/redaction/reporting 012, 013, 016-018, 020, 030, 050, 051, 058, 062 | not started |

## Contract

```
Goal:       Every GAP-001..066 acceptance line implemented as a working CLI capability.
Acceptance: Each gap's acceptance criteria met, exercised via CLI, locked by a check in acid.
Done:       build clean + smoke green + acid green covering every shipped gap + docs/CLI.md current.
```

## Harnesses

```
./harness/smoke.sh          # build, every subcommand answers --help, cargo test --lib. Run BEFORE each unit of work.
./harness/acid.sh           # all locking checks. Run AFTER. Ratchet: only grows.
./harness/acid.sh 001 019   # filter to specific check files
FP_HARNESS_OFFLINE=1 ...    # skip checks needing live network
```

Add a gap's locking check as `harness/checks/<gap-number>-<slug>.sh`. It is
sourced, not executed, so it inherits the helpers in `harness/lib.sh`:
`check_ok`, `check_fails`, `check_contains`, `check_lacks`, `check_json_field`,
`pass`, `fail`, `skip`, `note`, plus `$BIN`, `$FIXTURE_DIR`, `$GOLDEN_DIR`,
`$WORK_DIR`, and `net_guard`. One file per gap so parallel agents never collide.

Every locking check must be proven to fail against the broken state before it is
trusted. Both existing gates were negative-tested this way.

## Ranked gotcha list, most likely to bite first

1. **The default route on this machine is a VPN tunnel (`utun6`, MTU 1412), not
   Wi-Fi.** `route -n get default` to confirm before interpreting any MTU, PMTU,
   or throughput result. Load tests and MTU probes must bind explicitly to the
   interface under test or the numbers describe the tunnel. This silently
   invalidates results rather than erroring.
2. **`harness/golden/*.help.txt` is the frozen pre-refactor CLI spec.** Never
   edit it to make a parity check pass. If a check fails, the code lost a flag.
   Adding new flags is fine; the gate only fails on loss.
3. **`set_df()` in `src/network_tests/quic_pmtud.rs` is a no-op on non-Linux.**
   Any DF-dependent probe silently loses its don't-fragment bit on macOS. Needs
   `IP_DONTFRAG` for Darwin.
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

- **GAP-001 reproduced.** `fraggle-packet quic 1.1.1.1` reports `[PASS]` with
  `largest_udp_payload_sent = 8972`. `src/network_tests/quic_pmtud.rs:103`
  counts a successful `send_to` as success with no response required. Baseline
  saved to `temp/gap001-before.txt`.
- **GAP-009 root cause located.** `src/network_tests/rtt.rs:150` matches
  `"rtt min/avg/max"` (Linux). Darwin emits `round-trip min/avg/max/stddev`, so
  every successful macOS run reports 0.0 for min/avg/max/jitter.

## Local tooling confirmed present

`iperf3` 3.21, `tshark`, `capinfos`, `editcap`, `tcpdump`, `networkQuality`,
`wdutil` (root only), `dig`, `nc`. Most gaps are live-testable on this machine.

## Resume checklist

1. `git log --oneline -8` and read this file.
2. `./harness/smoke.sh` then `./harness/acid.sh`. Both must be green before new
   work. A red acid halts new work until fixed or reverted.
3. `route -n get default` to see which interface you are actually measuring.
4. Pick the lowest-numbered incomplete sprint from the table above.
