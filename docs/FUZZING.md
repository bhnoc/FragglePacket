# Fuzzing, Replay, Capture, and Active Probes

All native packet work lives under `src/fuzzing/`. Two FuzzMode enums exist today; the canonical one is `fraggle_packet::fuzzing::FuzzMode` in `src/fuzzing/mod.rs`. The wrapper in `src/network_tests/fuzzing.rs` adds an `All` variant for the NetworkTest path.

## FuzzMode variants

| Variant | Strategy |
| --- | --- |
| SegmentSize | Varies TCP segment payload size from zero up through 65535 bytes, including MTU boundaries |
| LengthMismatch | Crafts IP packets whose header length field disagrees with total length (Heartbleed-style) |
| TcpOptions | Emits malformed MSS, SACK, and Window Scale options, including truncated and oversized encodings |
| Fragmentation | Produces overlapping, tiny, and last-fragment-missing IP fragment sets |
| Checksum | Pairs correct and deliberately wrong IP/TCP/UDP checksums to exercise parsers and offload paths |
| All (network_tests wrapper only) | Runs every fuzzer in sequence into the same PCAP |

`FuzzMode::from_str` in the mod.rs accepts both the short names (`segment`, `length`, `options`, `frag`, `checksum`) and the hyphenated forms (`segment-size`, `length-mismatch`, `tcp-options`, `fragmentation`). The wrapper additionally accepts `all`.

## PacketContext

```rust
PacketContext::new("192.168.1.100", "8.8.8.8")?
```

Holds source and destination IPv4 addresses plus baseline MAC and port values. Fuzzers consume it to produce layered packets with `etherparse`. Defined in `src/fuzzing/context.rs`.

## Packet DSL

`src/fuzzing/dsl.rs` exposes a Scapy-style layered builder.

Layer constructors:

* `Ether::new()`
* `Vlan::new()`
* `Ip::new()`, `Ipv6::new()`
* `Tcp::new()`, `Udp::new()`
* `Icmp::new()`, `Icmpv6::new()`
* `Raw::of_size(n, byte)` for payload blobs

Composition uses the division operator, just like Scapy:

```rust
let pkt = Ether::new()
    / Ip::new().dst_addr("1.1.1.1".parse()?).df()
    / Tcp::new().dport(443).syn().options(vec![TcpOpt::Mss(1460), TcpOpt::SAckOK])
    / Raw::of_size(32, b'X');

println!("{}", pkt.summary());
println!("{}", pkt.hexdump()?);
let bytes = pkt.build()?;
```

Flags exposed on `Ip` include `df()`, `mf()`, `frag_offset()`, `ttl()`. `Tcp` covers `syn()`, `ack()`, `fin()`, `rst()`, `psh()`, `urg()`, plus `options()` taking a `Vec<TcpOpt>`.

Run the `fraggle-packet dsl-demo` subcommand to see a summary and hexdump without touching the wire.

## PCAP writer

`src/fuzzing/writer.rs` wraps `pcap-file` 3.0.0-rc1. `PcapWriter::new(path)` opens the file, `write_packet(bytes, timestamp)` appends, and drop finalizes. Every fuzzer writes through this writer, producing standard libpcap files.

## Replay

`src/fuzzing/replay.rs` reads any PCAP and transmits each packet onto a raw socket.

| Option | Field | Purpose |
| --- | --- | --- |
| Interface | `iface` | Required on Linux, picks outbound NIC for AF_PACKET |
| Packets per second | `pps` | Optional rate limit; falls back to as-fast-as-possible |
| Loop count | `loop_count` | Repeat the full capture N times |
| Rewrite src/dst MAC | `rewrite_src_mac`, `rewrite_dst_mac` | L2 overwrite before send |
| Rewrite src/dst IP | `rewrite_src_ip`, `rewrite_dst_ip` | L3 overwrite with IPv4 checksum fixup |
| Preserve timing | `preserve_timing` | Honor original inter-packet intervals when set |

Backends:

| Platform | Socket |
| --- | --- |
| Linux | AF_PACKET, SOCK_RAW, ETH_P_ALL (layer 2) |
| macOS, other BSDs | IPPROTO_RAW with IP_HDRINCL (layer 3, Ethernet header stripped before send) |
| Others | Returns `ReplayError::Unsupported` |

Raw sockets require root, `CAP_NET_RAW` plus `CAP_NET_ADMIN`, or an elevated process on Windows.

## Capture

`src/fuzzing/capture.rs` exposes a minimal passive sniffer.

* Linux uses AF_PACKET with ETH_P_ALL.
* macOS opens the next available `/dev/bpfN` and sets `BIOCSETIF`.
* Other platforms return unsupported.

`start_capture(iface, filter: FilterFn)` returns a `CaptureHandle` that streams `CapturedFrame` structs through a `std::sync::mpsc` channel. Filters run in userspace; no BPF compiler.

## Active probe

`src/fuzzing/probe.rs` fuses capture and replay to mimic Scapy `sr1`.

| Entry point | Behavior |
| --- | --- |
| `send_and_wait(iface, packet, filter, timeout)` | Sends one packet, blocks for a matching response |
| `active_pmtu_probe(iface, target, min, max, timeout)` | Binary-searches PMTU with DF-bit pings, watches ICMP type 3 code 4 |

Return type `ActivePmtuReport { samples_tried, frag_needed_reported, estimated_mtu }` surfaces every probe size plus the final estimate.

## CLI entry points

| Subcommand | Backing module |
| --- | --- |
| `fuzz` | `src/bin/cli/fuzzing.rs` -> `fuzzing::run_campaign` |
| `dsl-demo` | Inline in `main.rs` using `fuzzing::dsl` |
| `replay` | `fuzzing::replay::replay_pcap` with `ReplayOptions` |
| `probe` | `fuzzing::probe::active_pmtu_probe` |

## Desktop probes panel

The Probes tab exposes DSL Demo, PCAP Replay, Active PMTU Probe, Scenario Runner, and Prometheus Metrics in one screen. Replay and Active PMTU Probe buttons disable themselves when `AppState::is_privileged` is false and surface a toast pointing at the setcap hint.
