# Network Troubleshooter + RustPacketFuzz - Visual Architecture

## System Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                  NETWORK TROUBLESHOOTER SUITE                       │
│                    "what the hell is up with mtu?"                  │
└─────────────────────────────────────────────────────────────────────┘
                                  │
                 ┌────────────────┴────────────────┐
                 │                                  │
         ┌───────▼────────┐              ┌────────▼───────────┐
         │  CLI Interface │              │   TUI Interface    │
         │  (main.rs)     │              │   (tui_main.rs)    │
         └───────┬────────┘              └────────┬───────────┘
                 │                                 │
                 └────────────┬───────────────────┘
                              │
         ┌────────────────────▼────────────────────────┐
         │         TEST ORCHESTRATOR                    │
         │  • Manages test execution                    │
         │  • Stores results per target/category        │
         │  • Triggers diagnosis engine                 │
         └────────────────────┬────────────────────────┘
                              │
      ┌───────────────────────┴───────────────────────────────────┐
      │                                                            │
┌─────▼─────────────────────────────────┐    ┌──────────────────▼─────┐
│   DIAGNOSTIC TEST CATEGORIES (1-9)    │    │   SECURITY TESTING     │
│                                       │    │   CATEGORY 10          │
│  1. MTU Tests                         │    │                        │
│  2. RTT/Latency                       │    │   RustPacketFuzz       │
│  3. Packet Loss                       │    │   ════════════════     │
│  4. Path Analysis                     │    │   • Segment fuzzing    │
│  5. TCP Health                        │    │   • Header manip       │
│  6. DNS Tests                         │    │   • Option corrupt     │
│  7. HTTPS Tests                       │    │   • Fragmentation      │
│  8. IPv6 Tests                        │    │   • PCAP export        │
│  9. App Tests                         │    │                        │
└───────────────────────────────────────┘    └────────────────────────┘
           │                                              │
           │ Real network                                 │ Synthetic
           │ diagnostics                                  │ packets
           │                                              │
           └──────────────────┬──────────────────────────┘
                              │
                   ┌──────────▼──────────┐
                   │  DIAGNOSIS ENGINE   │
                   │  • Correlate tests  │
                   │  • Apply rules      │
                   │  • Generate reports │
                   └──────────┬──────────┘
                              │
               ┌──────────────┼──────────────┐
               │              │              │
        ┌──────▼─────┐  ┌────▼────┐  ┌─────▼──────┐
        │ JSON Report│  │  PCAP   │  │ TUI Display│
        │  .json     │  │  .pcap  │  │  Terminal  │
        └────────────┘  └─────────┘  └────────────┘
```

---

## Test Category Flow

```
User Action (TUI)
       │
       ▼
   Press [F]                    ← Packet Fuzzing Button
       │
       ▼
┌──────────────────────────────────────────────┐
│        FUZZING PANEL APPEARS                 │
│                                              │
│  Select Mode:                                │
│    [1] Segment Size                          │
│    [2] Length Mismatch                       │
│    [3] TCP Options                           │
│    [4] Fragmentation                         │
│    [5] Checksum                              │
│    [A] Run All                               │
└──────────────────────────────────────────────┘
       │
       ▼ (User selects [1])
       │
┌──────▼─────────────────────────────────────┐
│   SEGMENT SIZE FUZZER                      │
│                                            │
│   For each size in [0,1,2...9,           │
│                     536,1460,1500,        │
│                     4096,9000,65535]:     │
│                                            │
│   1. Create PacketContext                 │
│   2. Build base layers                    │
│   3. Mutate payload size                  │
│   4. Serialize to bytes                   │
│   5. Write to PCAP                        │
└────────────────────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────────┐
│   PCAP FILE CREATED                      │
│                                          │
│   Path: reports/fuzz-github-DATE.pcap   │
│   Packets: 17                            │
│   Size: 2.3 KB                           │
│                                          │
│   [C] Copy path                          │
│   [O] Open in Wireshark                  │
└──────────────────────────────────────────┘
       │
       ▼
   NEXT STEPS (shown in UI)
       │
       ├─────► Wireshark: Open PCAP for manual inspection
       │
       ├─────► Suricata: suricata -r fuzz.pcap -l ./
       │
       ├─────► tcpreplay: Replay to live network
       │
       └─────► Add to regression test suite
```

---

## Fuzzing Module Architecture

```
src/fuzzing/
    │
    ├── mod.rs                    ← Public API
    │      pub fn run_fuzzing_campaign(...)
    │      pub enum FuzzMode { ... }
    │
    ├── context.rs                ← Packet metadata
    │      pub struct PacketContext {
    │          src_ip, dst_ip,
    │          src_mac, dst_mac,
    │          src_port, dst_port
    │      }
    │      impl build_base_layers(size) → (Eth, IP, TCP, Payload)
    │
    ├── builder.rs                ← Packet construction
    │      fn serialize_packet(...) → Vec<u8>
    │      fn apply_mutation(...) → Packet
    │
    ├── writer.rs                 ← PCAP output
    │      pub struct PcapWriter {
    │          file: File,
    │          packets_written: usize,
    │      }
    │      impl write_packet(&self, data: &[u8])
    │
    ├── cli.rs                    ← Command-line integration
    │      pub fn handle_fuzz_command(args: FuzzArgs)
    │
    └── fuzzers/                  ← Individual fuzzing strategies
        │
        ├── mod.rs
        │      pub trait Fuzzer {
        │          fn name(&self) -> &str;
        │          fn fuzz(&self, ctx: &PacketContext, writer: &mut PcapWriter);
        │      }
        │
        ├── segment_size.rs
        │      pub struct SegmentSizeFuzzer;
        │      impl Fuzzer for SegmentSizeFuzzer { ... }
        │
        ├── length_mismatch.rs
        │      pub struct LengthMismatchFuzzer;
        │      impl Fuzzer for LengthMismatchFuzzer { ... }
        │
        ├── tcp_options.rs
        │      pub struct TcpOptionFuzzer;
        │      impl Fuzzer for TcpOptionFuzzer { ... }
        │
        ├── fragmentation.rs
        │      pub struct FragmentationFuzzer;
        │      impl Fuzzer for FragmentationFuzzer { ... }
        │
        └── checksum.rs
               pub struct ChecksumFuzzer;
               impl Fuzzer for ChecksumFuzzer { ... }
```

---

## Data Flow: Packet Generation

```
1. User Input
   ┌──────────────────────┐
   │ Target: github.com   │
   │ Mode: Segment Size   │
   └──────────────────────┘
           │
           ▼
2. PacketContext Creation
   ┌─────────────────────────────┐
   │ src_ip: 192.168.1.100       │
   │ dst_ip: 140.82.121.4        │
   │ src_mac: aa:bb:cc:dd:ee:ff  │
   │ dst_mac: 11:22:33:44:55:66  │
   │ src_port: 12345             │
   │ dst_port: 443               │
   └─────────────────────────────┘
           │
           ▼
3. Base Layer Generation (for each size)
   ┌─────────────────────────────────────┐
   │ Ethernet Header (14 bytes)          │
   │   src: aa:bb:cc:dd:ee:ff            │
   │   dst: 11:22:33:44:55:66            │
   │   type: 0x0800 (IPv4)               │
   ├─────────────────────────────────────┤
   │ IPv4 Header (20 bytes)              │
   │   src: 192.168.1.100                │
   │   dst: 140.82.121.4                 │
   │   total_len: 20 + 20 + payload_len  │
   │   protocol: 6 (TCP)                 │
   │   TTL: 64                           │
   ├─────────────────────────────────────┤
   │ TCP Header (20 bytes)               │
   │   src_port: 12345                   │
   │   dst_port: 443                     │
   │   seq: 0                            │
   │   flags: SYN                        │
   │   window: 65535                     │
   ├─────────────────────────────────────┤
   │ Payload (N bytes)                   │
   │   Random data (0x41414141...)       │
   └─────────────────────────────────────┘
           │
           ▼
4. Mutation (Fuzzer-Specific)
   
   SegmentSizeFuzzer:
   ┌──────────────────────────┐
   │ Payload size = 0         │  → Packet #1
   │ Payload size = 1         │  → Packet #2
   │ Payload size = 2         │  → Packet #3
   │ ...                      │
   │ Payload size = 536       │  → Packet #10
   │ Payload size = 1460      │  → Packet #11
   │ Payload size = 65535     │  → Packet #17
   └──────────────────────────┘
           │
           ▼
5. Serialization
   ┌────────────────────────────┐
   │ Vec<u8>:                   │
   │ [0xaa, 0xbb, 0xcc, ...     │
   │  0x45, 0x00, 0x00, ...     │  ← Raw bytes
   │  0xc0, 0xa8, 0x01, ...]    │
   └────────────────────────────┘
           │
           ▼
6. PCAP Writing
   ┌──────────────────────────────────┐
   │ PCAP Global Header               │
   │   magic: 0xa1b2c3d4              │
   │   version: 2.4                   │
   │   snaplen: 65535                 │
   │   linktype: 1 (Ethernet)         │
   ├──────────────────────────────────┤
   │ Packet #1 Header                 │
   │   ts_sec: 1702156800             │
   │   ts_usec: 123456                │
   │   incl_len: 54                   │
   │   orig_len: 54                   │
   ├──────────────────────────────────┤
   │ Packet #1 Data (54 bytes)        │
   ├──────────────────────────────────┤
   │ Packet #2 Header                 │
   │ ...                              │
   └──────────────────────────────────┘
           │
           ▼
7. Output File
   reports/fuzz-github-20251209.pcap
```

---

## Integration with Existing Tests

```
┌──────────────────────────────────────────────────────────────┐
│                    SCENARIO: MTU Blackhole                   │
└──────────────────────────────────────────────────────────────┘

Step 1: Run MTU Test (Category 1)
   │
   ▼
┌────────────────────────────────┐
│ MTU Test Result:               │
│ ICMP MTU: 1500                 │
│ TCP MTU: 1500                  │
│ Path MTU: 1400 (at hop 3)      │
└────────────────────────────────┘
   │
   ▼
Step 2: Run HTTPS Test (Category 7)
   │
   ▼
┌────────────────────────────────┐
│ HTTPS Test Result:             │
│ TCP Connect: ✓                 │
│ TLS Handshake: TIMEOUT         │
│ Diagnosis: MTU BLACKHOLE       │
└────────────────────────────────┘
   │
   ▼
Step 3: Diagnosis Engine Correlates
   │
   ▼
┌─────────────────────────────────────────┐
│ CORRELATION:                            │
│ • ICMP MTU shows 1500 (misleading)      │
│ • Path MTU actually 1400 (hop 3 drop)   │
│ • TLS fails (large cert chain)          │
│ → CLASSIC MTU BLACKHOLE                 │
└─────────────────────────────────────────┘
   │
   ▼
Step 4: Generate Test Cases (RustPacketFuzz)
   │
   ▼
┌─────────────────────────────────────────┐
│ RustPacketFuzz Campaign:                │
│ • Generate packets: 1399, 1400, 1401   │
│ • Generate packets: 1500               │
│ • Export to PCAP                       │
│                                         │
│ Purpose:                                │
│ • Validate firewall drops >1400         │
│ • Create regression test                │
│ • Demonstrate to vendor                 │
└─────────────────────────────────────────┘
   │
   ▼
Step 5: Validation
   │
   ▼
┌─────────────────────────────────────────┐
│ tcpreplay -i eth0 mtu-test.pcap         │
│ tcpdump -i eth1 -w received.pcap        │
│                                         │
│ Result:                                 │
│ • 1399-byte packets: ✓ received        │
│ • 1400-byte packets: ✓ received        │
│ • 1401-byte packets: ✗ dropped         │
│ • 1500-byte packets: ✗ dropped         │
│                                         │
│ → Confirms path MTU = 1400              │
└─────────────────────────────────────────┘
```

---

## TUI Navigation Flow

```
┌─────────────────────────────────────────────────────────────┐
│                       MAIN DASHBOARD                        │
│                                                             │
│  Target: github.com                                         │
│                                                             │
│  [1] MTU  [2] RTT  [3] Loss  [4] Path  [5] TCP            │
│  [6] DNS  [7] HTTPS [8] IPv6 [9] App  [F] Fuzzing         │
│  [0] RUN ALL                                               │
│                                                             │
│  Results: (per category)                                    │
│  Diagnosis: (correlated issues)                             │
└─────────────────────────────────────────────────────────────┘
                            │
                            │ User presses [F]
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                    FUZZING CAMPAIGN PANEL                   │
│                                                             │
│  Target: github.com                                         │
│                                                             │
│  Fuzzing Modes:                                             │
│  [1] Segment Size         Status: - Not run                 │
│  [2] Length Mismatch      Status: - Not run                 │
│  [3] TCP Options          Status: - Not run                 │
│  [4] Fragmentation        Status: - Not run                 │
│  [5] Checksum             Status: - Not run                 │
│  [A] Run All Modes                                          │
│                                                             │
│  Output: reports/fuzz-github-DATE.pcap                      │
│                                                             │
│  [ESC] Back    [?] Help                                     │
└─────────────────────────────────────────────────────────────┘
                            │
                            │ User presses [1]
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                   FUZZING IN PROGRESS                       │
│                                                             │
│  Mode: Segment Size Fuzzing                                 │
│                                                             │
│  Progress: ████████████░░░░░░░░ 65%                        │
│  Packets Generated: 11 / 17                                 │
│  Current: Testing 4096-byte segments                        │
│                                                             │
│  Time Elapsed: 0.8s                                         │
│  Est. Remaining: 0.4s                                       │
└─────────────────────────────────────────────────────────────┘
                            │
                            │ Completes
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                   FUZZING COMPLETE                          │
│                                                             │
│  Mode: Segment Size Fuzzing                                 │
│  Status: ✓ Complete                                         │
│                                                             │
│  Results:                                                   │
│  • Packets Generated: 17                                    │
│  • PCAP File: reports/fuzz-github-20251209.pcap            │
│  • File Size: 2.3 KB                                       │
│                                                             │
│  Next Steps:                                                │
│  1. Open in Wireshark: [O]                                  │
│  2. Feed to Suricata: [S]                                   │
│  3. Copy path: [C]                                          │
│                                                             │
│  Commands:                                                  │
│  suricata -r fuzz-github-20251209.pcap -l ./               │
│                                                             │
│  [ESC] Back    [R] Rerun    [A] Run Another Mode           │
└─────────────────────────────────────────────────────────────┘
```

---

## Dependency Graph

```
mtu-detective
    │
    ├─── clap (CLI parsing)
    ├─── socket2 (raw sockets - existing tests)
    ├─── rayon (parallel test execution)
    ├─── colored (terminal output)
    │
    ├─── tokio (async runtime - HTTPS test)
    ├─── quinn (QUIC testing)
    ├─── rustls (TLS testing)
    │
    ├─── ratatui (TUI framework)
    ├─── crossterm (terminal control)
    │
    ├─── serde/serde_json (JSON reports)
    ├─── chrono (timestamps)
    │
    └─── RustPacketFuzz Dependencies:
         │
         ├─── etherparse
         │    Purpose: Build Ethernet/IP/TCP headers
         │    Why: Low-level control, allows invalid packets
         │    Version: 0.15
         │
         ├─── pcap-file
         │    Purpose: Write PCAP files
         │    Why: Pure Rust, no C deps, simple API
         │    Version: 3.0
         │
         ├─── thiserror
         │    Purpose: Error handling
         │    Why: Ergonomic error definitions
         │    Version: 1.0
         │
         └─── rand (already present)
              Purpose: Random payload generation
```

---

## Comparison: Before vs After

### Before Integration
```
Network Troubleshooter
├── 9 diagnostic test categories
├── Reports: JSON only
├── Output: Terminal + JSON
└── Use case: Diagnose real network issues
```

### After Integration
```
Network Troubleshooter + RustPacketFuzz
├── 9 diagnostic test categories
├── 1 security testing category (fuzzing)
├── Reports: JSON + PCAP
├── Output: Terminal + JSON + PCAP
├── Use case #1: Diagnose real network issues
├── Use case #2: Security testing (parser validation)
├── Use case #3: Regression test generation
└── Use case #4: Vendor demonstrations
```

---

## Security Testing Workflow

```
┌─────────────────────────────────────────────────────────┐
│               PARSER VULNERABILITY TESTING              │
└─────────────────────────────────────────────────────────┘

Phase 1: Generate Test Cases
   │
   ├─► RustPacketFuzz: Generate 1000-packet PCAP
   │   • Segment sizes: 0-65535 (random)
   │   • Header mismatches: 20% of packets
   │   • Corrupt options: 10% of packets
   │   • Invalid checksums: 5% of packets
   │
   └─► Output: stress-test.pcap

Phase 2: Baseline Testing
   │
   ├─► Feed to Suricata:
   │   suricata -r stress-test.pcap -l ./baseline/
   │
   └─► Capture:
       • Alerts triggered
       • CPU usage
       • Memory usage
       • Processing time

Phase 3: Identify Anomalies
   │
   ├─► Check for:
   │   • Crashes (dmesg, core dumps)
   │   • Hangs (processing time >> expected)
   │   • Memory leaks (valgrind)
   │   • Unexpected alerts
   │
   └─► Document findings

Phase 4: Isolate Vulnerable Packets
   │
   ├─► For each anomaly:
   │   • Identify packet # that caused issue
   │   • Extract to separate PCAP
   │   • Analyze in Wireshark
   │
   └─► Create minimal reproduction case

Phase 5: Report & Remediate
   │
   ├─► Submit to vendor:
   │   • Vulnerability description
   │   • PCAP proof of concept
   │   • Impact analysis
   │   • Suggested fix
   │
   └─► Add to regression suite
```

---

## Performance Characteristics

```
Fuzzing Performance (Estimated)
────────────────────────────────

Segment Size Fuzzer (17 packets):
   Generation time: ~0.5s
   PCAP size: ~2.5 KB
   Memory usage: <10 MB

Length Mismatch Fuzzer (10 packets):
   Generation time: ~0.3s
   PCAP size: ~1.5 KB
   Memory usage: <10 MB

TCP Options Fuzzer (15 packets):
   Generation time: ~0.4s
   PCAP size: ~2.0 KB
   Memory usage: <10 MB

Full Campaign (100 packets):
   Generation time: ~2s
   PCAP size: ~15 KB
   Memory usage: <20 MB

Stress Test (1000 packets):
   Generation time: ~15s
   PCAP size: ~150 KB
   Memory usage: ~50 MB

────────────────────────────────
All operations single-threaded.
Could parallelize for 3-5x speedup.
```

---

## Future Expansion (Post-MVP)

```
v1.0 (MVP)
└── TCP Fuzzing + PCAP Export

v1.1
├── Live packet injection (requires root)
├── Real-time response capture
└── Automated feedback loop

v2.0
├── UDP fuzzing (DNS, DHCP)
├── ICMP fuzzing (router ads, redirects)
├── QUIC fuzzing (key updates, migration)
└── IPv6 fuzzing

v3.0
├── Application-layer fuzzing
│   ├── HTTP headers
│   ├── TLS handshakes
│   └── DNS responses
├── Grammar-based fuzzing
├── Coverage-guided fuzzing (AFL-style)
└── ML-driven mutation strategies

v4.0
├── Distributed fuzzing (multiple nodes)
├── Cloud integration (fuzz as a service)
└── Automated triage & crash analysis
```

---

## Summary

RustPacketFuzz is now architecturally integrated as Test Category #10, providing:

✓ Security testing capabilities
✓ PCAP export for validation
✓ Parser stress testing
✓ Regression test generation
✓ Seamless TUI integration
✓ CLI access for automation

Ready for implementation.

