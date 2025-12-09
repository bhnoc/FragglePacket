# MTU Detective - Enterprise Architecture

## Vision
The most comprehensive, enterprise-grade MTU analysis tool that leaves no stone unturned.

---

## Testing Modules (Planned)

### Module 1: ICMP Prober (Current)
- [x] ICMP Echo with DF bit
- [x] Binary search MTU discovery
- [x] Parallel testing
- [ ] Per-hop MTU via tracepath integration
- [ ] ICMP timestamp/netmask variants

### Module 2: TCP Prober (Current)
- [x] TCP connect test
- [x] Basic data transfer probe
- [ ] MSS capture and analysis
- [ ] TLS handshake size detection
- [ ] HTTP/2 and HTTP/3 frame size analysis
- [ ] TCP window scale factor detection

### Module 3: UDP Prober (NEW)
- [ ] UDP datagram size testing
- [ ] DPLPMTUD implementation (RFC 8899)
- [ ] DNS EDNS0 buffer probing
- [ ] VoIP/RTP path testing
- [ ] UDP traceroute variant

### Module 4: QUIC Prober (NEW)
- [ ] QUIC connection MTU discovery
- [ ] QUIC PING frame probing
- [ ] Detect QUIC-specific middlebox issues

### Module 5: Tracepath Integration (NEW)
- [ ] Per-hop MTU analysis
- [ ] Identify exact device causing MTU drop
- [ ] Correlate with ICMP/TCP findings
- [ ] ASN/geolocation for each hop

### Module 6: Packet Capture Analysis (NEW)
- [ ] Passive MSS observation
- [ ] Fragmentation detection
- [ ] ICMP error message capture
- [ ] TCP retransmission correlation

### Module 7: Application Layer Testing (NEW)
- [ ] HTTPS large object fetch
- [ ] WebSocket frame size test
- [ ] API endpoint testing
- [ ] CDN-specific tests

### Module 8: Tunnel Detector (NEW)
- [ ] Detect if traffic is tunneled
- [ ] Estimate tunnel overhead
- [ ] Identify tunnel type from signatures
- [ ] Nested tunnel detection

### Module 9: Packet Fuzzing (RustPacketFuzz)
- [ ] TCP segment size fuzzing
- [ ] Header length mismatch attacks
- [ ] TCP option corruption
- [ ] IP fragmentation edge cases
- [ ] Checksum validation testing
- [ ] PCAP export for parser testing

---

## Target Categories

### targets.txt Structure (Enhanced)
```
# Format: target,description,tcp_port,udp_port,priority,category
8.8.8.8,Google DNS,0,53,1,dns
github.com,GitHub,443,0,1,developer
outlook.office365.com,M365,443,0,1,microsoft
stun.l.google.com,Google STUN,0,19302,2,voip
```

### Categories
1. **DNS** - UDP 53, verify large responses work
2. **Web** - TCP 443, standard HTTPS
3. **Microsoft 365** - Critical for enterprise
4. **Google Workspace** - Alternative productivity
5. **Developer** - GitHub, GitLab, package registries
6. **VoIP/RTC** - STUN/TURN servers, Teams media
7. **Cloud** - AWS, Azure, GCP endpoints
8. **CDN** - Cloudflare, Akamai, Fastly
9. **Security** - Zscaler, Netskope test endpoints
10. **Custom** - User-defined targets

---

## Output Formats

### Interactive (Current)
- Colored terminal output
- Real-time progress
- Summary with verdict

### JSON (NEW)
```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "source_ip": "192.168.1.100",
  "tests": [
    {
      "target": "github.com",
      "icmp_mtu": 1500,
      "tcp_mtu": 1500,
      "udp_mtu": null,
      "per_hop": [...]
    }
  ],
  "verdict": "PASS",
  "recommended_mtu": 1500,
  "recommended_mss": 1460
}
```

### HTML Report (NEW)
- Visual graphs
- Per-target breakdown
- Trend over time (if multiple runs)

### CSV (NEW)
- Spreadsheet import
- Historical tracking

---

## Deployment Modes

### Mode 1: Standalone CLI (Current)
```bash
./mtu-detective kitchen-sink
```

### Mode 2: Docker Container (NEW)
```bash
docker run --net=host mtu-detective
```

### Mode 3: Kubernetes Job (NEW)
```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: mtu-test
spec:
  template:
    spec:
      containers:
      - name: mtu-detective
        image: mtu-detective:latest
        securityContext:
          capabilities:
            add: ["NET_RAW"]
```

### Mode 4: Agent Mode (NEW)
- Long-running daemon
- Periodic testing
- Alert on changes
- Prometheus metrics export

### Mode 5: Web UI (NEW)
- Browser-based interface
- No installation required
- WebRTC-based testing from browser

---

## Implementation Phases

### Phase 1: Foundation (Current)
- [x] ICMP testing
- [x] TCP testing
- [x] Parallel execution
- [x] Statistical analysis
- [x] Basic verdict

### Phase 2: Protocol Expansion
- [ ] UDP probing module
- [ ] tracepath integration
- [ ] Enhanced TCP MSS analysis
- [ ] QUIC support

### Phase 3: Intelligence
- [ ] Per-hop MTU breakdown
- [ ] Automatic tunnel detection
- [ ] VPN overhead auto-calculation
- [ ] Black hole detection improvements

### Phase 4: Enterprise Features
- [ ] JSON/HTML/CSV output
- [ ] Configuration file
- [ ] Scheduled runs
- [ ] Alerting integration

### Phase 5: Distribution
- [ ] Docker image
- [ ] Package for apt/yum/brew
- [ ] Windows build
- [ ] macOS build

---

## Dependencies (Planned)

### Rust Crates
```toml
# Current
clap = "4.0"           # CLI
socket2 = "0.5"        # Raw sockets
rayon = "1.8"          # Parallelism
colored = "2"          # Terminal colors

# Phase 2
tokio = "1"            # Async runtime
quinn = "0.10"         # QUIC implementation
trust-dns-client = "0.23"  # DNS probing

# Phase 3
pnet = "0.34"          # Packet parsing
pcap = "1.0"           # Packet capture

# Phase 4
serde = "1.0"          # Serialization
serde_json = "1.0"     # JSON output
tera = "1.19"          # HTML templates

# RustPacketFuzz
etherparse = "0.15"    # Packet crafting/manipulation
pcap-file = "3.0"      # PCAP file writing
thiserror = "1.0"      # Error handling
```

### External Tools (Optional Integration)
- tracepath (Linux iputils)
- tcpdump/libpcap
- nmap (for advanced probing)
- curl (HTTP testing)

---

## File Structure
```
mtu/
├── Cargo.toml
├── main.rs                 # Entry point
├── start.sh                # Easy launcher
├── targets.txt             # Test targets
├── docs/
│   ├── RFC-REFERENCE.md    # RFC documentation
│   ├── MTU-TESTING-METHODS.md
│   ├── TUNNEL-OVERHEADS.md
│   ├── ARCHITECTURE.md     # This file
│   └── RUSTPACKETFUZZ-INTEGRATION.md  # Fuzzing module
├── src/
│   ├── lib.rs             # Library root (future)
│   ├── probers/
│   │   ├── mod.rs
│   │   ├── icmp.rs
│   │   ├── tcp.rs
│   │   ├── udp.rs
│   │   └── quic.rs
│   ├── analysis/
│   │   ├── mod.rs
│   │   ├── statistics.rs
│   │   └── verdict.rs
│   ├── output/
│   │   ├── mod.rs
│   │   ├── terminal.rs
│   │   ├── json.rs
│   │   └── html.rs
│   └── fuzzing/           # RustPacketFuzz
│       ├── mod.rs
│       ├── context.rs
│       ├── builder.rs
│       ├── writer.rs
│       ├── fuzzers/
│       │   ├── mod.rs
│       │   ├── segment_size.rs
│       │   ├── length_mismatch.rs
│       │   ├── tcp_options.rs
│       │   ├── fragmentation.rs
│       │   └── checksum.rs
│       └── cli.rs
└── tests/
    └── integration_tests.rs
```

---

## Success Criteria

### Functional
- Detect MTU issues with 99% accuracy
- No false positives (don't recommend changes when none needed)
- Identify exact cause (which hop, which protocol)
- Work without root (TCP/UDP modes)

### Performance
- Test 50 targets in < 30 seconds
- Minimal network overhead
- Low CPU usage

### Usability
- Zero configuration default
- One command to run everything
- Clear, actionable output
- Enterprise report generation


