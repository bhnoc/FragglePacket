# Network Troubleshooter - Comprehensive Plan

## Executive Summary
Transform "what the hell is up with mtu?" from MTU-focused tool into comprehensive network diagnostics platform testing all OSI layers.

---

## Current State Analysis

### Strengths
- Working MTU discovery (ICMP, TCP, UDP, QUIC)
- Parallel testing infrastructure
- TUI with retro green aesthetic
- Per-target result tracking
- VPN overhead calculator
- Basic tracepath integration

### Gaps from todo.txt
1. **IPv6** - not tested
2. **HTTPS validation** - can ping but not browse issue
3. **TCP segmentation** - firewall segments to MTU 100, need to detect
4. **Layer 3-7 diagnostics** - RTT, jitter, packet loss, DNS timing, TLS handshake, etc.
5. **TUI limitations** - runs all tests auto, needs selective test buttons

---

## Architecture: Test Categories

### Category 1: MTU & Fragmentation (Layer 2-3) ✓ EXISTING
**Purpose:** Path MTU discovery and fragmentation detection

**Tests:**
- ICMP Echo with DF bit (existing)
- TCP MSS negotiation (existing)
- UDP datagram sizing (existing)
- QUIC MTU probe (existing)
- IPv6 MTU discovery (NEW)
- Per-hop MTU via tracepath (partial)

**Button:** `[MTU Tests]`

---

### Category 2: RTT & Latency (Layer 3)
**Purpose:** Measure round-trip time, identify high latency hops

**Tests:**
- Basic ping latency (min/max/avg/stddev)
- Per-hop latency (traceroute/mtr)
- Latency under load (detect bufferbloat)
- Jitter calculation (variance in RTT)
- Geographic latency correlation

**Implementation:**
```rust
struct LatencyResult {
    min_ms: f64,
    max_ms: f64,
    avg_ms: f64,
    stddev_ms: f64,
    jitter_ms: f64,
    packet_count: usize,
}

fn measure_latency(target: IpAddr, count: usize) -> LatencyResult {
    // Send count ICMP packets
    // Calculate statistics
    // Return comprehensive latency profile
}
```

**Button:** `[RTT/Latency]`

---

### Category 3: Packet Loss & Reliability (Layer 3)
**Purpose:** Detect packet loss, identify lossy hops

**Tests:**
- ICMP packet loss % (send 100 pings)
- TCP connection success rate
- Per-hop loss detection (mtr-style)
- Loss pattern detection (random vs burst)
- Bidirectional loss (if possible)

**Detection:**
- Even 1% loss = significant for TCP
- Burst loss = buffer overflow likely
- Random loss = physical/wireless issue

**Button:** `[Packet Loss]`

---

### Category 4: Routing & Path Analysis (Layer 3)
**Purpose:** Analyze routing path, detect loops, identify problematic hops

**Tests:**
- Traceroute/tracepath (existing partial)
- TTL analysis
- Routing loop detection
- AS path identification
- Route stability (run multiple times)
- Asymmetric routing detection

**Implementation:**
```rust
struct PathAnalysis {
    hops: Vec<HopDetail>,
    total_hops: u8,
    has_loops: bool,
    loop_hops: Vec<u8>,
    as_path: Vec<String>,
    mtu_drop_hop: Option<u8>,
}
```

**Button:** `[Path Analysis]`

---

### Category 5: TCP Health (Layer 4)
**Purpose:** TCP connection quality, retransmissions, windowing

**Tests:**
- TCP 3-way handshake timing
- TCP retransmission detection (via netstat -s or tcpdump)
- TCP window size analysis
- Zero window events
- Port connectivity matrix (80, 443, 22, custom)
- Bandwidth estimation (iperf3 style if server available)

**The BIG issue from todo.txt:**
> "firewall segments all tcp traffic to 100"
> Need to detect if TCP packets are being artificially limited

**Detection approach:**
```rust
// Send large TCP payload, monitor fragmentation
// Compare effective throughput to bandwidth
// Check for unusual segment sizes in tcpdump
```

**Button:** `[TCP Tests]`

---

### Category 6: DNS Resolution (Layer 7)
**Purpose:** DNS performance and reliability

**Tests:**
- DNS lookup time for target
- Multiple DNS server comparison (8.8.8.8, 1.1.1.1, system)
- DNS timeout detection
- DNSSEC validation
- IPv4 vs IPv6 resolution
- Reverse DNS lookup

**Implementation:**
```rust
struct DnsResult {
    resolution_time_ms: u64,
    servers_tried: Vec<String>,
    ipv4_addresses: Vec<IpAddr>,
    ipv6_addresses: Vec<IpAddr>,
    ttl: u32,
    authoritative: bool,
}
```

**Button:** `[DNS Tests]`

---

### Category 7: HTTPS/TLS (Layer 7)
**Purpose:** Full HTTPS stack validation - the "can ping but can't browse" issue

**Tests:**
1. TCP connect to :443
2. TLS handshake timing
3. TLS version negotiated
4. Certificate validation
5. Certificate chain length
6. HTTP request/response
7. Time to First Byte (TTFB)
8. Full page fetch
9. HTTP status codes

**This solves the todo.txt issue:**
> "ping www.github.com works but can't browse - HTTPS issue"
> "request going out, seeing SYN ACK but then nothing back"

**Detection:**
```rust
enum HttpsIssue {
    TcpConnectFails,           // Port 443 blocked
    TlsHandshakeFails,         // TLS/cert issue
    TlsHandshakeTimeout,       // MTU blackhole during handshake
    HttpRequestTimeout,        // MTU blackhole during data transfer
    CertificateError,          // Invalid cert
    HttpError(u16),            // Got HTTP error code
    Success { ttfb_ms: u64 },
}

fn diagnose_https(target: &str) -> HttpsIssue {
    // Step-by-step diagnosis
    // 1. Can we TCP connect?
    // 2. Can we TLS handshake?
    // 3. Can we send HTTP request?
    // 4. Can we receive response?
}
```

**This is critical - test each stage separately**

**Button:** `[HTTPS Tests]`

---

### Category 8: IPv6 Support (Layer 3)
**Purpose:** Test IPv6 connectivity and MTU

**Tests:**
- IPv6 reachability
- IPv6 MTU discovery
- IPv6 vs IPv4 latency comparison
- Dual-stack behavior
- IPv6 DNS (AAAA records)

**Button:** `[IPv6 Tests]`

---

### Category 9: Application-Specific (Layer 7)
**Purpose:** Test specific app protocols

**Tests:**
- HTTP/2 support
- HTTP/3/QUIC support
- WebSocket connectivity
- SMTP (port 25, 587)
- SSH (port 22)
- RDP (port 3389)
- Custom port testing

**Button:** `[App Tests]`

---

### Category 10: Packet Fuzzing (RustPacketFuzz)
**Purpose:** Security testing via malformed packet generation

**Tests:**
- TCP segment size fuzzing (0-65535 bytes)
- Header length mismatch (IP header lies about size)
- TCP option corruption (MSS, SACK, Window Scale)
- IP fragmentation edge cases
- Checksum validation (valid/invalid)
- PCAP export for parser stress testing

**Use Cases:**
1. **Parser vulnerability testing** - Feed to Suricata/Snort
2. **Firewall validation** - Verify edge case handling
3. **Regression testing** - Create test suite for QA
4. **MTU correlation** - Generate packets at exact MTU boundaries

**Implementation:**
```rust
pub struct FuzzingResult {
    packets_generated: usize,
    pcap_file: PathBuf,
    fuzzing_modes: Vec<FuzzMode>,
    anomalies_detected: Vec<String>,
}

pub enum FuzzMode {
    SegmentSize,      // Vary payload 0-65535
    LengthMismatch,   // Header.len != actual
    TcpOptions,       // Corrupt MSS/SACK/WS
    Fragmentation,    // IP fragment edge cases
    Checksum,         // Valid vs invalid
}
```

**Button:** `[F] Packet Fuzzing`

---

## TUI Design - Dashboard Layout

```
╔══════════════════════════════════════════════════════════════════════════════╗
║              what the hell is up with mtu? - NETWORK TROUBLESHOOTER          ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  Selected Target: github.com (142.250.185.46)           [Up/Down to change] ║
║                                                                              ║
║  ┌─────────────────────────────── TEST SUITES ───────────────────────────┐  ║
║  │                                                                         │  ║
║  │   [1] MTU Tests         [2] RTT/Latency      [3] Packet Loss          │  ║
║  │   [4] Path Analysis     [5] TCP Tests        [6] DNS Tests            │  ║
║  │   [7] HTTPS Tests       [8] IPv6 Tests       [9] App Tests            │  ║
║  │   [F] Packet Fuzzing    [0] RUN ALL                                   │  ║
║  │                                                                         │  ║
║  │   [A] Run ALL MTU across all targets                                  │  ║
║  │   [B] Run ALL RTT across all targets                                  │  ║
║  │                                                                         │  ║
║  └─────────────────────────────────────────────────────────────────────────┘  ║
║                                                                              ║
║  ┌──────────────────────── RESULTS: github.com ──────────────────────────┐  ║
║  │                                                                         │  ║
║  │  MTU Tests:         ✓ Complete  [View Details: Enter]                 │  ║
║  │    ICMP MTU:  1500   TCP MTU: 1500   UDP MTU: 1500   QUIC: 1420      │  ║
║  │                                                                         │  ║
║  │  RTT/Latency:       ✓ Complete  [View Details: Enter]                 │  ║
║  │    Min: 12ms   Avg: 15ms   Max: 23ms   Jitter: 2.1ms                 │  ║
║  │                                                                         │  ║
║  │  Packet Loss:       ✓ Complete  [View Details: Enter]                 │  ║
║  │    Loss: 0.0%   (0/100 packets)                                       │  ║
║  │                                                                         │  ║
║  │  Path Analysis:     ⚠ Issues    [View Details: Enter]                 │  ║
║  │    Hops: 12   MTU drop at hop 3 (1500→1400)                          │  ║
║  │                                                                         │  ║
║  │  TCP Tests:         ✓ Complete  [View Details: Enter]                 │  ║
║  │    Connect: 14ms   Retrans: 0   Window: 65535                        │  ║
║  │                                                                         │  ║
║  │  DNS Tests:         ✓ Complete  [View Details: Enter]                 │  ║
║  │    Resolution: 8ms   IPv4: ✓   IPv6: ✓                               │  ║
║  │                                                                         │  ║
║  │  HTTPS Tests:       ✗ FAILED    [View Details: Enter]                 │  ║
║  │    TCP: OK   TLS Handshake: TIMEOUT (MTU blackhole suspected)        │  ║
║  │                                                                         │  ║
║  │  IPv6 Tests:        - Not Run   [Press 8 to run]                      │  ║
║  │                                                                         │  ║
║  │  App Tests:         - Not Run   [Press 9 to run]                      │  ║
║  │                                                                         │  ║
║  │  Packet Fuzzing:    ✓ Complete  [View Details: Enter]                 │  ║
║  │    PCAP: fuzz-github.pcap   Packets: 42   Modes: 3                   │  ║
║  │                                                                         │  ║
║  └─────────────────────────────────────────────────────────────────────────┘  ║
║                                                                              ║
║  ┌──────────────────────────── DIAGNOSIS ─────────────────────────────────┐  ║
║  │                                                                         │  ║
║  │  STATUS: ⚠ ACTION NEEDED                                               │  ║
║  │                                                                         │  ║
║  │  Issues Detected:                                                      │  ║
║  │   1. HTTPS timing out but TCP/ping work → MTU blackhole               │  ║
║  │   2. Path MTU drops from 1500 to 1400 at hop 3 (10.20.30.1)          │  ║
║  │                                                                         │  ║
║  │  Recommended Actions:                                                  │  ║
║  │   → Set interface MTU to 1400                                         │  ║
║  │   → Set TCP MSS clamp to 1360                                         │  ║
║  │   → Contact ISP about hop 3 (10.20.30.1) MTU restriction             │  ║
║  │                                                                         │  ║
║  └─────────────────────────────────────────────────────────────────────────┘  ║
║                                                                              ║
║  [T] All Targets View  [?] Help  [S] Save Report  [Q] Quit                  ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

---

## TUI Design - All Targets View

Press `T` to switch to this view:

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                          ALL TARGETS - OVERVIEW                              ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  [A] Run MTU all    [B] Run RTT all    [C] Run Loss all                     ║
║                                                                              ║
║  ┌──────────────────────────── RESULTS ─────────────────────────────────┐   ║
║  │                                                                        │   ║
║  │  TARGET            MTU    RTT    LOSS   TCP   DNS  HTTPS  STATUS     │   ║
║  │  ──────────────────────────────────────────────────────────────────   │   ║
║  │▶ 8.8.8.8           1500   8ms   0.0%    ✓     ✓     ✓     OK        │   ║
║  │  1.1.1.1           1500   12ms  0.0%    ✓     ✓     ✓     OK        │   ║
║  │  github.com        1500   15ms  0.0%    ✓     ✓     ✗     WARN      │   ║
║  │  outlook.o365.com  1500   22ms  0.0%    ✓     ✓     ✓     OK        │   ║
║  │  teams.ms.com      1400   18ms  0.5%    ✓     ✓     ⚠     REVIEW    │   ║
║  │  slack.com         1500   25ms  0.0%    ✓     ✓     ✓     OK        │   ║
║  │  zoom.us           1500   30ms  0.0%    ✓     ✓     ✓     OK        │   ║
║  │                                                                        │   ║
║  └────────────────────────────────────────────────────────────────────────┘   ║
║                                                                              ║
║  Summary: 5/7 OK   1 WARNING   1 REVIEW                                     ║
║                                                                              ║
║  [Enter] Select target for details    [D] Back to Dashboard                 ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

---

## TUI Design - Test Detail View

When you press Enter on "HTTPS Tests" result:

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                    HTTPS TEST DETAILS - github.com                           ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  Target: github.com (140.82.121.4)                      [R] Retest          ║
║                                                                              ║
║  ┌───────────────────── TEST STAGES ──────────────────────┐                 ║
║  │                                                         │                 ║
║  │  1. DNS Resolution              ✓    8ms               │                 ║
║  │  2. TCP Connect :443            ✓    14ms              │                 ║
║  │  3. TLS Handshake               ✗    TIMEOUT (5000ms)  │                 ║
║  │  4. HTTP GET Request            -    Not reached       │                 ║
║  │  5. HTTP Response               -    Not reached       │                 ║
║  │  6. Data Transfer               -    Not reached       │                 ║
║  │                                                         │                 ║
║  └─────────────────────────────────────────────────────────┘                 ║
║                                                                              ║
║  ┌────────────────── DIAGNOSIS ─────────────────────┐                       ║
║  │                                                   │                       ║
║  │  ISSUE: TLS handshake timeout                    │                       ║
║  │                                                   │                       ║
║  │  TCP connection succeeds but TLS times out.      │                       ║
║  │  This is CLASSIC MTU blackhole:                  │                       ║
║  │                                                   │                       ║
║  │   1. Small packets (SYN, ACK) work               │                       ║
║  │   2. Large packets (TLS cert chain) dropped      │                       ║
║  │   3. Firewall/router drops DF packets silently   │                       ║
║  │   4. No ICMP "frag needed" sent back             │                       ║
║  │                                                   │                       ║
║  │  Root Cause: Path MTU < interface MTU            │                       ║
║  │    Your MTU: 1500                                │                       ║
║  │    Path MTU: ~1400 (from MTU test)               │                       ║
║  │                                                   │                       ║
║  └───────────────────────────────────────────────────┘                       ║
║                                                                              ║
║  ┌────────────────── RECOMMENDED FIX ──────────────────────┐                 ║
║  │                                                         │                 ║
║  │  sudo ip link set eth0 mtu 1400                        │                 ║
║  │  sudo iptables -A FORWARD -p tcp --tcp-flags SYN,RST \ │                 ║
║  │               SYN -j TCPMSS --set-mss 1360            │                 ║
║  │                                                         │                 ║
║  │  [C] Copy to clipboard                                 │                 ║
║  │                                                         │                 ║
║  └─────────────────────────────────────────────────────────┘                 ║
║                                                                              ║
║  [ESC] Back    [T] Run Tracepath    [M] MTU Test                            ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

---

## Implementation Plan - Phase by Phase

### Phase 1: Test Infrastructure (Week 1-2)
**Goal:** Build test category framework

1. **Create test trait system**
```rust
trait NetworkTest {
    fn name(&self) -> &str;
    fn category(&self) -> TestCategory;
    fn run(&self, target: &str) -> TestResult;
    fn required_privileges(&self) -> Privileges;
}

enum TestCategory {
    MTU,
    Latency,
    PacketLoss,
    PathAnalysis,
    TCP,
    DNS,
    HTTPS,
    IPv6,
    Application,
    PacketFuzzing,  // NEW
}
```

2. **Create result types**
```rust
struct TestResult {
    category: TestCategory,
    target: String,
    status: TestStatus,
    data: TestData,
    diagnosis: Option<Diagnosis>,
    recommendations: Vec<String>,
}

enum TestData {
    MTU(MtuData),
    Latency(LatencyData),
    PacketLoss(PacketLossData),
    PacketFuzzing(FuzzingData),  // NEW
    // ... etc
}

struct FuzzingData {
    pcap_file: PathBuf,
    packets_generated: usize,
    modes_used: Vec<FuzzMode>,
    file_size_bytes: u64,
}
```

3. **Test runner orchestration**
```rust
struct TestOrchestrator {
    tests: HashMap<TestCategory, Vec<Box<dyn NetworkTest>>>,
    results: Arc<Mutex<HashMap<String, HashMap<TestCategory, TestResult>>>>,
}
```

---

### Phase 2: Individual Test Implementation (Week 3-5)

**Priority order (by impact):**

1. **HTTPS Testing** (solves todo.txt #2)
   - Implement stage-by-stage HTTPS test
   - Detect exact failure point
   - Distinguish MTU blackhole from other issues

2. **TCP Segmentation Detection** (solves todo.txt #3)
   - Monitor effective segment size
   - Compare to expected MSS
   - Detect artificial limits

3. **RTT/Latency Tests**
   - Ping statistics (100 packets)
   - Jitter calculation
   - Per-hop latency

4. **Packet Loss Tests**
   - Loss percentage
   - Loss pattern analysis

5. **Enhanced Path Analysis**
   - Full traceroute with MTU detection
   - AS path lookup
   - Routing loop detection

6. **DNS Testing**
   - Resolution timing
   - Multiple server comparison

7. **IPv6 Support** (solves todo.txt #1)
   - IPv6 connectivity
   - IPv6 MTU discovery
   - Dual-stack testing

8. **Packet Fuzzing** (RustPacketFuzz)
   - Segment size fuzzing
   - Header manipulation
   - PCAP generation for parser testing

---

### Phase 3: TUI Refactoring (Week 6)

**Changes to TUI:**

1. **Dashboard mode**
   - Single target focus
   - Test category buttons (1-9, 0)
   - Results per category
   - Diagnosis panel

2. **All targets mode** (`T` key)
   - Table view
   - Batch test buttons
   - Summary statistics

3. **Detail views**
   - Per-category detail screens
   - Stage-by-stage results for complex tests
   - Copy-paste commands

4. **State management**
```rust
struct AppState {
    // Per target, per category results
    results: HashMap<String, EnumMap<TestCategory, Option<TestResult>>>,
    
    // Current view state
    selected_target: String,
    view_mode: ViewMode,
    
    // Running tests
    active_tests: HashSet<(String, TestCategory)>,
}

enum ViewMode {
    Dashboard,
    AllTargets,
    CategoryDetail(TestCategory),
    Help,
}
```

---

### Phase 4: Diagnosis Engine (Week 7)

**Smart diagnosis:**

```rust
struct DiagnosisEngine {
    rules: Vec<DiagnosisRule>,
}

trait DiagnosisRule {
    fn check(&self, results: &HashMap<TestCategory, TestResult>) -> Option<Issue>;
}

struct Issue {
    severity: Severity,
    title: String,
    description: String,
    evidence: Vec<String>,
    recommendations: Vec<String>,
    commands: Vec<String>,
}

// Example rules:
// - If TCP connect OK but HTTPS times out → MTU blackhole
// - If ICMP works but TCP fails → port blocking
// - If latency spikes at specific hop → congested router
// - If packet loss only on return path → asymmetric routing issue
```

**Correlation logic:**
- MTU test shows 1500
- HTTPS test times out at TLS handshake
- Path analysis shows MTU drop at hop 3
- **Diagnosis:** MTU blackhole caused by hop 3

---

## File Structure Changes

```
mtu/
├── Cargo.toml
├── main.rs                     # Entry point (choose CLI or TUI)
├── tui_main.rs                 # TUI entry
├── cli_main.rs                 # CLI entry (existing main.rs renamed)
├── docs/
│   ├── NETWORK-TROUBLESHOOTER-PLAN.md  # This file
│   └── ...
├── src/
│   ├── tests/
│   │   ├── mod.rs
│   │   ├── trait.rs           # NetworkTest trait
│   │   ├── mtu.rs             # MTU tests (refactor existing)
│   │   ├── latency.rs         # NEW
│   │   ├── packet_loss.rs     # NEW
│   │   ├── path_analysis.rs   # NEW
│   │   ├── tcp.rs             # NEW
│   │   ├── dns.rs             # NEW
│   │   ├── https.rs           # NEW - critical
│   │   ├── ipv6.rs            # NEW
│   │   └── application.rs     # NEW
│   ├── fuzzing/               # RustPacketFuzz
│   │   ├── mod.rs
│   │   ├── context.rs
│   │   ├── builder.rs
│   │   ├── writer.rs
│   │   ├── fuzzers/
│   │   │   ├── mod.rs
│   │   │   ├── segment_size.rs
│   │   │   ├── length_mismatch.rs
│   │   │   ├── tcp_options.rs
│   │   │   ├── fragmentation.rs
│   │   │   └── checksum.rs
│   │   └── cli.rs
│   ├── diagnosis/
│   │   ├── mod.rs
│   │   ├── engine.rs
│   │   ├── rules.rs
│   │   └── correlator.rs
│   ├── tui/
│   │   ├── mod.rs
│   │   ├── app.rs
│   │   ├── dashboard.rs       # Single target dashboard
│   │   ├── all_targets.rs     # All targets table
│   │   ├── detail_views.rs    # Per-category detail views
│   │   └── events.rs
│   └── orchestrator.rs
├── tui.rs                      # Existing, refactor into src/tui/
└── test_runner.rs              # Existing, refactor into src/tests/
```

---

## Key Implementation Details

### HTTPS Testing - The Critical One

```rust
pub async fn test_https_comprehensive(target: &str) -> HttpsTestResult {
    let mut stages = Vec::new();
    
    // Stage 1: DNS
    let dns_start = Instant::now();
    let ip = match resolve_dns(target).await {
        Ok(ip) => {
            stages.push(HttpsStage {
                name: "DNS Resolution",
                status: StageStatus::Success,
                duration_ms: dns_start.elapsed().as_millis() as u64,
                details: format!("Resolved to {}", ip),
            });
            ip
        }
        Err(e) => {
            stages.push(HttpsStage {
                name: "DNS Resolution",
                status: StageStatus::Failed,
                duration_ms: dns_start.elapsed().as_millis() as u64,
                details: e.to_string(),
            });
            return HttpsTestResult { stages, diagnosis: None };
        }
    };
    
    // Stage 2: TCP Connect
    let tcp_start = Instant::now();
    let stream = match TcpStream::connect_timeout(&(ip, 443).into(), Duration::from_secs(5)) {
        Ok(s) => {
            stages.push(HttpsStage {
                name: "TCP Connect",
                status: StageStatus::Success,
                duration_ms: tcp_start.elapsed().as_millis() as u64,
                details: format!("Connected to {}:443", ip),
            });
            s
        }
        Err(e) => {
            stages.push(HttpsStage {
                name: "TCP Connect",
                status: StageStatus::Failed,
                duration_ms: tcp_start.elapsed().as_millis() as u64,
                details: e.to_string(),
            });
            
            let diag = Diagnosis {
                issue: "TCP connection failed".to_string(),
                explanation: "Port 443 may be blocked by firewall".to_string(),
                recommendations: vec![
                    "Check firewall rules".to_string(),
                    "Verify target is listening on 443".to_string(),
                ],
            };
            return HttpsTestResult { stages, diagnosis: Some(diag) };
        }
    };
    
    // Stage 3: TLS Handshake
    let tls_start = Instant::now();
    let connector = TlsConnector::new().unwrap();
    
    // Set timeout for TLS handshake
    let tls_result = timeout(Duration::from_secs(10), async {
        connector.connect(target, stream).await
    }).await;
    
    match tls_result {
        Ok(Ok(tls_stream)) => {
            stages.push(HttpsStage {
                name: "TLS Handshake",
                status: StageStatus::Success,
                duration_ms: tls_start.elapsed().as_millis() as u64,
                details: "TLS 1.3 established".to_string(),
            });
            
            // Continue with HTTP request...
        }
        Ok(Err(e)) => {
            stages.push(HttpsStage {
                name: "TLS Handshake",
                status: StageStatus::Failed,
                duration_ms: tls_start.elapsed().as_millis() as u64,
                details: e.to_string(),
            });
            
            // TLS error - certificate or protocol issue
            let diag = Diagnosis {
                issue: "TLS handshake failed".to_string(),
                explanation: format!("TLS negotiation error: {}", e),
                recommendations: vec![
                    "Check certificate validity".to_string(),
                    "Verify TLS version support".to_string(),
                ],
            };
            return HttpsTestResult { stages, diagnosis: Some(diag) };
        }
        Err(_) => {
            // TIMEOUT - this is the MTU blackhole signature
            stages.push(HttpsStage {
                name: "TLS Handshake",
                status: StageStatus::Timeout,
                duration_ms: 10000,
                details: "Timeout after 10 seconds".to_string(),
            });
            
            let diag = Diagnosis {
                issue: "TLS handshake timeout - MTU BLACKHOLE DETECTED".to_string(),
                explanation: r#"TCP connection succeeded but TLS handshake timed out.
                
This is the classic signature of an MTU blackhole:
1. Small packets (TCP SYN/ACK) work fine
2. Large packets (TLS certificate chain) are silently dropped
3. A router/firewall is dropping DF packets without sending ICMP errors

The TLS handshake sends ~4KB of data (certificate chain), which gets
fragmented into ~3 packets at MTU 1500. If path MTU is smaller and 
no ICMP errors are returned, these packets are lost forever."#.to_string(),
                recommendations: vec![
                    format!("Set interface MTU to lower value (try 1400)"),
                    format!("Set TCP MSS clamp: iptables -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1360"),
                    format!("Run Path MTU test to find exact limit"),
                    format!("Check for broken PMTUD on path"),
                ],
            };
            return HttpsTestResult { stages, diagnosis: Some(diag) };
        }
    }
    
    // Stage 4-6: HTTP request/response (if we get here)
    // ...
}
```

This is THE key test that solves the "can ping but can't browse" issue.

---

### TCP Segmentation Detection

```rust
pub fn detect_tcp_segmentation(target: &str) -> TcpSegmentationResult {
    // Send data of various sizes
    // Monitor actual segment sizes via tcpdump or similar
    
    let test_sizes = vec![100, 500, 1000, 1400, 1460];
    let mut actual_segments = Vec::new();
    
    for size in test_sizes {
        let segments = send_and_monitor_tcp(target, size);
        actual_segments.push((size, segments));
    }
    
    // Check if segments are artificially limited
    let expected_mss = 1460; // For MTU 1500
    let actual_max_segment = actual_segments.iter()
        .flat_map(|(_, segs)| segs)
        .max()
        .unwrap_or(&0);
    
    if *actual_max_segment < 200 && *actual_max_segment < expected_mss {
        TcpSegmentationResult {
            is_limited: true,
            max_observed_segment: *actual_max_segment,
            expected_mss,
            explanation: format!(
                "TCP segments are being limited to {} bytes. \
                 This may be a firewall policy. Expected MSS was {}.",
                actual_max_segment, expected_mss
            ),
        }
    } else {
        TcpSegmentationResult {
            is_limited: false,
            max_observed_segment: *actual_max_segment,
            expected_mss,
            explanation: "TCP segmentation appears normal".to_string(),
        }
    }
}
```

---

## Success Metrics

### User Experience
- **Zero config:** Run `mtu-tui`, see dashboard, press number to test
- **Clear results:** Each test shows pass/fail/warning with details
- **Actionable diagnosis:** Tell user WHAT is wrong and HOW to fix
- **Selective testing:** Don't run everything always - user chooses

### Technical
- **Comprehensive:** Test all OSI layers 2-7
- **Fast:** Single test <2s, full suite <30s
- **Accurate:** No false positives
- **Privileged mode handling:** Gracefully degrade if not root

---

## Target Defaults - Extended

Update `targets.txt` format:

```
# target,description,tcp_port,udp_port,test_sets
8.8.8.8,Google DNS,0,53,mtu+rtt+loss+path+dns
1.1.1.1,Cloudflare DNS,0,53,mtu+rtt+loss+path+dns
github.com,GitHub,443,0,mtu+rtt+loss+path+tcp+dns+https
outlook.office365.com,M365 Outlook,443,0,mtu+rtt+tcp+dns+https
teams.microsoft.com,MS Teams,443,0,mtu+rtt+tcp+dns+https+ipv6
```

Test sets determine which button groups apply.

---

## Keyboard Shortcuts - Complete Map

### Global
- `q` - Quit
- `?`/`h` - Help
- `Esc` - Back/Cancel
- `Tab` - Switch between panels

### Dashboard Mode
- `1`-`9` - Run test category on selected target
- `0` - Run ALL tests on selected target
- `Up`/`Down` - Select target
- `Enter` - View target details
- `T` - Switch to all targets view
- `R` - Retest current view
- `S` - Save report

### All Targets Mode
- `A` - Run MTU on all targets
- `B` - Run RTT on all targets
- `C` - Run packet loss on all targets
- `D` - Back to dashboard
- `Enter` - Focus on selected target (go to dashboard)

### Detail Views
- `Esc` - Back to dashboard
- `R` - Rerun this test
- `C` - Copy commands to clipboard (if applicable)
- `T` - Run tracepath (if applicable)

---

## Next Steps

1. **Review this plan** - make sure it addresses all todo.txt items
2. **Start Phase 1** - test infrastructure
3. **Implement HTTPS test first** - highest priority
4. **Iterate on TUI** - get user feedback

Questions to resolve:
- Privilege handling strategy? (detect, warn, degrade gracefully)
- Packet capture approach? (raw sockets, tcpdump wrapper, both?)
- Async runtime? (tokio for network tests, keep rayon for parallel targets?)
- Cross-platform? (focus Linux first, Windows/Mac later?)

