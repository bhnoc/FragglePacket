# FragglePacket 🔍

** Network Diagnostic Tool for MTU Path Discovery, Protocol Testing, and Packet Fuzzing**

---

## 🚀 Features

### 🎯 Core Capabilities

- **MTU Path Discovery** - ICMP, TCP, UDP, and QUIC-based MTU detection with binary search
- **HTTPS Stage Testing** - Diagnose MTU blackholes with stage-by-stage TLS analysis
- **Packet Fuzzing** - RustPacketFuzz integration for security testing with 5 fuzzing modes
- **TCP Health Metrics** - Handshake timing, window analysis, retransmission detection
- **Path Analysis** - Traceroute with per-hop MTU discovery
- **Protocol Tests** - DNS, IPv6, RTT, packet loss, application-layer protocols
- **VPN/SASE Calculator** - Optimal MTU for 12+ tunnel types (WireGuard, Zscaler, GlobalProtect, etc.)

### 🖥️ Dual Interface

**Interactive TUI** (Terminal User Interface)
- Retro green-on-black aesthetic
- Real-time test execution with progress tracking
- Multi-panel design: Dashboard, Test Panel, Fuzzing, HTTPS, Simulator, Help
- Live tracepath output streaming
- Context-aware key bindings

**CLI**
- Batch testing of 159 default targets
- JSON report generation
- Pipe-friendly output
- Quick ICMP-only mode for fast checks

---

## 🚀 Quick Setup & Start

**Automatic setup and launch:**

```bash
git clone https://github.com/yourusername/FragglePacket.git
cd FragglePacket
./setup.sh   # Installs deps, builds, verifies
./start.sh   # Launches TUI
```

**What `setup.sh` does:**
- Installs system deps (traceroute, tcpdump, dnsutils)
- Installs Rust if needed
- Builds release binary
- Verifies capabilities

**What `start.sh` does:**
- Default: launches TUI
- Options: `-1` quick, `-2` diagnose, `-6` test, `-h` help
- Handles sudo prompts

**Requirements:** Rust 1.70+, Linux with raw sockets, sudo for ICMP

---

## 🎮 Usage

### Interactive TUI (Recommended)

```bash
./start.sh  # Default mode
```

**Navigation:**
- `[T]` - Test Panel (10 test categories)
- `[F]` - Fuzzing Panel (packet crafting)
- `[H]` - HTTPS Testing (MTU blackhole detection)
- `[3]` - MTU Simulator (what-if analysis)
- `[?]` - Help screen
- `[q]` - Quit

### CLI Examples (via start.sh)

**Quick ICMP MTU test:**
```bash
./start.sh -1 github.com
```

**Full diagnostic (DNS → TCP → TLS → HTTP):**
```bash
./start.sh -2 github.com
```

**Test multiple targets:**
```bash
./start.sh -3 8.8.8.8,1.1.1.1,github.com
```

**HTTPS stage-by-stage with diagnosis:**
```bash
./start.sh -8 example.com
```

**Run specific test category:**
```bash
./start.sh -6 dns github.com
./start.sh -7 github.com  # All categories
```

**VPN MTU calculator:**
```bash
./start.sh -4 zscaler
./start.sh -9  # List all VPN types
```

**Packet fuzzing:**
```bash
./start.sh -f tcp-options reports/evil.pcap
```

**Comprehensive test suite:**
```bash
./start.sh -10       # Kitchen sink mode
./start.sh -11       # Kitchen sink + JSON report
```

### Direct Binary Usage

If you prefer direct access:

### Direct Binary Usage

If you prefer direct access:

```bash
sudo ./target/release/fraggle-packet tui
sudo ./target/release/fraggle-packet quick github.com
sudo ./target/release/fraggle-packet diagnose github.com --port 443
```

sudo ./target/release/fraggle-packet diagnose github.com --port 443
# Install globally for convenience
sudo cp target/release/fraggle-packet /usr/local/bin/
sudo fraggle-packet tui
```

---

## 🎯 Use Cases

### 1️⃣ **Enterprise Network Troubleshooting**
- Diagnose M365/Teams connectivity issues
- Identify MTU blackholes causing TLS failures
- Test Zscaler/SASE tunnel configurations

### 2️⃣ **DevOps & Cloud**
- Verify AWS/Azure/GCP connectivity paths
- Test Docker registry/NPM/PyPI access
- Validate CI/CD pipeline network requirements

### 3️⃣ **Security Research**
- Fuzz network appliances with malformed packets
- Test IDS/IPS bypass techniques
- Validate firewall MTU handling

### 4️⃣ **VPN Configuration**
- Calculate optimal MTU for WireGuard/OpenVPN
- Avoid fragmentation in Zero Trust tunnels
- Test GlobalProtect/AnyConnect settings

---

## 📊 Test Framework

FragglePacket includes 10 comprehensive test categories:

| # | Category | Tests | Description |
|---|----------|-------|-------------|
| 1 | **DNS** | Resolution, EDNS0 | Verify DNS connectivity |
| 2 | **MTU** | ICMP, TCP, UDP, QUIC | Multi-protocol MTU discovery |
| 3 | **HTTPS** | TLS stages | MTU blackhole detection |
| 4 | **TCP Health** | Handshake, window, retrans | TCP stack analysis |
| 5 | **RTT** | Latency, jitter | Round-trip time measurements |
| 6 | **Packet Loss** | Loss rate, patterns | Packet drop detection |
| 7 | **Path Analysis** | Traceroute, per-hop MTU | Network path mapping |
| 8 | **IPv6** | Connectivity, comparison | IPv6 vs IPv4 testing |
| 9 | **Application** | HTTP/2, HTTP/3, WebSocket | Protocol support |
| 10 | **Fuzzing** | 5 modes | Packet crafting for security |

---

## 🔧 Configuration

### Custom Targets

Create a `targets.txt` file in the project directory:

```
# Format: target,description,port
github.com,GitHub,443
1.1.1.1,Cloudflare DNS,0
internal.corp.local,Internal App,8080
```

Port 0 = ICMP-only (no TCP test)

### Default Targets

FragglePacket includes 159 pre-configured targets across 10 tiers:
- Tier 1: Critical Infrastructure (DNS, M365, Google Workspace)
- Tier 2: Cloud Providers (AWS, Azure, GCP)
- Tier 3: Developer Tools (GitHub, npm, Docker Hub)
- Tier 4-10: Collaboration, Security, CDN, Consumer, Regional, Specialized

See `targets.txt` for the complete list.

---

## 📖 Documentation

Comprehensive documentation available in the `docs/` directory:

- **[ARCHITECTURE.md](docs/ARCHITECTURE.md)** - System design and components
- **[TEST-FRAMEWORK.md](docs/TEST-FRAMEWORK.md)** - Test implementation guide
- **[TUI-INTEGRATION-PLAN.md](docs/TUI-INTEGRATION-PLAN.md)** - TUI architecture
- **[QUICKSTART-RUSTPACKETFUZZ.md](docs/QUICKSTART-RUSTPACKETFUZZ.md)** - Fuzzing guide
- **[MTU-TESTING-METHODS.md](docs/MTU-TESTING-METHODS.md)** - MTU discovery techniques
- **[TUNNEL-OVERHEADS.md](docs/TUNNEL-OVERHEADS.md)** - VPN overhead calculations
- **[RFC-REFERENCE.md](docs/RFC-REFERENCE.md)** - Related RFCs

---

## 🐛 Known Issues & Troubleshooting

### "Permission denied" errors
FragglePacket requires root/sudo for raw socket access (ICMP).

```bash
sudo fraggle-packet tui
```

### ICMP blocked by firewall
Use TCP-based discovery:

```bash
sudo fraggle-packet tcp github.com:443
```

### TLS timeout on large downloads
This is the MTU blackhole! The tool will detect it:

```bash
sudo fraggle-packet https example.com --diagnose
```

### High CPU during bulk tests
Rate limiting will be added in v1.0. For now, reduce target count or use `kitchen-sink` with smaller batches.

---

## 🧪 Testing

```bash
# Run unit tests
cargo test --lib

# Run integration tests
cargo test --test test_runner

# Run with verbose output
cargo test -- --nocapture
```

---

## 🛠️ Manual Installation

### From Source (Detailed)

```bash
# Clone repository
git clone https://github.com/yourusername/FragglePacket.git
cd FragglePacket

# Build release binary
cargo build --release

# Copy to system path (optional)
sudo cp target/release/fraggle-packet /usr/local/bin/

# Verify installation
fraggle-packet --version
```

### System Requirements

- **Rust:** 1.70 or later
- **OS:** Linux with raw socket support
- **Permissions:** sudo required for ICMP tests
- **Optional:** `tracepath` or `traceroute` for path analysis

### Development Setup

```bash
git clone https://github.com/yourusername/FragglePacket.git
cd FragglePacket
cargo build
cargo test
cargo run -- tui
```

### Code Style

- Follow Rust 2021 idioms
- Run `cargo fmt` before committing
- Run `cargo clippy` and address warnings
- Add tests for new features
