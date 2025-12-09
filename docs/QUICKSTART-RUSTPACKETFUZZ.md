# RustPacketFuzz - Quick Start Guide

## For Developers: Implementing the Feature

### Files Updated (Review These First)

1. **TODO-CHECKLIST.md** - Implementation timeline and task breakdown
2. **docs/RUSTPACKETFUZZ-INTEGRATION.md** - Complete design document
3. **docs/INTEGRATION-SUMMARY.md** - High-level overview
4. **docs/VISUAL-ARCHITECTURE.md** - Diagrams and visual reference
5. **docs/ARCHITECTURE.md** - Updated system architecture
6. **docs/NETWORK-TROUBLESHOOTER-PLAN.md** - Test category integration
7. **Cargo.toml** - Dependencies added

---

## Phase 1: Getting Started (Week 1-2)

### Step 1: Review Documentation
Read in this order:
1. INTEGRATION-SUMMARY.md (10 min)
2. VISUAL-ARCHITECTURE.md (15 min) 
3. RUSTPACKETFUZZ-INTEGRATION.md (30 min)
4. TODO-CHECKLIST.md (review week 1-2 tasks)

### Step 2: Create Module Skeleton

```bash
# Create fuzzing module directory
mkdir -p src/fuzzing/fuzzers

# Create empty files
touch src/fuzzing/mod.rs
touch src/fuzzing/context.rs
touch src/fuzzing/builder.rs
touch src/fuzzing/writer.rs
touch src/fuzzing/cli.rs
touch src/fuzzing/fuzzers/mod.rs
touch src/fuzzing/fuzzers/segment_size.rs
touch src/fuzzing/fuzzers/length_mismatch.rs
touch src/fuzzing/fuzzers/tcp_options.rs
touch src/fuzzing/fuzzers/fragmentation.rs
touch src/fuzzing/fuzzers/checksum.rs
```

### Step 3: Add Dependencies

Already done in `Cargo.toml`:
```toml
etherparse = "0.15"
pcap-file = "3.0"
thiserror = "1.0"
```

Run: `cargo build` to fetch dependencies

### Step 4: Implement PacketContext

File: `src/fuzzing/context.rs`

Copy implementation from RUSTPACKETFUZZ-INTEGRATION.md Phase 2 section.

Key struct:
```rust
pub struct PacketContext {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub src_port: u16,
    pub dst_port: u16,
}

impl PacketContext {
    pub fn build_base_layers(&self, payload_len: usize) 
        -> Result<(Ethernet2Header, Ipv4Header, TcpHeader, Vec<u8>)>
    {
        // Implementation here
    }
}
```

### Step 5: Test Compilation

```bash
cargo check
```

Fix any errors before proceeding.

---

## Phase 2: First Fuzzer (Week 3)

### Implement Segment Size Fuzzer

File: `src/fuzzing/fuzzers/segment_size.rs`

Reference: RUSTPACKETFUZZ-INTEGRATION.md Phase 3

**Test it works:**
```bash
# Create test binary
cargo build --release

# Run (once CLI is hooked up)
./target/release/mtu-detective fuzz \
    --output test.pcap \
    --mode segment-size \
    --target github.com

# Verify PCAP
wireshark test.pcap
```

**Expected output:**
- 17 packets in PCAP
- Sizes: 0, 1, 2...9, 536, 1460, 1500, 4096, 9000, 65535 bytes
- Valid Ethernet/IP/TCP headers

---

## Phase 3: PCAP Writer (Week 3)

### Implement PcapWriter Wrapper

File: `src/fuzzing/writer.rs`

```rust
use pcap_file::{PcapWriter as RawPcapWriter, PcapHeader};
use std::fs::File;
use std::io::Write;

pub struct PcapWriter {
    writer: RawPcapWriter<File>,
    packets_written: usize,
}

impl PcapWriter {
    pub fn new(path: &str) -> Result<Self> {
        let file = File::create(path)?;
        let header = PcapHeader {
            magic_number: 0xa1b2c3d4,
            version_major: 2,
            version_minor: 4,
            snaplen: 65535,
            network: 1, // Ethernet
            ts_correction: 0,
            ts_accuracy: 0,
        };
        let writer = RawPcapWriter::with_header(file, header)?;
        Ok(Self { writer, packets_written: 0 })
    }
    
    pub fn write_packet(&mut self, data: &[u8]) -> Result<()> {
        // Implementation
        self.packets_written += 1;
        Ok(())
    }
}
```

---

## Phase 4: CLI Integration (Week 3)

### Add Subcommand

File: `main.rs` (or new `src/fuzzing/cli.rs`)

```rust
use clap::{Parser, Subcommand};

#[derive(Subcommand)]
enum Commands {
    // ... existing commands ...
    
    /// Packet fuzzing and crafting
    Fuzz {
        /// Target hostname or IP
        #[arg(short, long)]
        target: String,
        
        /// Output PCAP file
        #[arg(short, long, default_value = "fuzz.pcap")]
        output: String,
        
        /// Fuzzing mode
        #[arg(short, long, default_value = "segment-size")]
        mode: String,
    },
}
```

**Test:**
```bash
cargo run -- fuzz --help
```

---

## Phase 5: Advanced Fuzzers (Week 4)

### Length Mismatch Fuzzer

File: `src/fuzzing/fuzzers/length_mismatch.rs`

Reference: RUSTPACKETFUZZ-INTEGRATION.md Phase 4

**Key implementation:**
- Create packet with actual size 100 bytes
- Set `ipv4.total_len = 50` (lie short)
- Set `ipv4.total_len = 200` (lie long)
- Write to PCAP

**Test with Suricata:**
```bash
# Generate PCAP
./target/release/mtu-detective fuzz \
    --target github.com \
    --output mismatch.pcap \
    --mode length-mismatch

# Feed to Suricata
suricata -r mismatch.pcap -l ./logs/

# Check for alerts
cat logs/fast.log
```

### TCP Options Fuzzer

File: `src/fuzzing/fuzzers/tcp_options.rs`

Reference: RUSTPACKETFUZZ-INTEGRATION.md Phase 5

**Test cases:**
- MSS = 1460 (normal)
- MSS = 0 (invalid)
- MSS = 65535 (max)
- Malformed option (kind=2, len=2 instead of 4)

---

## Phase 6: TUI Integration (Week 6)

### Add [F] Button Handler

File: `tui.rs` or `src/tui/events.rs`

```rust
match key.code {
    KeyCode::Char('1') => { /* MTU test */ },
    KeyCode::Char('2') => { /* RTT test */ },
    // ...
    KeyCode::Char('f') | KeyCode::Char('F') => {
        // Switch to fuzzing panel
        app.view_mode = ViewMode::FuzzingPanel;
    },
    // ...
}
```

### Create Fuzzing Panel View

File: `src/tui/fuzzing_panel.rs` (new)

```rust
pub fn render_fuzzing_panel(f: &mut Frame, app: &App, area: Rect) {
    // Render fuzzing mode selection
    // Show progress bars
    // Display PCAP output path
    // Next steps section
}
```

Reference: VISUAL-ARCHITECTURE.md for UI mockup

---

## Testing Checklist

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_packet_context_creation() {
        let ctx = PacketContext {
            src_ip: "192.168.1.1".parse().unwrap(),
            dst_ip: "8.8.8.8".parse().unwrap(),
            // ...
        };
        assert!(ctx.src_ip.is_ipv4());
    }
    
    #[test]
    fn test_segment_size_fuzzer() {
        let ctx = PacketContext::new(/* ... */);
        let mut writer = PcapWriter::new("test.pcap").unwrap();
        
        let fuzzer = SegmentSizeFuzzer::new();
        fuzzer.fuzz(&ctx, &mut writer).unwrap();
        
        assert_eq!(writer.packets_written(), 17);
    }
}
```

### Integration Tests

```bash
# Test 1: Generate PCAP
./target/release/mtu-detective fuzz \
    --target 8.8.8.8 \
    --output test1.pcap \
    --mode segment-size

# Verify file exists
ls -lh test1.pcap

# Test 2: Open in Wireshark (manual)
wireshark test1.pcap

# Test 3: Validate with tshark
tshark -r test1.pcap | wc -l
# Expected: 17 lines (17 packets)

# Test 4: Check packet sizes
tshark -r test1.pcap -T fields -e frame.len
```

### Fuzzing Validation

```bash
# Test against Suricata
suricata -r test1.pcap -l ./logs/

# Expected: Some alerts for edge cases
# Check logs/fast.log for triggered rules
```

---

## Common Issues & Solutions

### Issue 1: PCAP Not Opening in Wireshark

**Symptom:** Wireshark says "not a capture file"

**Solution:**
- Check magic number: 0xa1b2c3d4
- Verify pcap-file version compatibility
- Test with: `file test.pcap` (should say "pcap capture file")

### Issue 2: Packets Have Invalid Checksums

**Expected:** Checksums will be wrong unless calculated

**Solution:**
- For normal packets: Calculate checksums with etherparse
- For fuzzing: Invalid checksums are often intentional
- Document which packets have correct vs corrupt checksums

### Issue 3: etherparse Version Mismatch

**Symptom:** Compilation errors with etherparse

**Solution:**
```bash
cargo update etherparse
# Or pin version in Cargo.toml
```

### Issue 4: Root Privileges Error

**Symptom:** "Permission denied" when writing file

**Solution:**
- PCAP writing doesn't need root
- Check file permissions: `ls -l reports/`
- Ensure directory exists: `mkdir -p reports/`

---

## Performance Optimization Tips

### Parallel PCAP Generation

```rust
use rayon::prelude::*;

let packets: Vec<Vec<u8>> = test_sizes
    .par_iter()
    .map(|size| generate_packet(&ctx, *size))
    .collect();

// Then write serially (PCAP writing must be sequential)
for packet in packets {
    writer.write_packet(&packet)?;
}
```

### Memory Efficiency

```rust
// Instead of:
let mut all_packets = Vec::new();
for size in sizes {
    all_packets.push(generate_packet(size));
}
// Write all at once

// Do:
for size in sizes {
    let packet = generate_packet(size);
    writer.write_packet(&packet)?; // Write immediately
} // Packet drops from memory
```

---

## Documentation Requirements

### Each Fuzzer Should Document:

1. **Purpose** - What vulnerability does it test?
2. **Test cases** - Specific values/scenarios
3. **Expected behavior** - What should happen?
4. **Known issues** - Which parsers fail?
5. **References** - CVEs, RFCs, research papers

Example:
```rust
/// Segment Size Fuzzer
/// 
/// **Purpose:** Test parser handling of various TCP payload sizes
/// 
/// **Test Cases:**
/// - 0 bytes: Null pointer dereference
/// - 1-9 bytes: Off-by-one errors
/// - 65535 bytes: Integer overflow
/// 
/// **Known Vulnerabilities:**
/// - CVE-XXXX-YYYY: Parser X crashes on 0-byte payload
/// - CVE-XXXX-ZZZZ: Parser Y hangs on 65535-byte payload
/// 
/// **References:**
/// - RFC 793: TCP Specification
/// - RFC 879: TCP Maximum Segment Size Option
pub struct SegmentSizeFuzzer;
```

---

## Next Steps After Implementation

### 1. Security Testing
- Test against Suricata (various versions)
- Test against Snort
- Test against tcpdump
- Document which versions have issues

### 2. Create Test Suite
- Generate baseline PCAPs for regression testing
- Add to CI/CD pipeline
- Version control known-good PCAPs

### 3. User Documentation
- Write fuzzing tutorial
- Create example campaigns
- Document security testing workflow

### 4. Community Engagement
- Blog post about implementation
- Submit to security conferences
- Share on GitHub

---

## Resources

### Documentation
- Main design: `docs/RUSTPACKETFUZZ-INTEGRATION.md`
- Visual guide: `docs/VISUAL-ARCHITECTURE.md`
- Summary: `docs/INTEGRATION-SUMMARY.md`
- Tasks: `TODO-CHECKLIST.md`

### External References
- etherparse docs: https://docs.rs/etherparse/
- pcap-file docs: https://docs.rs/pcap-file/
- PCAP format: https://wiki.wireshark.org/Development/LibpcapFileFormat
- TCP RFC: https://www.rfc-editor.org/rfc/rfc793.html

### Tools
- Wireshark: https://www.wireshark.org/
- Suricata: https://suricata.io/
- tcpreplay: https://tcpreplay.appneta.com/
- tshark: https://www.wireshark.org/docs/man-pages/tshark.html

---

## Questions?

Refer to:
1. INTEGRATION-SUMMARY.md for high-level answers
2. RUSTPACKETFUZZ-INTEGRATION.md for implementation details
3. VISUAL-ARCHITECTURE.md for diagrams
4. TODO-CHECKLIST.md for task breakdowns

Good luck implementing! 🚀

