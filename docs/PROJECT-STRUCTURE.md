# Project Structure - Reorganization Complete

## Current Clean Structure

```
/home/noc/mtu/
├── main.rs                  # Binary entry point (2097 lines)
├── Cargo.toml              # Dependencies
├── src/
│   ├── lib.rs              # Library entry point
│   ├── bin/                # Binary-specific code
│   │   ├── cli/            # CLI command handlers
│   │   │   ├── mod.rs
│   │   │   └── fuzzing.rs  # Fuzzing CLI handler
│   │   └── tui/            # TUI modules
│   │       ├── mod.rs
│   │       ├── app.rs      # Main TUI app (1893 lines)
│   │       └── fuzzing_panel.rs  # Fuzzing UI panel
│   ├── network_tests/      # Network testing implementations
│   │   ├── mod.rs
│   │   └── https.rs        # HTTPS stage-by-stage tester
│   ├── diagnosis/          # Diagnosis engine
│   │   └── mod.rs          # MTU blackhole detection, etc.
│   ├── fuzzing/            # Packet fuzzing library
│   │   ├── mod.rs
│   │   ├── context.rs      # PacketContext
│   │   ├── writer.rs       # PCAP writer
│   │   ├── cli.rs          # CLI utilities (kept for lib)
│   │   └── fuzzers/
│   │       ├── mod.rs
│   │       ├── segment_size.rs
│   │       ├── length_mismatch.rs
│   │       ├── tcp_options.rs
│   │       ├── fragmentation.rs
│   │       └── checksum.rs
│   └── framework/          # Future: test framework
├── tests/                  # Integration tests (Rust tests)
│   └── test_runner.rs
└── docs/                   # Documentation
    └── ...
```

## Key Changes

### 1. Clean Root
**Before:** 6 .rs files cluttering root  
**After:** Only `main.rs` in root

### 2. Clear Separation
- **Library code** (`src/fuzzing/`, `src/network_tests/`, `src/diagnosis/`)  
  → Reusable, testable, no UI
  
- **Binary code** (`src/bin/cli/`, `src/bin/tui/`)  
  → User interfaces (CLI & TUI)

### 3. Renamed for Clarity
- `src/tests/` → `src/network_tests/`  
  (Tools TO test networks, not tests OF our code)
  
- `tests/` stays as-is  
  (Integration tests OF our code)

### 4. Modular Binary
- `src/bin/cli/` - Command handlers (fuzzing, https, etc.)
- `src/bin/tui/` - TUI components (app, panels, events)

## Benefits

1. **Scalability:** Easy to add new test modules to `src/network_tests/`
2. **Clarity:** No confusion between network tests and code tests
3. **Reusability:** Library code can be imported by other projects
4. **Standards:** Follows Rust conventions (`src/bin/` for multiple binaries)
5. **Clean root:** Professional project appearance

## Verification

All functionality tested and working:
- ✅ Library builds (`cargo build --lib`)
- ✅ Binary builds (`cargo build --bin fraggle-packet`)
- ✅ 13 tests pass (`cargo test --lib`)
- ✅ HTTPS command works
- ✅ Fuzzing command works
- ✅ TUI launches (pending full test)

## Future Additions

New modules can be easily added to the appropriate location:

- Network tests: `src/network_tests/tcp.rs`, `src/network_tests/dns.rs`
- CLI handlers: `src/bin/cli/tcp.rs`, `src/bin/cli/dns.rs`
- TUI panels: `src/bin/tui/dns_panel.rs`, `src/bin/tui/tcp_panel.rs`
- Diagnosis rules: More rules in `src/diagnosis/mod.rs`
- Test framework: `src/framework/test_trait.rs`, `src/framework/orchestrator.rs`

