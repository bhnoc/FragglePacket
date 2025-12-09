# Test Framework

## Overview

The test framework provides a unified architecture for all network tests in FragglePacket. All tests implement the `NetworkTest` trait and are managed by the `TestOrchestrator`.

## Core Components

### NetworkTest Trait

```rust
pub trait NetworkTest: Send + Sync {
    fn name(&self) -> &str;
    fn category(&self) -> TestCategory;
    fn run(&self, target: &str) -> Result<TestResult, Box<dyn Error>>;
    fn requires_root(&self) -> bool { false }
    fn estimated_duration(&self) -> u64 { 5 }
}
```

### TestCategory Enum

10 test categories:
- MTU - MTU discovery tests
- RTT - RTT and latency measurements
- PacketLoss - Packet loss detection
- PathAnalysis - Path analysis (traceroute, MTU per hop)
- TCPHealth - TCP health metrics
- DNS - DNS resolution tests
- HTTPS - HTTPS stage-by-stage testing
- IPv6 - IPv6 connectivity
- Application - Application-layer tests
- Fuzzing - Packet fuzzing (RustPacketFuzz)

### TestResult Structure

Unified result structure with:
- `name` - Test name
- `category` - Test category
- `target` - Target tested
- `status` - TestStatus (Pending, Running, Success, Warning, Failed, Skipped)
- `metrics` - HashMap of numeric metrics (MTU size, latency ms, etc.)
- `metadata` - HashMap of string metadata (error messages, warnings)
- `diagnoses` - Vec of detected issues with recommendations
- `duration` - Test execution time
- `timestamp` - When test was run

### TestOrchestrator

Manages test execution and result storage:

```rust
let mut orchestrator = TestOrchestrator::new();
orchestrator.register(Box::new(HttpsTest::new()));

// Run all tests
let results = orchestrator.run_all("google.com");

// Run specific category
let https_results = orchestrator.run_category("google.com", TestCategory::HTTPS);

// Get stored results
let result = orchestrator.get_result("google.com", TestCategory::HTTPS);
```

## Usage Example

See `tests/test_framework_demo.rs`:

```bash
cargo test --test test_framework_demo -- --nocapture
```

## Implementing New Tests

1. Create test struct
2. Implement NetworkTest trait
3. Register with orchestrator
4. Run via orchestrator

Example:

```rust
pub struct MyTest;

impl NetworkTest for MyTest {
    fn name(&self) -> &str { "My Test" }
    fn category(&self) -> TestCategory { TestCategory::DNS }
    
    fn run(&self, target: &str) -> Result<TestResult, Box<dyn Error>> {
        let mut result = TestResult::new(
            self.name().to_string(),
            self.category(),
            target.to_string(),
        );
        
        // Run your test logic
        result.add_metric("latency_ms", 42.0);
        result.set_status(TestStatus::Success);
        
        Ok(result)
    }
}
```

## Diagnosis System

Tests can add diagnoses with recommendations:

```rust
result.add_diagnosis(Diagnosis::new(
    DiagnosisSeverity::Critical,
    "MTU Blackhole Detected".to_string(),
    "TCP OK but TLS timeout".to_string(),
).with_recommendation("Lower MTU to 1400")
 .with_related_test("MTU Tests"));
```

## Migration Status

- [x] Framework core complete
- [x] HTTPS test migrated
- [ ] MTU tests to migrate
- [ ] Fuzzing tests to migrate
- [ ] TUI integration

## Files

- `src/framework/mod.rs` - Module exports
- `src/framework/test_trait.rs` - NetworkTest trait, TestCategory
- `src/framework/result.rs` - TestResult, TestStatus, Diagnosis
- `src/framework/orchestrator.rs` - TestOrchestrator
- `examples/test_framework_demo.rs` - Usage example

