# TUI Integration with Test Framework

## Current Status

The TUI (`src/bin/tui/app.rs`) has its own architecture with:
- AppState with results, hops, fuzzing_results, https_results
- Multiple AppMode (Dashboard, FuzzingPanel, HttpsPanel, etc.)
- Manual test execution

## Integration Plan

To integrate TestOrchestrator into TUI:

### 1. Add TestOrchestrator to App State

```rust
pub struct App {
    // ... existing fields ...
    pub orchestrator: TestOrchestrator,
    pub selected_category: Option<TestCategory>,
}
```

### 2. Category Selection Buttons

Add to dashboard rendering:

```rust
// Test category buttons [1-10]
let categories = TestCategory::all();
for (i, cat) in categories.iter().enumerate() {
    let button = format!("[{}] {}", i + 1, cat.as_str());
    // Render button, highlight if selected
}
```

### 3. Selective Test Execution

```rust
// Key handlers
KeyCode::Char('1') => self.run_category(TestCategory::DNS),
KeyCode::Char('2') => self.run_category(TestCategory::MTU),
// ... etc

fn run_category(&mut self, category: TestCategory) {
    let target = self.get_selected_target();
    let results = self.orchestrator.run_category(&target, category);
    self.update_state_with_results(results);
}
```

### 4. Dashboard vs All Targets View

```rust
pub enum ViewMode {
    Dashboard,      // Single target, all tests
    AllTargets,     // Multiple targets, selective tests
}

// In Dashboard: show all test results for one target
// In AllTargets: show table of targets with test status
```

### 5. Result Display

```rust
// Get results from orchestrator
let target_results = self.orchestrator.get_target_results(&target);

for (category, result) in target_results {
    // Render test result with:
    // - Status (Success/Warning/Failed)
    // - Key metrics
    // - Diagnoses with recommendations
}
```

## Quick Win Implementation

For immediate integration without full refactor:

```rust
// In main.rs, add test command that uses orchestrator
Commands::Test { target, categories, count, verbose } => {
    let mut orch = TestOrchestrator::new();
    // Register all tests based on categories
    // Run and display results
}
```

## Files to Modify

1. `src/bin/tui/app.rs` - Add orchestrator field
2. `src/bin/tui/mod.rs` - Add test category rendering
3. New: `src/bin/tui/test_panel.rs` - Test framework panel
4. New: `src/bin/tui/events.rs` - Key handler for categories

## Recommended Approach

**Phase 1** (Immediate): CLI integration only
- Keep TUI as-is with existing panels
- Add `test` CLI command using orchestrator
- Users can run: `fraggle-packet test google.com -c dns,https`

**Phase 2** (Later): Full TUI refactor
- Replace AppState.results with orchestrator.get_all_results()
- Add category selection UI
- Unified test result display
- Smart execution based on view mode

## Current Workaround

TUI works with existing tests. Test framework accessible via:
1. CLI `test` command (when binary compiles)
2. Library API for custom tools
3. Test demos in `tests/`

## Note

Binary currently has compilation issues due to AppState field changes. Fixing requires:
- Update all AppState::default() to include new fields
- Update all App instantiation
- Update event handlers for new fields

This is deferred to avoid scope creep. Test framework is complete and usable via library.


