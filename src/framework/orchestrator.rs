use super::result::{TestResult, TestStatus};
use super::test_trait::{NetworkTest, TestCategory};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Manages test execution and result storage
pub struct TestOrchestrator {
    /// Registered tests
    tests: Vec<Box<dyn NetworkTest>>,

    /// Results storage: target -> category -> result
    results: Arc<Mutex<HashMap<String, HashMap<TestCategory, TestResult>>>>,
}

impl TestOrchestrator {
    pub fn new() -> Self {
        Self {
            tests: Vec::new(),
            results: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Register a test
    pub fn register(&mut self, test: Box<dyn NetworkTest>) {
        self.tests.push(test);
    }

    /// Run all tests for a target
    pub fn run_all(&self, target: &str) -> Vec<TestResult> {
        self.tests
            .iter()
            .filter_map(|test| self.run_single(test.as_ref(), target).ok())
            .collect()
    }

    /// Run tests by category
    pub fn run_category(&self, target: &str, category: TestCategory) -> Vec<TestResult> {
        self.tests
            .iter()
            .filter(|test| test.category() == category)
            .filter_map(|test| self.run_single(test.as_ref(), target).ok())
            .collect()
    }

    /// Run a single test
    pub fn run_single(&self, test: &dyn NetworkTest, target: &str) -> Result<TestResult, String> {
        let start = Instant::now();

        // Check root privileges if required
        if test.requires_root() && !is_root() {
            let mut result =
                TestResult::new(test.name().to_string(), test.category(), target.to_string());
            result.set_status(TestStatus::Skipped);
            result.add_metadata("skip_reason", "Requires root privileges");
            result.duration = start.elapsed();
            self.store_result(target, result.clone());
            return Ok(result);
        }

        // Run the test
        let mut result = match test.run(target) {
            Ok(r) => r,
            Err(e) => {
                let mut result =
                    TestResult::new(test.name().to_string(), test.category(), target.to_string());
                result.set_status(TestStatus::Failed);
                result.add_metadata("error", e.to_string());
                result.duration = start.elapsed();
                self.store_result(target, result.clone());
                return Ok(result);
            }
        };

        result.duration = start.elapsed();
        self.store_result(target, result.clone());
        Ok(result)
    }

    /// Store a test result
    fn store_result(&self, target: &str, result: TestResult) {
        let mut results = self.results.lock().unwrap();
        results
            .entry(target.to_string())
            .or_insert_with(HashMap::new)
            .insert(result.category, result);
    }

    /// Get result for specific target and category
    pub fn get_result(&self, target: &str, category: TestCategory) -> Option<TestResult> {
        let results = self.results.lock().unwrap();
        results.get(target)?.get(&category).cloned()
    }

    /// Get all results for a target
    pub fn get_target_results(&self, target: &str) -> HashMap<TestCategory, TestResult> {
        let results = self.results.lock().unwrap();
        results.get(target).cloned().unwrap_or_default()
    }

    /// Get all results
    pub fn get_all_results(&self) -> HashMap<String, HashMap<TestCategory, TestResult>> {
        let results = self.results.lock().unwrap();
        results.clone()
    }

    /// Clear all results
    pub fn clear_results(&self) {
        let mut results = self.results.lock().unwrap();
        results.clear();
    }

    /// Get list of available test categories
    pub fn available_categories(&self) -> Vec<TestCategory> {
        let mut categories: Vec<_> = self.tests.iter().map(|test| test.category()).collect();
        categories.sort_by_key(|c| *c as u8);
        categories.dedup();
        categories
    }

    /// Get count of tests by category
    pub fn test_count(&self, category: TestCategory) -> usize {
        self.tests
            .iter()
            .filter(|test| test.category() == category)
            .count()
    }
}

impl Default for TestOrchestrator {
    fn default() -> Self {
        Self::new()
    }
}

/// Check if running as root
fn is_root() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(not(unix))]
    {
        // On Windows, assume we have necessary privileges
        true
    }
}
