#[cfg(test)]
mod test_framework_demo {
    use fraggle_packet::framework::{TestOrchestrator, TestCategory};
    use fraggle_packet::network_tests::https::HttpsTest;

    #[test]
    #[ignore] // Run with: cargo test --test test_framework_demo -- --ignored --nocapture
    fn demo_test_framework() {
        // Create orchestrator
        let mut orchestrator = TestOrchestrator::new();
        
        // Register tests
        orchestrator.register(Box::new(HttpsTest::new()));
        
        // Run all tests for a target
        let target = "google.com";
        println!("Running all tests for {}...", target);
        let results = orchestrator.run_all(target);
        
        for result in &results {
            println!("\n{} ({}): {:?}", result.name, result.category.as_str(), result.status);
            
            // Show metrics
            for (key, value) in &result.metrics {
                println!("  {}: {}", key, value);
            }
            
            // Show diagnoses
            for diag in &result.diagnoses {
                println!("  [{:?}] {}", diag.severity, diag.title);
                println!("    {}", diag.description);
                for rec in &diag.recommendations {
                    println!("    → {}", rec);
                }
            }
        }
        
        // Run only HTTPS tests
        println!("\n\nRunning HTTPS tests only...");
        let https_results = orchestrator.run_category(target, TestCategory::HTTPS);
        println!("Found {} HTTPS test(s)", https_results.len());
        
        // Get specific result
        if let Some(result) = orchestrator.get_result(target, TestCategory::HTTPS) {
            println!("\nRetrieved HTTPS result: {:?}", result.status);
        }
    }
}

