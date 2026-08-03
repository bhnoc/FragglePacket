#[cfg(test)]
mod unified_test_demo {
    use fraggle_packet::framework::{TestCategory, TestOrchestrator, TestStatus};
    use fraggle_packet::network_tests::dns::DnsTest;
    use fraggle_packet::network_tests::https::HttpsTest;
    use fraggle_packet::network_tests::ipv6::Ipv6Test;
    use fraggle_packet::network_tests::mtu::{IcmpMtuTest, TcpMtuTest};
    use fraggle_packet::network_tests::packet_loss::PacketLossTest;
    use fraggle_packet::network_tests::path_analysis::PathAnalysisTest;
    use fraggle_packet::network_tests::rtt::RttTest;
    use fraggle_packet::network_tests::tcp_segmentation::TcpSegmentationTest;

    #[test]
    #[ignore] // Run with: cargo test unified_test_demo -- --ignored --nocapture
    fn demo_unified_tests() {
        let target = "google.com";

        println!("═══════════════════════════════════════════════════════════");
        println!("  FragglePacket - Unified Test Framework Demo");
        println!("═══════════════════════════════════════════════════════════\n");
        println!("Target: {}\n", target);

        // Create orchestrator and register all tests
        let mut orchestrator = TestOrchestrator::new();
        orchestrator.register(Box::new(DnsTest::new()));
        orchestrator.register(Box::new(Ipv6Test::new()));
        orchestrator.register(Box::new(IcmpMtuTest::new()));
        orchestrator.register(Box::new(TcpMtuTest::new()));
        orchestrator.register(Box::new(HttpsTest::new()));
        orchestrator.register(Box::new(TcpSegmentationTest::new()));
        orchestrator.register(Box::new(RttTest::new().with_count(10)));
        orchestrator.register(Box::new(PacketLossTest::new().with_count(10)));
        orchestrator.register(Box::new(PathAnalysisTest::new().with_max_hops(15)));

        println!(
            "Registered {} test categories\n",
            orchestrator.available_categories().len()
        );

        // Run all tests
        println!("Running all tests...\n");
        let results = orchestrator.run_all(&target);

        // Display results by category
        for result in &results {
            println!("┌─────────────────────────────────────────────────────────┐");
            println!("│ {} - {:?}", result.name, result.status);
            println!("└─────────────────────────────────────────────────────────┘");

            // Metrics
            if !result.metrics.is_empty() {
                println!("\n  Metrics:");
                for (key, value) in &result.metrics {
                    println!("    {}: {:.2}", key, value);
                }
            }

            // Metadata
            if !result.metadata.is_empty() {
                println!("\n  Info:");
                for (key, value) in &result.metadata {
                    if key != "error" && !value.is_empty() && value.len() < 100 {
                        println!("    {}: {}", key, value);
                    }
                }
            }

            // Diagnoses
            if !result.diagnoses.is_empty() {
                println!("\n  Issues:");
                for diag in &result.diagnoses {
                    println!("    [{:?}] {}", diag.severity, diag.title);
                    println!("      {}", diag.description);
                    if !diag.recommendations.is_empty() {
                        println!("      Recommendations:");
                        for rec in &diag.recommendations {
                            println!("        → {}", rec);
                        }
                    }
                }
            }

            println!("\n  Duration: {:?}\n", result.duration);
        }

        // Summary
        println!("═══════════════════════════════════════════════════════════");
        println!("  Summary");
        println!("═══════════════════════════════════════════════════════════");

        let success = results
            .iter()
            .filter(|r| matches!(r.status, TestStatus::Success))
            .count();
        let warnings = results
            .iter()
            .filter(|r| matches!(r.status, TestStatus::Warning))
            .count();
        let failed = results
            .iter()
            .filter(|r| matches!(r.status, TestStatus::Failed))
            .count();

        println!("  Total tests: {}", results.len());
        println!("  Success: {}", success);
        println!("  Warnings: {}", warnings);
        println!("  Failed: {}", failed);

        let issues: usize = results.iter().map(|r| r.diagnoses.len()).sum();
        println!("  Issues detected: {}", issues);

        println!("\n═══════════════════════════════════════════════════════════\n");
    }
}
