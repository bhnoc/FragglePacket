//! CLI command for running test framework tests

use fraggle_packet::framework::{TestOrchestrator, TestCategory, TestStatus};
use fraggle_packet::network_tests::https::HttpsTest;
use fraggle_packet::network_tests::tcp_segmentation::TcpSegmentationTest;
use fraggle_packet::network_tests::rtt::RttTest;
use fraggle_packet::network_tests::dns::DnsTest;
use fraggle_packet::network_tests::packet_loss::PacketLossTest;
use colored::*;

pub struct TestCommand {
    pub target: String,
    pub categories: String,
    pub count: usize,
    pub verbose: bool,
}

pub fn run_tests(cmd: TestCommand) {
    println!("{}", "═══════════════════════════════════════════════════════════".cyan());
    println!("  {}", "FragglePacket - Network Test Suite".cyan().bold());
    println!("{}", "═══════════════════════════════════════════════════════════".cyan());
    println!("\nTarget: {}\n", cmd.target.green().bold());
    
    // Create orchestrator
    let mut orchestrator = TestOrchestrator::new();
    
    // Parse categories
    let categories: Vec<&str> = cmd.categories.split(',').map(|s| s.trim()).collect();
    let run_all = categories.contains(&"all");
    
    // Register tests based on categories
    if run_all || categories.contains(&"dns") {
        orchestrator.register(Box::new(DnsTest::new()));
    }
    if run_all || categories.contains(&"https") {
        orchestrator.register(Box::new(HttpsTest::new()));
    }
    if run_all || categories.contains(&"tcp") {
        orchestrator.register(Box::new(TcpSegmentationTest::new()));
    }
    if run_all || categories.contains(&"rtt") {
        orchestrator.register(Box::new(RttTest::new().with_count(cmd.count)));
    }
    if run_all || categories.contains(&"loss") {
        orchestrator.register(Box::new(PacketLossTest::new().with_count(cmd.count)));
    }
    
    let test_count = orchestrator.available_categories().len();
    println!("Running {} test categories...\n", test_count);
    
    // Run tests
    let results = orchestrator.run_all(&cmd.target);
    
    // Display results
    for result in &results {
        let status_str = match result.status {
            TestStatus::Success => "✓ SUCCESS".green().bold(),
            TestStatus::Warning => "⚠ WARNING".yellow().bold(),
            TestStatus::Failed => "✗ FAILED".red().bold(),
            TestStatus::Skipped => "⊘ SKIPPED".bright_black(),
            _ => "• PENDING".white(),
        };
        
        println!("┌─────────────────────────────────────────────────────────┐");
        println!("│ {} - {}", result.name.cyan().bold(), status_str);
        println!("└─────────────────────────────────────────────────────────┘");
        
        // Show key metrics
        if !result.metrics.is_empty() {
            println!("\n  {}:", "Metrics".yellow());
            let mut metrics: Vec<_> = result.metrics.iter().collect();
            metrics.sort_by_key(|(k, _)| *k);
            
            for (key, value) in metrics.iter().take(if cmd.verbose { 100 } else { 5 }) {
                if **value >= 0.0 {
                    println!("    {}: {:.2}", key, value);
                }
            }
        }
        
        // Show diagnoses
        if !result.diagnoses.is_empty() {
            println!("\n  {}:", "Issues Detected".red().bold());
            for diag in &result.diagnoses {
                let severity_str = match diag.severity {
                    fraggle_packet::framework::DiagnosisSeverity::Critical => "CRITICAL".red().bold(),
                    fraggle_packet::framework::DiagnosisSeverity::Error => "ERROR".red(),
                    fraggle_packet::framework::DiagnosisSeverity::Warning => "WARNING".yellow(),
                    fraggle_packet::framework::DiagnosisSeverity::Info => "INFO".blue(),
                };
                
                println!("    [{}] {}", severity_str, diag.title.bold());
                println!("      {}", diag.description);
                
                if !diag.recommendations.is_empty() {
                    println!("      {}:", "Recommendations".cyan());
                    for rec in &diag.recommendations {
                        println!("        → {}", rec);
                    }
                }
            }
        }
        
        if cmd.verbose {
            println!("\n  Duration: {:?}", result.duration);
        }
        
        println!();
    }
    
    // Summary
    println!("{}", "═══════════════════════════════════════════════════════════".cyan());
    println!("  {}", "Summary".cyan().bold());
    println!("{}", "═══════════════════════════════════════════════════════════".cyan());
    
    let success = results.iter().filter(|r| matches!(r.status, TestStatus::Success)).count();
    let warnings = results.iter().filter(|r| matches!(r.status, TestStatus::Warning)).count();
    let failed = results.iter().filter(|r| matches!(r.status, TestStatus::Failed)).count();
    let issues: usize = results.iter().map(|r| r.diagnoses.len()).sum();
    
    println!("  Total tests: {}", results.len());
    println!("  Success: {}", success.to_string().green());
    println!("  Warnings: {}", warnings.to_string().yellow());
    println!("  Failed: {}", failed.to_string().red());
    println!("  Issues detected: {}", if issues > 0 { issues.to_string().red() } else { issues.to_string().green() });
    
    println!("\n{}\n", "═══════════════════════════════════════════════════════════".cyan());
}

