use colored::*;

#[derive(clap::Args, Debug)]
pub struct HttpsArgs {
    /// Target hostname (e.g., google.com, github.com)
    pub target: String,
    /// Timeout in seconds
    #[arg(short = 'T', long, default_value_t = 10)]
    pub timeout: u64,
    /// Show diagnosis and recommendations
    #[arg(short = 'd', long)]
    pub diagnose: bool,
}

pub fn run(args: &HttpsArgs) {
    run_https_test(&args.target, args.timeout, args.diagnose);
}

/// Run HTTPS test from CLI
fn run_https_test(target: &str, timeout: u64, diagnose: bool) {
    use fraggle_packet::diagnosis::{DiagnosisEngine, DiagnosisEvidence};
    use fraggle_packet::network_tests::{diagnose_mtu_blackhole, test_https_stages};

    println!("============================================================");
    println!(" HTTPS Testing - Stage-by-Stage Analysis");
    println!("============================================================\n");

    println!("Target: {}", target);
    println!("Timeout: {}s\n", timeout);

    println!("Running HTTPS test...\n");

    let result = test_https_stages(target, timeout);

    // Display results
    println!("┌─────────────────────────────────────┐");
    println!("│ Stage 1: DNS Resolution             │");
    println!("└─────────────────────────────────────┘");
    if let Some(time) = result.dns_time_ms {
        println!("  {} Success: {} ms", "✓".green(), time);
        println!("  Resolved IPs: {}", result.dns_ips.join(", "));
    } else {
        println!("  {} Failed", "✗".red());
    }
    println!();

    println!("┌─────────────────────────────────────┐");
    println!("│ Stage 2: TCP Connect                │");
    println!("└─────────────────────────────────────┘");
    if result.tcp_success {
        println!(
            "  {} Success: {} ms",
            "✓".green(),
            result.tcp_connect_time_ms.unwrap_or(0)
        );
    } else {
        println!("  {} Failed", "✗".red());
    }
    println!();

    println!("┌─────────────────────────────────────┐");
    println!("│ Stage 3: TLS Handshake (CRITICAL)  │");
    println!("└─────────────────────────────────────┘");
    if result.tls_success {
        println!(
            "  {} Success: {} ms",
            "✓".green(),
            result.tls_handshake_time_ms.unwrap_or(0)
        );
    } else {
        println!("  {} Failed or Timeout", "✗".red());
        if result.tcp_success {
            println!(
                "  {} TCP connected but TLS failed - possible MTU blackhole!",
                "⚠".yellow()
            );
        }
    }
    println!();

    if result.tls_success {
        println!("┌─────────────────────────────────────┐");
        println!("│ Stage 4: HTTP Request               │");
        println!("└─────────────────────────────────────┘");
        if let Some(time) = result.http_request_time_ms {
            println!("  {} Success: {} ms", "✓".green(), time);
        } else {
            println!("  {} Failed", "✗".red());
        }
        println!();

        println!("┌─────────────────────────────────────┐");
        println!("│ Stage 5: HTTP Response & TTFB       │");
        println!("└─────────────────────────────────────┘");
        if let Some(ttfb) = result.ttfb_ms {
            println!("  {} Success", "✓".green());
            println!("  Status Code: {}", result.status_code.unwrap_or(0));
            println!("  Time to First Byte: {} ms", ttfb);
        } else {
            println!("  {} Failed or Timeout", "✗".red());
        }
        println!();
    }

    println!("════════════════════════════════════════");
    println!("Total Time: {} ms", result.total_time_ms);
    println!("Diagnosis: {:?}", result.diagnosis);
    println!("════════════════════════════════════════\n");

    // Run diagnosis engine if requested
    if diagnose {
        println!("\n╔════════════════════════════════════════╗");
        println!("║  Diagnosis & Recommendations          ║");
        println!("╚════════════════════════════════════════╝\n");

        // Quick MTU blackhole check
        if diagnose_mtu_blackhole(&result, Some(1500)) {
            println!("{} MTU BLACKHOLE DETECTED!\n", "⚠️".yellow().bold());
        }

        // Run full diagnosis engine
        let evidence = DiagnosisEvidence {
            https_result: Some(result.clone()),
            interface_mtu: Some(1500), // TODO: Get actual interface MTU
            ..Default::default()
        };

        let engine = DiagnosisEngine::new();
        let diagnoses = engine.diagnose(&evidence);

        if diagnoses.is_empty() {
            println!("{} No issues detected", "✓".green());
        } else {
            for (i, diagnosis) in diagnoses.iter().enumerate() {
                println!(
                    "{} Issue #{}: {:?}",
                    "!".red().bold(),
                    i + 1,
                    diagnosis.issue
                );
                println!("  Severity: {:?}", diagnosis.severity);
                println!("  Description: {}", diagnosis.description);
                println!("\n  Recommendation:");
                println!("  {}", diagnosis.recommendation.replace("\n", "\n  "));
                println!("\n  Related Tests: {}", diagnosis.related_tests.join(", "));
                println!("\n{}\n", "─".repeat(60));
            }
        }
    }
}
