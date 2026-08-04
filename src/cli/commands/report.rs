use colored::*;

use crate::cli::common::print_test_result;

#[derive(clap::Args, Debug)]
pub struct ReportArgs {
    /// Target hostname
    pub target: String,

    /// Emit every probe result plus the diagnoses as one JSON object
    #[arg(long)]
    pub json: bool,
}

pub fn run(args: &ReportArgs) {
    run_unified_report(&args.target, args.json);
}

fn run_unified_report(target: &str, json: bool) {
    use fraggle_packet::diagnosis::{render_unified_report, DiagnosisEngine, DiagnosisEvidence};
    use fraggle_packet::framework::NetworkTest;
    use fraggle_packet::network_tests::{
        https::HttpsTest, Raw9100BulkTest, SshDataPathTest, UploadSizeSweepTest,
    };
    let mut ev = DiagnosisEvidence::default();
    // In JSON mode every probe result is collected and emitted once as an array,
    // rather than four separate objects that would not parse as one document.
    let mut collected: Vec<fraggle_packet::framework::TestResult> = Vec::new();
    if !json {
        println!("{}", format!("Running unified probe suite against {}", target).cyan().bold());
    }

    if let Ok(r) = HttpsTest::new().run(target) {
        if let Some(connect) = r.metrics.get("tls_success") {
            ev.tcp_connect_success = Some(*connect > 0.5);
        }
        if json { collected.push(r.clone()); } else { print_test_result(&r); }
    }
    if let Ok(r) = UploadSizeSweepTest::new().run(target) {
        let fails = r.metadata.get("upload_fail_sizes").cloned().unwrap_or_default();
        ev.upload_fail_sizes = fails
            .split(',')
            .filter_map(|s| s.trim().parse().ok())
            .collect();
        if json { collected.push(r.clone()); } else { print_test_result(&r); }
    }
    if let Ok(r) = SshDataPathTest::new().run(target) {
        ev.ssh_banner_ok = r
            .metadata
            .get("ssh_banner_ok")
            .and_then(|v| v.parse().ok());
        ev.ssh_exec_ok = r
            .metadata
            .get("ssh_exec_ok")
            .and_then(|v| v.parse().ok());
        if json { collected.push(r.clone()); } else { print_test_result(&r); }
    }
    if let Ok(r) = Raw9100BulkTest::new().run(target) {
        let fails = r
            .metadata
            .get("printer_fail_sizes")
            .cloned()
            .unwrap_or_default();
        ev.printer_fail_sizes = fails
            .split(',')
            .filter_map(|s| s.trim().parse().ok())
            .collect();
        if json { collected.push(r.clone()); } else { print_test_result(&r); }
    }

    let engine = DiagnosisEngine::new();
    let diagnoses = engine.diagnose(&ev);

    if json {
        let doc = serde_json::json!({
            "target": target,
            "probe_results": collected,
            "diagnoses": diagnoses,
        });
        match serde_json::to_string_pretty(&doc) {
            Ok(s) => println!("{s}"),
            Err(e) => eprintln!("failed to serialize report: {e}"),
        }
        return;
    }

    println!("\n{}", "╔════════════════════════════════════════════════╗".cyan());
    println!("{}", "║   FragglePacket Unified Report (README_FIRST)  ║".cyan().bold());
    println!("{}", "╚════════════════════════════════════════════════╝".cyan());
    println!();
    println!("{}", render_unified_report(&diagnoses, &ev));
}
