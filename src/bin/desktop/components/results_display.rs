//! Results display component with specialized visualizations
//!
//! Shows:
//! - HTTPS results: Waterfall chart
//! - PathAnalysis results: Hop table
//! - Other results: Generic key/value display

use dioxus::prelude::*;
use fraggle_packet::framework::{TestResult, TestStatus, TestCategory, DiagnosisSeverity};

/// Display a list of test results with specialized visualizations
pub fn render_results(results: &[TestResult]) -> Element {
    if results.is_empty() {
        return rsx! {
            div { class: "no-results",
                "No results yet. Run a test to see results."
            }
        };
    }

    rsx! {
        div { class: "results-display",
            for result in results.iter() {
                {render_result_card(result)}
            }
        }
    }
}

/// Render a single result card with category-specific visualization
fn render_result_card(result: &TestResult) -> Element {
    let status_class = match result.status {
        TestStatus::Success => "status-success",
        TestStatus::Warning => "status-warning",
        TestStatus::Failed => "status-error",
        TestStatus::Skipped => "status-pending",
        TestStatus::Running => "status-pending",
        TestStatus::Pending => "status-pending",
    };

    let status_text = match result.status {
        TestStatus::Success => "PASS",
        TestStatus::Warning => "WARN",
        TestStatus::Failed => "FAIL",
        TestStatus::Skipped => "SKIP",
        TestStatus::Running => "RUN",
        TestStatus::Pending => "PEND",
    };

    let name = result.name.clone();
    let target = result.target.clone();
    let duration_ms = result.duration.as_millis();
    let category = result.category;

    rsx! {
        div { class: "result-card",
            // Header
            div { class: "result-header",
                span { class: "result-name", "{name}" }
                span { class: "result-status {status_class}", "{status_text}" }
            }
            div { class: "result-target", "Target: {target}" }
            div { class: "result-duration", "Duration: {duration_ms}ms" }

            // Category-specific visualization
            {match category {
                TestCategory::HTTPS => render_https_waterfall(result),
                TestCategory::PathAnalysis => render_path_hops(result),
                _ => render_generic_metrics(result),
            }}

            // Diagnoses (shown for all)
            {render_diagnoses(result)}
        }
    }
}

/// Render HTTPS waterfall chart
fn render_https_waterfall(result: &TestResult) -> Element {
    let stages: Vec<(&str, f64, bool)> = vec![
        ("DNS", result.metrics.get("dns_time_ms").copied().unwrap_or(0.0), true),
        ("TCP Connect", result.metrics.get("tcp_connect_time_ms").copied().unwrap_or(0.0),
         result.metadata.get("tcp_success").map(|s| s == "true").unwrap_or(true)),
        ("TLS Handshake", result.metrics.get("tls_handshake_time_ms").copied().unwrap_or(0.0),
         result.metadata.get("tls_success").map(|s| s == "true").unwrap_or(true)),
        ("TTFB", result.metrics.get("ttfb_ms").copied().unwrap_or(0.0), true),
        ("Total", result.metrics.get("total_time_ms").copied().unwrap_or(0.0), true),
    ];

    let max_time = stages.iter().map(|(_, t, _)| *t).fold(0.0_f64, f64::max).max(1.0);

    // Get HTTP status if available
    let http_status = result.metadata.get("http_status").cloned().unwrap_or_default();

    rsx! {
        div { class: "result-visualization",
            div { class: "viz-header",
                span { class: "viz-title", "Connection Waterfall" }
                if !http_status.is_empty() {
                    span { class: "viz-status", "HTTP {http_status}" }
                }
            }
            div { class: "waterfall",
                for (stage, time, success) in stages {
                    {
                        let width_pct = if max_time > 0.0 { (time / max_time * 100.0) as u32 } else { 0 };
                        let bar_class = if success { "waterfall-fill" } else { "waterfall-fill error" };
                        let min_width = if time > 0.0 { "40px" } else { "0" };
                        let time_text = if time > 0.0 { format!("{:.0}ms", time) } else { "-".to_string() };
                        rsx! {
                            div { class: "waterfall-stage",
                                div { class: "waterfall-label", "{stage}" }
                                div { class: "waterfall-bar",
                                    div {
                                        class: "{bar_class}",
                                        style: "width: {width_pct}%; min-width: {min_width};",
                                        "{time_text}"
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Render Path Analysis hop table
fn render_path_hops(result: &TestResult) -> Element {
    // Parse hop data from metadata (hop_N_addr, hop_N_rtt)
    let mut hops: Vec<(u32, String, f64, String)> = Vec::new();
    for i in 1..=30 {
        let addr_key = format!("hop_{}_addr", i);
        let rtt_key = format!("hop_{}_rtt", i);
        if let Some(addr) = result.metadata.get(&addr_key) {
            let rtt = result.metrics.get(&rtt_key).copied().unwrap_or(0.0);
            let mtu = result.metadata.get(&format!("hop_{}_mtu", i))
                .cloned()
                .unwrap_or_else(|| "1500".to_string());
            hops.push((i as u32, addr.clone(), rtt, mtu));
        } else {
            break;
        }
    }

    // If no hop data, show summary metrics instead
    if hops.is_empty() {
        return render_generic_metrics(result);
    }

    let hop_count = hops.len();

    rsx! {
        div { class: "result-visualization",
            div { class: "viz-header",
                span { class: "viz-title", "Route Path" }
                span { class: "viz-status", "{hop_count} hops" }
            }
            table { class: "table hop-table",
                thead {
                    tr {
                        th { "Hop" }
                        th { "Address" }
                        th { "RTT" }
                        th { "MTU" }
                    }
                }
                tbody {
                    for (hop, addr, rtt, mtu) in hops {
                        {
                            let mtu_val: u32 = mtu.parse().unwrap_or(1500);
                            let mtu_class = if mtu_val < 1500 { "status-warning" } else { "" };
                            rsx! {
                                tr {
                                    td { "{hop}" }
                                    td { class: "hop-addr", "{addr}" }
                                    td { "{rtt:.1}ms" }
                                    td { class: "{mtu_class}", "{mtu}" }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Render generic metrics and metadata
fn render_generic_metrics(result: &TestResult) -> Element {
    let metrics: Vec<_> = result.metrics.iter()
        .filter(|(k, _)| !k.starts_with("hop_"))  // Skip hop data for generic view
        .map(|(k, v)| (k.clone(), *v))
        .collect();
    let metadata: Vec<_> = result.metadata.iter()
        .filter(|(k, _)| !k.starts_with("cli_") && !k.starts_with("hop_"))  // Skip cli commands and hop data
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    rsx! {
        // Metrics
        if !metrics.is_empty() {
            div { class: "result-metrics",
                h4 { "Metrics" }
                div { class: "metrics-grid",
                    for (key, value) in metrics.iter() {
                        div { class: "metric",
                            span { class: "metric-key", "{key}:" }
                            span { class: "metric-value", "{value:.2}" }
                        }
                    }
                }
            }
        }

        // Metadata
        if !metadata.is_empty() {
            div { class: "result-metadata",
                h4 { "Details" }
                for (key, value) in metadata.iter() {
                    div { class: "metadata",
                        span { class: "metadata-key", "{key}:" }
                        span { class: "metadata-value", "{value}" }
                    }
                }
            }
        }
    }
}

/// Render diagnoses
fn render_diagnoses(result: &TestResult) -> Element {
    let diagnoses: Vec<_> = result.diagnoses.clone();

    if diagnoses.is_empty() {
        return rsx! {};
    }

    rsx! {
        div { class: "result-diagnoses",
            h4 { "Diagnoses" }
            for diagnosis in diagnoses.iter() {
                {
                    let severity_class = match diagnosis.severity {
                        DiagnosisSeverity::Info => "diagnosis-info",
                        DiagnosisSeverity::Warning => "diagnosis-warning",
                        DiagnosisSeverity::Error => "diagnosis-error",
                        DiagnosisSeverity::Critical => "diagnosis-critical",
                    };
                    let title = diagnosis.title.clone();
                    let desc = diagnosis.description.clone();
                    let recs: Vec<_> = diagnosis.recommendations.clone();
                    rsx! {
                        div { class: "diagnosis {severity_class}",
                            div { class: "diagnosis-title", "{title}" }
                            div { class: "diagnosis-desc", "{desc}" }
                            if !recs.is_empty() {
                                div { class: "diagnosis-recs",
                                    strong { "Recommendations:" }
                                    ul {
                                        for rec in recs.iter() {
                                            li { "{rec}" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// ResultsDisplay - call render_results directly
pub struct ResultsDisplay;

impl ResultsDisplay {
    pub fn render(results: &[TestResult]) -> Element {
        render_results(results)
    }
}
