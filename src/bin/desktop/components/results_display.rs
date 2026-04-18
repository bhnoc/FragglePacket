//! Results display component for showing test results

use dioxus::prelude::*;
use fraggle_packet::framework::{TestResult, TestStatus, DiagnosisSeverity};

/// Display a list of test results
/// Note: We pass results as a Signal to avoid PartialEq requirement
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

/// Render a single result card
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
    let metrics: Vec<_> = result.metrics.iter().map(|(k, v)| (k.clone(), *v)).collect();
    let metadata: Vec<_> = result.metadata.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    let diagnoses: Vec<_> = result.diagnoses.clone();

    rsx! {
        div { class: "result-card",
            div { class: "result-header",
                span { class: "result-name", "{name}" }
                span { class: "result-status {status_class}", "{status_text}" }
            }
            div { class: "result-target", "Target: {target}" }
            div { class: "result-duration", "Duration: {duration_ms}ms" }

            // Metrics
            if !metrics.is_empty() {
                div { class: "result-metrics",
                    h4 { "Metrics" }
                    for (key, value) in metrics.iter() {
                        div { class: "metric",
                            span { class: "metric-key", "{key}:" }
                            span { class: "metric-value", "{value:.2}" }
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

            // Diagnoses
            if !diagnoses.is_empty() {
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
    }
}

/// ResultsDisplay - call render_results directly instead of using as a component
pub struct ResultsDisplay;

impl ResultsDisplay {
    pub fn render(results: &[TestResult]) -> Element {
        render_results(results)
    }
}
