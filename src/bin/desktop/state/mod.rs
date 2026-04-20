//! Application state management for FragglePacket Desktop

pub mod test_runner;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use dioxus::prelude::*;
use tokio::sync::mpsc;
use fraggle_packet::framework::{TestCategory, TestResult, TestOrchestrator, TestStatus};
use chrono::{DateTime, Local};

use crate::test_registration::register_all_tests;
use test_runner::{TestRunner, TestUpdate};

/// Panel identifiers for tab management
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PanelId {
    Dashboard,
    Tests,
    Https,
    Fuzzing,
    Path,
    Simulator,
    VpnCalculator,
    Targets,
    Logs,
    History,
}

impl PanelId {
    pub fn label(&self) -> &'static str {
        match self {
            PanelId::Dashboard => "Dashboard",
            PanelId::Tests => "Tests",
            PanelId::Https => "HTTPS",
            PanelId::Fuzzing => "Fuzzing",
            PanelId::Path => "Path",
            PanelId::Simulator => "Simulator",
            PanelId::VpnCalculator => "VPN Calc",
            PanelId::Targets => "Targets",
            PanelId::Logs => "Logs",
            PanelId::History => "History",
        }
    }

    /// Returns panels shown in the main tab bar
    /// Note: HTTPS and Path visualizations are now integrated into Tests results
    pub fn all() -> Vec<PanelId> {
        vec![
            PanelId::Dashboard,
            PanelId::Tests,
            PanelId::Fuzzing,
            PanelId::Simulator,
            PanelId::Logs,
            PanelId::History,
        ]
    }
}

/// Target category for grouping in dropdown
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetCategory {
    Dns,
    CloudProviders,
    Microsoft365,
    Collaboration,
    DevTools,
    Cdn,
    Custom,
}

impl TargetCategory {
    pub fn label(&self) -> &'static str {
        match self {
            TargetCategory::Dns => "DNS Servers",
            TargetCategory::CloudProviders => "Cloud Providers",
            TargetCategory::Microsoft365 => "Microsoft 365",
            TargetCategory::Collaboration => "Collaboration",
            TargetCategory::DevTools => "Dev Tools",
            TargetCategory::Cdn => "CDN / Edge",
            TargetCategory::Custom => "Custom",
        }
    }

    pub fn all() -> Vec<TargetCategory> {
        vec![
            TargetCategory::Dns,
            TargetCategory::CloudProviders,
            TargetCategory::Microsoft365,
            TargetCategory::Collaboration,
            TargetCategory::DevTools,
            TargetCategory::Cdn,
        ]
    }
}

/// Target configuration
#[derive(Debug, Clone)]
pub struct Target {
    pub host: String,
    pub description: String,
    pub port: u16,
    pub category: TargetCategory,
    /// Which test categories this target supports
    pub supported_tests: Vec<TestCategory>,
}

impl Target {
    pub fn new(host: impl Into<String>, description: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            description: description.into(),
            port,
            category: TargetCategory::Custom,
            supported_tests: Vec::new(),
        }
    }

    pub fn with_category(mut self, category: TargetCategory) -> Self {
        self.category = category;
        self
    }

    pub fn with_tests(mut self, tests: Vec<TestCategory>) -> Self {
        self.supported_tests = tests;
        self
    }

    /// Check if this target supports a given test category
    pub fn supports_test(&self, test: TestCategory) -> bool {
        self.supported_tests.is_empty() || self.supported_tests.contains(&test)
    }
}

/// Get the built-in preset targets organized by category
/// Note: All test categories work with all targets (verified via CLI testing)
pub fn get_preset_targets() -> Vec<Target> {
    // All tests work with all targets - no filtering needed
    let all_tests = TestCategory::all();

    vec![
        // DNS Servers (also support HTTPS via DNS-over-HTTPS)
        Target::new("8.8.8.8", "Google DNS", 443)
            .with_category(TargetCategory::Dns)
            .with_tests(all_tests.clone()),
        Target::new("8.8.4.4", "Google DNS Secondary", 443)
            .with_category(TargetCategory::Dns)
            .with_tests(all_tests.clone()),
        Target::new("1.1.1.1", "Cloudflare DNS", 443)
            .with_category(TargetCategory::Dns)
            .with_tests(all_tests.clone()),
        Target::new("1.0.0.1", "Cloudflare DNS Secondary", 443)
            .with_category(TargetCategory::Dns)
            .with_tests(all_tests.clone()),
        Target::new("9.9.9.9", "Quad9 DNS", 443)
            .with_category(TargetCategory::Dns)
            .with_tests(all_tests.clone()),
        Target::new("208.67.222.222", "OpenDNS", 443)
            .with_category(TargetCategory::Dns)
            .with_tests(all_tests.clone()),

        // Cloud Providers
        Target::new("aws.amazon.com", "AWS", 443)
            .with_category(TargetCategory::CloudProviders)
            .with_tests(all_tests.clone()),
        Target::new("console.aws.amazon.com", "AWS Console", 443)
            .with_category(TargetCategory::CloudProviders)
            .with_tests(all_tests.clone()),
        Target::new("azure.microsoft.com", "Azure", 443)
            .with_category(TargetCategory::CloudProviders)
            .with_tests(all_tests.clone()),
        Target::new("portal.azure.com", "Azure Portal", 443)
            .with_category(TargetCategory::CloudProviders)
            .with_tests(all_tests.clone()),
        Target::new("cloud.google.com", "Google Cloud", 443)
            .with_category(TargetCategory::CloudProviders)
            .with_tests(all_tests.clone()),
        Target::new("console.cloud.google.com", "GCP Console", 443)
            .with_category(TargetCategory::CloudProviders)
            .with_tests(all_tests.clone()),

        // Microsoft 365
        Target::new("outlook.office365.com", "M365 Outlook", 443)
            .with_category(TargetCategory::Microsoft365)
            .with_tests(all_tests.clone()),
        Target::new("teams.microsoft.com", "MS Teams", 443)
            .with_category(TargetCategory::Microsoft365)
            .with_tests(all_tests.clone()),
        Target::new("login.microsoftonline.com", "M365 Auth", 443)
            .with_category(TargetCategory::Microsoft365)
            .with_tests(all_tests.clone()),
        Target::new("sharepoint.com", "SharePoint", 443)
            .with_category(TargetCategory::Microsoft365)
            .with_tests(all_tests.clone()),
        Target::new("onedrive.live.com", "OneDrive", 443)
            .with_category(TargetCategory::Microsoft365)
            .with_tests(all_tests.clone()),

        // Collaboration
        Target::new("slack.com", "Slack", 443)
            .with_category(TargetCategory::Collaboration)
            .with_tests(all_tests.clone()),
        Target::new("zoom.us", "Zoom", 443)
            .with_category(TargetCategory::Collaboration)
            .with_tests(all_tests.clone()),
        Target::new("meet.google.com", "Google Meet", 443)
            .with_category(TargetCategory::Collaboration)
            .with_tests(all_tests.clone()),
        Target::new("mail.google.com", "Gmail", 443)
            .with_category(TargetCategory::Collaboration)
            .with_tests(all_tests.clone()),
        Target::new("discord.com", "Discord", 443)
            .with_category(TargetCategory::Collaboration)
            .with_tests(all_tests.clone()),

        // Dev Tools
        Target::new("github.com", "GitHub", 443)
            .with_category(TargetCategory::DevTools)
            .with_tests(all_tests.clone()),
        Target::new("gitlab.com", "GitLab", 443)
            .with_category(TargetCategory::DevTools)
            .with_tests(all_tests.clone()),
        Target::new("bitbucket.org", "Bitbucket", 443)
            .with_category(TargetCategory::DevTools)
            .with_tests(all_tests.clone()),
        Target::new("npmjs.com", "npm Registry", 443)
            .with_category(TargetCategory::DevTools)
            .with_tests(all_tests.clone()),
        Target::new("pypi.org", "PyPI", 443)
            .with_category(TargetCategory::DevTools)
            .with_tests(all_tests.clone()),
        Target::new("crates.io", "crates.io", 443)
            .with_category(TargetCategory::DevTools)
            .with_tests(all_tests.clone()),

        // CDN / Edge
        Target::new("cloudflare.com", "Cloudflare", 443)
            .with_category(TargetCategory::Cdn)
            .with_tests(all_tests.clone()),
        Target::new("akamai.com", "Akamai", 443)
            .with_category(TargetCategory::Cdn)
            .with_tests(all_tests.clone()),
        Target::new("fastly.com", "Fastly", 443)
            .with_category(TargetCategory::Cdn)
            .with_tests(all_tests.clone()),
        Target::new("cdn.jsdelivr.net", "jsDelivr CDN", 443)
            .with_category(TargetCategory::Cdn)
            .with_tests(all_tests.clone()),
    ]
}

/// Toast notification
#[derive(Debug, Clone)]
pub struct Toast {
    pub id: u64,
    pub message: String,
    pub toast_type: ToastType,
}

#[derive(Debug, Clone, Copy)]
pub enum ToastType {
    Success,
    Warning,
    Error,
    Info,
}

/// Log entry for live test output
#[derive(Debug, Clone)]
pub struct LogEntry {
    pub timestamp: DateTime<Local>,
    pub level: LogLevel,
    pub message: String,
    /// Optional CLI command that was run
    pub cli_command: Option<String>,
    /// Optional detailed output/results
    pub details: Option<String>,
    /// Optional metrics as key-value pairs
    pub metrics: Vec<(String, String)>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LogLevel {
    Info,
    Running,
    Success,
    Warning,
    Error,
}

impl LogEntry {
    pub fn new(level: LogLevel, message: impl Into<String>) -> Self {
        Self {
            timestamp: Local::now(),
            level,
            message: message.into(),
            cli_command: None,
            details: None,
            metrics: Vec::new(),
        }
    }

    pub fn with_cli_command(mut self, cmd: impl Into<String>) -> Self {
        self.cli_command = Some(cmd.into());
        self
    }

    pub fn with_details(mut self, details: impl Into<String>) -> Self {
        self.details = Some(details.into());
        self
    }

    pub fn with_metrics(mut self, metrics: Vec<(String, String)>) -> Self {
        self.metrics = metrics;
        self
    }
}

/// Historical test run record
#[derive(Debug, Clone)]
pub struct HistoryEntry {
    pub id: u64,
    pub timestamp: DateTime<Local>,
    pub target: String,
    /// Categories that were run (empty means all)
    pub categories: HashSet<TestCategory>,
    pub results: Vec<TestResult>,
    pub duration_secs: u64,
}

/// Main application state
#[derive(Clone)]
pub struct AppState {
    /// Currently active panel
    pub active_panel: Signal<PanelId>,

    /// Currently selected test categories (multi-select)
    pub selected_categories: Signal<HashSet<TestCategory>>,

    /// Current target for testing
    pub current_target: Signal<String>,

    /// All configured targets
    pub targets: Signal<Vec<Target>>,

    /// Test results: target -> list of results
    pub results: Signal<HashMap<String, Vec<TestResult>>>,

    /// Whether tests are currently running
    pub testing: Signal<bool>,

    /// Current test progress (0.0 - 1.0)
    pub progress: Signal<f64>,

    /// Status message
    pub status_message: Signal<String>,

    /// Toast notifications
    pub toasts: Signal<Vec<Toast>>,

    /// Toast ID counter
    toast_counter: Signal<u64>,

    /// Test runner for async execution
    pub test_runner: Arc<TestRunner>,

    /// Channel receiver for test updates
    pub update_rx: Signal<Option<mpsc::Receiver<TestUpdate>>>,

    /// Live log entries
    pub logs: Signal<Vec<LogEntry>>,

    /// History of completed test runs
    pub history: Signal<Vec<HistoryEntry>>,

    /// History ID counter
    history_counter: Signal<u64>,

    /// Currently running test name
    pub current_test_name: Signal<String>,

    /// Cancellation flag for stopping tests
    pub cancel_flag: Arc<AtomicBool>,

    /// Test start time for duration tracking
    pub test_start_time: Signal<Option<std::time::Instant>>,
}

impl AppState {
    pub fn new() -> Self {
        // Create and configure the test orchestrator
        let mut orchestrator = TestOrchestrator::new();
        register_all_tests(&mut orchestrator);

        // Create test runner
        let test_runner = Arc::new(TestRunner::new(orchestrator));

        // Use a subset of presets as default targets
        let default_targets = vec![
            Target::new("8.8.8.8", "Google DNS", 0).with_category(TargetCategory::Dns),
            Target::new("1.1.1.1", "Cloudflare DNS", 0).with_category(TargetCategory::Dns),
            Target::new("github.com", "GitHub", 443).with_category(TargetCategory::DevTools),
            Target::new("google.com", "Google", 443).with_category(TargetCategory::Collaboration),
        ];

        Self {
            active_panel: Signal::new(PanelId::Dashboard),
            selected_categories: Signal::new(HashSet::new()),
            current_target: Signal::new("github.com".to_string()),
            targets: Signal::new(default_targets),
            results: Signal::new(HashMap::new()),
            testing: Signal::new(false),
            progress: Signal::new(0.0),
            status_message: Signal::new("Ready".to_string()),
            toasts: Signal::new(Vec::new()),
            toast_counter: Signal::new(0),
            test_runner,
            update_rx: Signal::new(None),
            logs: Signal::new(Vec::new()),
            history: Signal::new(Vec::new()),
            history_counter: Signal::new(0),
            current_test_name: Signal::new(String::new()),
            cancel_flag: Arc::new(AtomicBool::new(false)),
            test_start_time: Signal::new(None),
        }
    }

    /// Add a toast notification
    pub fn add_toast(&mut self, message: impl Into<String>, toast_type: ToastType) {
        let id = *self.toast_counter.read();
        self.toast_counter.set(id + 1);

        let toast = Toast {
            id,
            message: message.into(),
            toast_type,
        };

        self.toasts.write().push(toast);
    }

    /// Remove a toast by ID
    pub fn remove_toast(&mut self, id: u64) {
        self.toasts.write().retain(|t| t.id != id);
    }

    /// Store test results for a target
    pub fn store_result(&mut self, target: &str, result: TestResult) {
        let mut all_results = self.results.write();
        all_results
            .entry(target.to_string())
            .or_insert_with(Vec::new)
            .push(result);
    }

    /// Get all results for a target
    pub fn get_target_results(&self, target: &str) -> Vec<TestResult> {
        self.results.read()
            .get(target)
            .cloned()
            .unwrap_or_default()
    }

    /// Get results filtered by category
    pub fn get_category_results(&self, target: &str, category: TestCategory) -> Vec<TestResult> {
        self.results.read()
            .get(target)
            .map(|results| {
                results.iter()
                    .filter(|r| r.category == category)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Clear all results
    pub fn clear_results(&mut self) {
        self.results.write().clear();
    }

    /// Count successful tests
    pub fn success_count(&self) -> usize {
        self.results.read()
            .values()
            .flat_map(|v| v.iter())
            .filter(|r| r.status == TestStatus::Success)
            .count()
    }

    /// Count total tests run
    pub fn total_tests(&self) -> usize {
        self.results.read()
            .values()
            .map(|v| v.len())
            .sum()
    }

    /// Add a log entry
    pub fn log(&mut self, level: LogLevel, message: impl Into<String>) {
        let entry = LogEntry::new(level, message);
        self.logs.write().push(entry);
        // Keep last 500 entries
    }

    /// Add a detailed log entry with CLI command and results
    pub fn log_detailed(&mut self, entry: LogEntry) {
        self.logs.write().push(entry);
        // Keep last 500 entries
        let mut logs = self.logs.write();
        if logs.len() > 500 {
            logs.drain(0..100);
        }
    }

    /// Clear logs
    pub fn clear_logs(&mut self) {
        self.logs.write().clear();
    }

    /// Save current results to history
    pub fn save_to_history(&mut self, target: &str, categories: HashSet<TestCategory>) {
        let results = self.results.read()
            .get(target)
            .cloned()
            .unwrap_or_default();

        if results.is_empty() {
            return;
        }

        let id = *self.history_counter.read();
        self.history_counter.set(id + 1);

        let duration = (*self.test_start_time.read())
            .map(|t| t.elapsed().as_secs())
            .unwrap_or(0);

        let entry = HistoryEntry {
            id,
            timestamp: Local::now(),
            target: target.to_string(),
            categories,
            results,
            duration_secs: duration,
        };

        self.history.write().insert(0, entry);

        // Keep last 50 history entries
        let mut history = self.history.write();
        if history.len() > 50 {
            history.truncate(50);
        }
    }

    /// Get results filtered by multiple categories
    pub fn get_categories_results(&self, target: &str, categories: &HashSet<TestCategory>) -> Vec<TestResult> {
        self.results.read()
            .get(target)
            .map(|results| {
                if categories.is_empty() {
                    results.clone()
                } else {
                    results.iter()
                        .filter(|r| categories.contains(&r.category))
                        .cloned()
                        .collect()
                }
            })
            .unwrap_or_default()
    }

    /// Clear history
    pub fn clear_history(&mut self) {
        self.history.write().clear();
    }

    /// Request cancellation of running tests
    pub fn cancel_tests(&self) {
        self.cancel_flag.store(true, Ordering::SeqCst);
    }

    /// Reset cancellation flag (call before starting new tests)
    pub fn reset_cancel(&self) {
        self.cancel_flag.store(false, Ordering::SeqCst);
    }

    /// Check if cancellation was requested
    pub fn is_cancelled(&self) -> bool {
        self.cancel_flag.load(Ordering::SeqCst)
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}
