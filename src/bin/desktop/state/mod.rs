//! Application state management for FragglePacket Desktop

pub mod test_runner;

use std::collections::HashMap;
use std::sync::Arc;
use dioxus::prelude::*;
use tokio::sync::mpsc;
use fraggle_packet::framework::{TestCategory, TestResult, TestOrchestrator, TestStatus};

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
        }
    }

    pub fn shortcut(&self) -> Option<&'static str> {
        match self {
            PanelId::Dashboard => Some("D"),
            PanelId::Tests => Some("T"),
            PanelId::Https => Some("H"),
            PanelId::Fuzzing => Some("F"),
            PanelId::Path => Some("P"),
            PanelId::Simulator => Some("S"),
            PanelId::VpnCalculator => Some("V"),
            PanelId::Targets => None,
        }
    }

    pub fn all() -> Vec<PanelId> {
        vec![
            PanelId::Dashboard,
            PanelId::Tests,
            PanelId::Https,
            PanelId::Fuzzing,
            PanelId::Path,
            PanelId::Simulator,
        ]
    }
}

/// Target configuration
#[derive(Debug, Clone)]
pub struct Target {
    pub host: String,
    pub description: String,
    pub port: u16,
}

impl Target {
    pub fn new(host: impl Into<String>, description: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            description: description.into(),
            port,
        }
    }
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

/// Main application state
#[derive(Clone)]
pub struct AppState {
    /// Currently active panel
    pub active_panel: Signal<PanelId>,

    /// Currently selected test category
    pub selected_category: Signal<Option<TestCategory>>,

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
}

impl AppState {
    pub fn new() -> Self {
        // Create and configure the test orchestrator
        let mut orchestrator = TestOrchestrator::new();
        register_all_tests(&mut orchestrator);

        // Create test runner
        let test_runner = Arc::new(TestRunner::new(orchestrator));

        let default_targets = vec![
            Target::new("8.8.8.8", "Google DNS", 0),
            Target::new("1.1.1.1", "Cloudflare DNS", 0),
            Target::new("github.com", "GitHub", 443),
            Target::new("google.com", "Google", 443),
        ];

        Self {
            active_panel: Signal::new(PanelId::Dashboard),
            selected_category: Signal::new(None),
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
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}
