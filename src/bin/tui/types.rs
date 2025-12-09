//! TUI Types and State

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use std::sync::mpsc;
use ratatui::widgets::{TableState, ListState};

use fraggle_packet::network_tests::HttpsTestResult;
use fraggle_packet::diagnosis::Diagnosis;
use fraggle_packet::framework::orchestrator::TestOrchestrator;
use fraggle_packet::framework::result::TestResult as FrameworkTestResult;

// =============================================================================
// TYPES AND STATE
// =============================================================================

#[derive(Clone, Debug)]
pub struct TargetResult {
    pub target: String,
    pub desc: String,
    pub icmp_mtu: Option<usize>,
    pub tcp_mtu: Option<usize>,
    pub udp_mtu: Option<usize>,
    pub quic_mtu: Option<usize>,
    pub tcp_mss: Option<usize>,
    pub status: TestStatus,
    pub last_tested: Option<Instant>,
    pub hops: Vec<HopInfo>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum TestStatus {
    Pending,
    Testing,
    Complete,
    Failed,
}

#[derive(Clone, Debug)]
pub struct HopInfo {
    pub hop: u8,
    pub addr: String,
    pub mtu: Option<usize>,
    pub rtt_ms: Option<f64>,
}

#[derive(Clone, Debug)]
pub struct AppState {
    pub results: Vec<TargetResult>,
    pub hops: Vec<HopInfo>,
    pub testing: bool,
    pub progress: f64,
    pub current_target: String,
    pub start_time: Option<Instant>,
    pub verdict: Option<Verdict>,
    pub mtu_history: Vec<usize>,
    pub simulated_mtu: usize,
    pub fuzzing_results: HashMap<String, FuzzingResult>,
    pub https_results: HashMap<String, HttpsTestResult>,
    pub diagnoses: Vec<Diagnosis>,
}

#[derive(Clone, Debug)]
pub struct FuzzingResult {
    pub mode: String,
    pub packets_generated: usize,
    pub pcap_path: String,
    pub file_size_bytes: u64,
    pub duration_ms: u64,
    pub status: FuzzingStatus,
}

#[derive(Clone, Debug, PartialEq)]
pub enum FuzzingStatus {
    Pending,
    Running,
    Complete,
    Failed(String),
}

#[derive(Clone, Debug)]
pub struct Verdict {
    pub status: String,
    pub recommended_mtu: Option<usize>,
    pub recommended_mss: Option<usize>,
    pub median_mtu: usize,
    pub percent_ok: f64,
}

pub enum ViewMode {
    Dashboard,
    AllTargets,
}

pub enum AppMode {
    Dashboard,
    TargetDetail,
    Simulator,
    FuzzingPanel,
    HttpsPanel,
    TestPanel,
    Help,
}

pub struct App {
    pub state: Arc<Mutex<AppState>>,
    pub mode: AppMode,
    pub view_mode: ViewMode,
    pub selected_target: usize,
    pub selected_hop: usize,
    pub selected_category: Option<usize>,
    pub table_state: TableState,
    pub hop_list_state: ListState,
    pub scroll_offset: usize,
    pub should_quit: bool,
    pub show_popup: bool,
    pub popup_message: String,
    pub test_tx: Option<mpsc::Sender<TestUpdate>>,
    pub test_rx: Option<mpsc::Receiver<TestUpdate>>,
    pub log_messages: Vec<String>,
    pub tracepath_running: bool,
    pub tracepath_output: Vec<String>,
    pub popup_scroll: usize,
    pub selected_fuzz_mode: usize,
    pub fuzzing_active: bool,
    pub selected_https_target: usize,
    pub https_testing: bool,
    pub orchestrator: TestOrchestrator,
    pub framework_results: HashMap<String, Vec<FrameworkTestResult>>,
    pub collapsed_panels: HashMap<String, bool>,  // NEW - track collapsed state
}

#[derive(Debug, Clone)]
pub enum TestUpdate {
    Started { target: String },
    Progress { target: String, progress: f64 },
    Complete { index: usize, result: crate::test_runner_mod::TestResult },
    Failed { index: usize, target: String },
    AllComplete,
    TracepathComplete { index: usize, hop_count: usize },
    TracepathOutput { line: String },
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            results: Vec::new(),
            hops: Vec::new(),
            testing: false,
            progress: 0.0,
            current_target: String::new(),
            start_time: None,
            verdict: None,
            mtu_history: vec![1500; 20],
            simulated_mtu: 1500,
            fuzzing_results: HashMap::new(),
            https_results: HashMap::new(),
            diagnoses: Vec::new(),
        }
    }
}

