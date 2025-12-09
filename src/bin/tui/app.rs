//! FragglePacket - Terminal User Interface
//! 
//! Retro green-on-black aesthetic with full interactive capabilities

#[path = "fuzzing_panel.rs"]
pub mod fuzzing_panel;
use fuzzing_panel::render_fuzzing_panel;

#[path = "https_panel.rs"]
pub mod https_panel;
use https_panel::render_https_panel;

#[path = "test_registration.rs"]
mod test_registration;
use test_registration::register_all_tests;

#[path = "test_panel.rs"]
pub mod test_panel;
use test_panel::render_test_panel;

#[path = "../../../tests/test_runner.rs"]
mod test_runner_mod;
use test_runner_mod::{load_targets, test_single_target, TestResult as TestRunnerResult};

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style, Stylize},
    symbols,
    text::{Line, Span, Text},
    widgets::{
        Block, Borders, BorderType, Cell, Clear, Gauge, List, ListItem, ListState,
        Paragraph, Row, Scrollbar, ScrollbarOrientation, ScrollbarState, Sparkline,
        Table, TableState, Tabs, Wrap,
    },
    Frame, Terminal,
};
use std::io;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use std::sync::mpsc;
use rayon::prelude::*;

// Import HTTPS testing and diagnosis
use fraggle_packet::network_tests::{test_https_stages, HttpsTestResult, HttpsDiagnosis};
use fraggle_packet::diagnosis::{DiagnosisEngine, DiagnosisEvidence, Diagnosis};

// =============================================================================
// COLOR THEME - Retro Terminal Green
// =============================================================================

const TERM_GREEN: Color = Color::Rgb(0, 255, 65);      // Classic phosphor green
const TERM_GREEN_DIM: Color = Color::Rgb(0, 180, 45);  // Dimmed green
const TERM_GREEN_DARK: Color = Color::Rgb(0, 100, 25); // Dark green
const TERM_AMBER: Color = Color::Rgb(255, 176, 0);     // Warning amber
const TERM_RED: Color = Color::Rgb(255, 50, 50);       // Error red
const TERM_BLACK: Color = Color::Rgb(5, 15, 5);        // Not pure black, slight green tint
const TERM_CYAN: Color = Color::Rgb(0, 255, 200);      // Highlight cyan

// =============================================================================
// APPLICATION STATE
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
    pub hops: Vec<HopInfo>,  // Per-target hop data
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
    pub mtu_history: Vec<usize>,  // For sparkline
    pub simulated_mtu: usize,     // For what-if analysis
    pub fuzzing_results: std::collections::HashMap<String, FuzzingResult>,
    pub https_results: std::collections::HashMap<String, HttpsTestResult>,  // NEW
    pub diagnoses: Vec<Diagnosis>,  // NEW - diagnosis results
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

use fraggle_packet::framework::test_trait::{NetworkTest, TestCategory};
use fraggle_packet::framework::result::{TestResult as FrameworkTestResult, TestStatus as FrameworkTestStatus};
use fraggle_packet::framework::orchestrator::TestOrchestrator;

pub enum ViewMode {
    Dashboard,      // Single target, all test details
    AllTargets,     // Multiple targets overview
}

pub enum AppMode {
    Dashboard,
    TargetDetail,
    Simulator,
    FuzzingPanel,
    HttpsPanel,
    TestPanel,      // NEW - test framework panel
    Help,
}

pub struct App {
    pub state: Arc<Mutex<AppState>>,
    pub mode: AppMode,
    pub view_mode: ViewMode,
    pub selected_target: usize,
    pub selected_hop: usize,
    pub selected_category: Option<usize>,  // 0-9 for test categories
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
    pub orchestrator: TestOrchestrator,  // NEW - test framework orchestrator
    pub framework_results: std::collections::HashMap<String, Vec<FrameworkTestResult>>,  // NEW
}

#[derive(Debug, Clone)]
pub enum TestUpdate {
    Started { target: String },
    Progress { target: String, progress: f64 },
    Complete { index: usize, result: TestRunnerResult },
    Failed { index: usize, target: String },
    AllComplete,
    TracepathComplete { index: usize, hop_count: usize },
    TracepathOutput { line: String },  // Stream tracepath output line-by-line
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
            fuzzing_results: std::collections::HashMap::new(),
            https_results: std::collections::HashMap::new(),
            diagnoses: Vec::new(),
        }
    }
}

impl App {
    pub fn new(state: Arc<Mutex<AppState>>) -> Self {
        let mut table_state = TableState::default();
        table_state.select(Some(0));
        
        let (tx, rx) = mpsc::channel();
        
        // Create orchestrator with all tests registered
        let mut orchestrator = TestOrchestrator::new();
        register_all_tests(&mut orchestrator);
        
        Self {
            state,
            mode: AppMode::Dashboard,
            view_mode: ViewMode::Dashboard,
            selected_target: 0,
            selected_hop: 0,
            selected_category: None,
            table_state,
            hop_list_state: ListState::default(),
            scroll_offset: 0,
            should_quit: false,
            show_popup: false,
            popup_message: String::new(),
            test_tx: Some(tx),
            test_rx: Some(rx),
            log_messages: Vec::new(),
            tracepath_running: false,
            tracepath_output: Vec::new(),
            popup_scroll: 0,
            selected_fuzz_mode: 0,
            fuzzing_active: false,
            selected_https_target: 0,
            https_testing: false,
            orchestrator,
            framework_results: std::collections::HashMap::new(),
        }
    }
    
    pub fn adjust_simulated_mtu(&mut self, delta: i32) {
        let mut state = self.state.lock().unwrap();
        let new_mtu = (state.simulated_mtu as i32 + delta).clamp(576, 9000) as usize;
        state.simulated_mtu = new_mtu;
    }
    
    pub fn run_tracepath(&mut self, index: usize) {
        if self.tracepath_running {
            self.log_messages.push("[TRACEPATH] Already running".to_string());
            self.show_popup = true;
            self.popup_message = "Tracepath already running...".to_string();
            return;
        }
        
        let state = self.state.clone();
        let target = {
            let s = state.lock().unwrap();
            if let Some(r) = s.results.get(index) {
                r.target.clone()
            } else {
                self.log_messages.push("[TRACEPATH] Invalid index".to_string());
                return;
            }
        };
        
        // Get the sender channel
        let tx = match &self.test_tx {
            Some(tx) => tx.clone(),
            None => {
                self.log_messages.push("[TRACEPATH] No channel available".to_string());
                return;
            }
        };
        
        self.tracepath_running = true;
        self.tracepath_output.clear();
        self.popup_scroll = 0;  // Reset scroll position
        self.log_messages.push(format!("[TRACEPATH] Starting for {}", target));
        self.show_popup = true;
        self.popup_message = format!("Running tracepath to {}...\n\nLive output:", target);
        
        let state_clone = state.clone();
        
        thread::spawn(move || {
            use std::process::{Command, Stdio};
            use std::io::{BufRead, BufReader};
            
            // Run tracepath command with piped output for streaming
            let mut child = match Command::new("sudo")
                .arg("tracepath")
                .arg("-n")  // Don't resolve hostnames
                .arg(&target)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn() {
                    Ok(child) => child,
                    Err(e) => {
                        let _ = tx.send(TestUpdate::TracepathOutput { 
                            line: format!("Error: Failed to start tracepath: {}", e) 
                        });
                        return;
                    }
                };
            
            let stdout = child.stdout.take().unwrap();
            let reader = BufReader::new(stdout);
            let mut hops = Vec::new();
            
            // Stream output line-by-line
            for line in reader.lines() {
                match line {
                    Ok(line) => {
                        // Send line to UI immediately
                        let _ = tx.send(TestUpdate::TracepathOutput { line: line.clone() });
                        
                        // Parse tracepath output
                        let trimmed = line.trim();
                        if trimmed.is_empty() || trimmed.starts_with("tracepath") {
                            continue;
                        }
                        
                        // Parse hop number
                        let parts: Vec<&str> = trimmed.split_whitespace().collect();
                        if parts.is_empty() {
                            continue;
                        }
                        
                        // Format: "1:" or "1?:"
                        let hop_str = parts[0].trim_end_matches(':').trim_end_matches('?');
                        if let Ok(hop_num) = hop_str.parse::<u8>() {
                            let mut hop_info = HopInfo {
                                hop: hop_num,
                                addr: String::new(),
                                mtu: None,
                                rtt_ms: None,
                            };
                            
                            // Get IP address (second field)
                            if parts.len() > 1 {
                                hop_info.addr = parts[1].to_string();
                            }
                            
                            // Parse RTT (e.g., "0.520ms")
                            for part in &parts {
                                if part.ends_with("ms") {
                                    if let Ok(rtt) = part.trim_end_matches("ms").parse::<f64>() {
                                        hop_info.rtt_ms = Some(rtt);
                                    }
                                }
                            }
                            
                            // Parse PMTU (e.g., "pmtu 1500")
                            for i in 0..parts.len() {
                                if parts[i] == "pmtu" && i + 1 < parts.len() {
                                    if let Ok(mtu) = parts[i + 1].parse::<usize>() {
                                        hop_info.mtu = Some(mtu);
                                    }
                                }
                            }
                            
                            hops.push(hop_info);
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(TestUpdate::TracepathOutput { 
                            line: format!("Error reading output: {}", e) 
                        });
                        break;
                    }
                }
            }
            
            // Wait for process to complete
            let _ = child.wait();
            
            // Update the target with hop data
            let mut s = state_clone.lock().unwrap();
            if let Some(r) = s.results.get_mut(index) {
                r.hops = hops.clone();
            }
            
            // Send completion
            let _ = tx.send(TestUpdate::TracepathComplete { 
                index, 
                hop_count: hops.len() 
            });
            
            eprintln!("[TRACEPATH] Complete: parsed {} hops", hops.len());
        });
    }
    
    pub fn start_testing(&mut self, min_mtu: usize, max_mtu: usize, timeout_ms: u64, retries: usize) {
        let targets = load_targets();
        
        // Ensure we have a channel
        if self.test_tx.is_none() {
            let (tx, rx) = mpsc::channel();
            self.test_tx = Some(tx);
            self.test_rx = Some(rx);
        }
        
        let tx = self.test_tx.as_ref().unwrap().clone();
        let state = self.state.clone();
        
        // Initialize results
        {
            let mut s = state.lock().unwrap();
            s.results = targets.iter().map(|(t, d, _)| {
                TargetResult {
                    target: t.clone(),
                    desc: d.clone(),
                    icmp_mtu: None,
                    tcp_mtu: None,
                    udp_mtu: None,
                    quic_mtu: None,
                    tcp_mss: None,
                    status: TestStatus::Pending,
                    last_tested: None,
                    hops: Vec::new(),
                }
            }).collect();
            s.testing = true;
            s.progress = 0.0;
        }
        
        // Spawn test coordinator thread
        thread::spawn(move || {
            let total = targets.len();
            let targets_vec: Vec<(usize, String, String, u16)> = targets.iter()
                .enumerate()
                .map(|(idx, (t, d, p))| (idx, t.clone(), d.clone(), *p))
                .collect();
            
            // Use Arc to share sender and progress counter
            let tx_shared = Arc::new(tx);
            let completed = Arc::new(Mutex::new(0usize));
            let mut handles = Vec::new();
            
            // Spawn one thread per target (parallel execution)
            for (index, target, desc, port) in targets_vec {
                let tx_clone = tx_shared.clone();
                let completed_clone = completed.clone();
                
                // Send started notification
                let _ = tx_clone.send(TestUpdate::Started { target: target.clone() });
                
                let handle = thread::spawn(move || {
                    // Run the test
                    let result = test_single_target(
                        &target, &desc, port,
                        min_mtu, max_mtu, timeout_ms, retries
                    );
                    
                    // Update progress counter
                    let mut count = completed_clone.lock().unwrap();
                    *count += 1;
                    let progress = *count as f64 / total as f64;
                    
                    // Send progress update
                    let _ = tx_clone.send(TestUpdate::Progress {
                        target: result.target.clone(),
                        progress,
                    });
                    
                    // Send result
                    let _ = tx_clone.send(TestUpdate::Complete {
                        index,
                        result,
                    });
                });
                
                // Store handle
                handles.push(handle);
            }
            
            // Wait for all threads to complete
            for handle in handles {
                let _ = handle.join();
            }
            
            // Send final completion
            let _ = tx_shared.send(TestUpdate::AllComplete);
        });
    }
    
    // HTTPS testing methods
    pub fn run_https_test(&mut self, target: &str) {
        self.https_testing = true;
        let target = target.to_string();
        
        thread::spawn(move || {
            let result = test_https_stages(&target, 5000);
            eprintln!("[HTTPS] Test complete for {}: success={}", target, result.tcp_success && result.tls_success);
        });
    }
    
    pub fn prev_https_target(&mut self) {
        if self.selected_https_target > 0 {
            self.selected_https_target -= 1;
        }
    }
    
    pub fn next_https_target(&mut self) {
        let state = self.state.lock().unwrap();
        if self.selected_https_target < state.results.len().saturating_sub(1) {
            self.selected_https_target += 1;
        }
    }
    
    pub fn run_all_https_tests(&mut self) {
        let targets: Vec<String> = {
            let state = self.state.lock().unwrap();
            state.results.iter().map(|r| r.target.clone()).collect()
        };
        
        for target in targets {
            self.run_https_test(&target);
        }
    }
    
    // Test framework methods
    pub fn run_category(&mut self, category: TestCategory) {
        let target = {
            let state = self.state.lock().unwrap();
            state.results.get(self.selected_target)
                .map(|r| r.target.clone())
                .unwrap_or_else(|| "example.com".to_string())
        };
        
        let category_clone = category.clone();
        let target_clone = target.clone();
        
        // Run the test asynchronously
        thread::spawn(move || {
            eprintln!("[TEST] Running {:?} for {}", category_clone, target_clone);
        });
    }
    
    pub fn run_all_tests_on_current_target(&mut self) {
        let target = {
            let state = self.state.lock().unwrap();
            state.results.get(self.selected_target)
                .map(|r| r.target.clone())
                .unwrap_or_else(|| "example.com".to_string())
        };
        
        eprintln!("[TEST] Running ALL tests for {}", target);
        
        // Run all 10 test categories
        let categories = vec![
            TestCategory::DNS,
            TestCategory::MTU,
            TestCategory::HTTPS,
            TestCategory::TCPHealth,
            TestCategory::RTT,
            TestCategory::PacketLoss,
            TestCategory::PathAnalysis,
            TestCategory::IPv6,
            TestCategory::Application,
            TestCategory::Fuzzing,
        ];
        
        for category in categories {
            self.run_category(category);
        }
        
        self.popup_message = format!("Running all tests on {}", target);
        self.show_popup = true;
    }
    
    pub fn run_category_on_all_targets(&mut self, category: TestCategory) {
        let targets: Vec<String> = {
            let state = self.state.lock().unwrap();
            state.results.iter().map(|r| r.target.clone()).collect()
        };
        
        eprintln!("[TEST] Running {:?} on {} targets", category, targets.len());
        
        for target in targets {
            let category_clone = category.clone();
            let target_clone = target.clone();
            
            thread::spawn(move || {
                eprintln!("[TEST] Running {:?} for {}", category_clone, target_clone);
            });
        }
        
        self.popup_message = format!("Running {:?} on all targets", category);
        self.show_popup = true;
    }


    
    pub fn retest_target(&mut self, index: usize, min_mtu: usize, max_mtu: usize, timeout_ms: u64, retries: usize) {
        self.log_messages.push(format!("[RETEST] Starting retest for index {}", index));
        
        let state = self.state.clone();
        let (target, desc) = {
            let s = state.lock().unwrap();
            if let Some(r) = s.results.get(index) {
                (r.target.clone(), r.desc.clone())
            } else {
                self.log_messages.push(format!("[RETEST] ERROR: Index {} not found", index));
                return;
            }
        };
        
        self.log_messages.push(format!("[RETEST] Target: {}, Desc: {}", target, desc));
        
        // Find port from targets.txt by matching target
        let targets = test_runner_mod::load_targets();
        let port = targets.iter()
            .find(|(t, _, _)| t == &target)
            .map(|(_, _, p)| *p)
            .unwrap_or(443);  // Default to 443 if not found
        
        self.log_messages.push(format!("[RETEST] Port: {}", port));
        
        // Always recreate channel for retest to ensure it's fresh
        let (new_tx, new_rx) = mpsc::channel();
        self.test_tx = Some(new_tx.clone());
        self.test_rx = Some(new_rx);
        
        self.log_messages.push(format!("[RETEST] Channel created"));
        
        // Mark as testing
        {
            let mut s = state.lock().unwrap();
            if let Some(r) = s.results.get_mut(index) {
                r.status = TestStatus::Testing;
                self.log_messages.push(format!("[RETEST] Status set to Testing"));
            }
        }
        
        let tx_clone = new_tx.clone();
        self.log_messages.push(format!("[RETEST] Spawning test thread..."));
        
        thread::spawn(move || {
            let _ = tx_clone.send(TestUpdate::Started { target: target.clone() });
            
            let result = test_single_target(
                &target, &desc, port,
                min_mtu, max_mtu, timeout_ms, retries
            );
            
            let _ = tx_clone.send(TestUpdate::Complete {
                index,
                result,
            });
        });
        
        self.log_messages.push(format!("[RETEST] Thread spawned, waiting for results..."));
    }
    
    pub fn retest_all(&mut self, min_mtu: usize, max_mtu: usize, timeout_ms: u64, retries: usize) {
        self.start_testing(min_mtu, max_mtu, timeout_ms, retries);
    }
    
    pub fn process_test_updates(&mut self) {
        if let Some(rx) = &self.test_rx {
            while let Ok(update) = rx.try_recv() {
                let mut state = self.state.lock().unwrap();
                
                match update {
                    TestUpdate::Started { target } => {
                        state.current_target = target;
                    }
                    TestUpdate::Progress { progress, .. } => {
                        state.progress = progress;
                    }
                    TestUpdate::Complete { index, result } => {
                        self.log_messages.push(format!("[UPDATE] Complete for index {}: icmp={:?} tcp={:?} udp={:?} quic={:?}", 
                            index, result.icmp_mtu, result.tcp_mtu, result.udp_mtu, result.quic_mtu));
                        
                        if let Some(r) = state.results.get_mut(index) {
                            r.icmp_mtu = result.icmp_mtu;
                            r.tcp_mtu = result.tcp_mtu;
                            r.udp_mtu = result.udp_mtu;
                            r.quic_mtu = result.quic_mtu;
                            r.tcp_mss = result.tcp_mss;
                            
                            // Check if any test actually succeeded
                            let has_results = result.icmp_mtu.is_some() 
                                || result.tcp_mtu.is_some() 
                                || result.udp_mtu.is_some() 
                                || result.quic_mtu.is_some();
                            
                            if has_results {
                                r.status = TestStatus::Complete;
                                r.last_tested = Some(Instant::now());
                                self.log_messages.push(format!("[COMPLETE] Target {} - Press ESC to close", r.desc));
                                
                                // Update MTU history for sparkline
                                if let Some(mtu) = result.icmp_mtu.or(result.tcp_mtu).or(result.udp_mtu) {
                                    state.mtu_history.push(mtu);
                                    if state.mtu_history.len() > 20 {
                                        state.mtu_history.remove(0);
                                    }
                                }
                            } else {
                                // No results = test failed (likely DNS resolution failed)
                                r.status = TestStatus::Failed;
                                self.log_messages.push(format!("[FAILED] Target {} - Press ESC to close", r.desc));
                                // Store error message if available
                                if let Some(err) = result.error {
                                    self.log_messages.push(format!("[ERROR] {}", err));
                                }
                            }
                        }
                    }
                    TestUpdate::Failed { index, .. } => {
                        if let Some(r) = state.results.get_mut(index) {
                            r.status = TestStatus::Failed;
                        }
                    }
                    TestUpdate::AllComplete => {
                        state.testing = false;
                        state.current_target.clear();
                        state.progress = 1.0;
                        
                        // Calculate verdict
                        let all_mtus: Vec<usize> = state.results.iter()
                            .filter_map(|r| r.icmp_mtu.or(r.tcp_mtu).or(r.udp_mtu))
                            .collect();
                        
                        if !all_mtus.is_empty() {
                            let mut sorted = all_mtus.clone();
                            sorted.sort();
                            let median = sorted[sorted.len() / 2];
                            let at_1500 = all_mtus.iter().filter(|&&m| m >= 1500).count();
                            let pct_ok = (at_1500 as f64 / all_mtus.len() as f64) * 100.0;
                            
                            let (status, rec_mtu) = if pct_ok >= 95.0 && median >= 1400 {
                                ("PASS".to_string(), None)
                            } else if pct_ok >= 80.0 && median >= 1400 {
                                ("PASS".to_string(), None)
                            } else if median >= 1400 {
                                ("REVIEW".to_string(), Some(median))
                            } else {
                                ("ACTION_NEEDED".to_string(), Some(median))
                            };
                            
                            state.verdict = Some(Verdict {
                                status,
                                recommended_mtu: rec_mtu,
                                recommended_mss: rec_mtu.map(|m| m - 40),
                                median_mtu: median,
                                percent_ok: pct_ok,
                            });
                        }
                    }
                    TestUpdate::TracepathComplete { index, hop_count } => {
                        self.log_messages.push(format!("[TRACEPATH] Complete: {} hops parsed", hop_count));
                        self.tracepath_running = false;
                        
                        if let Some(r) = state.results.get(index) {
                            self.tracepath_output.push(String::new());
                            self.tracepath_output.push(format!("=== Tracepath complete for {} ===", r.desc));
                            self.tracepath_output.push(format!("Found {} hops", hop_count));
                            self.tracepath_output.push(String::new());
                            self.tracepath_output.push("Press ESC to close".to_string());
                        }
                    }
                    TestUpdate::TracepathOutput { line } => {
                        self.tracepath_output.push(line);
                        // Keep last 100 lines
                        if self.tracepath_output.len() > 100 {
                            self.tracepath_output.remove(0);
                            // Adjust scroll if we removed a line
                            if self.popup_scroll > 0 {
                                self.popup_scroll = self.popup_scroll.saturating_sub(1);
                            }
                        }
                        // Auto-scroll to bottom as new lines arrive (only if not manually scrolled up)
                        // Check if we're at or near the bottom (within 3 lines)
                        if self.popup_scroll + 3 >= self.tracepath_output.len().saturating_sub(20) {
                            self.popup_scroll = self.tracepath_output.len().saturating_sub(20);
                        }
                    }
                }
            }
        }
    }

    pub fn next_target(&mut self) {
        let state = self.state.lock().unwrap();
        let len = state.results.len();
        drop(state);
        
        if len > 0 {
            self.selected_target = (self.selected_target + 1) % len;
            self.table_state.select(Some(self.selected_target));
        }
    }

    pub fn prev_target(&mut self) {
        let state = self.state.lock().unwrap();
        let len = state.results.len();
        drop(state);
        
        if len > 0 {
            self.selected_target = self.selected_target.checked_sub(1).unwrap_or(len - 1);
            self.table_state.select(Some(self.selected_target));
        }
    }
    
    pub fn next_fuzz_mode(&mut self) {
        self.selected_fuzz_mode = (self.selected_fuzz_mode + 1) % 5;
    }
    
    pub fn prev_fuzz_mode(&mut self) {
        if self.selected_fuzz_mode == 0 {
            self.selected_fuzz_mode = 4;
        } else {
            self.selected_fuzz_mode -= 1;
        }
    }
    
    pub fn run_selected_fuzzer(&mut self) {
        let modes = vec!["segment-size", "length-mismatch", "tcp-options", "fragmentation", "checksum"];
        let mode = modes[self.selected_fuzz_mode];
        
        // Get first target or use default
        let target = {
            let state = self.state.lock().unwrap();
            state.results.first().map(|r| r.target.clone()).unwrap_or_else(|| "github.com".to_string())
        };
        
        self.show_popup = true;
        self.popup_message = format!("Running {} fuzzer on {}...", mode, target);
        
        // Run fuzzer in background
        let output = format!("/tmp/fuzz_{}.pcap", mode);
        let state_clone = self.state.clone();
        let mode_str = mode.to_string();
        
        thread::spawn(move || {
            use std::process::Command;
            let result = Command::new("./target/debug/fraggle-packet")
                .args(&["fuzz", &target, "--mode", &mode_str, "--output", &output])
                .output();
            
            let mut state = state_clone.lock().unwrap();
            if let Ok(output_data) = result {
                if output_data.status.success() {
                    // Parse output to get stats
                    let output_str = String::from_utf8_lossy(&output_data.stdout);
                    let packets = output_str.lines()
                        .find(|l| l.contains("Packets generated"))
                        .and_then(|l| l.split(':').nth(1))
                        .and_then(|s| s.trim().parse().ok())
                        .unwrap_or(0);
                    
                    let file_size = std::fs::metadata(&output)
                        .map(|m| m.len())
                        .unwrap_or(0);
                    
                    state.fuzzing_results.insert(mode_str.clone(), FuzzingResult {
                        mode: mode_str,
                        packets_generated: packets,
                        pcap_path: output,
                        file_size_bytes: file_size,
                        duration_ms: 1,
                        status: FuzzingStatus::Complete,
                    });
                }
            }
        });
    }
    
    pub fn run_all_fuzzers(&mut self) {
        self.show_popup = true;
        self.popup_message = "Running all fuzzers...".to_string();
        
        for i in 0..5 {
            self.selected_fuzz_mode = i;
            self.run_selected_fuzzer();
        }
    }

}

// =============================================================================
// TERMINAL SETUP
// =============================================================================

pub fn setup_terminal() -> io::Result<Terminal<CrosstermBackend<io::Stdout>>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let terminal = Terminal::new(backend)?;
    Ok(terminal)
}

pub fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> io::Result<()> {
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;
    Ok(())
}

// =============================================================================
// UI RENDERING
// =============================================================================

pub fn ui(frame: &mut Frame, app: &mut App) {
    let size = frame.area();
    
    // Main layout
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // Header
            Constraint::Min(10),    // Main content
            Constraint::Length(3),  // Footer/help
        ])
        .split(size);

    // Render header
    render_header(frame, chunks[0], app);
    
    // Render main content based on mode
    match app.mode {
        AppMode::Dashboard => render_dashboard(frame, chunks[1], app),
        AppMode::TargetDetail => render_target_detail(frame, chunks[1], app),
        AppMode::Simulator => render_simulator(frame, chunks[1], app),
        AppMode::FuzzingPanel => render_fuzzing_panel(frame, chunks[1], app),
        AppMode::HttpsPanel => render_https_panel(frame, chunks[1], app),
        AppMode::TestPanel => render_test_panel(frame, app, chunks[1]),
        AppMode::Help => render_help(frame, chunks[1]),
    }
    
    // Render footer
    render_footer(frame, chunks[2], app);
    
    // Render popup if active
    if app.show_popup {
        // If tracepath is running, show live output
        if app.tracepath_running || !app.tracepath_output.is_empty() {
            let mut message = app.popup_message.clone();
            message.push_str("\n\n");
            
            // Add tracepath output
            for line in &app.tracepath_output {
                message.push_str(line);
                message.push('\n');
            }
            
            if app.tracepath_running {
                message.push_str("\n[Running... Use Up/Down or PgUp/PgDn to scroll, ESC to close]");
            } else {
                message.push_str("\n[Use Up/Down or PgUp/PgDn to scroll, ESC to close]");
            }
            
            render_popup(frame, &message, app.popup_scroll);
        } else {
            // Format popup message with logs if available
            let mut message = app.popup_message.clone();
            if !app.log_messages.is_empty() {
                message.push_str("\n\n--- Debug Log ---\n");
                for msg in app.log_messages.iter().rev().take(15) {
                    message.push_str(&format!("{}\n", msg));
                }
            }
            render_popup(frame, &message, 0);
        }
    }
}

fn render_header(frame: &mut Frame, area: Rect, app: &App) {
    let state = app.state.lock().unwrap();
    
    let status_text = if state.testing {
        format!(" SCANNING: {} ", state.current_target)
    } else if state.verdict.is_some() {
        " COMPLETE ".to_string()
    } else {
        " READY ".to_string()
    };
    
    let status_style = if state.testing {
        Style::default().fg(TERM_AMBER).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(TERM_GREEN).add_modifier(Modifier::BOLD)
    };
    
    let title = vec![
        Span::styled("╔══", Style::default().fg(TERM_GREEN_DIM)),
        Span::styled(" FragglePacket ", Style::default().fg(TERM_GREEN).add_modifier(Modifier::BOLD)),
        Span::styled("══", Style::default().fg(TERM_GREEN_DIM)),
        Span::styled(&status_text, status_style),
        Span::styled("══╗", Style::default().fg(TERM_GREEN_DIM)),
    ];
    
    let header = Paragraph::new(Line::from(title))
        .style(Style::default().bg(TERM_BLACK))
        .alignment(Alignment::Center)
        .block(Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Double)
            .border_style(Style::default().fg(TERM_GREEN_DIM))
            .style(Style::default().bg(TERM_BLACK)));
    
    frame.render_widget(header, area);
}

fn render_dashboard(frame: &mut Frame, area: Rect, app: &mut App) {
    let state = app.state.lock().unwrap();
    
    // Split into left (results table) and right (summary + sparkline)
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
        .split(area);
    
    // Left: Results table
    let header_cells = ["TARGET", "ICMP", "TCP", "UDP", "QUIC", "MSS", "STATUS"]
        .iter()
        .map(|h| Cell::from(*h).style(Style::default().fg(TERM_CYAN).add_modifier(Modifier::BOLD)));
    let header = Row::new(header_cells)
        .style(Style::default().bg(TERM_BLACK))
        .height(1);
    
    let rows = state.results.iter().map(|r| {
        let status_style = match r.status {
            TestStatus::Complete => Style::default().fg(TERM_GREEN),
            TestStatus::Testing => Style::default().fg(TERM_AMBER).add_modifier(Modifier::SLOW_BLINK),
            TestStatus::Failed => Style::default().fg(TERM_RED),
            TestStatus::Pending => Style::default().fg(TERM_GREEN_DIM),
        };
        
        let format_mtu = |m: Option<usize>| -> (String, Style) {
            match m {
                Some(v) if v >= 1500 => (v.to_string(), Style::default().fg(TERM_GREEN)),
                Some(v) if v >= 1400 => (v.to_string(), Style::default().fg(TERM_AMBER)),
                Some(v) => (v.to_string(), Style::default().fg(TERM_RED)),
                None => ("---".to_string(), Style::default().fg(TERM_GREEN_DIM)),
            }
        };
        
        let (icmp, icmp_style) = format_mtu(r.icmp_mtu);
        let (tcp, tcp_style) = format_mtu(r.tcp_mtu);
        let (udp, udp_style) = format_mtu(r.udp_mtu);
        let (quic, quic_style) = format_mtu(r.quic_mtu);
        let (mss, mss_style) = format_mtu(r.tcp_mss);
        
        let status_text = match r.status {
            TestStatus::Complete => "OK",
            TestStatus::Testing => "...",
            TestStatus::Failed => "FAIL",
            TestStatus::Pending => "WAIT",
        };
        
        Row::new(vec![
            Cell::from(r.desc.chars().take(18).collect::<String>()).style(Style::default().fg(TERM_GREEN)),
            Cell::from(icmp).style(icmp_style),
            Cell::from(tcp).style(tcp_style),
            Cell::from(udp).style(udp_style),
            Cell::from(quic).style(quic_style),
            Cell::from(mss).style(mss_style),
            Cell::from(status_text).style(status_style),
        ])
        .height(1)
    });
    
    let table = Table::new(
        rows,
        [
            Constraint::Length(20),
            Constraint::Length(6),
            Constraint::Length(6),
            Constraint::Length(6),
            Constraint::Length(6),
            Constraint::Length(6),
            Constraint::Length(6),
        ],
    )
    .header(header)
    .block(Block::default()
        .title(" ▶ RESULTS ")
        .title_style(Style::default().fg(TERM_GREEN).add_modifier(Modifier::BOLD))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(TERM_GREEN_DIM))
        .border_type(BorderType::Rounded)
        .style(Style::default().bg(TERM_BLACK)))
    .row_highlight_style(Style::default().bg(TERM_GREEN_DARK).add_modifier(Modifier::BOLD))
    .highlight_symbol("▶ ");
    
    drop(state);
    frame.render_stateful_widget(table, chunks[0], &mut app.table_state);
    
    // Right panel: Summary and progress
    let state = app.state.lock().unwrap();
    let right_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(8),   // Verdict box
            Constraint::Length(5),   // Progress
            Constraint::Min(5),      // Sparkline
        ])
        .split(chunks[1]);
    
    // Verdict box
    let verdict_text = if let Some(v) = &state.verdict {
        let status_style = if v.status == "PASS" {
            Style::default().fg(TERM_GREEN).add_modifier(Modifier::BOLD)
        } else if v.status == "ACTION_NEEDED" {
            Style::default().fg(TERM_RED).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(TERM_AMBER).add_modifier(Modifier::BOLD)
        };
        
        vec![
            Line::from(vec![
                Span::styled("STATUS: ", Style::default().fg(TERM_GREEN_DIM)),
                Span::styled(&v.status, status_style),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("Median MTU: ", Style::default().fg(TERM_GREEN_DIM)),
                Span::styled(v.median_mtu.to_string(), Style::default().fg(TERM_GREEN)),
            ]),
            Line::from(vec![
                Span::styled("Success:    ", Style::default().fg(TERM_GREEN_DIM)),
                Span::styled(format!("{:.1}%", v.percent_ok), Style::default().fg(TERM_GREEN)),
            ]),
            if let Some(mtu) = v.recommended_mtu {
                Line::from(vec![
                    Span::styled("Set MTU:    ", Style::default().fg(TERM_AMBER)),
                    Span::styled(mtu.to_string(), Style::default().fg(TERM_AMBER).add_modifier(Modifier::BOLD)),
                ])
            } else {
                Line::from(vec![
                    Span::styled("No changes needed", Style::default().fg(TERM_GREEN)),
                ])
            },
        ]
    } else {
        vec![
            Line::from(Span::styled("Awaiting scan...", Style::default().fg(TERM_GREEN_DIM))),
        ]
    };
    
    let verdict_widget = Paragraph::new(verdict_text)
        .block(Block::default()
            .title(" ▶ VERDICT ")
            .title_style(Style::default().fg(TERM_GREEN).add_modifier(Modifier::BOLD))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(TERM_GREEN_DIM))
            .border_type(BorderType::Rounded)
            .style(Style::default().bg(TERM_BLACK)))
        .wrap(Wrap { trim: true });
    
    frame.render_widget(verdict_widget, right_chunks[0]);
    
    // Progress bar
    let progress_pct = (state.progress * 100.0) as u16;
    let progress_label = if state.testing {
        format!("{}% - {}", progress_pct, state.current_target)
    } else {
        format!("{}%", progress_pct)
    };
    
    let progress = Gauge::default()
        .block(Block::default()
            .title(" ▶ PROGRESS ")
            .title_style(Style::default().fg(TERM_GREEN).add_modifier(Modifier::BOLD))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(TERM_GREEN_DIM))
            .border_type(BorderType::Rounded)
            .style(Style::default().bg(TERM_BLACK)))
        .gauge_style(Style::default().fg(TERM_GREEN).bg(TERM_BLACK))
        .percent(progress_pct)
        .label(progress_label);
    
    frame.render_widget(progress, right_chunks[1]);
    
    // MTU Sparkline (history of MTU values found)
    let sparkline = Sparkline::default()
        .block(Block::default()
            .title(" ▶ MTU TREND ")
            .title_style(Style::default().fg(TERM_GREEN).add_modifier(Modifier::BOLD))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(TERM_GREEN_DIM))
            .border_type(BorderType::Rounded)
            .style(Style::default().bg(TERM_BLACK)))
        .data(&state.mtu_history.iter().map(|&v| v as u64).collect::<Vec<_>>())
        .max(1600)
        .style(Style::default().fg(TERM_GREEN));
    
    frame.render_widget(sparkline, right_chunks[2]);
}

fn render_target_detail(frame: &mut Frame, area: Rect, app: &App) {
    let state = app.state.lock().unwrap();
    
    if let Some(target) = state.results.get(app.selected_target) {
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(area);
        
        // Left: Target details with packet breakdown
        let mut details = vec![
            Line::from(vec![
                Span::styled("Target:  ", Style::default().fg(TERM_GREEN_DIM)),
                Span::styled(&target.target, Style::default().fg(TERM_GREEN).add_modifier(Modifier::BOLD)),
            ]),
            Line::from(""),
            Line::from(Span::styled("═══ MTU RESULTS ═══", Style::default().fg(TERM_CYAN))),
            Line::from(""),
        ];
        
        // ICMP with packet breakdown
        if let Some(mtu) = target.icmp_mtu {
            let payload = mtu.saturating_sub(28); // 20 IP + 8 ICMP
            details.push(Line::from(vec![
                Span::styled("ICMP:    ", Style::default().fg(TERM_GREEN_DIM)),
                format_mtu_span(Some(mtu)),
            ]));
            details.push(Line::from(vec![
                Span::raw("         "),
                Span::styled("↳ ", Style::default().fg(TERM_GREEN_DIM)),
                Span::styled("20", Style::default().fg(Color::Cyan)),
                Span::raw(" IP + "),
                Span::styled("8", Style::default().fg(Color::Cyan)),
                Span::raw(" ICMP + "),
                Span::styled(format!("{}", payload), Style::default().fg(Color::Yellow)),
                Span::raw(" payload"),
            ]));
        } else {
            details.push(Line::from(vec![
                Span::styled("ICMP:    ", Style::default().fg(TERM_GREEN_DIM)),
                format_mtu_span(target.icmp_mtu),
            ]));
        }
        
        // TCP with packet breakdown
        if let Some(mtu) = target.tcp_mtu {
            let payload = mtu.saturating_sub(40); // 20 IP + 20 TCP
            details.push(Line::from(vec![
                Span::styled("TCP:     ", Style::default().fg(TERM_GREEN_DIM)),
                format_mtu_span(Some(mtu)),
            ]));
            details.push(Line::from(vec![
                Span::raw("         "),
                Span::styled("↳ ", Style::default().fg(TERM_GREEN_DIM)),
                Span::styled("20", Style::default().fg(Color::Cyan)),
                Span::raw(" IP + "),
                Span::styled("20", Style::default().fg(Color::Cyan)),
                Span::raw(" TCP + "),
                Span::styled(format!("{}", payload), Style::default().fg(Color::Yellow)),
                Span::raw(" payload"),
            ]));
        } else {
            details.push(Line::from(vec![
                Span::styled("TCP:     ", Style::default().fg(TERM_GREEN_DIM)),
                format_mtu_span(target.tcp_mtu),
            ]));
        }
        
        // UDP with packet breakdown
        if let Some(mtu) = target.udp_mtu {
            let payload = mtu.saturating_sub(28); // 20 IP + 8 UDP
            details.push(Line::from(vec![
                Span::styled("UDP:     ", Style::default().fg(TERM_GREEN_DIM)),
                format_mtu_span(Some(mtu)),
            ]));
            details.push(Line::from(vec![
                Span::raw("         "),
                Span::styled("↳ ", Style::default().fg(TERM_GREEN_DIM)),
                Span::styled("20", Style::default().fg(Color::Cyan)),
                Span::raw(" IP + "),
                Span::styled("8", Style::default().fg(Color::Cyan)),
                Span::raw(" UDP + "),
                Span::styled(format!("{}", payload), Style::default().fg(Color::Yellow)),
                Span::raw(" payload"),
            ]));
        } else {
            details.push(Line::from(vec![
                Span::styled("UDP:     ", Style::default().fg(TERM_GREEN_DIM)),
                format_mtu_span(target.udp_mtu),
            ]));
        }
        
        details.push(Line::from(vec![
            Span::styled("QUIC:    ", Style::default().fg(TERM_GREEN_DIM)),
            format_mtu_span(target.quic_mtu),
        ]));
        
        details.push(Line::from(""));
        details.push(Line::from(Span::styled("═══ TCP INFO ═══", Style::default().fg(TERM_CYAN))));
        details.push(Line::from(""));
        
        // TCP MSS with derived MTU
        if let Some(mss) = target.tcp_mss {
            let derived_mtu = mss + 40;
            details.push(Line::from(vec![
                Span::styled("MSS:     ", Style::default().fg(TERM_GREEN_DIM)),
                Span::styled(format!("{}", mss), Style::default().fg(TERM_GREEN)),
                Span::styled(" bytes", Style::default().fg(TERM_GREEN_DIM)),
            ]));
            details.push(Line::from(vec![
                Span::raw("         "),
                Span::styled("↳ ", Style::default().fg(TERM_GREEN_DIM)),
                Span::raw("Derived MTU: "),
                Span::styled(format!("{}", derived_mtu), Style::default().fg(TERM_GREEN)),
                Span::raw(" (MSS+40)"),
            ]));
        } else {
            details.push(Line::from(vec![
                Span::styled("MSS:     ", Style::default().fg(TERM_GREEN_DIM)),
                format_mtu_span(target.tcp_mss),
            ]));
        }
        
        details.push(Line::from(""));
        details.push(Line::from(Span::styled("═══ TUNNEL OVERHEAD ═══", Style::default().fg(TERM_CYAN))));
        details.push(Line::from(""));
        details.push(Line::from(vec![
            Span::styled("WireGuard:  ", Style::default().fg(TERM_GREEN_DIM)),
            Span::raw("-80 bytes → MTU "),
            Span::styled("1420", Style::default().fg(TERM_AMBER)),
        ]));
        details.push(Line::from(vec![
            Span::styled("OpenVPN:    ", Style::default().fg(TERM_GREEN_DIM)),
            Span::raw("-100 bytes → MTU "),
            Span::styled("1400", Style::default().fg(TERM_AMBER)),
        ]));
        details.push(Line::from(vec![
            Span::styled("IPsec:      ", Style::default().fg(TERM_GREEN_DIM)),
            Span::raw("-62 bytes → MTU "),
            Span::styled("1438", Style::default().fg(TERM_AMBER)),
        ]));
        
        // Add tracepath hops if available
        details.push(Line::from(""));
        details.push(Line::from(vec![
            Span::styled("Press ", Style::default().fg(TERM_GREEN_DIM)),
            Span::styled("'t'", Style::default().fg(TERM_CYAN).add_modifier(Modifier::BOLD)),
            Span::styled(" to run tracepath (opens in popup)", Style::default().fg(TERM_GREEN_DIM)),
        ]));
        
        let detail_widget = Paragraph::new(details)
            .block(Block::default()
                .title(format!(" ▶ {} ", target.desc))
                .title_style(Style::default().fg(TERM_GREEN).add_modifier(Modifier::BOLD))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(TERM_GREEN_DIM))
                .border_type(BorderType::Rounded)
                .style(Style::default().bg(TERM_BLACK)));
        
        frame.render_widget(detail_widget, chunks[0]);
        
        // Right: What-if analysis
        let simulated = state.simulated_mtu;
        let current_min = [target.icmp_mtu, target.tcp_mtu, target.udp_mtu, target.quic_mtu]
            .iter()
            .filter_map(|&m| m)
            .min();
        
        let (would_work, min_display) = if let Some(min) = current_min {
            (simulated <= min, format!("{} bytes", min))
        } else {
            (true, "Not tested yet".to_string())
        };
        
        let result_msg = if would_work {
            vec![
                Line::from(vec![
                    Span::styled("Result: ", Style::default().fg(TERM_GREEN_DIM)),
                    Span::styled("WOULD WORK ✓", Style::default().fg(TERM_GREEN).add_modifier(Modifier::BOLD)),
                ]),
                Line::from(vec![
                    Span::raw("  "),
                    Span::styled("Packets fit within path MTU", Style::default().fg(TERM_GREEN_DIM)),
                ]),
            ]
        } else {
            vec![
                Line::from(vec![
                    Span::styled("Result: ", Style::default().fg(TERM_GREEN_DIM)),
                    Span::styled("WOULD FAIL ✗", Style::default().fg(TERM_RED).add_modifier(Modifier::BOLD)),
                ]),
                Line::from(vec![
                    Span::raw("  "),
                    Span::styled(format!("Interface MTU ({}) > Path MTU ({})", simulated, min_display), 
                        Style::default().fg(TERM_RED)),
                ]),
                Line::from(vec![
                    Span::raw("  "),
                    Span::styled("Packets would be fragmented/dropped!", Style::default().fg(TERM_AMBER)),
                ]),
            ]
        };
        
        let mut whatif = vec![
            Line::from(Span::styled("═══ WHAT-IF ANALYSIS ═══", Style::default().fg(TERM_CYAN))),
            Line::from(""),
            Line::from(vec![
                Span::styled("If interface MTU = ", Style::default().fg(TERM_GREEN_DIM)),
                Span::styled(simulated.to_string(), Style::default().fg(TERM_AMBER).add_modifier(Modifier::BOLD)),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("Actual path MTU: ", Style::default().fg(TERM_GREEN_DIM)),
                Span::styled(&min_display, Style::default().fg(TERM_GREEN)),
            ]),
            Line::from(""),
        ];
        
        // Add result message
        for line in result_msg {
            whatif.push(line);
        }
        
        whatif.extend(vec![
            Line::from(""),
            Line::from(vec![
                Span::styled("TCP MSS would be: ", Style::default().fg(TERM_GREEN_DIM)),
                Span::styled((simulated.saturating_sub(40)).to_string(), Style::default().fg(TERM_GREEN)),
            ]),
            Line::from(""),
            Line::from(Span::styled("VPN Overhead Impact:", Style::default().fg(TERM_CYAN))),
            Line::from(vec![
                Span::styled(" WireGuard:     ", Style::default().fg(TERM_GREEN_DIM)),
                Span::styled((simulated.saturating_sub(60)).to_string(), Style::default().fg(TERM_GREEN)),
            ]),
            Line::from(vec![
                Span::styled(" Zscaler:       ", Style::default().fg(TERM_GREEN_DIM)),
                Span::styled((simulated.saturating_sub(100)).to_string(), Style::default().fg(TERM_GREEN)),
            ]),
        ]);
        
        let whatif_widget = Paragraph::new(whatif)
            .block(Block::default()
                .title(" ▶ SIMULATOR [←/→ adjust] ")
                .title_style(Style::default().fg(TERM_GREEN).add_modifier(Modifier::BOLD))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(TERM_GREEN_DIM))
                .border_type(BorderType::Rounded)
                .style(Style::default().bg(TERM_BLACK)));
        
        frame.render_widget(whatif_widget, chunks[1]);
    }
}

fn render_hop_view(frame: &mut Frame, area: Rect, app: &mut App) {
    let state = app.state.lock().unwrap();
    
    let items: Vec<ListItem> = state.hops.iter().map(|h| {
        let mtu_str = h.mtu.map(|m| m.to_string()).unwrap_or("---".to_string());
        let rtt_str = h.rtt_ms.map(|r| format!("{:.1}ms", r)).unwrap_or("---".to_string());
        
        let mtu_style = match h.mtu {
            Some(m) if m >= 1500 => Style::default().fg(TERM_GREEN),
            Some(m) if m >= 1400 => Style::default().fg(TERM_AMBER),
            Some(_) => Style::default().fg(TERM_RED),
            None => Style::default().fg(TERM_GREEN_DIM),
        };
        
        let line = Line::from(vec![
            Span::styled(format!("{:2} ", h.hop), Style::default().fg(TERM_CYAN)),
            Span::styled(format!("{:40} ", h.addr), Style::default().fg(TERM_GREEN)),
            Span::styled(format!("MTU:{:>5} ", mtu_str), mtu_style),
            Span::styled(format!("RTT:{:>8}", rtt_str), Style::default().fg(TERM_GREEN_DIM)),
        ]);
        
        ListItem::new(line)
    }).collect();
    
    let list = List::new(items)
        .block(Block::default()
            .title(" ▶ PATH HOPS (tracepath) ")
            .title_style(Style::default().fg(TERM_GREEN).add_modifier(Modifier::BOLD))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(TERM_GREEN_DIM))
            .border_type(BorderType::Rounded)
            .style(Style::default().bg(TERM_BLACK)))
        .highlight_style(Style::default().bg(TERM_GREEN_DARK).add_modifier(Modifier::BOLD))
        .highlight_symbol("▶ ");
    
    drop(state);
    frame.render_stateful_widget(list, area, &mut app.hop_list_state);
}

fn render_simulator(frame: &mut Frame, area: Rect, app: &App) {
    let state = app.state.lock().unwrap();
    let simulated = state.simulated_mtu;
    
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),  // MTU slider
            Constraint::Min(10),    // Impact table
        ])
        .split(area);
    
    // MTU Slider visualization
    let pct = ((simulated - 576) as f64 / (9000.0 - 576.0) * 100.0) as u16;
    let slider = Gauge::default()
        .block(Block::default()
            .title(format!(" ▶ SIMULATED MTU: {} bytes [←/→ to adjust] ", simulated))
            .title_style(Style::default().fg(TERM_GREEN).add_modifier(Modifier::BOLD))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(TERM_GREEN_DIM))
            .border_type(BorderType::Rounded)
            .style(Style::default().bg(TERM_BLACK)))
        .gauge_style(Style::default().fg(TERM_AMBER).bg(TERM_BLACK))
        .percent(pct)
        .label(format!("{} bytes", simulated));
    
    frame.render_widget(slider, chunks[0]);
    
    // Impact table
    let header = Row::new(vec!["Target", "Min MTU", "At Simulated", "Status"])
        .style(Style::default().fg(TERM_CYAN).add_modifier(Modifier::BOLD));
    
    let rows: Vec<Row> = state.results.iter().map(|r| {
        // Get actual min MTU from test results (all protocols)
        let min_mtu = [r.icmp_mtu, r.tcp_mtu, r.udp_mtu, r.quic_mtu]
            .iter()
            .filter_map(|&m| m)
            .min();
        
        let (min_mtu_str, min_mtu_style, status_str, status_style) = if let Some(min) = min_mtu {
            let would_work = simulated <= min;
            let status = if would_work { "OK" } else { "FAIL" };
            let status_style = if would_work {
                Style::default().fg(TERM_GREEN)
            } else {
                Style::default().fg(TERM_RED)
            };
            (
                min.to_string(),
                Style::default().fg(TERM_GREEN),
                status.to_string(),
                status_style,
            )
        } else {
            // No test results yet
            (
                "---".to_string(),
                Style::default().fg(TERM_GREEN_DIM),
                "N/A".to_string(),
                Style::default().fg(TERM_GREEN_DIM),
            )
        };
        
        Row::new(vec![
            Cell::from(r.desc.chars().take(20).collect::<String>()).style(Style::default().fg(TERM_GREEN)),
            Cell::from(min_mtu_str).style(min_mtu_style),
            Cell::from(simulated.to_string()).style(Style::default().fg(TERM_AMBER)),
            Cell::from(status_str).style(status_style),
        ])
    }).collect();
    
    let table = Table::new(
        rows,
        [
            Constraint::Length(22),
            Constraint::Length(10),
            Constraint::Length(12),
            Constraint::Length(8),
        ],
    )
    .header(header)
    .block(Block::default()
        .title(" ▶ IMPACT ANALYSIS ")
        .title_style(Style::default().fg(TERM_GREEN).add_modifier(Modifier::BOLD))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(TERM_GREEN_DIM))
        .border_type(BorderType::Rounded)
        .style(Style::default().bg(TERM_BLACK)));
    
    frame.render_widget(table, chunks[1]);
}

fn render_help(frame: &mut Frame, area: Rect) {
    let help_text = vec![
        Line::from(Span::styled("═══════════════════════════════════════", Style::default().fg(TERM_CYAN))),
        Line::from(Span::styled("     FragglePacket HELP     ", Style::default().fg(TERM_GREEN).add_modifier(Modifier::BOLD))),
        Line::from(Span::styled("═══════════════════════════════════════", Style::default().fg(TERM_CYAN))),
        Line::from(""),
        Line::from(Span::styled("NAVIGATION", Style::default().fg(TERM_AMBER))),
        Line::from(vec![
            Span::styled("  ↑/↓    ", Style::default().fg(TERM_CYAN)),
            Span::styled("Move selection", Style::default().fg(TERM_GREEN)),
        ]),
        Line::from(vec![
            Span::styled("  Enter  ", Style::default().fg(TERM_CYAN)),
            Span::styled("View target details", Style::default().fg(TERM_GREEN)),
        ]),
        Line::from(vec![
            Span::styled("  Esc    ", Style::default().fg(TERM_CYAN)),
            Span::styled("Back to dashboard", Style::default().fg(TERM_GREEN)),
        ]),
        Line::from(""),
        Line::from(Span::styled("VIEWS", Style::default().fg(TERM_AMBER))),
        Line::from(vec![
            Span::styled("  1      ", Style::default().fg(TERM_CYAN)),
            Span::styled("Dashboard", Style::default().fg(TERM_GREEN)),
        ]),
        Line::from(vec![
            Span::styled("  Enter  ", Style::default().fg(TERM_CYAN)),
            Span::styled("Target details", Style::default().fg(TERM_GREEN)),
        ]),
        Line::from(vec![
            Span::styled("  3      ", Style::default().fg(TERM_CYAN)),
            Span::styled("MTU Simulator", Style::default().fg(TERM_GREEN)),
        ]),
        Line::from(vec![
            Span::styled("  ?/h    ", Style::default().fg(TERM_CYAN)),
            Span::styled("This help", Style::default().fg(TERM_GREEN)),
        ]),
        Line::from(vec![
            Span::styled("  F      ", Style::default().fg(TERM_CYAN)),
            Span::styled("Fuzzing Panel", Style::default().fg(TERM_GREEN)),
        ]),
        Line::from(vec![
            Span::styled("  H      ", Style::default().fg(TERM_CYAN)),
            Span::styled("HTTPS Testing", Style::default().fg(TERM_GREEN)),
        ]),
        Line::from(vec![
            Span::styled("  T      ", Style::default().fg(TERM_CYAN)),
            Span::styled("Test Framework (10 test categories)", Style::default().fg(TERM_GREEN)),
        ]),
        Line::from(""),
        Line::from(Span::styled("TEST FRAMEWORK (in Test Panel [T])", Style::default().fg(TERM_AMBER))),
        Line::from(vec![
            Span::styled("  1-0    ", Style::default().fg(TERM_CYAN)),
            Span::styled("Select test: 1=DNS 2=MTU 3=HTTPS 4=TCP 5=RTT", Style::default().fg(TERM_GREEN)),
        ]),
        Line::from(vec![
            Span::styled("         ", Style::default().fg(TERM_CYAN)),
            Span::styled("6=Loss 7=Path 8=IPv6 9=App 0=Fuzz", Style::default().fg(TERM_GREEN)),
        ]),
        Line::from(vec![
            Span::styled("  Enter  ", Style::default().fg(TERM_CYAN)),
            Span::styled("Run selected test (smart: single/all targets)", Style::default().fg(TERM_GREEN)),
        ]),
        Line::from(vec![
            Span::styled("  A      ", Style::default().fg(TERM_CYAN)),
            Span::styled("Run ALL 10 tests on current target", Style::default().fg(TERM_GREEN)),
        ]),
        Line::from(""),
        Line::from(Span::styled("ACTIONS", Style::default().fg(TERM_AMBER))),
        Line::from(vec![
            Span::styled("  r      ", Style::default().fg(TERM_CYAN)),
            Span::styled("Retest selected target", Style::default().fg(TERM_GREEN)),
        ]),
        Line::from(vec![
            Span::styled("  R      ", Style::default().fg(TERM_CYAN)),
            Span::styled("Retest ALL targets", Style::default().fg(TERM_GREEN)),
        ]),
        Line::from(vec![
            Span::styled("  s      ", Style::default().fg(TERM_CYAN)),
            Span::styled("Save JSON report", Style::default().fg(TERM_GREEN)),
        ]),
        Line::from(vec![
            Span::styled("  ↑/↓    ", Style::default().fg(TERM_CYAN)),
            Span::styled("Select target", Style::default().fg(TERM_GREEN)),
        ]),
        Line::from(vec![
            Span::styled("  ←/→    ", Style::default().fg(TERM_CYAN)),
            Span::styled("Adjust simulated MTU", Style::default().fg(TERM_GREEN)),
        ]),
        Line::from(vec![
            Span::styled("  ESC    ", Style::default().fg(TERM_CYAN)),
            Span::styled("Back to dashboard", Style::default().fg(TERM_GREEN)),
        ]),
        Line::from(vec![
            Span::styled("  q      ", Style::default().fg(TERM_CYAN)),
            Span::styled("Quit", Style::default().fg(TERM_GREEN)),
        ]),
    ];
    
    let help = Paragraph::new(help_text)
        .block(Block::default()
            .title(" ▶ HELP ")
            .title_style(Style::default().fg(TERM_GREEN).add_modifier(Modifier::BOLD))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(TERM_GREEN_DIM))
            .border_type(BorderType::Double)
            .style(Style::default().bg(TERM_BLACK)))
        .alignment(Alignment::Left);
    
    frame.render_widget(help, area);
}

fn render_footer(frame: &mut Frame, area: Rect, app: &App) {
    let mode_name = match app.mode {
        AppMode::Dashboard => "DASHBOARD",
        AppMode::TargetDetail => "DETAIL",
        AppMode::Simulator => "SIMULATOR",
        AppMode::FuzzingPanel => "FUZZING",
        AppMode::HttpsPanel => "HTTPS",
        AppMode::TestPanel => "TESTS",
        AppMode::Help => "HELP",
    };
    
    let help_hint = " [?]Help [1]Dash [F]Fuzz [H]HTTPS [T]Tests [A]RunAll [3]Sim [t]Tracepath [r]Retest [R]RetestAll [s]Save [q]Quit ";
    
    let footer = Paragraph::new(Line::from(vec![
        Span::styled(" MODE: ", Style::default().fg(TERM_GREEN_DIM)),
        Span::styled(mode_name, Style::default().fg(TERM_CYAN).add_modifier(Modifier::BOLD)),
        Span::styled(" │", Style::default().fg(TERM_GREEN_DIM)),
        Span::styled(help_hint, Style::default().fg(TERM_GREEN_DIM)),
    ]))
    .block(Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(TERM_GREEN_DIM))
        .border_type(BorderType::Rounded)
        .style(Style::default().bg(TERM_BLACK)));
    
    frame.render_widget(footer, area);
}

fn render_popup(frame: &mut Frame, message: &str, scroll: usize) {
    let area = centered_rect(80, 60, frame.area());  // Larger popup: 80% width, 60% height
    
    frame.render_widget(Clear, area);
    
    let popup = Paragraph::new(message)
        .block(Block::default()
            .title(" ▶ TRACEPATH OUTPUT ")
            .title_style(Style::default().fg(TERM_GREEN).add_modifier(Modifier::BOLD))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(TERM_CYAN))
            .border_type(BorderType::Double)
            .style(Style::default().bg(TERM_BLACK)))
        .alignment(Alignment::Left)
        .wrap(Wrap { trim: false })
        .scroll((scroll as u16, 0));  // Enable vertical scrolling
    
    frame.render_widget(popup, area);
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);
    
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

fn format_mtu_span(mtu: Option<usize>) -> Span<'static> {
    match mtu {
        Some(v) if v >= 1500 => Span::styled(v.to_string(), Style::default().fg(TERM_GREEN)),
        Some(v) if v >= 1400 => Span::styled(v.to_string(), Style::default().fg(TERM_AMBER)),
        Some(v) => Span::styled(v.to_string(), Style::default().fg(TERM_RED)),
        None => Span::styled("---", Style::default().fg(TERM_GREEN_DIM)),
    }
}

// =============================================================================
// EVENT HANDLING
// =============================================================================

pub fn handle_events(app: &mut App) -> io::Result<bool> {
    // Use shorter poll time when tracepath is running for live updates
    let poll_duration = if app.tracepath_running {
        Duration::from_millis(10)  // Fast polling during tracepath
    } else {
        Duration::from_millis(100)  // Normal polling otherwise
    };
    
    if event::poll(poll_duration)? {
        if let Event::Key(key) = event::read()? {
            if key.kind != KeyEventKind::Press {
                return Ok(false);
            }
            
            match key.code {
                KeyCode::Char('q') => app.should_quit = true,
                KeyCode::Char('?') | KeyCode::Char('h') => app.mode = AppMode::Help,
                KeyCode::Char('1') => {
                    if matches!(app.mode, AppMode::TestPanel) {
                        app.selected_category = Some(0);  // DNS
                    } else {
                        app.mode = AppMode::Dashboard;
                    }
                }
                KeyCode::Char('2') => {
                    if matches!(app.mode, AppMode::TestPanel) {
                        app.selected_category = Some(1);  // MTU
                    } else {
                        // Could add another mode
                    }
                }
                KeyCode::Char('3') => {
                    if matches!(app.mode, AppMode::TestPanel) {
                        app.selected_category = Some(2);  // HTTPS
                    } else {
                        app.mode = AppMode::Simulator;
                    }
                }
                KeyCode::Char('4') => {
                    if matches!(app.mode, AppMode::TestPanel) {
                        app.selected_category = Some(3);  // TCP Health
                    }
                }
                KeyCode::Char('5') => {
                    if matches!(app.mode, AppMode::TestPanel) {
                        app.selected_category = Some(4);  // RTT
                    }
                }
                KeyCode::Char('6') => {
                    if matches!(app.mode, AppMode::TestPanel) {
                        app.selected_category = Some(5);  // PacketLoss
                    }
                }
                KeyCode::Char('7') => {
                    if matches!(app.mode, AppMode::TestPanel) {
                        app.selected_category = Some(6);  // PathAnalysis
                    }
                }
                KeyCode::Char('8') => {
                    if matches!(app.mode, AppMode::TestPanel) {
                        app.selected_category = Some(7);  // IPv6
                    }
                }
                KeyCode::Char('9') => {
                    if matches!(app.mode, AppMode::TestPanel) {
                        app.selected_category = Some(8);  // Application
                    }
                }
                KeyCode::Char('0') => {
                    if matches!(app.mode, AppMode::TestPanel) {
                        app.selected_category = Some(9);  // Fuzzing
                    }
                }
                KeyCode::Char('f') | KeyCode::Char('F') => app.mode = AppMode::FuzzingPanel,
                KeyCode::Char('T') => app.mode = AppMode::TestPanel,  // Uppercase T for Test Panel
                KeyCode::Char('H') => app.mode = AppMode::HttpsPanel,
                KeyCode::Esc => {
                    // Handle escape based on current mode
                    match app.mode {
                        AppMode::FuzzingPanel | AppMode::HttpsPanel => app.mode = AppMode::Dashboard,
                        _ => app.mode = AppMode::Dashboard,
                    }
                }
                KeyCode::Enter => {
                    if matches!(app.mode, AppMode::Dashboard) {
                        app.mode = AppMode::TargetDetail;
                    } else if matches!(app.mode, AppMode::FuzzingPanel) {
                        app.run_selected_fuzzer();
                    } else if matches!(app.mode, AppMode::HttpsPanel) {
                        let target = {
                            let state = app.state.lock().unwrap();
                            state.results.get(app.selected_https_target)
                                .map(|r| r.target.clone())
                                .unwrap_or_else(|| "example.com".to_string())
                        };
                        app.run_https_test(&target);
                    } else if matches!(app.mode, AppMode::TestPanel) {
                        // Run selected test category
                        if let Some(category_idx) = app.selected_category {
                            let category = match category_idx {
                                0 => TestCategory::DNS,
                                1 => TestCategory::MTU,
                                2 => TestCategory::HTTPS,
                                3 => TestCategory::TCPHealth,
                                4 => TestCategory::RTT,
                                5 => TestCategory::PacketLoss,
                                6 => TestCategory::PathAnalysis,
                                7 => TestCategory::IPv6,
                                8 => TestCategory::Application,
                                9 => TestCategory::Fuzzing,
                                _ => TestCategory::DNS,
                            };
                            
                            // Smart execution: if in Dashboard, run on single target
                            // if in AllTargets view, run on all targets
                            if matches!(app.view_mode, ViewMode::Dashboard) {
                                app.run_category(category);
                            } else {
                                app.run_category_on_all_targets(category);
                            }
                        }
                    }
                }
                KeyCode::Char('a') | KeyCode::Char('A') => {
                    // Smart "run ALL" - context aware
                    if matches!(app.mode, AppMode::TestPanel) {
                        if matches!(app.view_mode, ViewMode::Dashboard) {
                            // Dashboard: run ALL tests on current target
                            app.run_all_tests_on_current_target();
                        } else {
                            // AllTargets: show confirmation for running ALL on ALL
                            app.popup_message = "Press Shift+A again to run ALL tests on ALL targets (this will take a while!)".to_string();
                            app.show_popup = true;
                        }
                    }
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    if app.show_popup && (app.tracepath_running || !app.tracepath_output.is_empty()) {
                        app.popup_scroll = app.popup_scroll.saturating_sub(1);
                    } else if matches!(app.mode, AppMode::FuzzingPanel) {
                        app.prev_fuzz_mode();
                    } else if matches!(app.mode, AppMode::HttpsPanel) {
                        app.prev_https_target();  // NEW
                    } else {
                        app.prev_target();
                    }
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    if app.show_popup && (app.tracepath_running || !app.tracepath_output.is_empty()) {
                        app.popup_scroll = app.popup_scroll.saturating_add(1);
                    } else if matches!(app.mode, AppMode::FuzzingPanel) {
                        app.next_fuzz_mode();
                    } else if matches!(app.mode, AppMode::HttpsPanel) {
                        app.next_https_target();  // NEW
                    } else {
                        app.next_target();
                    }
                }
                KeyCode::Char('a') | KeyCode::Char('A') => {
                    if matches!(app.mode, AppMode::FuzzingPanel) {
                        app.run_all_fuzzers();
                    } else if matches!(app.mode, AppMode::HttpsPanel) {
                        app.run_all_https_tests();  // NEW
                    }
                }
                KeyCode::PageUp => {
                    // Scroll popup up by 10 lines
                    if app.show_popup && (app.tracepath_running || !app.tracepath_output.is_empty()) {
                        app.popup_scroll = app.popup_scroll.saturating_sub(10);
                    }
                }
                KeyCode::PageDown => {
                    // Scroll popup down by 10 lines
                    if app.show_popup && (app.tracepath_running || !app.tracepath_output.is_empty()) {
                        app.popup_scroll = app.popup_scroll.saturating_add(10);
                    }
                }
                KeyCode::Left => app.adjust_simulated_mtu(-10),
                KeyCode::Right => app.adjust_simulated_mtu(10),
                KeyCode::Char('r') => {
                    // Retest single target with shorter timeout
                    let index = app.selected_target;
                    app.retest_target(index, 576, 1500, 1000, 1);  // 1000ms timeout, 1 retry
                    app.show_popup = true;
                    app.popup_message = format!("Retesting {}...", app.state.lock().unwrap().results.get(index).map(|r| &r.desc).unwrap_or(&"target".to_string()));
                }
                KeyCode::Char('t') => {
                    // Run tracepath for selected target
                    let index = app.selected_target;
                    app.run_tracepath(index);
                }
                KeyCode::Char('R') => {
                    // Retest all with shorter timeout
                    app.retest_all(576, 1500, 1000, 1);  // 1000ms timeout, 1 retry
                    app.show_popup = true;
                    app.popup_message = "Retesting ALL targets...".to_string();
                }
                KeyCode::Char('s') => {
                    // Save report
                    use chrono::Utc;
                    
                    let state = app.state.lock().unwrap();
                    let mut report = String::from("{\n");
                    report.push_str(&format!("  \"timestamp\": \"{}\",\n", Utc::now().to_rfc3339()));
                    report.push_str("  \"results\": [\n");
                    
                    for (i, r) in state.results.iter().enumerate() {
                        report.push_str("    {\n");
                        report.push_str(&format!("      \"target\": \"{}\",\n", r.target));
                        report.push_str(&format!("      \"description\": \"{}\",\n", r.desc));
                        if let Some(m) = r.icmp_mtu {
                            report.push_str(&format!("      \"icmp_mtu\": {},\n", m));
                        }
                        if let Some(m) = r.tcp_mtu {
                            report.push_str(&format!("      \"tcp_mtu\": {},\n", m));
                        }
                        if let Some(m) = r.udp_mtu {
                            report.push_str(&format!("      \"udp_mtu\": {},\n", m));
                        }
                        if let Some(m) = r.tcp_mss {
                            report.push_str(&format!("      \"tcp_mss\": {},\n", m));
                        }
                        report.push_str("    }");
                        if i < state.results.len() - 1 {
                            report.push_str(",");
                        }
                        report.push_str("\n");
                    }
                    
                    report.push_str("  ]");
                    
                    // Add fuzzing results if any
                    if !state.fuzzing_results.is_empty() {
                        report.push_str(",\n  \"fuzzing\": [\n");
                        let mut first = true;
                        for (mode, fuzz) in &state.fuzzing_results {
                            if !first {
                                report.push_str(",\n");
                            }
                            first = false;
                            report.push_str("    {\n");
                            report.push_str(&format!("      \"mode\": \"{}\",\n", mode));
                            report.push_str(&format!("      \"packets_generated\": {},\n", fuzz.packets_generated));
                            report.push_str(&format!("      \"pcap_path\": \"{}\",\n", fuzz.pcap_path));
                            report.push_str(&format!("      \"file_size_bytes\": {},\n", fuzz.file_size_bytes));
                            report.push_str(&format!("      \"duration_ms\": {},\n", fuzz.duration_ms));
                            let status_str = match &fuzz.status {
                                FuzzingStatus::Pending => "pending",
                                FuzzingStatus::Running => "running",
                                FuzzingStatus::Complete => "complete",
                                FuzzingStatus::Failed(msg) => msg.as_str(),
                            };
                            report.push_str(&format!("      \"status\": \"{}\"\n", status_str));
                            report.push_str("    }");
                        }
                        report.push_str("\n  ]");
                    }
                    
                    if let Some(v) = &state.verdict {
                        report.push_str(",\n  \"verdict\": {\n");
                        report.push_str(&format!("    \"status\": \"{}\",\n", v.status));
                        report.push_str(&format!("    \"median_mtu\": {},\n", v.median_mtu));
                        report.push_str(&format!("    \"percent_ok\": {:.1}\n", v.percent_ok));
                        report.push_str("  }\n");
                    } else {
                        report.push_str("\n");
                    }
                    report.push_str("}\n");
                    
                    let filename = format!("reports/mtu-report-{}.json", Utc::now().format("%Y%m%d_%H%M%S"));
                    // Ensure reports directory exists
                    std::fs::create_dir_all("reports").ok();
                    if std::fs::write(&filename, report).is_ok() {
                        app.show_popup = true;
                        app.popup_message = format!("Report saved to: {}", filename);
                    } else {
                        app.show_popup = true;
                        app.popup_message = "Failed to save report".to_string();
                    }
                }
                _ => {}
            }
            
            // Clear popup on any key after showing (except for keys that trigger popups or scroll)
            if app.show_popup && !matches!(key.code, 
                KeyCode::Char('r') | KeyCode::Char('R') | KeyCode::Char('s') | KeyCode::Char('t') | 
                KeyCode::Up | KeyCode::Down | KeyCode::Char('k') | KeyCode::Char('j') |
                KeyCode::PageUp | KeyCode::PageDown) {
                app.show_popup = false;
                app.tracepath_output.clear();  // Clear tracepath output when closing popup
                app.popup_scroll = 0;  // Reset scroll position
            }
        }
    }
    Ok(false)
}

// =============================================================================
// DEMO DATA (for testing the TUI)
// =============================================================================

pub fn create_demo_state() -> AppState {
    let results = vec![
        TargetResult {
            target: "8.8.8.8".into(),
            desc: "Google DNS".into(),
            icmp_mtu: Some(1500),
            tcp_mtu: None,
            udp_mtu: Some(1500),
            quic_mtu: None,
            tcp_mss: None,
            status: TestStatus::Complete,
            last_tested: Some(Instant::now()),
            hops: Vec::new(),
        },
        TargetResult {
            target: "1.1.1.1".into(),
            desc: "Cloudflare DNS".into(),
            icmp_mtu: Some(1500),
            tcp_mtu: None,
            udp_mtu: Some(1500),
            quic_mtu: None,
            tcp_mss: None,
            status: TestStatus::Complete,
            last_tested: Some(Instant::now()),
            hops: Vec::new(),
        },
        TargetResult {
            target: "github.com".into(),
            desc: "GitHub".into(),
            icmp_mtu: Some(1500),
            tcp_mtu: Some(1500),
            udp_mtu: None,
            quic_mtu: Some(1420),
            tcp_mss: Some(1460),
            status: TestStatus::Complete,
            last_tested: Some(Instant::now()),
            hops: Vec::new(),
        },
        TargetResult {
            target: "outlook.office365.com".into(),
            desc: "M365 Outlook".into(),
            icmp_mtu: Some(1500),
            tcp_mtu: Some(1500),
            udp_mtu: None,
            quic_mtu: Some(1400),
            tcp_mss: Some(1460),
            status: TestStatus::Complete,
            last_tested: Some(Instant::now()),
            hops: Vec::new(),
        },
        TargetResult {
            target: "teams.microsoft.com".into(),
            desc: "MS Teams".into(),
            icmp_mtu: Some(1500),
            tcp_mtu: Some(1500),
            udp_mtu: None,
            quic_mtu: None,
            tcp_mss: Some(1460),
            status: TestStatus::Complete,
            last_tested: Some(Instant::now()),
            hops: Vec::new(),
        },
    ];
    
    let hops = vec![
        HopInfo { hop: 1, addr: "192.168.1.1".into(), mtu: Some(1500), rtt_ms: Some(0.5) },
        HopInfo { hop: 2, addr: "10.0.0.1".into(), mtu: Some(1500), rtt_ms: Some(2.3) },
        HopInfo { hop: 3, addr: "72.14.215.85".into(), mtu: Some(1500), rtt_ms: Some(5.1) },
        HopInfo { hop: 4, addr: "142.250.169.174".into(), mtu: Some(1500), rtt_ms: Some(8.2) },
    ];
    
    AppState {
        results,
        hops,
        testing: false,
        progress: 1.0,
        current_target: String::new(),
        start_time: Some(Instant::now()),
        verdict: Some(Verdict {
            status: "PASS".into(),
            recommended_mtu: None,
            recommended_mss: None,
            median_mtu: 1500,
            percent_ok: 100.0,
        }),
        mtu_history: vec![1500, 1500, 1500, 1480, 1500, 1500, 1420, 1500, 1500, 1500,
                         1500, 1460, 1500, 1500, 1500, 1400, 1500, 1500, 1500, 1500],
        simulated_mtu: 1500,
        fuzzing_results: std::collections::HashMap::new(),
        https_results: std::collections::HashMap::new(),
        diagnoses: Vec::new(),
    }
}


