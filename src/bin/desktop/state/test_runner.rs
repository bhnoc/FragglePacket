//! Async test execution service
//!
//! Wraps the blocking TestOrchestrator calls in async tasks to prevent UI freezing.

use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::mpsc;
use fraggle_packet::framework::{TestOrchestrator, TestCategory, TestResult};

/// Test update events sent from the test runner to the UI
#[derive(Debug, Clone)]
pub enum TestUpdate {
    /// Test execution started
    Started {
        target: String,
        category: Option<TestCategory>,
    },
    /// Single test result completed
    Result {
        target: String,
        result: TestResult,
    },
    /// All tests completed
    Completed {
        target: String,
    },
    /// Test execution failed
    Failed {
        target: String,
        error: String,
    },
    /// Progress update (0.0 - 1.0)
    Progress {
        target: String,
        progress: f64,
    },
}

/// Async test runner service
pub struct TestRunner {
    orchestrator: Arc<TestOrchestrator>,
}

impl TestRunner {
    pub fn new(orchestrator: TestOrchestrator) -> Self {
        Self {
            orchestrator: Arc::new(orchestrator),
        }
    }

    /// Create a channel for receiving test updates
    pub fn create_channel() -> (mpsc::Sender<TestUpdate>, mpsc::Receiver<TestUpdate>) {
        mpsc::channel(100)
    }

    /// Run a specific test category asynchronously
    pub fn run_category(
        &self,
        target: String,
        category: TestCategory,
        tx: mpsc::Sender<TestUpdate>,
    ) {
        let orchestrator = self.orchestrator.clone();

        tokio::spawn(async move {
            // Notify start
            let _ = tx.send(TestUpdate::Started {
                target: target.clone(),
                category: Some(category),
            }).await;

            // Run blocking test in a separate thread
            let target_clone = target.clone();
            let result = tokio::task::spawn_blocking(move || {
                orchestrator.run_category(&target_clone, category)
            }).await;

            match result {
                Ok(results) => {
                    let total = results.len();
                    for (i, result) in results.into_iter().enumerate() {
                        let _ = tx.send(TestUpdate::Result {
                            target: target.clone(),
                            result,
                        }).await;

                        // Send progress
                        let _ = tx.send(TestUpdate::Progress {
                            target: target.clone(),
                            progress: (i + 1) as f64 / total as f64,
                        }).await;
                    }
                    let _ = tx.send(TestUpdate::Completed {
                        target,
                    }).await;
                }
                Err(e) => {
                    let _ = tx.send(TestUpdate::Failed {
                        target,
                        error: e.to_string(),
                    }).await;
                }
            }
        });
    }

    /// Run multiple test categories asynchronously
    pub fn run_categories(
        &self,
        target: String,
        categories: HashSet<TestCategory>,
        tx: mpsc::Sender<TestUpdate>,
    ) {
        let orchestrator = self.orchestrator.clone();

        tokio::spawn(async move {
            // Notify start
            let _ = tx.send(TestUpdate::Started {
                target: target.clone(),
                category: None, // Multiple categories
            }).await;

            let target_clone = target.clone();
            let categories_clone = categories.clone();
            let result = tokio::task::spawn_blocking(move || {
                let mut all_results = Vec::new();
                for category in categories_clone {
                    let cat_results = orchestrator.run_category(&target_clone, category);
                    all_results.extend(cat_results);
                }
                all_results
            }).await;

            match result {
                Ok(results) => {
                    let total = results.len().max(1);
                    for (i, result) in results.into_iter().enumerate() {
                        let _ = tx.send(TestUpdate::Result {
                            target: target.clone(),
                            result,
                        }).await;

                        // Send progress
                        let _ = tx.send(TestUpdate::Progress {
                            target: target.clone(),
                            progress: (i + 1) as f64 / total as f64,
                        }).await;
                    }
                    let _ = tx.send(TestUpdate::Completed {
                        target,
                    }).await;
                }
                Err(e) => {
                    let _ = tx.send(TestUpdate::Failed {
                        target,
                        error: e.to_string(),
                    }).await;
                }
            }
        });
    }

    /// Run all tests for a target asynchronously
    pub fn run_all(
        &self,
        target: String,
        tx: mpsc::Sender<TestUpdate>,
    ) {
        let orchestrator = self.orchestrator.clone();

        tokio::spawn(async move {
            // Notify start
            let _ = tx.send(TestUpdate::Started {
                target: target.clone(),
                category: None,
            }).await;

            let target_clone = target.clone();
            let result = tokio::task::spawn_blocking(move || {
                orchestrator.run_all(&target_clone)
            }).await;

            match result {
                Ok(results) => {
                    let total = results.len();
                    for (i, result) in results.into_iter().enumerate() {
                        let _ = tx.send(TestUpdate::Result {
                            target: target.clone(),
                            result,
                        }).await;

                        // Send progress
                        let _ = tx.send(TestUpdate::Progress {
                            target: target.clone(),
                            progress: (i + 1) as f64 / total as f64,
                        }).await;
                    }
                    let _ = tx.send(TestUpdate::Completed {
                        target,
                    }).await;
                }
                Err(e) => {
                    let _ = tx.send(TestUpdate::Failed {
                        target,
                        error: e.to_string(),
                    }).await;
                }
            }
        });
    }
}
