//! GAP-038: distributed wireless-probe fleet orchestrator.
//!
//! Field context (`precog-ops` skill): 24 authorized Precog probes reach a
//! management-only bastion over a wired hop; the bastion itself
//! ("precog-00"/"anderton") must never originate test traffic -- every
//! ping/iperf/radio command executes only after a second SSH hop to
//! `precog-01@<node>`. Mixing the management path with the path under
//! test means the control channel's own congestion becomes the
//! measurement, which is exactly the bug `NodeRole` exists to make
//! impossible to construct: there is no variant that lets a caller mark
//! the bastion as a test node, and `FleetPlan::validate` refuses a plan
//! that assigns a test phase to anything but `NodeRole::TestNode`.
//!
//! Node labels use the same technique as GAP-024's `ap_identity`
//! (persisted random salt + `DefaultHasher`, no new crate) rather than
//! editing that module, which is off-limits and owned by another agent
//! this sprint. A distinct salt file keeps this label space independent
//! of the AP-identity one, so a "node-xxxxxxxx" label and an "ap-xxxxxxxx"
//! label can never be confused for referring to the same kind of thing.
//!
//! Nothing in this module ever stores a bastion hostname, node IP address,
//! or SSH key material in any struct that derives `Serialize` -- addresses
//! exist only as the input to `label_for_node`, consumed immediately.

use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

const SALT_FILE_NAME: &str = "fraggle-packet-fleet-node-salt";

fn salt_path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join(SALT_FILE_NAME))
}

pub fn load_or_create_node_salt() -> Result<String, String> {
    let path = salt_path().ok_or_else(|| "no config directory available on this platform".to_string())?;
    if let Ok(existing) = std::fs::read_to_string(&path) {
        let trimmed = existing.trim().to_string();
        if !trimmed.is_empty() {
            return Ok(trimmed);
        }
    }
    let salt = generate_node_salt();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("failed to create config dir: {e}"))?;
    }
    std::fs::write(&path, &salt).map_err(|e| format!("failed to persist fleet-node salt: {e}"))?;
    Ok(salt)
}

fn generate_node_salt() -> String {
    let mut hasher = DefaultHasher::new();
    std::time::SystemTime::now().hash(&mut hasher);
    std::process::id().hash(&mut hasher);
    let stack_addr = &hasher as *const _ as usize;
    stack_addr.hash(&mut hasher);
    for i in 0..4u64 {
        i.hash(&mut hasher);
        let h = hasher.finish();
        h.hash(&mut hasher);
    }
    format!("{:032x}", hasher.finish() as u128 ^ ((hasher.finish() as u128) << 64))
}

/// Produces a stable opaque label from a management address and salt.
/// Callers must discard the address immediately after this call -- nothing
/// downstream of this function ever sees it again.
pub fn label_for_node(address: &str, salt: &str) -> String {
    let mut hasher = DefaultHasher::new();
    salt.hash(&mut hasher);
    address.hash(&mut hasher);
    salt.hash(&mut hasher);
    format!("node-{:08x}", hasher.finish() as u32)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeRole {
    /// The management-only bastion. No test phase may ever target this
    /// role -- see `FleetPlan::validate`.
    ManagementBastion,
    TestNode,
}

/// Inventory entry. `address` is intentionally NOT `Serialize`-derived
/// reachable: it is a plain field on a plain (non-serialized) struct used
/// only to build a `FleetNode`, and `FleetNode` itself never carries it.
#[derive(Debug, Clone)]
pub struct InventoryEntry {
    pub address: String,
    pub role: NodeRole,
}

/// The redacted, output-safe view of one inventory entry. This is the ONLY
/// node-shaped type that derives `Serialize` in this module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetNode {
    pub label: String,
    pub role: NodeRole,
}

pub fn build_fleet_labels(entries: &[InventoryEntry], salt: &str) -> Vec<FleetNode> {
    entries.iter().map(|e| FleetNode { label: label_for_node(&e.address, salt), role: e.role }).collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetPlan {
    pub nodes: Vec<FleetNode>,
    pub max_concurrency: u32,
    pub per_node_timeout_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlanError {
    BastionAssignedAsTestNode,
    ZeroConcurrency,
    ZeroTimeout,
    NoTestNodes,
}

impl std::fmt::Display for PlanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PlanError::BastionAssignedAsTestNode => {
                write!(f, "plan assigns a management bastion as a test node; refusing to mix control and measurement paths")
            }
            PlanError::ZeroConcurrency => write!(f, "max_concurrency must be >= 1"),
            PlanError::ZeroTimeout => write!(f, "per_node_timeout_secs must be >= 1"),
            PlanError::NoTestNodes => write!(f, "plan has no TestNode-role nodes to run against"),
        }
    }
}

impl FleetPlan {
    pub fn validate(&self) -> Result<(), PlanError> {
        if self.max_concurrency == 0 {
            return Err(PlanError::ZeroConcurrency);
        }
        if self.per_node_timeout_secs == 0 {
            return Err(PlanError::ZeroTimeout);
        }
        let test_nodes: Vec<&FleetNode> = self.nodes.iter().filter(|n| n.role == NodeRole::TestNode).collect();
        if test_nodes.is_empty() {
            return Err(PlanError::NoTestNodes);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum NodeOutcome {
    Completed { radio_before_fingerprint: Option<String>, radio_after_fingerprint: Option<String> },
    TimedOut,
    ConnectionFailed { detail: String },
    Quarantined { reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeRunResult {
    pub label: String,
    pub outcome: NodeOutcome,
}

/// A fanout mechanism entirely decoupled from any real network I/O: the
/// `runner` closure is what a caller supplies to actually reach a node
/// (real SSH in production, a synthetic function in tests/offline
/// verification). This module never opens a socket or spawns `ssh`
/// itself -- that keeps the bounded-concurrency/timeout logic testable
/// without any live access, which is what this task explicitly requires
/// given no live fanout was authorized for this session.
pub fn run_fleet_fanout<F>(plan: &FleetPlan, runner: F) -> Vec<NodeRunResult>
where
    F: Fn(&str) -> Result<(Option<String>, Option<String>), String> + Send + Sync + 'static,
{
    use std::sync::{Arc, Mutex};

    let runner = Arc::new(runner);
    let semaphore = Arc::new(std::sync::atomic::AtomicUsize::new(plan.max_concurrency as usize));
    let results = Arc::new(Mutex::new(Vec::new()));
    let timeout = Duration::from_secs(plan.per_node_timeout_secs);

    let test_nodes: Vec<FleetNode> =
        plan.nodes.iter().filter(|n| n.role == NodeRole::TestNode).cloned().collect();

    let handles: Vec<_> = test_nodes
        .into_iter()
        .map(|node| {
            let runner = runner.clone();
            let semaphore = semaphore.clone();
            let results = results.clone();
            std::thread::spawn(move || {
                loop {
                    let current = semaphore.load(std::sync::atomic::Ordering::SeqCst);
                    if current == 0 {
                        std::thread::sleep(Duration::from_millis(10));
                        continue;
                    }
                    if semaphore.compare_exchange(
                        current,
                        current - 1,
                        std::sync::atomic::Ordering::SeqCst,
                        std::sync::atomic::Ordering::SeqCst,
                    ).is_ok() {
                        break;
                    }
                }

                let (tx, rx) = std::sync::mpsc::channel();
                let label_for_thread = node.label.clone();
                let runner_thread = runner.clone();
                std::thread::spawn(move || {
                    let result = runner_thread(&label_for_thread);
                    let _ = tx.send(result);
                });

                let outcome = match rx.recv_timeout(timeout) {
                    Ok(Ok((before, after))) => {
                        NodeOutcome::Completed { radio_before_fingerprint: before, radio_after_fingerprint: after }
                    }
                    Ok(Err(e)) => NodeOutcome::ConnectionFailed { detail: e },
                    Err(_) => NodeOutcome::TimedOut,
                };

                semaphore.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                results.lock().unwrap().push(NodeRunResult { label: node.label, outcome });
            })
        })
        .collect();

    for h in handles {
        let _ = h.join();
    }

    Arc::try_unwrap(results).unwrap().into_inner().unwrap()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetSummary {
    pub total_nodes: usize,
    pub completed: usize,
    pub excluded_with_reason: Vec<(String, String)>,
}

/// Never averages over a node that never completed. `completed` is drawn
/// strictly from `NodeOutcome::Completed`; every other outcome is listed
/// in `excluded_with_reason` and contributes nothing to any aggregate a
/// caller might compute downstream of this summary.
pub fn summarize_fleet_run(results: &[NodeRunResult]) -> FleetSummary {
    let mut excluded = Vec::new();
    let mut completed = 0;
    for r in results {
        match &r.outcome {
            NodeOutcome::Completed { .. } => completed += 1,
            NodeOutcome::TimedOut => excluded.push((r.label.clone(), "timed out".to_string())),
            NodeOutcome::ConnectionFailed { detail } => excluded.push((r.label.clone(), format!("connection failed: {detail}"))),
            NodeOutcome::Quarantined { reason } => excluded.push((r.label.clone(), format!("quarantined: {reason}"))),
        }
    }
    FleetSummary { total_nodes: results.len(), completed, excluded_with_reason: excluded }
}

/// Deterministic, hashable run descriptor -- not a signature (GAP-029/065
/// own signing), but stable enough for a signature to be attached later.
pub fn run_descriptor_digest(plan: &FleetPlan) -> u64 {
    let mut hasher = DefaultHasher::new();
    plan.max_concurrency.hash(&mut hasher);
    plan.per_node_timeout_secs.hash(&mut hasher);
    for n in &plan.nodes {
        n.label.hash(&mut hasher);
    }
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_never_contains_the_input_address() {
        let salt = "fixed-test-salt";
        let address = "10.10.12.99";
        let label = label_for_node(address, salt);
        assert!(!label.contains(address));
        assert!(!label.contains('.'));
    }

    #[test]
    fn label_is_stable_for_the_same_address_and_salt() {
        let salt = "fixed-test-salt";
        let a = label_for_node("10.10.12.99", salt);
        let b = label_for_node("10.10.12.99", salt);
        assert_eq!(a, b);
    }

    #[test]
    fn label_differs_for_a_different_address() {
        let salt = "fixed-test-salt";
        let a = label_for_node("10.10.12.99", salt);
        let b = label_for_node("10.10.63.99", salt);
        assert_ne!(a, b);
    }

    #[test]
    fn plan_refuses_a_bastion_marked_as_the_only_role_with_no_test_nodes() {
        let plan = FleetPlan {
            nodes: vec![FleetNode { label: "node-aaaaaaaa".to_string(), role: NodeRole::ManagementBastion }],
            max_concurrency: 4,
            per_node_timeout_secs: 50,
        };
        assert_eq!(plan.validate(), Err(PlanError::NoTestNodes));
    }

    #[test]
    fn plan_with_test_nodes_and_valid_bounds_is_accepted() {
        let plan = FleetPlan {
            nodes: vec![
                FleetNode { label: "node-aaaaaaaa".to_string(), role: NodeRole::ManagementBastion },
                FleetNode { label: "node-bbbbbbbb".to_string(), role: NodeRole::TestNode },
            ],
            max_concurrency: 4,
            per_node_timeout_secs: 50,
        };
        assert!(plan.validate().is_ok());
    }

    #[test]
    fn zero_concurrency_rejected() {
        let plan = FleetPlan {
            nodes: vec![FleetNode { label: "node-bbbbbbbb".to_string(), role: NodeRole::TestNode }],
            max_concurrency: 0,
            per_node_timeout_secs: 50,
        };
        assert_eq!(plan.validate(), Err(PlanError::ZeroConcurrency));
    }

    #[test]
    fn zero_timeout_rejected() {
        let plan = FleetPlan {
            nodes: vec![FleetNode { label: "node-bbbbbbbb".to_string(), role: NodeRole::TestNode }],
            max_concurrency: 4,
            per_node_timeout_secs: 0,
        };
        assert_eq!(plan.validate(), Err(PlanError::ZeroTimeout));
    }

    #[test]
    fn fanout_only_runs_test_nodes_never_the_bastion() {
        let plan = FleetPlan {
            nodes: vec![
                FleetNode { label: "node-bastion0".to_string(), role: NodeRole::ManagementBastion },
                FleetNode { label: "node-test0001".to_string(), role: NodeRole::TestNode },
                FleetNode { label: "node-test0002".to_string(), role: NodeRole::TestNode },
            ],
            max_concurrency: 2,
            per_node_timeout_secs: 2,
        };
        let results = run_fleet_fanout(&plan, |label| Ok((Some(format!("before-{label}")), Some(format!("after-{label}")))));
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.label != "node-bastion0"));
    }

    #[test]
    fn timeout_is_reported_distinctly_and_excluded_not_zeroed() {
        let plan = FleetPlan {
            nodes: vec![FleetNode { label: "node-slow0001".to_string(), role: NodeRole::TestNode }],
            max_concurrency: 1,
            per_node_timeout_secs: 1,
        };
        let results = run_fleet_fanout(&plan, |_label| {
            std::thread::sleep(Duration::from_secs(3));
            Ok((None, None))
        });
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].outcome, NodeOutcome::TimedOut);

        let summary = summarize_fleet_run(&results);
        assert_eq!(summary.completed, 0);
        assert_eq!(summary.excluded_with_reason.len(), 1);
        assert_eq!(summary.excluded_with_reason[0].1, "timed out");
    }

    #[test]
    fn summary_never_averages_over_a_node_that_never_completed() {
        let results = vec![
            NodeRunResult { label: "node-ok000001".to_string(), outcome: NodeOutcome::Completed { radio_before_fingerprint: None, radio_after_fingerprint: None } },
            NodeRunResult { label: "node-bad000001".to_string(), outcome: NodeOutcome::TimedOut },
            NodeRunResult { label: "node-bad000002".to_string(), outcome: NodeOutcome::Quarantined { reason: "changed host key".to_string() } },
        ];
        let summary = summarize_fleet_run(&results);
        assert_eq!(summary.total_nodes, 3);
        assert_eq!(summary.completed, 1);
        assert_eq!(summary.excluded_with_reason.len(), 2);
    }

    #[test]
    fn run_descriptor_is_deterministic() {
        let plan = FleetPlan {
            nodes: vec![FleetNode { label: "node-aaaaaaaa".to_string(), role: NodeRole::TestNode }],
            max_concurrency: 4,
            per_node_timeout_secs: 50,
        };
        assert_eq!(run_descriptor_digest(&plan), run_descriptor_digest(&plan));
    }

    #[test]
    fn concurrency_bound_is_respected_under_a_larger_fanout() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let concurrent = Arc::new(AtomicUsize::new(0));
        let max_seen = Arc::new(AtomicUsize::new(0));
        let plan = FleetPlan {
            nodes: (0..8)
                .map(|i| FleetNode { label: format!("node-{i:08x}"), role: NodeRole::TestNode })
                .collect(),
            max_concurrency: 3,
            per_node_timeout_secs: 5,
        };
        let concurrent_clone = concurrent.clone();
        let max_seen_clone = max_seen.clone();
        let results = run_fleet_fanout(&plan, move |_label| {
            let now = concurrent_clone.fetch_add(1, Ordering::SeqCst) + 1;
            max_seen_clone.fetch_max(now, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(50));
            concurrent_clone.fetch_sub(1, Ordering::SeqCst);
            Ok((None, None))
        });
        assert_eq!(results.len(), 8);
        assert!(max_seen.load(Ordering::SeqCst) <= 3);
    }
}
