use super::test_trait::TestCategory;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

/// Unified test result structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestResult {
    /// Test name
    pub name: String,
    
    /// Test category
    pub category: TestCategory,
    
    /// Target that was tested
    pub target: String,
    
    /// Overall test status
    pub status: TestStatus,
    
    /// Numeric metrics (MTU size, latency ms, loss %, etc.)
    pub metrics: HashMap<String, f64>,
    
    /// String metadata (error messages, warnings, info)
    pub metadata: HashMap<String, String>,
    
    /// Detected issues with diagnosis
    pub diagnoses: Vec<Diagnosis>,
    
    /// Test execution time
    pub duration: Duration,
    
    /// Timestamp when test was run
    pub timestamp: u64,
}

impl TestResult {
    pub fn new(name: String, category: TestCategory, target: String) -> Self {
        Self {
            name,
            category,
            target,
            status: TestStatus::Running,
            metrics: HashMap::new(),
            metadata: HashMap::new(),
            diagnoses: Vec::new(),
            duration: Duration::from_secs(0),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }
    
    pub fn add_metric(&mut self, key: impl Into<String>, value: f64) {
        self.metrics.insert(key.into(), value);
    }
    
    pub fn add_metadata(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.metadata.insert(key.into(), value.into());
    }
    
    pub fn add_diagnosis(&mut self, diagnosis: Diagnosis) {
        self.diagnoses.push(diagnosis);
    }
    
    pub fn set_status(&mut self, status: TestStatus) {
        self.status = status;
    }
    
    pub fn has_issues(&self) -> bool {
        !self.diagnoses.is_empty() || self.status == TestStatus::Failed
    }
}

/// Test execution status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TestStatus {
    /// Test not yet started
    Pending,
    
    /// Test currently running
    Running,
    
    /// Test completed successfully
    Success,
    
    /// Test completed with warnings
    Warning,
    
    /// Test failed to complete
    Failed,
    
    /// Test skipped (e.g., no root privileges)
    Skipped,
}

/// Diagnosis of detected network issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Diagnosis {
    /// Issue severity
    pub severity: DiagnosisSeverity,
    
    /// Short issue title
    pub title: String,
    
    /// Detailed description
    pub description: String,
    
    /// Recommended actions
    pub recommendations: Vec<String>,
    
    /// Related test results (for cross-test correlation)
    pub related_tests: Vec<String>,
}

impl Diagnosis {
    pub fn new(severity: DiagnosisSeverity, title: String, description: String) -> Self {
        Self {
            severity,
            title,
            description,
            recommendations: Vec::new(),
            related_tests: Vec::new(),
        }
    }
    
    pub fn with_recommendation(mut self, recommendation: impl Into<String>) -> Self {
        self.recommendations.push(recommendation.into());
        self
    }
    
    pub fn with_related_test(mut self, test_name: impl Into<String>) -> Self {
        self.related_tests.push(test_name.into());
        self
    }
}

/// Issue severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiagnosisSeverity {
    /// Informational only
    Info,
    
    /// Minor issue, may cause degraded performance
    Warning,
    
    /// Serious issue, likely causing problems
    Error,
    
    /// Critical issue, definitely causing connectivity problems
    Critical,
}

// Serde support for TestCategory
impl Serialize for TestCategory {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for TestCategory {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "MTU" => Ok(TestCategory::MTU),
            "RTT" => Ok(TestCategory::RTT),
            "Packet Loss" => Ok(TestCategory::PacketLoss),
            "Path Analysis" => Ok(TestCategory::PathAnalysis),
            "TCP Health" => Ok(TestCategory::TCPHealth),
            "DNS" => Ok(TestCategory::DNS),
            "HTTPS" => Ok(TestCategory::HTTPS),
            "IPv6" => Ok(TestCategory::IPv6),
            "Application" => Ok(TestCategory::Application),
            "Fuzzing" => Ok(TestCategory::Fuzzing),
            _ => Err(serde::de::Error::custom(format!("Unknown test category: {}", s))),
        }
    }
}


