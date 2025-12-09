//! Diagnosis Engine - Correlate test results and provide recommendations

use crate::network_tests::{HttpsTestResult, HttpsDiagnosis};

#[derive(Debug, Clone)]
pub struct Diagnosis {
    pub issue: DiagnosisIssue,
    pub severity: Severity,
    pub description: String,
    pub recommendation: String,
    pub related_tests: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DiagnosisIssue {
    MtuBlackhole,
    TcpSegmentationLimit,
    DnsFailure,
    PortBlocking,
    HighLatency,
    PacketLoss,
    PathMtuMismatch,
}

#[derive(Debug, Clone, PartialEq, Ord, PartialOrd, Eq)]
pub enum Severity {
    Critical,  // Service unusable
    High,      // Major functionality broken
    Medium,    // Performance degraded
    Low,       // Minor issue
    Info,      // Informational
}

pub trait DiagnosisRule {
    fn name(&self) -> &str;
    fn check(&self, evidence: &DiagnosisEvidence) -> Option<Diagnosis>;
}

#[derive(Debug, Clone, Default)]
pub struct DiagnosisEvidence {
    pub https_result: Option<HttpsTestResult>,
    pub interface_mtu: Option<usize>,
    pub icmp_mtu: Option<usize>,
    pub tcp_mtu: Option<usize>,
    pub tcp_segment_limit: Option<usize>,
}

/// MTU Blackhole Detection Rule
pub struct MtuBlackholeRule;

impl DiagnosisRule for MtuBlackholeRule {
    fn name(&self) -> &str {
        "MTU Blackhole Detector"
    }
    
    fn check(&self, evidence: &DiagnosisEvidence) -> Option<Diagnosis> {
        let https = evidence.https_result.as_ref()?;
        
        // Signature: TCP OK + TLS timeout + high interface MTU
        if https.tcp_success 
            && https.diagnosis == HttpsDiagnosis::TlsTimeout
            && evidence.interface_mtu.unwrap_or(0) >= 1500 {
            
            // Find suggested MTU
            let suggested_mtu = evidence.tcp_mtu
                .or(evidence.icmp_mtu)
                .map(|m| m - 100)  // Safety margin
                .unwrap_or(1400);
            
            return Some(Diagnosis {
                issue: DiagnosisIssue::MtuBlackhole,
                severity: Severity::Critical,
                description: format!(
                    "MTU blackhole detected on {}. TCP connects but TLS times out. \
                    This occurs when intermediate routers drop large packets without \
                    sending ICMP 'Packet Too Big' messages.",
                    https.target
                ),
                recommendation: format!(
                    "Lower interface MTU to {} bytes:\n\
                    Linux: sudo ip link set dev eth0 mtu {}\n\
                    Windows: netsh interface ipv4 set subinterface \"Ethernet\" mtu={} store=persistent\n\
                    macOS: sudo ifconfig en0 mtu {}",
                    suggested_mtu, suggested_mtu, suggested_mtu, suggested_mtu
                ),
                related_tests: vec![
                    "HTTPS Test".to_string(),
                    "MTU Test".to_string(),
                ],
            });
        }
        
        None
    }
}

/// Path MTU Mismatch Rule
pub struct PathMtuMismatchRule;

impl DiagnosisRule for PathMtuMismatchRule {
    fn name(&self) -> &str {
        "Path MTU Mismatch Detector"
    }
    
    fn check(&self, evidence: &DiagnosisEvidence) -> Option<Diagnosis> {
        let interface_mtu = evidence.interface_mtu?;
        let icmp_mtu = evidence.icmp_mtu?;
        
        // Path MTU < Interface MTU = potential issue
        if icmp_mtu < interface_mtu && interface_mtu - icmp_mtu > 50 {
            return Some(Diagnosis {
                issue: DiagnosisIssue::PathMtuMismatch,
                severity: Severity::High,
                description: format!(
                    "Path MTU ({} bytes) is lower than interface MTU ({} bytes). \
                    This can cause fragmentation or dropped packets.",
                    icmp_mtu, interface_mtu
                ),
                recommendation: format!(
                    "Consider lowering interface MTU to {} bytes to match path MTU.",
                    icmp_mtu
                ),
                related_tests: vec!["MTU Test".to_string()],
            });
        }
        
        None
    }
}

/// Diagnosis Engine - runs all rules
pub struct DiagnosisEngine {
    rules: Vec<Box<dyn DiagnosisRule>>,
}

impl DiagnosisEngine {
    pub fn new() -> Self {
        let rules: Vec<Box<dyn DiagnosisRule>> = vec![
            Box::new(MtuBlackholeRule),
            Box::new(PathMtuMismatchRule),
        ];
        
        Self { rules }
    }
    
    pub fn diagnose(&self, evidence: &DiagnosisEvidence) -> Vec<Diagnosis> {
        let mut diagnoses = Vec::new();
        
        for rule in &self.rules {
            if let Some(diagnosis) = rule.check(evidence) {
                diagnoses.push(diagnosis);
            }
        }
        
        // Sort by severity
        diagnoses.sort_by(|a, b| b.severity.cmp(&a.severity));
        
        diagnoses
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network_tests::HttpsTestResult;
    
    #[test]
    fn test_mtu_blackhole_detection() {
        let mut https_result = HttpsTestResult::new("test.com".to_string());
        https_result.tcp_success = true;
        https_result.diagnosis = HttpsDiagnosis::TlsTimeout;
        
        let evidence = DiagnosisEvidence {
            https_result: Some(https_result),
            interface_mtu: Some(1500),
            icmp_mtu: Some(1400),
            ..Default::default()
        };
        
        let engine = DiagnosisEngine::new();
        let diagnoses = engine.diagnose(&evidence);
        
        assert!(!diagnoses.is_empty());
        // MTU blackhole is Critical, so should be first after sorting
        let has_blackhole = diagnoses.iter().any(|d| d.issue == DiagnosisIssue::MtuBlackhole);
        assert!(has_blackhole, "Should detect MTU blackhole");
        
        // Also has path mismatch
        let has_mismatch = diagnoses.iter().any(|d| d.issue == DiagnosisIssue::PathMtuMismatch);
        assert!(has_mismatch, "Should also detect path MTU mismatch");
    }
    
    #[test]
    fn test_path_mtu_mismatch() {
        let evidence = DiagnosisEvidence {
            interface_mtu: Some(1500),
            icmp_mtu: Some(1400),
            ..Default::default()
        };
        
        let engine = DiagnosisEngine::new();
        let diagnoses = engine.diagnose(&evidence);
        
        let has_mismatch = diagnoses.iter()
            .any(|d| d.issue == DiagnosisIssue::PathMtuMismatch);
        assert!(has_mismatch);
    }
}

