use super::result::TestResult;
use std::error::Error;

/// Core trait for all network tests
pub trait NetworkTest: Send + Sync {
    /// Human-readable test name
    fn name(&self) -> &str;
    
    /// Test category
    fn category(&self) -> TestCategory;
    
    /// Run the test against a target
    fn run(&self, target: &str) -> Result<TestResult, Box<dyn Error>>;
    
    /// Whether this test requires root/admin privileges
    fn requires_root(&self) -> bool {
        false
    }
    
    /// Estimated runtime in seconds
    fn estimated_duration(&self) -> u64 {
        5
    }
}

/// Test categories for organization and selective execution
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TestCategory {
    /// MTU discovery tests (ICMP, TCP, UDP, QUIC)
    MTU,
    
    /// RTT and latency measurements
    RTT,
    
    /// Packet loss detection
    PacketLoss,
    
    /// Path analysis (traceroute, MTU per hop)
    PathAnalysis,
    
    /// TCP health metrics (handshake, retrans, window)
    TCPHealth,
    
    /// DNS resolution tests
    DNS,
    
    /// HTTPS stage-by-stage testing
    HTTPS,
    
    /// IPv6 connectivity and comparison
    IPv6,
    
    /// Application-layer tests (HTTP/2, HTTP/3, WebSocket)
    Application,
    
    /// Packet fuzzing and crafting (RustPacketFuzz)
    Fuzzing,
}

impl TestCategory {
    pub fn all() -> Vec<TestCategory> {
        vec![
            TestCategory::MTU,
            TestCategory::RTT,
            TestCategory::PacketLoss,
            TestCategory::PathAnalysis,
            TestCategory::TCPHealth,
            TestCategory::DNS,
            TestCategory::HTTPS,
            TestCategory::IPv6,
            TestCategory::Application,
            TestCategory::Fuzzing,
        ]
    }
    
    pub fn as_str(&self) -> &str {
        match self {
            TestCategory::MTU => "MTU",
            TestCategory::RTT => "RTT",
            TestCategory::PacketLoss => "Packet Loss",
            TestCategory::PathAnalysis => "Path Analysis",
            TestCategory::TCPHealth => "TCP Health",
            TestCategory::DNS => "DNS",
            TestCategory::HTTPS => "HTTPS",
            TestCategory::IPv6 => "IPv6",
            TestCategory::Application => "Application",
            TestCategory::Fuzzing => "Fuzzing",
        }
    }
}


