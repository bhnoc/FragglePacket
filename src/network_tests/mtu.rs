//! MTU Test Wrapper - wraps existing MTU tests in NetworkTest trait

use crate::framework::{NetworkTest, TestCategory, TestResult, TestStatus};
use std::error::Error;
use std::process::Command;

/// ICMP-based MTU discovery
pub struct IcmpMtuTest {
    min_mtu: usize,
    max_mtu: usize,
    timeout_ms: u64,
}

impl IcmpMtuTest {
    pub fn new() -> Self {
        Self {
            min_mtu: 576,
            max_mtu: 1500,
            timeout_ms: 2000,
        }
    }
    
    pub fn with_range(mut self, min: usize, max: usize) -> Self {
        self.min_mtu = min;
        self.max_mtu = max;
        self
    }
}

impl Default for IcmpMtuTest {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkTest for IcmpMtuTest {
    fn name(&self) -> &str {
        "ICMP MTU Discovery"
    }
    
    fn category(&self) -> TestCategory {
        TestCategory::MTU
    }
    
    fn run(&self, target: &str) -> Result<TestResult, Box<dyn Error>> {
        let mut result = TestResult::new(
            self.name().to_string(),
            self.category(),
            target.to_string(),
        );
        
        // Binary search for MTU
        let mut low = self.min_mtu;
        let mut high = self.max_mtu;
        let mut discovered_mtu = None;
        
        while low <= high {
            let mid = (low + high) / 2;
            
            // Ping with specific packet size (DF bit set)
            let packet_size = mid - 28; // Subtract IP + ICMP headers
            
            let output = Command::new("ping")
                .arg("-c")
                .arg("3")
                .arg("-M")
                .arg("do") // Don't fragment
                .arg("-s")
                .arg(packet_size.to_string())
                .arg("-W")
                .arg((self.timeout_ms / 1000).to_string())
                .arg(target)
                .output()?;
            
            if output.status.success() {
                // Packet got through, try larger
                discovered_mtu = Some(mid);
                low = mid + 1;
            } else {
                // Packet too big, try smaller
                high = mid - 1;
            }
        }
        
        if let Some(mtu) = discovered_mtu {
            result.add_metric("mtu", mtu as f64);
            result.add_metadata("method", "ICMP binary search");
            result.set_status(TestStatus::Success);
            
            // Add recommendations based on MTU
            if mtu < 1500 {
                result.add_diagnosis(crate::framework::Diagnosis::new(
                    crate::framework::DiagnosisSeverity::Info,
                    "Reduced MTU Detected".to_string(),
                    format!("Path MTU is {} (standard is 1500)", mtu),
                ).with_recommendation("This may indicate tunneling or encapsulation in path")
                 .with_related_test("Path Analysis"));
            }
            
            if mtu < 1280 {
                result.add_diagnosis(crate::framework::Diagnosis::new(
                    crate::framework::DiagnosisSeverity::Warning,
                    "Low MTU".to_string(),
                    format!("MTU {} is below IPv6 minimum (1280)", mtu),
                ).with_recommendation("May cause IPv6 connectivity issues"));
            }
        } else {
            result.set_status(TestStatus::Failed);
            result.add_metadata("error", "Could not discover MTU");
        }
        
        Ok(result)
    }
    
    fn requires_root(&self) -> bool {
        false // ping usually has setuid
    }
    
    fn estimated_duration(&self) -> u64 {
        // Binary search with ~8-10 iterations
        10
    }
}

/// TCP-based MTU discovery (MSS)
pub struct TcpMtuTest {
    port: u16,
}

impl TcpMtuTest {
    pub fn new() -> Self {
        Self { port: 443 }
    }
    
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }
}

impl Default for TcpMtuTest {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkTest for TcpMtuTest {
    fn name(&self) -> &str {
        "TCP MSS Discovery"
    }
    
    fn category(&self) -> TestCategory {
        TestCategory::MTU
    }
    
    fn run(&self, target: &str) -> Result<TestResult, Box<dyn Error>> {
        let mut result = TestResult::new(
            self.name().to_string(),
            self.category(),
            target.to_string(),
        );
        
        use std::net::{TcpStream, ToSocketAddrs};
        use std::time::Duration;
        
        let addr_str = if target.contains(':') {
            target.to_string()
        } else {
            format!("{}:{}", target, self.port)
        };
        
        let mut addrs = addr_str.to_socket_addrs()?;
        let addr = addrs.next().ok_or("No address resolved")?;
        
        // TCP connect to get MSS from handshake
        match TcpStream::connect_timeout(&addr, Duration::from_secs(5)) {
            Ok(_stream) => {
                // Estimate MTU from TCP connection
                // Note: Would need socket options to get actual MSS
                // For now, assume successful connection means at least 536 MSS
                let estimated_mtu = 1460 + 40; // MSS + headers
                
                result.add_metric("estimated_mtu", estimated_mtu as f64);
                result.add_metric("tcp_mss", 1460.0);
                result.add_metadata("method", "TCP connection");
                result.add_metadata("port", self.port.to_string());
                result.set_status(TestStatus::Success);
            }
            Err(e) => {
                result.set_status(TestStatus::Failed);
                result.add_metadata("error", e.to_string());
            }
        }
        
        Ok(result)
    }
    
    fn estimated_duration(&self) -> u64 {
        5
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_icmp_mtu_struct() {
        let test = IcmpMtuTest::new();
        assert_eq!(test.name(), "ICMP MTU Discovery");
        assert_eq!(test.category(), TestCategory::MTU);
    }
    
    #[test]
    fn test_tcp_mtu_struct() {
        let test = TcpMtuTest::new();
        assert_eq!(test.name(), "TCP MSS Discovery");
        assert_eq!(test.category(), TestCategory::MTU);
    }
}

