//! IPv6 Connectivity Testing

use crate::framework::{NetworkTest, TestCategory, TestResult, TestStatus, Diagnosis, DiagnosisSeverity};
use std::error::Error;
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;
use std::process::Command;

/// IPv6 reachability and comparison
pub struct Ipv6Test {
    timeout_secs: u64,
}

impl Ipv6Test {
    pub fn new() -> Self {
        Self { timeout_secs: 5 }
    }
}

impl Default for Ipv6Test {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkTest for Ipv6Test {
    fn name(&self) -> &str {
        "IPv6 Connectivity"
    }
    
    fn category(&self) -> TestCategory {
        TestCategory::IPv6
    }
    
    fn run(&self, target: &str) -> Result<TestResult, Box<dyn Error>> {
        let mut result = TestResult::new(
            self.name().to_string(),
            self.category(),
            target.to_string(),
        );
        
        // Test DNS resolution for both IPv4 and IPv6
        let (ipv4_addrs, ipv6_addrs) = resolve_both(&format!("{}:80", target))?;
        
        result.add_metric("ipv4_count", ipv4_addrs.len() as f64);
        result.add_metric("ipv6_count", ipv6_addrs.len() as f64);
        
        if !ipv4_addrs.is_empty() {
            result.add_metadata("ipv4_addrs", ipv4_addrs.join(", "));
        }
        if !ipv6_addrs.is_empty() {
            result.add_metadata("ipv6_addrs", ipv6_addrs.join(", "));
        }
        
        // Test IPv6 connectivity
        let ipv6_reachable = if let Some(ipv6_addr) = ipv6_addrs.first() {
            test_connectivity(ipv6_addr, self.timeout_secs)
        } else {
            false
        };
        
        let ipv4_reachable = if let Some(ipv4_addr) = ipv4_addrs.first() {
            test_connectivity(ipv4_addr, self.timeout_secs)
        } else {
            false
        };
        
        result.add_metadata("ipv6_reachable", ipv6_reachable.to_string());
        result.add_metadata("ipv4_reachable", ipv4_reachable.to_string());
        
        // Dual-stack behavior analysis
        let dual_stack = ipv6_reachable && ipv4_reachable;
        result.add_metadata("dual_stack", dual_stack.to_string());
        
        if dual_stack {
            result.add_diagnosis(Diagnosis::new(
                DiagnosisSeverity::Info,
                "Dual-Stack Available".to_string(),
                "Target supports both IPv4 and IPv6".to_string(),
            ).with_recommendation("Consider preferring IPv6 for future-proofing"));
        }
        
        // IPv6 MTU discovery
        if ipv6_reachable {
            if let Some(ipv6_addr) = ipv6_addrs.first() {
                if let Some(mtu) = discover_ipv6_mtu(ipv6_addr) {
                    result.add_metric("ipv6_mtu", mtu as f64);
                    
                    if mtu < 1280 {
                        result.add_diagnosis(Diagnosis::new(
                            DiagnosisSeverity::Error,
                            "IPv6 MTU Too Small".to_string(),
                            format!("IPv6 MTU is {} (minimum should be 1280)", mtu),
                        ).with_recommendation("Check IPv6 tunnel configuration")
                         .with_recommendation("Verify path MTU is not being restricted"));
                    } else if mtu < 1500 {
                        result.add_diagnosis(Diagnosis::new(
                            DiagnosisSeverity::Warning,
                            "Reduced IPv6 MTU".to_string(),
                            format!("IPv6 MTU is {} (standard is 1500)", mtu),
                        ));
                    }
                }
            }
        }
        
        // Compare latency if both available
        if ipv6_reachable && ipv4_reachable {
            if let (Some(ipv6_rtt), Some(ipv4_rtt)) = (
                measure_rtt(ipv6_addrs.first().unwrap()),
                measure_rtt(ipv4_addrs.first().unwrap())
            ) {
                result.add_metric("ipv6_rtt_ms", ipv6_rtt);
                result.add_metric("ipv4_rtt_ms", ipv4_rtt);
                result.add_metric("rtt_diff_ms", (ipv6_rtt - ipv4_rtt).abs());
                
                if (ipv6_rtt - ipv4_rtt).abs() > 50.0 {
                    result.add_diagnosis(Diagnosis::new(
                        DiagnosisSeverity::Info,
                        "Significant Latency Difference".to_string(),
                        format!("IPv6: {:.1}ms, IPv4: {:.1}ms", ipv6_rtt, ipv4_rtt),
                    ));
                }
            }
        }
        
        // Status and diagnoses
        if ipv6_addrs.is_empty() {
            result.set_status(TestStatus::Warning);
            result.add_diagnosis(Diagnosis::new(
                DiagnosisSeverity::Warning,
                "No IPv6 Addresses".to_string(),
                "Target does not have AAAA records".to_string(),
            ).with_recommendation("Target may not support IPv6"));
        } else if !ipv6_reachable {
            result.set_status(TestStatus::Failed);
            result.add_diagnosis(Diagnosis::new(
                DiagnosisSeverity::Error,
                "IPv6 Not Reachable".to_string(),
                "Target has IPv6 addresses but is not reachable".to_string(),
            ).with_recommendation("Check local IPv6 connectivity")
             .with_recommendation("Verify firewall allows IPv6"));
        } else {
            result.set_status(TestStatus::Success);
            result.add_metadata("verdict", "IPv6 connectivity working");
        }
        
        Ok(result)
    }
    
    fn estimated_duration(&self) -> u64 {
        self.timeout_secs * 3
    }
}

fn resolve_both(target: &str) -> Result<(Vec<String>, Vec<String>), Box<dyn Error>> {
    let addrs: Vec<_> = target.to_socket_addrs()?.collect();
    
    let ipv4: Vec<String> = addrs.iter()
        .filter(|a| a.is_ipv4())
        .map(|a| a.ip().to_string())
        .collect();
    
    let ipv6: Vec<String> = addrs.iter()
        .filter(|a| a.is_ipv6())
        .map(|a| a.ip().to_string())
        .collect();
    
    Ok((ipv4, ipv6))
}

fn test_connectivity(addr: &str, timeout_secs: u64) -> bool {
    // Try TCP connect
    if let Ok(mut addrs) = format!("{}:80", addr).to_socket_addrs() {
        if let Some(socket_addr) = addrs.next() {
            return TcpStream::connect_timeout(&socket_addr, Duration::from_secs(timeout_secs)).is_ok();
        }
    }
    false
}

fn measure_rtt(addr: &str) -> Option<f64> {
    // Use ping to measure RTT
    let output = Command::new("ping")
        .arg("-c")
        .arg("3")
        .arg("-W")
        .arg("2")
        .arg(addr)
        .output()
        .ok()?;
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    
    // Parse average RTT from ping output
    for line in stdout.lines() {
        if line.contains("rtt") || line.contains("round-trip") {
            // Format: "rtt min/avg/max/mdev = 1.2/3.4/5.6/7.8 ms"
            if let Some(stats) = line.split('=').nth(1) {
                let nums: Vec<&str> = stats.trim().split('/').collect();
                if nums.len() >= 2 {
                    return nums[1].trim().parse().ok();
                }
            }
        }
    }
    
    None
}

fn discover_ipv6_mtu(addr: &str) -> Option<usize> {
    // Use ping6 with Don't Fragment to discover MTU
    // Start at 1500 and binary search down
    let test_sizes = vec![1500, 1280, 1400, 1450, 1480];
    
    for &size in &test_sizes {
        let output = Command::new("ping6")
            .arg("-c")
            .arg("1")
            .arg("-W")
            .arg("2")
            .arg("-M")
            .arg("do")  // Don't fragment
            .arg("-s")
            .arg((size - 48).to_string())  // Account for IPv6 + ICMP headers
            .arg(addr)
            .output();
        
        if let Ok(output) = output {
            if output.status.success() {
                return Some(size);
            }
        }
    }
    
    // Minimum IPv6 MTU
    Some(1280)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_ipv6_struct() {
        let test = Ipv6Test::new();
        assert_eq!(test.name(), "IPv6 Connectivity");
        assert_eq!(test.category(), TestCategory::IPv6);
    }
    
    #[test]
    fn test_resolve_both() {
        // Test with localhost
        let result = resolve_both("localhost:80");
        assert!(result.is_ok());
    }
}

