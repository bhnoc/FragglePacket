//! TCP Segmentation Detection
//! 
//! Detects artificial TCP segment size restrictions (e.g., firewall limiting to 100 bytes)

use crate::framework::{NetworkTest, TestCategory, TestResult, TestStatus, Diagnosis, DiagnosisSeverity};
use std::error::Error;
use std::net::{TcpStream, ToSocketAddrs};
use std::io::{Write, Read};
use std::time::{Duration, Instant};

/// Test different TCP segment sizes to detect artificial limits
pub struct TcpSegmentationTest {
    timeout_secs: u64,
    test_sizes: Vec<usize>,
}

impl TcpSegmentationTest {
    pub fn new() -> Self {
        Self {
            timeout_secs: 5,
            // Test standard MSS values and edge cases
            test_sizes: vec![100, 536, 1024, 1460],
        }
    }
    
    pub fn with_timeout(timeout_secs: u64) -> Self {
        Self { timeout_secs, ..Self::new() }
    }
    
    pub fn with_test_sizes(mut self, sizes: Vec<usize>) -> Self {
        self.test_sizes = sizes;
        self
    }
}

impl Default for TcpSegmentationTest {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkTest for TcpSegmentationTest {
    fn name(&self) -> &str {
        "TCP Segmentation Detection"
    }
    
    fn category(&self) -> TestCategory {
        TestCategory::TCPHealth
    }
    
    fn run(&self, target: &str) -> Result<TestResult, Box<dyn Error>> {
        let mut result = TestResult::new(
            self.name().to_string(),
            self.category(),
            target.to_string(),
        );
        
        // Try to connect to common ports (443 first, then 80)
        let ports = vec![443, 80];
        let mut connected_port = None;
        
        for port in ports {
            let addr_str = if target.contains(':') {
                target.to_string()
            } else {
                format!("{}:{}", target, port)
            };
            
            if let Ok(mut addrs) = addr_str.to_socket_addrs() {
                if let Some(addr) = addrs.next() {
                    if let Ok(_) = TcpStream::connect_timeout(&addr, Duration::from_secs(2)) {
                        connected_port = Some(port);
                        break;
                    }
                }
            }
        }
        
        if connected_port.is_none() {
            result.set_status(TestStatus::Failed);
            result.add_metadata("error", "Could not connect to target (tried ports 443, 80)");
            return Ok(result);
        }
        
        let port = connected_port.unwrap();
        result.add_metadata("port", port.to_string());
        
        // Test each segment size
        let mut successful_sizes = Vec::new();
        let mut failed_sizes = Vec::new();
        let mut timing_data = Vec::new();
        
        for &size in &self.test_sizes {
            match test_tcp_segment_size(target, port, size, self.timeout_secs) {
                Ok(rtt_ms) => {
                    successful_sizes.push(size);
                    timing_data.push(rtt_ms);
                    result.add_metric(&format!("size_{}_rtt_ms", size), rtt_ms);
                }
                Err(_) => {
                    failed_sizes.push(size);
                    result.add_metric(&format!("size_{}_rtt_ms", size), -1.0);
                }
            }
        }
        
        result.add_metadata("successful_sizes", 
            successful_sizes.iter().map(|s| s.to_string()).collect::<Vec<_>>().join(", "));
        result.add_metadata("failed_sizes", 
            failed_sizes.iter().map(|s| s.to_string()).collect::<Vec<_>>().join(", "));
        
        // Analyze results
        if successful_sizes.is_empty() {
            result.set_status(TestStatus::Failed);
            result.add_metadata("reason", "All segment sizes failed");
        } else if !failed_sizes.is_empty() {
            // Some sizes failed - likely artificial limit
            result.set_status(TestStatus::Warning);
            
            // Find the threshold
            let max_successful = *successful_sizes.iter().max().unwrap();
            let min_failed = failed_sizes.iter().min().copied();
            
            result.add_metric("max_successful_size", max_successful as f64);
            if let Some(min_fail) = min_failed {
                result.add_metric("min_failed_size", min_fail as f64);
                
                // Detect artificial limits
                if max_successful < 536 {
                    let mut diag = Diagnosis::new(
                        DiagnosisSeverity::Critical,
                        "Severe TCP Segment Size Restriction Detected".to_string(),
                        format!("TCP segments larger than {} bytes are failing. This indicates a firewall or middlebox is artificially limiting segment sizes.", max_successful),
                    );
                    diag = diag.with_recommendation(format!("Configure TCP MSS clamping to {} bytes", max_successful - 40))
                        .with_recommendation("Investigate firewall rules that may be inspecting/limiting TCP segments")
                        .with_recommendation("Check for deep packet inspection (DPI) devices in path")
                        .with_related_test("MTU Tests");
                    result.add_diagnosis(diag);
                } else if max_successful < 1460 {
                    let mut diag = Diagnosis::new(
                        DiagnosisSeverity::Warning,
                        "TCP Segment Size Restriction Detected".to_string(),
                        format!("TCP segments larger than {} bytes are failing. Normal MSS is 1460 for 1500 MTU.", max_successful),
                    );
                    diag = diag.with_recommendation(format!("Consider TCP MSS clamping to {} bytes", max_successful - 40))
                        .with_recommendation("Check for middleboxes or firewalls in path")
                        .with_related_test("MTU Tests");
                    result.add_diagnosis(diag);
                }
            }
        } else {
            // All sizes succeeded
            result.set_status(TestStatus::Success);
            result.add_metadata("verdict", "No artificial TCP segment size restrictions detected");
        }
        
        Ok(result)
    }
    
    fn estimated_duration(&self) -> u64 {
        (self.test_sizes.len() as u64) * self.timeout_secs + 2
    }
}

/// Test a specific TCP segment size
fn test_tcp_segment_size(target: &str, port: u16, size: usize, timeout_secs: u64) -> Result<f64, Box<dyn Error>> {
    let start = Instant::now();
    
    let addr_str = if target.contains(':') {
        target.to_string()
    } else {
        format!("{}:{}", target, port)
    };
    
    let mut addrs = addr_str.to_socket_addrs()?;
    let addr = addrs.next().ok_or("No address resolved")?;
    
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(timeout_secs))?;
    stream.set_read_timeout(Some(Duration::from_secs(timeout_secs)))?;
    stream.set_write_timeout(Some(Duration::from_secs(timeout_secs)))?;
    
    // Create payload of specified size
    let payload = vec![b'A'; size];
    
    // For port 80 (HTTP)
    if port == 80 {
        let request = format!(
            "POST / HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\n\r\n",
            target, size
        );
        stream.write_all(request.as_bytes())?;
        stream.write_all(&payload)?;
        stream.flush()?;
        
        // Try to read response
        let mut buf = vec![0u8; 1024];
        let _ = stream.read(&mut buf)?;
    }
    // For port 443 (HTTPS) - just send raw data
    else if port == 443 {
        // Send TLS-looking data (won't be valid, but tests segment size)
        stream.write_all(&payload)?;
        stream.flush()?;
        
        // Try to read (will likely fail/timeout, but that's OK)
        let mut buf = vec![0u8; 1024];
        let _ = stream.read(&mut buf);  // Ignore errors
    }
    
    let rtt = start.elapsed().as_millis() as f64;
    Ok(rtt)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_tcp_segmentation_struct() {
        let test = TcpSegmentationTest::new();
        assert_eq!(test.name(), "TCP Segmentation Detection");
        assert_eq!(test.category(), TestCategory::TCPHealth);
        assert_eq!(test.test_sizes, vec![100, 536, 1024, 1460]);
    }
    
    #[test]
    fn test_custom_sizes() {
        let test = TcpSegmentationTest::new().with_test_sizes(vec![200, 400]);
        assert_eq!(test.test_sizes, vec![200, 400]);
    }
}


