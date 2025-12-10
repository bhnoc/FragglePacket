//! TCP Health Tests - Comprehensive TCP connection analysis

use crate::framework::test_trait::{NetworkTest, TestCategory};
use crate::framework::result::{TestResult, TestStatus, Diagnosis, DiagnosisSeverity};
use std::error::Error;
use std::net::{TcpStream, SocketAddr};
use std::time::{Duration, Instant};
use std::io::{Read, Write};

pub struct TcpHealthTest {
    timeout_ms: u64,
    test_ports: Vec<u16>,
}

impl TcpHealthTest {
    pub fn new() -> Self {
        Self {
            timeout_ms: 5000,
            test_ports: vec![80, 443, 22, 21, 25, 110, 143, 993, 995, 3306, 5432, 6379],
        }
    }
    
    pub fn with_ports(mut self, ports: Vec<u16>) -> Self {
        self.test_ports = ports;
        self
    }
}

impl Default for TcpHealthTest {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkTest for TcpHealthTest {
    fn name(&self) -> &str {
        "TCP Health Analysis"
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
        
        // Test TCP handshake timing on port 80/443
        let handshake_result = test_tcp_handshake_timing(target, 443, self.timeout_ms);
        
        match handshake_result {
            Ok((connect_time, rtt)) => {
                result.add_metric("handshake_ms", connect_time as f64);
                result.add_metric("rtt_estimate_ms", rtt as f64);
                result.add_metadata("handshake_status", "success".to_string());
                
                if connect_time > 3000 {
                    result.add_diagnosis(Diagnosis::new(
                        DiagnosisSeverity::Warning,
                        "Slow TCP Handshake".to_string(),
                        format!("Handshake took {}ms (>3000ms)", connect_time),
                    ).with_recommendation("Check network latency and routing"));
                }
            }
            Err(e) => {
                result.add_metadata("handshake_status", format!("failed: {}", e));
                result.add_diagnosis(Diagnosis::new(
                    DiagnosisSeverity::Error,
                    "TCP Handshake Failed".to_string(),
                    format!("Unable to establish connection: {}", e),
                ).with_recommendation("Check if target is reachable")
                 .with_recommendation("Verify firewall rules"));
            }
        }
        
        // Port connectivity matrix
        let mut open_ports = Vec::new();
        let mut closed_ports = Vec::new();
        let mut filtered_ports = Vec::new();
        
        for &port in &self.test_ports {
            match test_port_connectivity(target, port, 2000) {
                PortStatus::Open => open_ports.push(port),
                PortStatus::Closed => closed_ports.push(port),
                PortStatus::Filtered => filtered_ports.push(port),
            }
        }
        
        result.add_metric("open_ports_count", open_ports.len() as f64);
        result.add_metric("closed_ports_count", closed_ports.len() as f64);
        result.add_metric("filtered_ports_count", filtered_ports.len() as f64);
        
        if !open_ports.is_empty() {
            result.add_metadata("open_ports", format!("{:?}", open_ports));
        }
        if !filtered_ports.is_empty() {
            result.add_metadata("filtered_ports", format!("{:?}", filtered_ports));
            result.add_diagnosis(Diagnosis::new(
                DiagnosisSeverity::Info,
                "Firewall Detected".to_string(),
                format!("{} ports appear filtered", filtered_ports.len()),
            ));
        }
        
        // Window size analysis (if connection successful)
        if let Ok(window_size) = test_window_size(target, 443) {
            result.add_metric("tcp_window_size", window_size as f64);
            
            if window_size < 8192 {
                result.add_diagnosis(Diagnosis::new(
                    DiagnosisSeverity::Warning,
                    "Small TCP Window".to_string(),
                    format!("Window size {}B may limit throughput", window_size),
                ).with_recommendation("Check TCP tuning parameters"));
            }
        }
        
        // Bandwidth estimation (simple probe)
        if let Ok(bandwidth_mbps) = estimate_bandwidth(target, 443, 1000) {
            result.add_metric("estimated_bandwidth_mbps", bandwidth_mbps);
            
            if bandwidth_mbps < 1.0 {
                result.add_diagnosis(Diagnosis::new(
                    DiagnosisSeverity::Warning,
                    "Low Bandwidth Detected".to_string(),
                    format!("Estimated {:.2} Mbps", bandwidth_mbps),
                ));
            }
        }
        
        // Overall status
        if result.diagnoses.iter().any(|d| matches!(d.severity, DiagnosisSeverity::Error | DiagnosisSeverity::Critical)) {
            result.set_status(TestStatus::Failed);
        } else if !result.diagnoses.is_empty() {
            result.set_status(TestStatus::Warning);
        } else {
            result.set_status(TestStatus::Success);
        }
        
        Ok(result)
    }
    
    fn estimated_duration(&self) -> u64 {
        // Port scan + handshake tests
        (self.test_ports.len() as u64 * 2) + 5
    }
}

#[derive(Debug, Clone, PartialEq)]
enum PortStatus {
    Open,
    Closed,
    Filtered,
}

fn test_tcp_handshake_timing(target: &str, port: u16, timeout_ms: u64) -> Result<(u128, u128), Box<dyn Error>> {
    let addr: SocketAddr = format!("{}:{}", target, port).parse()?;
    let timeout = Duration::from_millis(timeout_ms);
    
    let start = Instant::now();
    let stream = TcpStream::connect_timeout(&addr, timeout)?;
    let connect_time = start.elapsed().as_millis();
    
    // Estimate RTT (half of connect time as rough approximation)
    let rtt_estimate = connect_time / 2;
    
    drop(stream);
    Ok((connect_time, rtt_estimate))
}

fn test_port_connectivity(target: &str, port: u16, timeout_ms: u64) -> PortStatus {
    let addr_str = format!("{}:{}", target, port);
    
    if let Ok(addr) = addr_str.parse::<SocketAddr>() {
        let timeout = Duration::from_millis(timeout_ms);
        
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(_) => PortStatus::Open,
            Err(e) => {
                // Differentiate between refused (closed) and timeout (filtered)
                if e.kind() == std::io::ErrorKind::ConnectionRefused {
                    PortStatus::Closed
                } else {
                    PortStatus::Filtered
                }
            }
        }
    } else {
        PortStatus::Filtered
    }
}

fn test_window_size(target: &str, port: u16) -> Result<usize, Box<dyn Error>> {
    let addr: SocketAddr = format!("{}:{}", target, port).parse()?;
    let timeout = Duration::from_secs(2);
    
    let stream = TcpStream::connect_timeout(&addr, timeout)?;
    
    // Try to get TCP info (platform-specific)
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        use libc::{getsockopt, socklen_t, c_void, SOL_SOCKET, SO_RCVBUF};
        
        let fd = stream.as_raw_fd();
        let mut window_size: i32 = 0;
        let mut len: socklen_t = std::mem::size_of::<i32>() as socklen_t;
        
        unsafe {
            let ret = getsockopt(
                fd,
                SOL_SOCKET,
                SO_RCVBUF,
                &mut window_size as *mut i32 as *mut c_void,
                &mut len as *mut socklen_t,
            );
            
            if ret == 0 {
                return Ok(window_size as usize);
            }
        }
    }
    
    // Default/fallback
    Ok(65535)
}

fn estimate_bandwidth(target: &str, port: u16, probe_size_kb: usize) -> Result<f64, Box<dyn Error>> {
    let addr: SocketAddr = format!("{}:{}", target, port).parse()?;
    let timeout = Duration::from_secs(5);
    
    let mut stream = TcpStream::connect_timeout(&addr, timeout)?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
    
    // Send HTTP GET request and measure response time
    let request = format!("GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", target);
    
    let start = Instant::now();
    stream.write_all(request.as_bytes())?;
    
    let mut buffer = vec![0u8; probe_size_kb * 1024];
    let mut total_bytes = 0;
    
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => total_bytes += n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => break,
            Err(_) => break,
        }
        
        // Limit read time
        if start.elapsed() > Duration::from_secs(3) {
            break;
        }
    }
    
    let elapsed_secs = start.elapsed().as_secs_f64();
    
    if elapsed_secs > 0.0 && total_bytes > 0 {
        let bits = (total_bytes * 8) as f64;
        let mbps = (bits / elapsed_secs) / 1_000_000.0;
        Ok(mbps)
    } else {
        Ok(0.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_tcp_health_struct() {
        let test = TcpHealthTest::new();
        assert_eq!(test.name(), "TCP Health Analysis");
        assert_eq!(test.category(), TestCategory::TCPHealth);
    }
    
    #[test]
    fn test_port_status() {
        // Test localhost ports
        let status = test_port_connectivity("127.0.0.1", 65535, 100);
        assert!(matches!(status, PortStatus::Closed | PortStatus::Filtered));
    }
}


