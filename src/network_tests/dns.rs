//! DNS Resolution Testing

use crate::framework::{NetworkTest, TestCategory, TestResult, TestStatus, Diagnosis, DiagnosisSeverity};
use std::error::Error;
use std::net::ToSocketAddrs;
use std::time::Instant;

fn resolve_both(addr_str: &str) -> Result<(Vec<String>, Vec<String>), String> {
    let addrs: Vec<_> = addr_str.to_socket_addrs()
        .map_err(|e| e.to_string())?
        .collect();
    
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

fn reverse_dns_lookup(ip: &str) -> Result<String, Box<dyn std::error::Error>> {
    use std::process::Command;
    
    let output = Command::new("host")
        .arg(ip)
        .output()?;
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    
    for line in stdout.lines() {
        if line.contains("domain name pointer") {
            if let Some(name) = line.split("pointer").nth(1) {
                return Ok(name.trim().trim_end_matches('.').to_string());
            }
        }
    }
    
    Err("No reverse DNS record".into())
}

fn compare_dns_servers(target: &str, servers: &[String]) -> Vec<(String, f64)> {
    use std::process::Command;
    use std::time::Instant;
    
    let mut results = Vec::new();
    
    for server in servers {
        let start = Instant::now();
        
        // Use dig or host to query specific DNS server
        let output = Command::new("dig")
            .arg(&format!("@{}", server))
            .arg("+short")
            .arg("+time=2")
            .arg(target)
            .output();
        
        let elapsed_ms = start.elapsed().as_millis() as f64;
        
        if let Ok(output) = output {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                // If we got any output, DNS worked
                if !stdout.trim().is_empty() {
                    results.push((server.clone(), elapsed_ms));
                }
            }
        }
    }
    
    results
}

/// DNS resolution timing and testing
pub struct DnsTest {
    timeout_secs: u64,
    test_servers: Vec<String>,
}

impl DnsTest {
    pub fn new() -> Self {
        Self { 
            timeout_secs: 5,
            test_servers: vec![
                "1.1.1.1".to_string(),      // Cloudflare
                "8.8.8.8".to_string(),      // Google
                "9.9.9.9".to_string(),      // Quad9
            ],
        }
    }
    
    pub fn with_servers(mut self, servers: Vec<String>) -> Self {
        self.test_servers = servers;
        self
    }
}

impl Default for DnsTest {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkTest for DnsTest {
    fn name(&self) -> &str {
        "DNS Resolution"
    }
    
    fn category(&self) -> TestCategory {
        TestCategory::DNS
    }
    
    fn run(&self, target: &str) -> Result<TestResult, Box<dyn Error>> {
        let mut result = TestResult::new(
            self.name().to_string(),
            self.category(),
            target.to_string(),
        );
        
        // Test IPv4 resolution
        let start = Instant::now();
        let addr_str = if target.contains(':') {
            target.to_string()
        } else {
            format!("{}:80", target)
        };
        
        let (ipv4_addrs, ipv6_addrs) = match resolve_both(&addr_str) {
            Ok((v4, v6)) => (v4, v6),
            Err(e) => {
                result.set_status(TestStatus::Failed);
                result.add_metadata("error", e);
                result.add_diagnosis(Diagnosis::new(
                    DiagnosisSeverity::Error,
                    "DNS Resolution Failed".to_string(),
                    format!("Unable to resolve {}", target),
                ).with_recommendation("Check DNS server is reachable")
                 .with_recommendation("Verify hostname is correct")
                 .with_recommendation("Check /etc/resolv.conf"));
                return Ok(result);
            }
        };
        
        let elapsed_ms = start.elapsed().as_millis() as f64;
        
        result.add_metric("resolution_time_ms", elapsed_ms);
        result.add_metric("ipv4_count", ipv4_addrs.len() as f64);
        result.add_metric("ipv6_count", ipv6_addrs.len() as f64);
        
        if !ipv4_addrs.is_empty() {
            result.add_metadata("ipv4_addrs", ipv4_addrs.join(", "));
        }
        if !ipv6_addrs.is_empty() {
            result.add_metadata("ipv6_addrs", ipv6_addrs.join(", "));
        }
        
        // Reverse DNS lookup for first IP
        if let Some(first_ip) = ipv4_addrs.first().or(ipv6_addrs.first()) {
            if let Ok(reverse) = reverse_dns_lookup(first_ip) {
                result.add_metadata("reverse_dns", reverse);
            }
        }
        
        // Compare multiple DNS servers
        let server_results = compare_dns_servers(target, &self.test_servers);
        
        if !server_results.is_empty() {
            // Find fastest server
            if let Some((fastest_server, fastest_time)) = server_results.iter().min_by(|a, b| a.1.partial_cmp(&b.1).unwrap()) {
                result.add_metadata("fastest_dns_server", fastest_server.clone());
                result.add_metric("fastest_dns_ms", *fastest_time);
                
                // Compare with slowest
                if let Some((slowest_server, slowest_time)) = server_results.iter().max_by(|a, b| a.1.partial_cmp(&b.1).unwrap()) {
                    result.add_metadata("slowest_dns_server", slowest_server.clone());
                    result.add_metric("slowest_dns_ms", *slowest_time);
                    
                    let diff = slowest_time - fastest_time;
                    result.add_metric("dns_server_variance_ms", diff);
                    
                    if diff > 500.0 {
                        result.add_diagnosis(Diagnosis::new(
                            DiagnosisSeverity::Warning,
                            "High DNS Server Variance".to_string(),
                            format!("DNS server performance varies by {:.0}ms ({} vs {})", diff, fastest_server, slowest_server),
                        ).with_recommendation(format!("Consider using faster DNS: {}", fastest_server)));
                    }
                }
            }
            
            // Add all server timings
            for (server, time) in &server_results {
                result.add_metric(&format!("dns_{}_ms", server.replace(".", "_")), *time);
            }
        }
        
        // Compare IPv4 vs IPv6 availability
        if ipv4_addrs.is_empty() && !ipv6_addrs.is_empty() {
            result.add_diagnosis(Diagnosis::new(
                DiagnosisSeverity::Info,
                "IPv6-Only Host".to_string(),
                "Target has only IPv6 addresses".to_string(),
            ).with_related_test("IPv6"));
        } else if !ipv4_addrs.is_empty() && ipv6_addrs.is_empty() {
            result.add_diagnosis(Diagnosis::new(
                DiagnosisSeverity::Info,
                "IPv4-Only Host".to_string(),
                "Target has only IPv4 addresses (no AAAA records)".to_string(),
            ));
        } else if !ipv4_addrs.is_empty() && !ipv6_addrs.is_empty() {
            result.add_diagnosis(Diagnosis::new(
                DiagnosisSeverity::Info,
                "Dual-Stack Host".to_string(),
                "Target supports both IPv4 and IPv6".to_string(),
            ));
        }
        
        match addr_str.to_socket_addrs() {
            Ok(addrs) => {
                let ips: Vec<String> = addrs.map(|a| a.ip().to_string()).collect();
                
                result.add_metric("resolution_time_ms", elapsed_ms);
                result.add_metric("ip_count", ips.len() as f64);
                result.add_metadata("resolved_ips", ips.join(", "));
                
                // Analyze timing
                if elapsed_ms > 1000.0 {
                    result.set_status(TestStatus::Warning);
                    result.add_diagnosis(Diagnosis::new(
                        DiagnosisSeverity::Warning,
                        "Slow DNS Resolution".to_string(),
                        format!("DNS took {:.0}ms (>1000ms)", elapsed_ms),
                    ).with_recommendation("Check DNS server configuration")
                     .with_recommendation("Consider using faster DNS (1.1.1.1, 8.8.8.8)"));
                } else if elapsed_ms > 500.0 {
                    result.set_status(TestStatus::Warning);
                    result.add_diagnosis(Diagnosis::new(
                        DiagnosisSeverity::Info,
                        "Elevated DNS Latency".to_string(),
                        format!("DNS took {:.0}ms", elapsed_ms),
                    ));
                } else {
                    result.set_status(TestStatus::Success);
                }
                
                if ips.is_empty() {
                    result.set_status(TestStatus::Failed);
                    result.add_diagnosis(Diagnosis::new(
                        DiagnosisSeverity::Error,
                        "No IPs Resolved".to_string(),
                        "DNS lookup succeeded but returned no addresses".to_string(),
                    ));
                }
            }
            Err(e) => {
                result.set_status(TestStatus::Failed);
                result.add_metadata("error", e.to_string());
                result.add_diagnosis(Diagnosis::new(
                    DiagnosisSeverity::Error,
                    "DNS Resolution Failed".to_string(),
                    format!("Unable to resolve {}: {}", target, e),
                ).with_recommendation("Check DNS server is reachable")
                 .with_recommendation("Verify hostname is correct")
                 .with_recommendation("Check /etc/resolv.conf"));
            }
        }
        
        Ok(result)
    }
    
    fn estimated_duration(&self) -> u64 {
        self.timeout_secs + 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_dns_struct() {
        let test = DnsTest::new();
        assert_eq!(test.name(), "DNS Resolution");
        assert_eq!(test.category(), TestCategory::DNS);
    }
}

