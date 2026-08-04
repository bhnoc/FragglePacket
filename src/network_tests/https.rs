//! HTTPS Testing Module - Stage-by-stage analysis
//! 
//! Solves: "Can ping but can't browse" (MTU blackhole detection)
//! 
//! Stages:
//! 1. DNS Resolution
//! 2. TCP Connect to :443
//! 3. TLS Handshake (CRITICAL - timeout indicates MTU blackhole)
//! 4. HTTP GET Request
//! 5. Response & Time to First Byte (TTFB)

use crate::framework::{NetworkTest, TestCategory, TestResult, TestStatus, Diagnosis, DiagnosisSeverity};
use std::time::{Duration, Instant};
use std::net::{TcpStream, ToSocketAddrs};
use std::io::{Write, Read};
use serde::{Deserialize, Serialize};
use std::error::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpsTestResult {
    pub target: String,
    pub dns_time_ms: Option<u64>,
    pub dns_ips: Vec<String>,
    pub tcp_connect_time_ms: Option<u64>,
    pub tcp_success: bool,
    pub tls_handshake_time_ms: Option<u64>,
    pub tls_success: bool,
    pub http_request_time_ms: Option<u64>,
    pub http_response_time_ms: Option<u64>,
    pub ttfb_ms: Option<u64>,
    pub status_code: Option<u16>,
    pub total_time_ms: u64,
    pub diagnosis: HttpsDiagnosis,
    pub cert_chain: Vec<CertInfo>,
    pub negotiated_alpn: Option<String>,
}

/// Summary of a single certificate in the peer chain.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CertInfo {
    pub subject: String,
    pub issuer: String,
    pub der_len: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum HttpsDiagnosis {
    Success,
    DnsFailure,
    TcpConnectFailed,
    TlsTimeout,  // MTU blackhole indicator
    TlsHandshakeFailed,
    HttpRequestFailed,
    HttpResponseTimeout,
    MtuBlackhole,  // Confirmed MTU blackhole
}

impl HttpsTestResult {
    pub fn new(target: String) -> Self {
        Self {
            target,
            dns_time_ms: None,
            dns_ips: Vec::new(),
            tcp_connect_time_ms: None,
            tcp_success: false,
            tls_handshake_time_ms: None,
            tls_success: false,
            http_request_time_ms: None,
            http_response_time_ms: None,
            ttfb_ms: None,
            status_code: None,
            total_time_ms: 0,
            diagnosis: HttpsDiagnosis::Success,
            cert_chain: Vec::new(),
            negotiated_alpn: None,
        }
    }
}

/// Test HTTPS connectivity with stage-by-stage breakdown
pub fn test_https_stages(target: &str, timeout_secs: u64) -> HttpsTestResult {
    let start_time = Instant::now();
    let mut result = HttpsTestResult::new(target.to_string());
    
    // Stage 1: DNS Resolution
    let dns_start = Instant::now();
    let addr = match resolve_dns(target) {
        Ok((ips, resolved_addr)) => {
            result.dns_time_ms = Some(dns_start.elapsed().as_millis() as u64);
            result.dns_ips = ips;
            resolved_addr
        }
        Err(_) => {
            result.diagnosis = HttpsDiagnosis::DnsFailure;
            result.total_time_ms = start_time.elapsed().as_millis() as u64;
            return result;
        }
    };
    
    // Stage 2: TCP Connect
    let tcp_start = Instant::now();
    let stream = match TcpStream::connect_timeout(&addr, Duration::from_secs(timeout_secs)) {
        Ok(s) => {
            result.tcp_connect_time_ms = Some(tcp_start.elapsed().as_millis() as u64);
            result.tcp_success = true;
            s
        }
        Err(_) => {
            result.diagnosis = HttpsDiagnosis::TcpConnectFailed;
            result.total_time_ms = start_time.elapsed().as_millis() as u64;
            return result;
        }
    };
    
    // Stage 3: TLS Handshake (CRITICAL for MTU blackhole detection)
    let _tls_start = Instant::now();
    match perform_tls_handshake(stream, target, timeout_secs) {
        Ok((mut tls_stream, handshake_time)) => {
            result.tls_handshake_time_ms = Some(handshake_time);
            result.tls_success = true;

            if let Ok(Some(cert)) = tls_stream.peer_certificate() {
                if let Ok(der) = cert.to_der() {
                    let info = CertInfo {
                        subject: String::new(),
                        issuer: String::new(),
                        der_len: der.len(),
                    };
                    result.cert_chain.push(info);
                }
            }
            
            // Stage 4: HTTP Request
            let http_start = Instant::now();
            if let Err(_) = send_http_get(&mut tls_stream, target) {
                result.diagnosis = HttpsDiagnosis::HttpRequestFailed;
                result.total_time_ms = start_time.elapsed().as_millis() as u64;
                return result;
            }
            result.http_request_time_ms = Some(http_start.elapsed().as_millis() as u64);
            
            // Stage 5: HTTP Response & TTFB
            let response_start = Instant::now();
            match read_http_response(&mut tls_stream, timeout_secs) {
                Ok((status, ttfb)) => {
                    result.http_response_time_ms = Some(response_start.elapsed().as_millis() as u64);
                    result.ttfb_ms = Some(ttfb);
                    result.status_code = Some(status);
                    result.diagnosis = HttpsDiagnosis::Success;
                }
                Err(_) => {
                    result.diagnosis = HttpsDiagnosis::HttpResponseTimeout;
                }
            }
        }
        Err(TlsError::Timeout) => {
            // TCP connected but TLS timed out = MTU blackhole
            result.diagnosis = HttpsDiagnosis::TlsTimeout;
        }
        Err(_) => {
            result.diagnosis = HttpsDiagnosis::TlsHandshakeFailed;
        }
    }
    
    result.total_time_ms = start_time.elapsed().as_millis() as u64;
    result
}

#[derive(Debug)]
enum TlsError {
    Timeout,
    HandshakeFailed,
    IoError,
}

fn resolve_dns(target: &str) -> Result<(Vec<String>, std::net::SocketAddr), String> {
    let addr_str = if target.contains(':') {
        target.to_string()
    } else {
        format!("{}:443", target)
    };
    
    match addr_str.to_socket_addrs() {
        Ok(mut addrs) => {
            let ips: Vec<String> = addrs.clone().map(|a| a.ip().to_string()).collect();
            if let Some(addr) = addrs.next() {
                Ok((ips, addr))
            } else {
                Err("No addresses resolved".to_string())
            }
        }
        Err(e) => Err(format!("DNS resolution failed: {}", e)),
    }
}

fn perform_tls_handshake(
    stream: TcpStream,
    hostname: &str,
    timeout_secs: u64,
) -> Result<(native_tls::TlsStream<TcpStream>, u64), TlsError> {
    let start = Instant::now();
    
    // Set socket timeout for TLS handshake
    stream.set_read_timeout(Some(Duration::from_secs(timeout_secs)))
        .map_err(|_| TlsError::IoError)?;
    stream.set_write_timeout(Some(Duration::from_secs(timeout_secs)))
        .map_err(|_| TlsError::IoError)?;
    
    // Use native-tls for TLS handshake
    let connector = native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)  // For testing
        .build()
        .map_err(|_| TlsError::HandshakeFailed)?;
    
    match connector.connect(hostname, stream) {
        Ok(tls_stream) => {
            let elapsed = start.elapsed().as_millis() as u64;
            Ok((tls_stream, elapsed))
        }
        Err(e) => {
            if e.to_string().contains("timed out") || e.to_string().contains("timeout") {
                Err(TlsError::Timeout)
            } else {
                Err(TlsError::HandshakeFailed)
            }
        }
    }
}

fn send_http_get(stream: &mut native_tls::TlsStream<TcpStream>, hostname: &str) -> std::io::Result<()> {
    let request = format!(
        "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: NetworkTroubleshooter/0.2\r\nConnection: close\r\n\r\n",
        hostname
    );
    stream.write_all(request.as_bytes())?;
    stream.flush()?;
    Ok(())
}

fn read_http_response(
    stream: &mut native_tls::TlsStream<TcpStream>,
    _timeout_secs: u64,
) -> Result<(u16, u64), String> {
    let start = Instant::now();
    let mut buffer = vec![0u8; 4096];
    
    // Read first chunk to get status code and TTFB
    match stream.read(&mut buffer) {
        Ok(n) if n > 0 => {
            let ttfb = start.elapsed().as_millis() as u64;
            let response = String::from_utf8_lossy(&buffer[..n]);
            
            // Parse status code
            let status = response.lines()
                .next()
                .and_then(|line| {
                    line.split_whitespace()
                        .nth(1)
                        .and_then(|code| code.parse::<u16>().ok())
                })
                .unwrap_or(0);
            
            Ok((status, ttfb))
        }
        Ok(_) => Err("Empty response".to_string()),
        Err(e) => Err(format!("Read error: {}", e)),
    }
}

/// Diagnose MTU blackhole by correlating HTTPS results with MTU tests
pub fn diagnose_mtu_blackhole(
    https_result: &HttpsTestResult,
    interface_mtu: Option<usize>,
) -> bool {
    // MTU blackhole signature:
    // 1. TCP connects successfully
    // 2. TLS handshake times out
    // 3. Interface MTU is 1500 (standard)
    
    if https_result.tcp_success 
        && https_result.diagnosis == HttpsDiagnosis::TlsTimeout
        && interface_mtu.unwrap_or(0) >= 1500 {
        return true;
    }
    
    false
}

/// NetworkTest implementation for HTTPS testing
pub struct HttpsTest {
    timeout_secs: u64,
}

impl HttpsTest {
    pub fn new() -> Self {
        Self { timeout_secs: 10 }
    }
    
    pub fn with_timeout(timeout_secs: u64) -> Self {
        Self { timeout_secs }
    }
}

impl Default for HttpsTest {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkTest for HttpsTest {
    fn name(&self) -> &str {
        "HTTPS Stage-by-Stage"
    }
    
    fn category(&self) -> TestCategory {
        TestCategory::HTTPS
    }
    
    fn run(&self, target: &str) -> Result<TestResult, Box<dyn Error>> {
        let https_result = test_https_stages(target, self.timeout_secs);
        let mut result = TestResult::new(
            self.name().to_string(),
            self.category(),
            target.to_string(),
        );

        // Add CLI equivalent commands for transparency
        result.add_metadata("cli_command", format!("curl -w 'DNS: %{{time_namelookup}}s\\nTCP: %{{time_connect}}s\\nTLS: %{{time_appconnect}}s\\nTTFB: %{{time_starttransfer}}s\\nTotal: %{{time_total}}s\\n' -so /dev/null https://{}", target));
        result.add_metadata("cli_simple", format!("curl -Iv https://{}", target));
        result.add_metadata("cli_openssl", format!("openssl s_client -connect {}:443 -servername {}", target, target));

        // Add metrics
        if let Some(dns_time) = https_result.dns_time_ms {
            result.add_metric("dns_time_ms", dns_time as f64);
        }
        if let Some(tcp_time) = https_result.tcp_connect_time_ms {
            result.add_metric("tcp_connect_time_ms", tcp_time as f64);
        }
        if let Some(tls_time) = https_result.tls_handshake_time_ms {
            result.add_metric("tls_handshake_time_ms", tls_time as f64);
        }
        if let Some(ttfb) = https_result.ttfb_ms {
            result.add_metric("ttfb_ms", ttfb as f64);
        }
        result.add_metric("total_time_ms", https_result.total_time_ms as f64);
        
        // Add metadata
        result.add_metadata("dns_ips", https_result.dns_ips.join(", "));
        result.add_metadata("tcp_success", https_result.tcp_success.to_string());
        result.add_metadata("tls_success", https_result.tls_success.to_string());
        if let Some(status) = https_result.status_code {
            result.add_metadata("http_status", status.to_string());
        }
        
        // Set status and diagnoses
        match https_result.diagnosis {
            HttpsDiagnosis::Success => {
                result.set_status(TestStatus::Success);
            }
            HttpsDiagnosis::DnsFailure => {
                result.set_status(TestStatus::Failed);
                result.add_diagnosis(Diagnosis::new(
                    DiagnosisSeverity::Error,
                    "DNS Resolution Failed".to_string(),
                    format!("Unable to resolve hostname: {}", target),
                ).with_recommendation("Check DNS configuration")
                 .with_recommendation("Verify target hostname is correct"));
            }
            HttpsDiagnosis::TcpConnectFailed => {
                result.set_status(TestStatus::Failed);
                result.add_diagnosis(Diagnosis::new(
                    DiagnosisSeverity::Error,
                    "TCP Connection Failed".to_string(),
                    "Unable to establish TCP connection to port 443".to_string(),
                ).with_recommendation("Check if target is reachable")
                 .with_recommendation("Verify firewall rules allow port 443"));
            }
            HttpsDiagnosis::TlsTimeout => {
                result.set_status(TestStatus::Warning);
                let mut diag = Diagnosis::new(
                    DiagnosisSeverity::Critical,
                    "MTU Blackhole Detected".to_string(),
                    "TCP connection succeeded but TLS handshake timed out. This is a classic MTU blackhole signature.".to_string(),
                );
                diag = diag.with_recommendation("Lower interface MTU to 1400: ip link set dev eth0 mtu 1400")
                    .with_recommendation("Or enable TCP MSS clamping: iptables -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu")
                    .with_recommendation("Check if ICMP fragmentation needed messages are being blocked")
                    .with_related_test("MTU Tests");
                result.add_diagnosis(diag);
            }
            HttpsDiagnosis::TlsHandshakeFailed => {
                result.set_status(TestStatus::Failed);
                result.add_diagnosis(Diagnosis::new(
                    DiagnosisSeverity::Error,
                    "TLS Handshake Failed".to_string(),
                    "TLS/SSL handshake failed (not a timeout)".to_string(),
                ).with_recommendation("Check certificate validity")
                 .with_recommendation("Verify TLS version compatibility"));
            }
            HttpsDiagnosis::HttpRequestFailed => {
                result.set_status(TestStatus::Warning);
                result.add_diagnosis(Diagnosis::new(
                    DiagnosisSeverity::Warning,
                    "HTTP Request Failed".to_string(),
                    "TLS succeeded but HTTP request failed".to_string(),
                ));
            }
            HttpsDiagnosis::HttpResponseTimeout => {
                result.set_status(TestStatus::Warning);
                result.add_diagnosis(Diagnosis::new(
                    DiagnosisSeverity::Warning,
                    "HTTP Response Timeout".to_string(),
                    "Request sent but no response received".to_string(),
                ));
            }
            HttpsDiagnosis::MtuBlackhole => {
                result.set_status(TestStatus::Warning);
                result.add_diagnosis(Diagnosis::new(
                    DiagnosisSeverity::Critical,
                    "Confirmed MTU Blackhole".to_string(),
                    "MTU blackhole confirmed through correlation with MTU tests".to_string(),
                ).with_recommendation("Lower interface MTU immediately"));
            }
        }
        
        Ok(result)
    }
    
    fn estimated_duration(&self) -> u64 {
        self.timeout_secs + 5
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_dns_resolution() {
        let result = resolve_dns("google.com");
        assert!(result.is_ok());
        let (ips, _) = result.unwrap();
        assert!(!ips.is_empty());
    }
    
    #[test]
    fn test_https_stages_google() {
        let result = test_https_stages("google.com", 10);
        assert!(result.dns_time_ms.is_some());
        assert!(!result.dns_ips.is_empty());
        // TCP should succeed for google.com
        assert!(result.tcp_success);
    }
    
    #[test]
    fn test_mtu_blackhole_detection() {
        let mut result = HttpsTestResult::new("test.com".to_string());
        result.tcp_success = true;
        result.diagnosis = HttpsDiagnosis::TlsTimeout;
        
        assert!(diagnose_mtu_blackhole(&result, Some(1500)));
        assert!(!diagnose_mtu_blackhole(&result, Some(1400)));
    }
    
    #[test]
    fn test_https_network_test_trait() {
        let test = HttpsTest::new();
        assert_eq!(test.name(), "HTTPS Stage-by-Stage");
        assert_eq!(test.category(), TestCategory::HTTPS);
    }
}

