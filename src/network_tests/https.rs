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

use std::time::{Duration, Instant};
use std::net::{TcpStream, ToSocketAddrs};
use std::io::{Write, Read};

#[derive(Debug, Clone)]
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
}

#[derive(Debug, Clone, PartialEq)]
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
    let tls_start = Instant::now();
    match perform_tls_handshake(stream, target, timeout_secs) {
        Ok((mut tls_stream, handshake_time)) => {
            result.tls_handshake_time_ms = Some(handshake_time);
            result.tls_success = true;
            
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
}

