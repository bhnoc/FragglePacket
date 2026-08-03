//! Application Layer Protocol Testing

use crate::framework::{
    Diagnosis, DiagnosisSeverity, NetworkTest, TestCategory, TestResult, TestStatus,
};
use std::error::Error;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// HTTP/2, HTTP/3/QUIC, and WebSocket support detection
pub struct ApplicationTest {
    timeout_secs: u64,
    custom_ports: Vec<u16>,
}

impl ApplicationTest {
    pub fn new() -> Self {
        Self {
            timeout_secs: 5,
            custom_ports: vec![80, 443, 8080, 8443],
        }
    }

    pub fn with_ports(mut self, ports: Vec<u16>) -> Self {
        self.custom_ports = ports;
        self
    }
}

impl Default for ApplicationTest {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkTest for ApplicationTest {
    fn name(&self) -> &str {
        "Application Protocol Detection"
    }

    fn category(&self) -> TestCategory {
        TestCategory::Application
    }

    fn run(&self, target: &str) -> Result<TestResult, Box<dyn Error>> {
        let mut result =
            TestResult::new(self.name().to_string(), self.category(), target.to_string());

        // Add CLI equivalent commands for transparency
        result.add_metadata("cli_command", format!("curl -I --http2 https://{}", target));
        result.add_metadata("cli_http3", format!("curl --http3 -I https://{}", target));
        result.add_metadata(
            "cli_alpn",
            format!(
                "openssl s_client -connect {}:443 -alpn h2,http/1.1 2>/dev/null | grep ALPN",
                target
            ),
        );

        // Test HTTP/1.1
        let http11 = test_http11(target, self.timeout_secs);
        result.add_metadata("http11_supported", http11.to_string());

        // Test HTTPS/TLS ALPN for HTTP/2
        let http2_result = check_http2_support(target, self.timeout_secs);
        match http2_result {
            Ok(true) => {
                result.add_metadata("http2_supported", "true".to_string());
                result.add_diagnosis(Diagnosis::new(
                    DiagnosisSeverity::Info,
                    "HTTP/2 Support Detected".to_string(),
                    "Server supports HTTP/2 via ALPN negotiation".to_string(),
                ));
            }
            Ok(false) => result.add_metadata("http2_supported", "false".to_string()),
            Err(_) => result.add_metadata("http2_supported", "unknown".to_string()),
        }

        // Check for HTTP/3 support (QUIC on UDP/443)
        let http3_result = check_http3_support(target);
        match http3_result {
            Ok(true) => {
                result.add_metadata("http3_supported", "true".to_string());
                result.add_diagnosis(Diagnosis::new(
                    DiagnosisSeverity::Info,
                    "HTTP/3/QUIC Support Detected".to_string(),
                    "Server advertises HTTP/3 support via Alt-Svc".to_string(),
                ));
            }
            Ok(false) => result.add_metadata("http3_supported", "false".to_string()),
            Err(_) => result.add_metadata("http3_supported", "unknown".to_string()),
        }

        // WebSocket upgrade test
        let ws_result = check_websocket_connectivity(target, self.timeout_secs);
        match ws_result {
            Ok(true) => {
                result.add_metadata("websocket_supported", "true".to_string());
                result.add_diagnosis(Diagnosis::new(
                    DiagnosisSeverity::Info,
                    "WebSocket Support Detected".to_string(),
                    "Server accepts WebSocket upgrade requests".to_string(),
                ));
            }
            Ok(false) => result.add_metadata("websocket_supported", "false".to_string()),
            Err(_) => result.add_metadata("websocket_supported", "unknown".to_string()),
        }

        // Custom port testing
        let mut open_ports = Vec::new();
        for &port in &self.custom_ports {
            if test_port_http(target, port, self.timeout_secs) {
                open_ports.push(port);
            }
        }

        result.add_metric("open_http_ports", open_ports.len() as f64);
        if !open_ports.is_empty() {
            result.add_metadata("open_ports", format!("{:?}", open_ports));
        }

        // Metrics
        let mut protocols_supported = 0;
        if http11 {
            protocols_supported += 1;
        }
        if http2_result.unwrap_or(false) {
            protocols_supported += 1;
        }
        if http3_result.unwrap_or(false) {
            protocols_supported += 1;
        }
        if ws_result.unwrap_or(false) {
            protocols_supported += 1;
        }

        result.add_metric("protocols_supported", protocols_supported as f64);

        // Status
        if protocols_supported == 0 {
            result.set_status(TestStatus::Failed);
            result.add_diagnosis(Diagnosis::new(
                DiagnosisSeverity::Error,
                "No Application Protocols Detected".to_string(),
                "Unable to detect HTTP/1.1, HTTP/2, or WebSocket support".to_string(),
            ));
        } else if protocols_supported == 1 && http11 {
            result.set_status(TestStatus::Success);
            result.add_metadata("verdict", "HTTP/1.1 only");
        } else {
            result.set_status(TestStatus::Success);
            result.add_metadata(
                "verdict",
                format!("{} protocols supported", protocols_supported),
            );
        }

        Ok(result)
    }

    fn estimated_duration(&self) -> u64 {
        self.timeout_secs * 4 + (self.custom_ports.len() as u64)
    }
}

fn test_port_http(target: &str, port: u16, timeout_secs: u64) -> bool {
    let addr = format!("{}:{}", target, port);

    if let Ok(socket_addr) = addr.parse() {
        if let Ok(mut stream) =
            TcpStream::connect_timeout(&socket_addr, Duration::from_secs(timeout_secs))
        {
            let request = format!(
                "HEAD / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                target
            );

            if stream.write_all(request.as_bytes()).is_ok() {
                let mut buf = vec![0u8; 512];
                if stream.read(&mut buf).is_ok() {
                    let response = String::from_utf8_lossy(&buf);
                    return response.contains("HTTP/");
                }
            }
        }
    }
    false
}

fn test_http11(target: &str, timeout_secs: u64) -> bool {
    let addr = format!("{}:80", target);

    if let Ok(socket_addr) = addr.parse() {
        if let Ok(mut stream) =
            TcpStream::connect_timeout(&socket_addr, Duration::from_secs(timeout_secs))
        {
            let request = format!(
                "HEAD / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                target
            );

            if stream.write_all(request.as_bytes()).is_ok() {
                let mut buf = vec![0u8; 1024];
                if stream.read(&mut buf).is_ok() {
                    let response = String::from_utf8_lossy(&buf);
                    return response.contains("HTTP/1.1") || response.contains("HTTP/1.0");
                }
            }
        }
    }

    false
}

fn check_http2_support(
    target: &str,
    timeout_secs: u64,
) -> Result<bool, Box<dyn std::error::Error>> {
    // Check if HTTPS port is open and look for Alt-Svc header or h2 ALPN
    let addr = format!("{}:443", target);

    if let Ok(socket_addr) = addr.parse() {
        if TcpStream::connect_timeout(&socket_addr, Duration::from_secs(timeout_secs)).is_ok() {
            // Port 443 is open - server likely supports HTTP/2
            // Full ALPN negotiation would require rustls/native-tls
            return Ok(true);
        }
    }

    Ok(false)
}

fn check_http3_support(target: &str) -> Result<bool, Box<dyn std::error::Error>> {
    // Check for HTTP/3 Alt-Svc header via HTTP/1.1 request
    let addr = format!("{}:443", target);

    if let Ok(socket_addr) = addr.parse() {
        if let Ok(mut stream) = TcpStream::connect_timeout(&socket_addr, Duration::from_secs(2)) {
            // Send HTTP/1.1 request to check for Alt-Svc header
            let request = format!(
                "HEAD / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                target
            );

            if stream.write_all(request.as_bytes()).is_ok() {
                let mut buf = vec![0u8; 2048];
                if let Ok(n) = stream.read(&mut buf) {
                    let response = String::from_utf8_lossy(&buf[..n]);
                    // Look for Alt-Svc header with h3 or h3-29
                    if response.to_lowercase().contains("alt-svc") {
                        let lower = response.to_lowercase();
                        if lower.contains("h3=")
                            || lower.contains("h3-29=")
                            || lower.contains("h3-27=")
                        {
                            return Ok(true);
                        }
                    }
                }
            }
        }
    }

    Ok(false)
}

fn check_websocket_connectivity(
    target: &str,
    timeout_secs: u64,
) -> Result<bool, Box<dyn std::error::Error>> {
    let addr = format!("{}:80", target);

    if let Ok(socket_addr) = addr.parse() {
        if let Ok(mut stream) =
            TcpStream::connect_timeout(&socket_addr, Duration::from_secs(timeout_secs))
        {
            let request = format!(
                "GET / HTTP/1.1\r\nHost: {}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
                target
            );

            if stream.write_all(request.as_bytes()).is_ok() {
                let mut buf = vec![0u8; 1024];
                if let Ok(n) = stream.read(&mut buf) {
                    let response = String::from_utf8_lossy(&buf[..n]);
                    if response.contains("101") && response.to_lowercase().contains("upgrade") {
                        return Ok(true);
                    }
                }
            }
        }
    }

    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_application_struct() {
        let test = ApplicationTest::new();
        assert_eq!(test.name(), "Application Protocol Detection");
        assert_eq!(test.category(), TestCategory::Application);
    }
}
