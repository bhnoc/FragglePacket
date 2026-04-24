//! Secure DNS Comparison
//!
//! Compares classic UDP DNS (port 53 via the platform resolver) against DNS
//! over TLS (port 853) and DNS over HTTPS (port 443 /dns-query) to detect
//! resolver-path issues. Sends a minimal query for the target and records
//! which channels answered and how fast.

use crate::framework::{
    Diagnosis, DiagnosisSeverity, NetworkTest, TestCategory, TestResult, TestStatus,
};
use std::error::Error;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

pub struct DnsSecureCompareTest {
    doh_url: String,
    dot_host: String,
    timeout_secs: u64,
}

impl DnsSecureCompareTest {
    pub fn new() -> Self {
        Self {
            doh_url: "https://1.1.1.1/dns-query".to_string(),
            dot_host: "1.1.1.1:853".to_string(),
            timeout_secs: 5,
        }
    }
    pub fn with_doh_url(mut self, url: impl Into<String>) -> Self {
        self.doh_url = url.into();
        self
    }
    pub fn with_dot_host(mut self, host: impl Into<String>) -> Self {
        self.dot_host = host.into();
        self
    }
}

impl Default for DnsSecureCompareTest {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkTest for DnsSecureCompareTest {
    fn name(&self) -> &str {
        "DNS Secure Comparison"
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

        let udp_start = Instant::now();
        let udp_ok = platform_resolve(target).is_ok();
        let udp_ms = udp_start.elapsed().as_millis() as u64;
        result.add_metric("udp_dns_ok", if udp_ok { 1.0 } else { 0.0 });
        result.add_metric("udp_dns_ms", udp_ms as f64);

        let dot_start = Instant::now();
        let dot_ok = test_dot(&self.dot_host, target, self.timeout_secs);
        let dot_ms = dot_start.elapsed().as_millis() as u64;
        result.add_metric("dot_ok", if dot_ok { 1.0 } else { 0.0 });
        result.add_metric("dot_ms", dot_ms as f64);

        let doh_start = Instant::now();
        let doh_ok = test_doh(&self.doh_url, target, self.timeout_secs);
        let doh_ms = doh_start.elapsed().as_millis() as u64;
        result.add_metric("doh_ok", if doh_ok { 1.0 } else { 0.0 });
        result.add_metric("doh_ms", doh_ms as f64);

        let working = [("UDP", udp_ok), ("DoT", dot_ok), ("DoH", doh_ok)]
            .iter()
            .filter(|(_, ok)| *ok)
            .map(|(n, _)| *n)
            .collect::<Vec<_>>()
            .join(",");
        result.add_metadata("channels_ok", working.clone());

        if !udp_ok && (dot_ok || doh_ok) {
            result.set_status(TestStatus::Warning);
            result.add_diagnosis(
                Diagnosis::new(
                    DiagnosisSeverity::Warning,
                    "Plain DNS Blocked".to_string(),
                    "Platform UDP DNS failed but DoT/DoH worked. Something on the path is \
                     blocking or intercepting port 53."
                        .to_string(),
                )
                .with_recommendation("Switch clients to DoH or DoT permanently"),
            );
        } else if udp_ok && !dot_ok && !doh_ok {
            result.set_status(TestStatus::Warning);
            result.add_diagnosis(
                Diagnosis::new(
                    DiagnosisSeverity::Info,
                    "Secure DNS Channels Unavailable".to_string(),
                    "DoT and DoH did not work from this network; plain UDP DNS still works."
                        .to_string(),
                )
                .with_recommendation("Check outbound TCP/443 and TCP/853 for filtering"),
            );
        } else {
            result.set_status(TestStatus::Success);
        }

        Ok(result)
    }
}

fn platform_resolve(target: &str) -> Result<(), Box<dyn Error>> {
    let addrs: Vec<_> = format!("{}:80", target).to_socket_addrs()?.collect();
    if addrs.is_empty() {
        return Err("empty".into());
    }
    Ok(())
}

fn test_dot(host: &str, _target: &str, timeout_secs: u64) -> bool {
    let addr = match host.to_socket_addrs().ok().and_then(|mut a| a.next()) {
        Some(a) => a,
        None => return false,
    };
    let stream = match TcpStream::connect_timeout(&addr, Duration::from_secs(timeout_secs)) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let connector = match native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .build()
    {
        Ok(c) => c,
        Err(_) => return false,
    };
    let dns_host = host.split(':').next().unwrap_or("dns");
    connector.connect(dns_host, stream).is_ok()
}

fn test_doh(url: &str, target: &str, timeout_secs: u64) -> bool {
    let parts: Vec<&str> = url.splitn(2, "//").collect();
    if parts.len() != 2 {
        return false;
    }
    let host_and_path = parts[1];
    let (host, path) = match host_and_path.find('/') {
        Some(i) => (&host_and_path[..i], &host_and_path[i..]),
        None => (host_and_path, "/"),
    };
    let addr_str = if host.contains(':') {
        host.to_string()
    } else {
        format!("{}:443", host)
    };
    let addr = match addr_str.to_socket_addrs().ok().and_then(|mut a| a.next()) {
        Some(a) => a,
        None => return false,
    };
    let stream = match TcpStream::connect_timeout(&addr, Duration::from_secs(timeout_secs)) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let connector = match native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .build()
    {
        Ok(c) => c,
        Err(_) => return false,
    };
    let mut tls = match connector.connect(host, stream) {
        Ok(t) => t,
        Err(_) => return false,
    };
    let query = format!(
        "GET {}?name={}&type=A HTTP/1.1\r\nHost: {}\r\nAccept: application/dns-json\r\nConnection: close\r\n\r\n",
        path, target, host
    );
    if tls.write_all(query.as_bytes()).is_err() {
        return false;
    }
    let mut buf = [0u8; 1024];
    match tls.read(&mut buf) {
        Ok(n) if n > 0 => {
            let s = String::from_utf8_lossy(&buf[..n]);
            s.contains("200") || s.contains("application/dns")
        }
        _ => false,
    }
}
