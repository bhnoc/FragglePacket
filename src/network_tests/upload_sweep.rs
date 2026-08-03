//! HTTP(S) Upload Size Sweep
//!
//! Graduated POST sweep that detects the classic "TCP connects, but data stalls"
//! signature typical of MTU blackholes and misconfigured MSS clamps.
//!
//! Sends POST bodies of 256B, 1KB, 4KB, 16KB, 64KB, and 256KB while recording
//! per-stage timing (connect, TLS, TTFB, total) and reports any sizes that
//! failed to complete within their per-size budget.

use crate::framework::{
    Diagnosis, DiagnosisSeverity, NetworkTest, TestCategory, TestResult, TestStatus,
};
use std::error::Error;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

/// Default payload sizes used by the sweep.
pub const DEFAULT_SIZES: &[usize] = &[256, 1024, 4096, 16384, 65536, 262144];

/// Per-size probe result.
#[derive(Debug, Clone)]
pub struct SweepSample {
    pub size: usize,
    pub http_status: u16,
    pub connect_ms: u64,
    pub appconnect_ms: u64,
    pub ttfb_ms: u64,
    pub total_ms: u64,
    pub error: Option<String>,
}

impl SweepSample {
    pub fn ok(&self) -> bool {
        self.error.is_none() && self.http_status != 0
    }
}

/// Size-graduated HTTPS/HTTP upload sweep.
pub struct UploadSizeSweepTest {
    timeout_secs: u64,
    sizes: Vec<usize>,
    port: u16,
    use_tls: bool,
    path: String,
}

impl UploadSizeSweepTest {
    pub fn new() -> Self {
        Self {
            timeout_secs: 20,
            sizes: DEFAULT_SIZES.to_vec(),
            port: 443,
            use_tls: true,
            path: "/".to_string(),
        }
    }

    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self.use_tls = port == 443 || port == 8443;
        self
    }

    pub fn with_tls(mut self, use_tls: bool) -> Self {
        self.use_tls = use_tls;
        self
    }

    pub fn with_sizes(mut self, sizes: Vec<usize>) -> Self {
        self.sizes = sizes;
        self
    }

    pub fn with_timeout(mut self, timeout_secs: u64) -> Self {
        self.timeout_secs = timeout_secs;
        self
    }
}

impl Default for UploadSizeSweepTest {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkTest for UploadSizeSweepTest {
    fn name(&self) -> &str {
        "HTTP Upload Size Sweep"
    }

    fn category(&self) -> TestCategory {
        TestCategory::HTTPS
    }

    fn run(&self, target: &str) -> Result<TestResult, Box<dyn Error>> {
        let mut result = TestResult::new(
            self.name().to_string(),
            self.category(),
            target.to_string(),
        );

        result.add_metadata(
            "cli_command",
            format!(
                "for s in 256 1024 4096 16384 65536 262144; do head -c $s /dev/zero | curl -X POST --data-binary @- https://{}:{}/ -w \"%{{size_upload}} %{{http_code}}\\n\"; done",
                target, self.port
            ),
        );

        let mut samples = Vec::with_capacity(self.sizes.len());
        for size in &self.sizes {
            let sample = run_single_sweep(
                target,
                self.port,
                self.use_tls,
                &self.path,
                *size,
                self.timeout_secs,
            );
            samples.push(sample);
        }

        let mut fail_sizes = Vec::new();
        for sample in &samples {
            let prefix = format!("size_{}", sample.size);
            result.add_metric(format!("{}_connect_ms", prefix), sample.connect_ms as f64);
            result.add_metric(
                format!("{}_appconnect_ms", prefix),
                sample.appconnect_ms as f64,
            );
            result.add_metric(format!("{}_ttfb_ms", prefix), sample.ttfb_ms as f64);
            result.add_metric(format!("{}_total_ms", prefix), sample.total_ms as f64);
            result.add_metric(format!("{}_http", prefix), sample.http_status as f64);
            if let Some(err) = &sample.error {
                result.add_metadata(format!("{}_error", prefix), err.clone());
            }
            if !sample.ok() {
                fail_sizes.push(sample.size);
            }
        }

        result.add_metadata(
            "upload_fail_sizes",
            fail_sizes
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
                .join(","),
        );
        result.add_metric("total_samples", samples.len() as f64);
        result.add_metric("failed_samples", fail_sizes.len() as f64);

        if fail_sizes.is_empty() {
            result.set_status(TestStatus::Success);
        } else {
            let small_failed = fail_sizes.iter().any(|s| *s <= 1024);
            let large_failed = fail_sizes.iter().any(|s| *s >= 16384);
            if !small_failed && large_failed {
                result.set_status(TestStatus::Warning);
                let diag = Diagnosis::new(
                    DiagnosisSeverity::Critical,
                    "Data-Stall Signature Detected".to_string(),
                    format!(
                        "Small uploads succeeded but larger sizes failed: {:?}. This is a \
                         strong MTU/MSS blackhole indicator where TCP connects and small \
                         payloads flow but larger segments are silently dropped.",
                        fail_sizes
                    ),
                )
                .with_recommendation("Lower interface MTU to 1400 and retest")
                .with_recommendation("Enable TCP MSS clamping on the egress path")
                .with_recommendation("Check ICMP fragmentation-needed is not being filtered upstream")
                .with_related_test("ICMP MTU Discovery")
                .with_related_test("HTTPS Stage-by-Stage");
                result.add_diagnosis(diag);
            } else {
                result.set_status(TestStatus::Warning);
                let diag = Diagnosis::new(
                    DiagnosisSeverity::Warning,
                    "Upload Sweep Failures".to_string(),
                    format!(
                        "Some upload sizes did not complete cleanly: {:?}. Pattern is not a \
                         textbook blackhole (small sizes also failed) so the cause may be \
                         rate limits, WAF rules, or a flaky connection.",
                        fail_sizes
                    ),
                )
                .with_recommendation("Re-run with --timeout 40 to exclude slow responses")
                .with_recommendation("Check server-side upload limits");
                result.add_diagnosis(diag);
            }
        }

        Ok(result)
    }
}

fn run_single_sweep(
    target: &str,
    port: u16,
    use_tls: bool,
    path: &str,
    size: usize,
    timeout_secs: u64,
) -> SweepSample {
    let mut sample = SweepSample {
        size,
        http_status: 0,
        connect_ms: 0,
        appconnect_ms: 0,
        ttfb_ms: 0,
        total_ms: 0,
        error: None,
    };
    let total_start = Instant::now();

    let addr_str = format!("{}:{}", target, port);
    let addr = match addr_str.to_socket_addrs() {
        Ok(mut a) => match a.next() {
            Some(a) => a,
            None => {
                sample.error = Some("DNS resolved but no addresses".to_string());
                sample.total_ms = total_start.elapsed().as_millis() as u64;
                return sample;
            }
        },
        Err(e) => {
            sample.error = Some(format!("DNS: {}", e));
            sample.total_ms = total_start.elapsed().as_millis() as u64;
            return sample;
        }
    };

    let connect_start = Instant::now();
    let stream =
        match TcpStream::connect_timeout(&addr, Duration::from_secs(timeout_secs)) {
            Ok(s) => s,
            Err(e) => {
                sample.error = Some(format!("TCP: {}", e));
                sample.total_ms = total_start.elapsed().as_millis() as u64;
                return sample;
            }
        };
    sample.connect_ms = connect_start.elapsed().as_millis() as u64;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(timeout_secs)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(timeout_secs)));

    let body = vec![b'A'; size];
    let request = build_post_request(target, path, size);

    if use_tls {
        let connector = match native_tls::TlsConnector::builder()
            .danger_accept_invalid_certs(true)
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                sample.error = Some(format!("TLS init: {}", e));
                sample.total_ms = total_start.elapsed().as_millis() as u64;
                return sample;
            }
        };
        let app_start = Instant::now();
        let mut tls = match connector.connect(target, stream) {
            Ok(t) => t,
            Err(e) => {
                sample.error = Some(format!("TLS: {}", e));
                sample.total_ms = total_start.elapsed().as_millis() as u64;
                return sample;
            }
        };
        sample.appconnect_ms = app_start.elapsed().as_millis() as u64;
        do_post_and_read(&mut tls, &request, &body, &mut sample, total_start);
    } else {
        let mut plain = stream;
        do_post_and_read(&mut plain, &request, &body, &mut sample, total_start);
    }

    sample.total_ms = total_start.elapsed().as_millis() as u64;
    sample
}

fn build_post_request(host: &str, path: &str, body_len: usize) -> String {
    format!(
        "POST {} HTTP/1.1\r\n\
         Host: {}\r\n\
         User-Agent: FragglePacket/UploadSweep\r\n\
         Content-Type: application/octet-stream\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        path, host, body_len
    )
}

fn do_post_and_read<S: Read + Write>(
    stream: &mut S,
    request: &str,
    body: &[u8],
    sample: &mut SweepSample,
    total_start: Instant,
) {
    if let Err(e) = stream.write_all(request.as_bytes()) {
        sample.error = Some(format!("write headers: {}", e));
        return;
    }
    if let Err(e) = stream.write_all(body) {
        sample.error = Some(format!("write body: {}", e));
        return;
    }
    if let Err(e) = stream.flush() {
        sample.error = Some(format!("flush: {}", e));
        return;
    }

    let ttfb_start = Instant::now();
    let mut buf = [0u8; 4096];
    match stream.read(&mut buf) {
        Ok(n) if n > 0 => {
            sample.ttfb_ms = ttfb_start.elapsed().as_millis() as u64;
            sample.total_ms = total_start.elapsed().as_millis() as u64;
            let text = String::from_utf8_lossy(&buf[..n]);
            if let Some(first_line) = text.lines().next() {
                if let Some(code_str) = first_line.split_whitespace().nth(1) {
                    if let Ok(code) = code_str.parse::<u16>() {
                        sample.http_status = code;
                    }
                }
            }
        }
        Ok(_) => {
            sample.error = Some("empty response".to_string());
        }
        Err(e) => {
            sample.error = Some(format!("read: {}", e));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_sizes_present() {
        let t = UploadSizeSweepTest::new();
        assert_eq!(t.sizes, DEFAULT_SIZES);
    }

    #[test]
    fn test_build_post_request_has_content_length() {
        let req = build_post_request("example.com", "/", 1234);
        assert!(req.contains("Content-Length: 1234"));
        assert!(req.contains("Host: example.com"));
    }

    #[test]
    fn test_category_and_name() {
        let t = UploadSizeSweepTest::new();
        assert_eq!(t.category(), TestCategory::HTTPS);
        assert_eq!(t.name(), "HTTP Upload Size Sweep");
    }
}
