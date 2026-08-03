//! Raw JetDirect (port 9100) Bulk Stream Test
//!
//! Printers are famous for large-stream flakiness in fragmented or clamped
//! paths. This probe:
//!   * sends a PJL INFO STATUS control frame to confirm the port talks PJL
//!   * runs a size-graduated bulk PJL COMMENT push to expose path drops at
//!     specific segment sizes
//!
//! Payloads are PJL-safe comments so no actual print job is produced.

use crate::framework::{
    Diagnosis, DiagnosisSeverity, NetworkTest, TestCategory, TestResult, TestStatus,
};
use std::error::Error;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

pub const DEFAULT_BULK_SIZES: &[usize] = &[512, 1024, 4096, 16384, 32768, 65536];

#[derive(Debug, Clone)]
pub struct PrinterSample {
    pub size: usize,
    pub ok: bool,
    pub duration_ms: u64,
    pub error: Option<String>,
}

pub struct Raw9100BulkTest {
    port: u16,
    timeout_secs: u64,
    sizes: Vec<usize>,
}

impl Raw9100BulkTest {
    pub fn new() -> Self {
        Self {
            port: 9100,
            timeout_secs: 5,
            sizes: DEFAULT_BULK_SIZES.to_vec(),
        }
    }

    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    pub fn with_sizes(mut self, sizes: Vec<usize>) -> Self {
        self.sizes = sizes;
        self
    }
}

impl Default for Raw9100BulkTest {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkTest for Raw9100BulkTest {
    fn name(&self) -> &str {
        "Raw 9100 Bulk Sweep"
    }

    fn category(&self) -> TestCategory {
        TestCategory::Application
    }

    fn run(&self, target: &str) -> Result<TestResult, Box<dyn Error>> {
        let mut result = TestResult::new(
            self.name().to_string(),
            self.category(),
            target.to_string(),
        );
        result.add_metadata(
            "cli_pjl",
            format!(
                "printf '\\x1b%%-12345X@PJL INFO STATUS\\r\\n\\x1b%%-12345X' | nc -w 5 {} {}",
                target, self.port
            ),
        );
        result.add_metadata(
            "cli_bulk",
            format!(
                "head -c 65536 /dev/zero | nc -w 5 {} {}",
                target, self.port
            ),
        );

        let pjl_ok = probe_pjl(target, self.port, self.timeout_secs);
        result.add_metadata("pjl_probe_ok", pjl_ok.to_string());

        let mut samples = Vec::with_capacity(self.sizes.len());
        let mut fail_sizes = Vec::new();
        for size in &self.sizes {
            let s = bulk_push(target, self.port, *size, self.timeout_secs);
            if !s.ok {
                fail_sizes.push(s.size);
            }
            result.add_metric(format!("size_{}_ms", s.size), s.duration_ms as f64);
            result.add_metric(format!("size_{}_ok", s.size), if s.ok { 1.0 } else { 0.0 });
            if let Some(e) = &s.error {
                result.add_metadata(format!("size_{}_error", s.size), e.clone());
            }
            samples.push(s);
        }

        result.add_metadata(
            "printer_fail_sizes",
            fail_sizes
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
                .join(","),
        );

        if fail_sizes.is_empty() && pjl_ok {
            result.set_status(TestStatus::Success);
        } else if fail_sizes.iter().any(|s| *s >= 16384)
            && !fail_sizes.iter().any(|s| *s <= 1024)
        {
            result.set_status(TestStatus::Warning);
            let diag = Diagnosis::new(
                DiagnosisSeverity::Critical,
                "Printer Large-Stream Blackhole".to_string(),
                format!(
                    "Small PJL payloads went through but larger bulk pushes failed: {:?}. \
                     Classic signature of MTU/MSS blackhole affecting the print path.",
                    fail_sizes
                ),
            )
            .with_recommendation("Match printer MTU to its switch port and the path")
            .with_recommendation("Disable segmentation offload on any intermediate firewall");
            result.add_diagnosis(diag);
        } else if !fail_sizes.is_empty() {
            result.set_status(TestStatus::Warning);
            let diag = Diagnosis::new(
                DiagnosisSeverity::Warning,
                "Printer Bulk Push Anomaly".to_string(),
                format!(
                    "Some PJL bulk sizes did not complete cleanly: {:?}. Could be a flaky \
                     port, low printer buffer, or non-MTU policy issue.",
                    fail_sizes
                ),
            )
            .with_recommendation("Retry, then inspect printer web UI for errors");
            result.add_diagnosis(diag);
        } else {
            result.set_status(TestStatus::Warning);
            let diag = Diagnosis::new(
                DiagnosisSeverity::Warning,
                "PJL Probe Silent".to_string(),
                "Bulk pushes worked but the PJL INFO probe did not respond. Printer may not \
                 speak PJL or swallows control frames; data-path itself looks fine."
                    .to_string(),
            );
            result.add_diagnosis(diag);
        }

        Ok(result)
    }
}

fn probe_pjl(target: &str, port: u16, timeout_secs: u64) -> bool {
    let addr_str = format!("{}:{}", target, port);
    let addr = match addr_str.to_socket_addrs().ok().and_then(|mut a| a.next()) {
        Some(a) => a,
        None => return false,
    };
    let mut stream = match TcpStream::connect_timeout(&addr, Duration::from_secs(timeout_secs)) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(timeout_secs)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(timeout_secs)));
    let probe: &[u8] =
        b"\x1b%-12345X@PJL INFO STATUS\r\n@PJL INFO ID\r\n\x1b%-12345X";
    if stream.write_all(probe).is_err() {
        return false;
    }
    let mut buf = [0u8; 256];
    matches!(stream.read(&mut buf), Ok(n) if n > 0)
}

fn bulk_push(target: &str, port: u16, size: usize, timeout_secs: u64) -> PrinterSample {
    let start = Instant::now();
    let addr_str = format!("{}:{}", target, port);
    let addr = match addr_str.to_socket_addrs().ok().and_then(|mut a| a.next()) {
        Some(a) => a,
        None => {
            return PrinterSample {
                size,
                ok: false,
                duration_ms: start.elapsed().as_millis() as u64,
                error: Some("DNS failed".into()),
            };
        }
    };
    let mut stream = match TcpStream::connect_timeout(&addr, Duration::from_secs(timeout_secs)) {
        Ok(s) => s,
        Err(e) => {
            return PrinterSample {
                size,
                ok: false,
                duration_ms: start.elapsed().as_millis() as u64,
                error: Some(format!("connect: {}", e)),
            };
        }
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(timeout_secs)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(timeout_secs)));

    let prolog = b"\x1b%-12345X@PJL COMMENT NETTEST\r\n";
    let epilog = b"\r\n\x1b%-12345X";
    let pad_len = size.saturating_sub(prolog.len() + epilog.len());
    let mut payload = Vec::with_capacity(prolog.len() + pad_len + epilog.len());
    payload.extend_from_slice(prolog);
    payload.extend(std::iter::repeat(b'A').take(pad_len));
    payload.extend_from_slice(epilog);

    if let Err(e) = stream.write_all(&payload) {
        return PrinterSample {
            size,
            ok: false,
            duration_ms: start.elapsed().as_millis() as u64,
            error: Some(format!("write: {}", e)),
        };
    }
    let mut junk = [0u8; 128];
    let _ = stream.read(&mut junk);

    PrinterSample {
        size,
        ok: true,
        duration_ms: start.elapsed().as_millis() as u64,
        error: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_port_9100() {
        let t = Raw9100BulkTest::new();
        assert_eq!(t.port, 9100);
    }

    #[test]
    fn default_sizes_present() {
        let t = Raw9100BulkTest::new();
        assert_eq!(t.sizes, DEFAULT_BULK_SIZES);
    }
}
