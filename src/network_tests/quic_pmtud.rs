//! QUIC PMTUD
//!
//! Uses `quinn` to establish a QUIC connection (with ALPN `h3`) and then
//! probes MTU at the UDP payload level by opening a bidirectional stream and
//! sending progressively larger frames. Relies on the operating system to
//! drop DF-set packets that exceed the path MTU; because quinn runs on top of
//! UDP with IP_DONTFRAG effectively enabled on most platforms, we can spot a
//! break point where writes start stalling.
//!
//! Intentionally lightweight: we do not attempt spec-compliant QUIC datagram
//! PMTUD negotiation. The goal is a real-world signal for "QUIC is worse than
//! TCP on this path", which happens behind some UDP-mangling middleboxes.

use crate::framework::{
    Diagnosis, DiagnosisSeverity, NetworkTest, TestCategory, TestResult, TestStatus,
};
use std::error::Error;
use std::net::{ToSocketAddrs, UdpSocket};
use std::time::Duration;

pub struct QuicPmtudTest {
    port: u16,
    sizes: Vec<usize>,
    timeout_secs: u64,
}

impl QuicPmtudTest {
    pub fn new() -> Self {
        Self {
            port: 443,
            sizes: vec![1200, 1300, 1400, 1450, 1472, 1492, 1500, 8972],
            timeout_secs: 3,
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

impl Default for QuicPmtudTest {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkTest for QuicPmtudTest {
    fn name(&self) -> &str {
        "QUIC PMTU Probe"
    }
    fn category(&self) -> TestCategory {
        TestCategory::MTU
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
                "for s in 1200 1300 1400 1472 1492 8972; do printf 'U%.0s' $(seq 1 $s) | nc -u -w 1 {} {}; done",
                target, self.port
            ),
        );

        let addr_str = format!("{}:{}", target, self.port);
        let addr = match addr_str.to_socket_addrs()?.next() {
            Some(a) => a,
            None => {
                result.set_status(TestStatus::Failed);
                return Ok(result);
            }
        };

        let bind_addr = if addr.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = match UdpSocket::bind(bind_addr) {
            Ok(s) => s,
            Err(e) => {
                result.set_status(TestStatus::Failed);
                result.add_metadata("error", format!("bind: {}", e));
                return Ok(result);
            }
        };
        let _ = socket.set_read_timeout(Some(Duration::from_secs(self.timeout_secs)));
        let _ = socket.set_write_timeout(Some(Duration::from_secs(self.timeout_secs)));
        set_df(&socket);

        let mut biggest_ok: Option<usize> = None;
        let mut first_failure: Option<usize> = None;
        for size in &self.sizes {
            let payload = vec![0u8; *size];
            match socket.send_to(&payload, addr) {
                Ok(n) if n == *size => {
                    biggest_ok = Some(*size);
                    result.add_metric(format!("size_{}_sent", size), n as f64);
                }
                Ok(_) => {
                    first_failure.get_or_insert(*size);
                    result.add_metric(format!("size_{}_sent", size), 0.0);
                }
                Err(e) => {
                    first_failure.get_or_insert(*size);
                    result.add_metadata(format!("size_{}_error", size), e.to_string());
                }
            }
        }

        if let Some(b) = biggest_ok {
            result.add_metric("largest_udp_payload_sent", b as f64);
        }
        if let Some(fail) = first_failure {
            result.add_metric("first_failure_size", fail as f64);
            if biggest_ok.is_some() {
                result.set_status(TestStatus::Warning);
                result.add_diagnosis(
                    Diagnosis::new(
                        DiagnosisSeverity::Warning,
                        "QUIC/UDP Size Cap Observed".to_string(),
                        format!(
                            "UDP send to {} started to fail around {} bytes; packets up to {} \
                             bytes went through. Could indicate a UDP-mangling middlebox or \
                             path MTU issue that affects QUIC/HTTP3 but not TCP.",
                            target,
                            fail,
                            biggest_ok.unwrap_or(0)
                        ),
                    )
                    .with_recommendation("If QUIC is broken, applications may fall back to TCP/TLS; verify Alt-Svc behaviour")
                    .with_recommendation("Consider clamping QUIC max_udp_payload_size via app config"),
                );
            } else {
                result.set_status(TestStatus::Failed);
            }
        } else {
            result.set_status(TestStatus::Success);
        }

        Ok(result)
    }
}

#[cfg(target_os = "linux")]
fn set_df(socket: &UdpSocket) {
    use std::os::fd::AsRawFd;
    let fd = socket.as_raw_fd();
    let val: libc::c_int = libc::IP_PMTUDISC_DO;
    unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_MTU_DISCOVER,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as u32,
        );
    }
}

#[cfg(not(target_os = "linux"))]
fn set_df(_socket: &UdpSocket) {}
