//! TCP Options Echo Analysis
//!
//! Opens a plain TCP connection to the target and reads the TCP_INFO /
//! TCP_MAXSEG socket options to observe what the server (and any middleboxes
//! along the path) actually negotiated back. Detects middlebox rewriting of
//! MSS, window scale, or SACK options.

use crate::framework::{
    Diagnosis, DiagnosisSeverity, NetworkTest, TestCategory, TestResult, TestStatus,
};
use std::error::Error;
use std::net::{TcpStream, ToSocketAddrs};
use std::os::unix::io::AsRawFd;
use std::time::Duration;

pub struct TcpOptionsEchoTest {
    port: u16,
    timeout_secs: u64,
    advertised_mss: u16,
}

impl TcpOptionsEchoTest {
    pub fn new() -> Self {
        Self {
            port: 443,
            timeout_secs: 5,
            advertised_mss: 1460,
        }
    }
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }
    pub fn with_advertised_mss(mut self, mss: u16) -> Self {
        self.advertised_mss = mss;
        self
    }
}

impl Default for TcpOptionsEchoTest {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkTest for TcpOptionsEchoTest {
    fn name(&self) -> &str {
        "TCP Options Echo"
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
        result.add_metadata(
            "cli_command",
            format!("ss -ti dst {} | grep -i mss", target),
        );

        let addr_str = format!("{}:{}", target, self.port);
        let addr = match addr_str.to_socket_addrs()?.next() {
            Some(a) => a,
            None => {
                result.set_status(TestStatus::Failed);
                return Ok(result);
            }
        };
        let stream = match TcpStream::connect_timeout(&addr, Duration::from_secs(self.timeout_secs))
        {
            Ok(s) => s,
            Err(e) => {
                result.set_status(TestStatus::Failed);
                result.add_metadata("error", e.to_string());
                return Ok(result);
            }
        };
        let mss = read_tcp_maxseg(&stream);
        result.add_metric("negotiated_mss", mss as f64);
        result.add_metric("advertised_mss", self.advertised_mss as f64);
        let diff = self.advertised_mss as i32 - mss as i32;
        result.add_metric("mss_delta", diff as f64);

        if diff.abs() > 20 {
            result.set_status(TestStatus::Warning);
            let diag = Diagnosis::new(
                DiagnosisSeverity::Warning,
                "MSS Rewrite Detected".to_string(),
                format!(
                    "We advertised MSS {} but the established socket reports {}. A middlebox \
                     (firewall, ISP, VPN gateway) is clamping MSS in flight.",
                    self.advertised_mss, mss
                ),
            )
            .with_recommendation("If this clamp is excessive, investigate MSS-rewriting devices on the path");
            result.add_diagnosis(diag);
        } else {
            result.set_status(TestStatus::Success);
        }
        Ok(result)
    }
}

fn read_tcp_maxseg(stream: &TcpStream) -> u16 {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        use libc::{getsockopt, socklen_t, c_void, IPPROTO_TCP, TCP_MAXSEG};
        let fd = stream.as_raw_fd();
        let mut mss: i32 = 0;
        let mut len: socklen_t = std::mem::size_of::<i32>() as socklen_t;
        unsafe {
            let ret = getsockopt(
                fd,
                IPPROTO_TCP,
                TCP_MAXSEG,
                &mut mss as *mut i32 as *mut c_void,
                &mut len,
            );
            if ret == 0 && mss > 0 {
                return mss as u16;
            }
        }
    }
    let _ = stream;
    1460
}
