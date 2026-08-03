//! TCP Options Echo Analysis
//!
//! Opens a TCP connection, reads TCP_MAXSEG, and compares it with the MSS
//! implied by the active route MTU. TCP_MAXSEG can be reduced by TCP options,
//! the peer, or a middlebox, so this test reports a possible clamp only when
//! the reduction is larger than the normal TCP-option allowance.

use crate::framework::{
    Diagnosis, DiagnosisSeverity, NetworkTest, TestCategory, TestResult, TestStatus,
};
use std::error::Error;
use std::net::{TcpStream, ToSocketAddrs};
use std::os::unix::io::AsRawFd;
use std::process::Command;
use std::time::Duration;

const IPV4_TCP_HEADERS: u16 = 40;
const IPV6_TCP_HEADERS: u16 = 60;
const NORMAL_TCP_OPTION_ALLOWANCE: i32 = 40;

pub struct TcpOptionsEchoTest {
    port: u16,
    timeout_secs: u64,
    requested_mss: Option<u16>,
}

impl TcpOptionsEchoTest {
    pub fn new() -> Self {
        Self {
            port: 443,
            timeout_secs: 5,
            requested_mss: None,
        }
    }
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }
    pub fn with_advertised_mss(mut self, mss: u16) -> Self {
        // Kept for API compatibility. This is a requested/reference value,
        // not a claim about the MSS option placed on the wire.
        self.requested_mss = Some(mss);
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
        let mut result =
            TestResult::new(self.name().to_string(), self.category(), target.to_string());
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
        if let Some(requested_mss) = self.requested_mss {
            result.add_metadata("requested_mss", requested_mss.to_string());
        }

        if let Some(route_mtu) = route_mtu(&addr.ip().to_string()) {
            let network_headers = if addr.is_ipv6() {
                IPV6_TCP_HEADERS
            } else {
                IPV4_TCP_HEADERS
            };
            let expected_path_mss = route_mtu.saturating_sub(network_headers);
            let diff = expected_path_mss as i32 - mss as i32;

            result.add_metric("route_mtu", route_mtu as f64);
            result.add_metric("expected_path_mss", expected_path_mss as f64);
            result.add_metric("mss_delta", diff as f64);

            if diff > NORMAL_TCP_OPTION_ALLOWANCE {
                result.set_status(TestStatus::Warning);
                result.add_metadata("mss_verdict", "possible_peer_or_middlebox_clamp");
                let diag = Diagnosis::new(
                    DiagnosisSeverity::Warning,
                    "Possible MSS Clamp Detected".to_string(),
                    format!(
                        "The route MTU {} supports an IPv4 MSS near {}, but TCP_MAXSEG is {} \
                         ({} bytes lower). The peer or a middlebox may be advertising a smaller MSS.",
                        route_mtu, expected_path_mss, mss, diff
                    ),
                )
                .with_recommendation(
                    "Capture the SYN and SYN-ACK MSS options to distinguish peer behavior from middlebox rewriting",
                );
                result.add_diagnosis(diag);
            } else {
                result.set_status(TestStatus::Success);
                result.add_metadata("mss_verdict", "consistent_with_route_mtu");
                if diff >= 0 {
                    result.add_metric("tcp_option_allowance", diff as f64);
                }
            }
        } else {
            result.set_status(TestStatus::Success);
            result.add_metadata("mss_verdict", "observed_route_mtu_unavailable");
            let diag = Diagnosis::new(
                DiagnosisSeverity::Info,
                "MSS Observed; Clamp Check Inconclusive".to_string(),
                format!(
                    "TCP_MAXSEG is {}, but the active route MTU could not be read without packet capture.",
                    mss
                ),
            )
            .with_recommendation("Capture SYN and SYN-ACK MSS options for a definitive clamp check");
            result.add_diagnosis(diag);
        }
        Ok(result)
    }
}

fn route_mtu(target_ip: &str) -> Option<u16> {
    #[cfg(target_os = "macos")]
    {
        let output = Command::new("route")
            .args(["-n", "get", target_ip])
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&output.stdout);
        let interface = parse_value_after_label(&text, "interface:")?;
        let output = Command::new("ifconfig").arg(interface).output().ok()?;
        return parse_mtu(&String::from_utf8_lossy(&output.stdout));
    }

    #[cfg(target_os = "linux")]
    {
        let output = Command::new("ip")
            .args(["route", "get", target_ip])
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&output.stdout);
        let interface = parse_value_after_label(&text, "dev")?;
        let mtu_path = format!("/sys/class/net/{}/mtu", interface);
        return std::fs::read_to_string(mtu_path).ok()?.trim().parse().ok();
    }

    #[allow(unreachable_code)]
    None
}

fn parse_value_after_label<'a>(text: &'a str, label: &str) -> Option<&'a str> {
    let tokens: Vec<&str> = text.split_whitespace().collect();
    tokens
        .windows(2)
        .find(|pair| pair[0] == label)
        .map(|pair| pair[1])
}

#[allow(dead_code)]
fn parse_mtu(text: &str) -> Option<u16> {
    parse_value_after_label(text, "mtu")?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_macos_interface_and_mtu() {
        let route = "route to: 1.1.1.1\n  interface: utun5\n";
        let iface = "utun5: flags=8051<UP> mtu 1412\n";
        assert_eq!(parse_value_after_label(route, "interface:"), Some("utun5"));
        assert_eq!(parse_mtu(iface), Some(1412));
    }

    #[test]
    fn normal_tcp_options_fit_route_allowance() {
        let route_mss = 1412_u16 - IPV4_TCP_HEADERS;
        assert_eq!(route_mss, 1372);
        assert!(route_mss as i32 - 1360 <= NORMAL_TCP_OPTION_ALLOWANCE);
    }
}

fn read_tcp_maxseg(stream: &TcpStream) -> u16 {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        use libc::{c_void, getsockopt, socklen_t, IPPROTO_TCP, TCP_MAXSEG};
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
