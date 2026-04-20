//! Tunnel & MSS Clamping Detection
//!
//! Detects VPN/tunnel overhead and recommends MSS clamping values.
//! Critical for conference networks with tunneled APs and student VPNs.

use crate::framework::{NetworkTest, TestCategory, TestResult, TestStatus, Diagnosis, DiagnosisSeverity};
use std::error::Error;
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;
use std::os::unix::io::AsRawFd;

/// Known VPN/tunnel overhead values
const OVERHEAD_WIREGUARD: u16 = 60;
const OVERHEAD_OPENVPN_UDP: u16 = 70;
const OVERHEAD_OPENVPN_TCP: u16 = 90;
const OVERHEAD_IPSEC_NAT_T: u16 = 72;
const OVERHEAD_L2TP_IPSEC: u16 = 76;
const OVERHEAD_VXLAN: u16 = 50;
const OVERHEAD_GRE: u16 = 24;
const OVERHEAD_GENEVE: u16 = 58;

/// Common tunnel MTU signatures (1500 - overhead)
const TUNNEL_SIGNATURES: &[(u16, &str)] = &[
    (1440, "WireGuard"),
    (1430, "OpenVPN UDP"),
    (1420, "Generic VPN tunnel"),
    (1410, "OpenVPN TCP"),
    (1400, "Conservative tunnel / double NAT"),
    (1380, "Double encapsulation (VPN over VPN)"),
    (1360, "Triple encapsulation"),
    (1280, "IPv6 minimum / heavily encapsulated"),
];

/// Test for tunnel overhead and MSS clamping requirements
pub struct TunnelMssClampingTest {
    timeout_secs: u64,
    port: u16,
}

impl TunnelMssClampingTest {
    pub fn new() -> Self {
        Self {
            timeout_secs: 5,
            port: 443,
        }
    }

    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }
}

impl Default for TunnelMssClampingTest {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkTest for TunnelMssClampingTest {
    fn name(&self) -> &str {
        "Tunnel MSS Clamping Analysis"
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

        // Add CLI equivalent commands for transparency
        result.add_metadata("cli_command", format!("ss -ti dst {} | grep -i mss", target));
        result.add_metadata("cli_tcpdump", format!("tcpdump -i any -c 5 'tcp[13] == 18' and host {} 2>/dev/null | grep -oE 'mss [0-9]+'", target));
        result.add_metadata("cli_note", "Reads TCP_MAXSEG socket option from established connection");

        let addr_str = if target.contains(':') {
            target.to_string()
        } else {
            format!("{}:{}", target, self.port)
        };

        let mut addrs = addr_str.to_socket_addrs()?;
        let addr = addrs.next().ok_or("No address resolved")?;

        // Connect and read actual TCP_MAXSEG
        let stream = match TcpStream::connect_timeout(&addr, Duration::from_secs(self.timeout_secs)) {
            Ok(s) => s,
            Err(e) => {
                result.set_status(TestStatus::Failed);
                result.add_metadata("error", format!("Connection failed: {}", e));
                return Ok(result);
            }
        };

        // Read actual MSS from socket
        let actual_mss = read_tcp_maxseg(&stream);
        result.add_metric("tcp_mss", actual_mss as f64);
        result.add_metadata("port", self.port.to_string());

        // Calculate effective MTU (MSS + 40 for IP+TCP headers)
        let effective_mtu = actual_mss + 40;
        result.add_metric("effective_mtu", effective_mtu as f64);

        // Detect tunnel overhead
        let overhead = 1500_u16.saturating_sub(effective_mtu);
        result.add_metric("detected_overhead", overhead as f64);

        // Match against known tunnel signatures
        let tunnel_type = identify_tunnel_type(effective_mtu);
        if let Some(tunnel) = tunnel_type {
            result.add_metadata("tunnel_detected", tunnel.to_string());
        }

        // Determine if clamping is needed
        // Use 1480 threshold to avoid false positives from minor MSS variations
        if effective_mtu >= 1480 {
            result.set_status(TestStatus::Success);
            result.add_metadata("clamping_needed", "false");
            result.add_metadata("verdict", "Standard MTU, no clamping required");
            result.add_metadata("effective_mtu_status", "normal");
        } else if effective_mtu >= 1400 {
            // Noticeable but not critical reduction (1400-1479)
            result.set_status(TestStatus::Success);
            result.add_metadata("clamping_needed", "optional");
            result.add_metadata("effective_mtu_status", "slightly_reduced");

            let diag = Diagnosis::new(
                DiagnosisSeverity::Info,
                "Minor MTU Reduction Detected".to_string(),
                format!("Effective MTU {} (overhead: {} bytes). Likely single tunnel or minor encapsulation.", effective_mtu, overhead),
            ).with_recommendation("Current setup should work for most traffic - clamping optional");
            result.add_diagnosis(diag);
        } else if effective_mtu >= 1280 {
            result.set_status(TestStatus::Warning);
            result.add_metadata("clamping_needed", "true");

            let mut diag = Diagnosis::new(
                DiagnosisSeverity::Warning,
                "Significant Tunnel Overhead Detected".to_string(),
                format!("Effective MTU {} indicates {} bytes overhead. {}",
                    effective_mtu, overhead,
                    tunnel_type.unwrap_or("Multiple encapsulation layers likely")),
            );
            diag = diag.with_recommendation(format!(
                "Apply MSS clamping: iptables -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss {}",
                actual_mss
            )).with_recommendation(format!(
                "Or use PMTU clamping: iptables -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu"
            )).with_recommendation("Check for VPN-over-VPN or tunneled AP configurations")
              .with_related_test("TCP Segmentation Detection");
            result.add_diagnosis(diag);
        } else {
            result.set_status(TestStatus::Warning);
            result.add_metadata("clamping_needed", "critical");

            let mut diag = Diagnosis::new(
                DiagnosisSeverity::Critical,
                "Severe MTU Restriction".to_string(),
                format!("Effective MTU {} is critically low ({} bytes overhead). Heavy encapsulation detected.",
                    effective_mtu, overhead),
            );
            diag = diag.with_recommendation(format!(
                "REQUIRED: Apply MSS clamping to {} bytes immediately", actual_mss
            )).with_recommendation(
                "Investigate tunnel stack - likely multiple VPN layers"
            ).with_recommendation(
                "For conference/event networks: ensure AP tunnels account for student VPN overhead"
            ).with_related_test("HTTPS Stage-by-Stage");
            result.add_diagnosis(diag);
        }

        // Add specific recommendations for conference networks
        if overhead >= 100 {
            let conference_diag = Diagnosis::new(
                DiagnosisSeverity::Warning,
                "Conference Network Pattern".to_string(),
                "High overhead pattern matches tunneled AP + VPN scenario common at conferences.".to_string(),
            ).with_recommendation("Pre-configure MSS clamping on tunnel endpoints")
             .with_recommendation("Consider reducing tunnel overhead or using more efficient encapsulation")
             .with_recommendation(format!("Safe MSS for this path: {} bytes", actual_mss.saturating_sub(20)));
            result.add_diagnosis(conference_diag);
        }

        Ok(result)
    }

    fn estimated_duration(&self) -> u64 {
        self.timeout_secs + 2
    }
}

/// Read TCP_MAXSEG socket option to get actual negotiated MSS
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

    // Fallback: assume standard MSS
    1460
}

/// Identify tunnel type based on effective MTU
fn identify_tunnel_type(effective_mtu: u16) -> Option<&'static str> {
    // Allow +/- 10 byte tolerance for matching
    for (mtu, tunnel_type) in TUNNEL_SIGNATURES {
        if effective_mtu >= mtu.saturating_sub(10) && effective_mtu <= mtu + 10 {
            return Some(tunnel_type);
        }
    }
    None
}

/// Calculate recommended MSS for a given overhead scenario
pub fn calculate_safe_mss(base_mtu: u16, overhead: u16) -> u16 {
    let effective_mtu = base_mtu.saturating_sub(overhead);
    // MSS = MTU - 40 (20 IP + 20 TCP headers)
    effective_mtu.saturating_sub(40)
}

/// Estimate total overhead from multiple tunnel layers
pub fn estimate_layered_overhead(layers: &[&str]) -> u16 {
    layers.iter().map(|layer| {
        match *layer {
            "wireguard" | "wg" => OVERHEAD_WIREGUARD,
            "openvpn-udp" | "ovpn-udp" => OVERHEAD_OPENVPN_UDP,
            "openvpn-tcp" | "ovpn-tcp" => OVERHEAD_OPENVPN_TCP,
            "ipsec" | "ipsec-nat-t" => OVERHEAD_IPSEC_NAT_T,
            "l2tp" | "l2tp-ipsec" => OVERHEAD_L2TP_IPSEC,
            "vxlan" => OVERHEAD_VXLAN,
            "gre" => OVERHEAD_GRE,
            "geneve" => OVERHEAD_GENEVE,
            _ => 50, // Unknown tunnel, assume moderate overhead
        }
    }).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tunnel_identification() {
        assert_eq!(identify_tunnel_type(1440), Some("WireGuard"));
        assert_eq!(identify_tunnel_type(1438), Some("WireGuard")); // Within tolerance
        assert_eq!(identify_tunnel_type(1380), Some("Double encapsulation (VPN over VPN)"));
        assert_eq!(identify_tunnel_type(1500), None);
    }

    #[test]
    fn test_safe_mss_calculation() {
        assert_eq!(calculate_safe_mss(1500, 60), 1400); // WireGuard
        assert_eq!(calculate_safe_mss(1500, 120), 1340); // Double tunnel
        assert_eq!(calculate_safe_mss(1500, 0), 1460); // No overhead
    }

    #[test]
    fn test_layered_overhead() {
        // Conference AP (WireGuard) + Student VPN (OpenVPN UDP)
        let overhead = estimate_layered_overhead(&["wireguard", "openvpn-udp"]);
        assert_eq!(overhead, 130); // 60 + 70
    }

    #[test]
    fn test_struct_creation() {
        let test = TunnelMssClampingTest::new();
        assert_eq!(test.name(), "Tunnel MSS Clamping Analysis");
        assert_eq!(test.category(), TestCategory::MTU);
    }
}
