use std::net::IpAddr;
use std::net::SocketAddr;
use std::time::Duration;

use crate::probe::icmp::IP_HEADER_SIZE;

pub const UDP_HEADER_SIZE: usize = 8;

/// Probe UDP path MTU by sending UDP packets with DF bit
/// Uses a high port that's likely to get ICMP port unreachable back
pub fn probe_udp(target: IpAddr, payload_len: usize, timeout_ms: u64, retries: usize) -> bool {
    for _ in 0..=retries {
        if send_udp_probe(target, payload_len, timeout_ms).unwrap_or(false) {
            return true;
        }
    }
    false
}

pub fn send_udp_probe(target: IpAddr, payload_len: usize, timeout_ms: u64) -> std::io::Result<bool> {
    use std::net::UdpSocket;

    // Bind to any available port
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(Duration::from_millis(timeout_ms)))?;
    socket.set_write_timeout(Some(Duration::from_millis(timeout_ms)))?;

    // Set DF bit
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let val: libc::c_int = libc::IP_PMTUDISC_DO;
        unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_MTU_DISCOVER,
                &val as *const _ as *const libc::c_void,
                std::mem::size_of_val(&val) as libc::socklen_t,
            );
        }
    }

    // Create payload
    let payload = vec![0x42u8; payload_len];

    // Send to a high port (likely to get ICMP unreachable = packet arrived)
    // Port 33434 is traditional traceroute port
    let dest = SocketAddr::new(target, 33434);

    match socket.send_to(&payload, dest) {
        Ok(_) => {
            // For UDP, if send succeeds without EMSGSIZE, the packet fit
            // We can try to receive an ICMP error back
            let mut buf = [0u8; 1024];
            match socket.recv_from(&mut buf) {
                Ok(_) => Ok(true),   // Got response
                Err(e) => {
                    // Timeout is expected (no response = packet probably arrived)
                    // EMSGSIZE means too big
                    if e.raw_os_error() == Some(libc::EMSGSIZE) {
                        Ok(false)
                    } else {
                        Ok(true) // Timeout = probably worked
                    }
                }
            }
        }
        Err(e) => {
            // EMSGSIZE = message too long (MTU exceeded)
            if e.raw_os_error() == Some(libc::EMSGSIZE) {
                Ok(false)
            } else {
                Err(e)
            }
        }
    }
}

pub fn binary_search_mtu_udp(target: IpAddr, min: usize, max: usize, timeout_ms: u64, retries: usize) -> Option<usize> {
    // First check if UDP works at all
    if !probe_udp(target, 64, timeout_ms, 1) {
        return None;
    }

    let mut low = min;
    let mut high = max;
    let mut best = min;

    while low <= high {
        let mid = (low + high) / 2;
        // UDP payload = MTU - IP header - UDP header
        let payload = mid.saturating_sub(IP_HEADER_SIZE + UDP_HEADER_SIZE);

        if probe_udp(target, payload, timeout_ms, retries) {
            best = mid;
            low = mid + 1;
        } else {
            if mid == 0 {
                break;
            }
            high = mid - 1;
        }
    }

    Some(best)
}
