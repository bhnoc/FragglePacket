use socket2::{Domain, Protocol, Socket, Type};
use std::mem::MaybeUninit;
use std::net::{IpAddr, SocketAddr};
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};

pub const ICMP_ECHO_REQUEST: u8 = 8;
pub const ICMP_HEADER_SIZE: usize = 8;
pub const IP_HEADER_SIZE: usize = 20;

pub fn binary_search_mtu_icmp(target: IpAddr, min: usize, max: usize, timeout_ms: u64, retries: usize) -> usize {
    let mut low = min;
    let mut high = max;
    let mut best = min;

    while low <= high {
        let mid = (low + high) / 2;
        let payload = mid.saturating_sub(IP_HEADER_SIZE + ICMP_HEADER_SIZE);

        if probe_icmp(target, payload, timeout_ms, retries) {
            best = mid;
            low = mid + 1;
        } else {
            if mid == 0 {
                break;
            }
            high = mid - 1;
        }
    }

    best
}

pub fn probe_icmp(target: IpAddr, payload_len: usize, timeout_ms: u64, retries: usize) -> bool {
    for _ in 0..=retries {
        if send_icmp_probe(target, payload_len, timeout_ms).unwrap_or(false) {
            return true;
        }
    }
    false
}

pub fn send_icmp_probe(target: IpAddr, payload_len: usize, timeout_ms: u64) -> std::io::Result<bool> {
    let socket = Socket::new(Domain::IPV4, Type::from(libc::SOCK_RAW), Some(Protocol::ICMPV4))?;

    // Set DF bit on Linux
    #[cfg(target_os = "linux")]
    {
        let val: libc::c_int = libc::IP_PMTUDISC_DO;
        unsafe {
            let ret = libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_MTU_DISCOVER,
                &val as *const _ as *const libc::c_void,
                std::mem::size_of_val(&val) as libc::socklen_t,
            );
            if ret < 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
    }

    socket.set_read_timeout(Some(Duration::from_millis(timeout_ms)))?;

    // Build ICMP packet
    let mut packet = vec![0u8; ICMP_HEADER_SIZE + payload_len];
    packet[0] = ICMP_ECHO_REQUEST;
    packet[1] = 0;

    static SEQ: AtomicU16 = AtomicU16::new(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let id: u16 = std::process::id() as u16;

    packet[4] = (id >> 8) as u8;
    packet[5] = id as u8;
    packet[6] = (seq >> 8) as u8;
    packet[7] = seq as u8;

    // Fill payload
    for i in 0..payload_len {
        packet[ICMP_HEADER_SIZE + i] = (i % 256) as u8;
    }

    // Checksum
    let checksum = icmp_checksum(&packet);
    packet[2] = (checksum >> 8) as u8;
    packet[3] = checksum as u8;

    let dest = SocketAddr::new(target, 0);

    if socket.send_to(&packet, &dest.into()).is_err() {
        return Ok(false);
    }

    // Wait for reply
    let mut buffer = [MaybeUninit::uninit(); 4096];
    let start = Instant::now();

    loop {
        if start.elapsed().as_millis() as u64 > timeout_ms {
            return Ok(false);
        }

        match socket.recv_from(&mut buffer) {
            Ok((size, _)) => {
                let received = unsafe {
                    std::slice::from_raw_parts(buffer[0].as_ptr() as *const u8, size)
                };

                if received.len() < 20 + ICMP_HEADER_SIZE {
                    continue;
                }

                let ip_header_len = ((received[0] & 0x0F) * 4) as usize;
                if received.len() < ip_header_len + ICMP_HEADER_SIZE {
                    continue;
                }

                let icmp = &received[ip_header_len..];

                // Echo Reply (type 0) with matching ID
                if icmp[0] == 0 {
                    let reply_id = ((icmp[4] as u16) << 8) | (icmp[5] as u16);
                    if reply_id == id {
                    return Ok(true);
                }
            }
            }
            Err(_) => return Ok(false),
        }
    }
}

pub fn icmp_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in data.chunks(2) {
        let word = ((chunk[0] as u32) << 8) + chunk.get(1).map(|&b| b as u32).unwrap_or(0);
        sum = sum.wrapping_add(word);
    }
    while (sum >> 16) > 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}
