//! Shared test runner for CLI and TUI

use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};
use socket2::{Domain, Protocol, Socket, Type};
use std::os::fd::AsRawFd;
use std::mem::MaybeUninit;
use std::io::{Read, Write};

const ICMP_ECHO_REQUEST: u8 = 8;
const ICMP_HEADER_SIZE: usize = 8;
const IP_HEADER_SIZE: usize = 20;
const UDP_HEADER_SIZE: usize = 8;

#[derive(Clone, Debug)]
pub struct TestResult {
    pub target: String,
    pub desc: String,
    pub icmp_mtu: Option<usize>,
    pub tcp_mtu: Option<usize>,
    pub udp_mtu: Option<usize>,
    pub quic_mtu: Option<usize>,
    pub tcp_mss: Option<usize>,
    pub error: Option<String>,  // Error message if test failed
}

pub fn resolve_hostname(host: &str) -> Result<IpAddr, String> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ip);
    }
    
    let addr = format!("{}:80", host);
    match addr.to_socket_addrs() {
        Ok(mut addrs) => {
            if let Some(addr) = addrs.next() {
                Ok(addr.ip())
            } else {
                Err("No addresses returned".into())
            }
        }
        Err(e) => Err(e.to_string()),
    }
}

pub fn probe_icmp(target: IpAddr, payload_len: usize, timeout_ms: u64, retries: usize) -> bool {
    for _ in 0..=retries {
        if send_icmp_probe(target, payload_len, timeout_ms).unwrap_or(false) {
            return true;
        }
    }
    false
}

fn send_icmp_probe(target: IpAddr, payload_len: usize, timeout_ms: u64) -> std::io::Result<bool> {
    let socket = Socket::new(Domain::IPV4, Type::from(libc::SOCK_RAW), Some(Protocol::ICMPV4))?;

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

    for i in 0..payload_len {
        packet[ICMP_HEADER_SIZE + i] = (i % 256) as u8;
    }

    let checksum = icmp_checksum(&packet);
    packet[2] = (checksum >> 8) as u8;
    packet[3] = checksum as u8;

    let dest = SocketAddr::new(target, 0);

    // Send packet - if it fails with EMSGSIZE, packet is too large for MTU
    match socket.send_to(&packet, &dest.into()) {
        Ok(_) => {}, // Sent successfully
        Err(e) => {
            // Check if error is EMSGSIZE (message too long - MTU exceeded)
            if e.raw_os_error() == Some(libc::EMSGSIZE) {
                return Ok(false);  // MTU exceeded
            }
            // Other errors - network unreachable, etc
            return Err(e);
        }
    }

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

pub fn binary_search_mtu_icmp(target: IpAddr, min: usize, max: usize, timeout_ms: u64, retries: usize) -> usize {
    let mut low = min;
    let mut high = max;
    let mut best = min;

    while low <= high {
        let mid = (low + high) / 2;
        let payload = mid.saturating_sub(IP_HEADER_SIZE + ICMP_HEADER_SIZE);

        let probe_result = probe_icmp(target, payload, timeout_ms, retries);
        
        if probe_result {
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

pub fn binary_search_mtu_tcp(target: &str, min: usize, max: usize, timeout_ms: u64) -> Option<usize> {
    let addr: SocketAddr = target.to_socket_addrs().ok()?.next()?;
    
    // For HTTPS (port 443), derive MTU from TCP MSS instead of binary search
    // TCP MSS is negotiated during handshake and is more reliable
    // MSS is the data payload size, so MTU = MSS + 40 (20 IP + 20 TCP headers)
    if addr.port() == 443 {
        // Get TCP MSS and derive MTU from it
        if let Some(mss) = probe_tcp_mss(target, timeout_ms) {
            // MTU = MSS + IP header (20) + TCP header (20)
            let derived_mtu = mss + 40;
            return Some(derived_mtu);
        }
        return None;
    }
    
    let timeout = Duration::from_millis(timeout_ms);

    let mut low = min;
    let mut high = max;
    let mut best = None;

    while low <= high {
        let mid = (low + high) / 2;
        let payload_size = mid.saturating_sub(40);

        if probe_tcp(&addr, payload_size, timeout) {
            best = Some(mid);
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

fn probe_tcp(addr: &SocketAddr, payload_size: usize, timeout: Duration) -> bool {
    let mut stream = match TcpStream::connect_timeout(addr, timeout) {
        Ok(s) => s,
        Err(_) => return false,
    };
    
    stream.set_write_timeout(Some(timeout)).ok();
    stream.set_read_timeout(Some(timeout)).ok();
    stream.set_nodelay(true).ok();
    
    // Set DF bit for PMTUD on Linux
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let val: libc::c_int = libc::IP_PMTUDISC_DO;
        unsafe {
            libc::setsockopt(
                stream.as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_MTU_DISCOVER,
                &val as *const _ as *const libc::c_void,
                std::mem::size_of_val(&val) as libc::socklen_t,
            );
        }
    }
    
    // Try to send data and see if we get EMSGSIZE (MTU exceeded)
    let test_data = vec![0u8; payload_size.min(1460)];  // Limit to reasonable size
    
    match stream.write_all(&test_data) {
        Ok(_) => {
            // Data sent successfully - try to flush
            if stream.flush().is_ok() {
                // Wait a bit to see if we get an ICMP error back
                thread::sleep(Duration::from_millis(50));
                
                // Try to read - if we get EMSGSIZE, MTU exceeded
                let mut buf = [0u8; 1];
                match stream.read(&mut buf) {
                    Ok(_) => true,  // Got response, MTU works
                    Err(e) => {
                        if e.raw_os_error() == Some(libc::EMSGSIZE) {
                            false  // MTU exceeded
                        } else {
                            // Other error - assume it worked (timeout is OK)
                            true
                        }
                    }
                }
            } else {
                false
            }
        }
        Err(e) => {
            // Check for EMSGSIZE (MTU exceeded) - this is the key indicator
            if e.raw_os_error() == Some(libc::EMSGSIZE) {
                false
            } else {
                // Other errors might be network issues, not MTU
                false
            }
        }
    }
}

pub fn binary_search_mtu_udp(target: IpAddr, min: usize, max: usize, timeout_ms: u64, retries: usize) -> Option<usize> {
    if !probe_udp(target, 64, timeout_ms, 1) {
        return None;
    }
    
    let mut low = min;
    let mut high = max;
    let mut best = min;

    while low <= high {
        let mid = (low + high) / 2;
        let payload = mid.saturating_sub(IP_HEADER_SIZE + UDP_HEADER_SIZE);

        let probe_result = probe_udp(target, payload, timeout_ms, retries);
        
        if probe_result {
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

fn probe_udp(target: IpAddr, payload_len: usize, timeout_ms: u64, retries: usize) -> bool {
    for _ in 0..=retries {
        if send_udp_probe(target, payload_len, timeout_ms).unwrap_or(false) {
            return true;
        }
    }
    false
}

fn send_udp_probe(target: IpAddr, payload_len: usize, timeout_ms: u64) -> std::io::Result<bool> {
    use std::net::UdpSocket;
    
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(Duration::from_millis(timeout_ms)))?;
    socket.set_write_timeout(Some(Duration::from_millis(timeout_ms)))?;
    
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
    
    let payload = vec![0x42u8; payload_len];
    let dest = SocketAddr::new(target, 33434);
    
    // Try to send - EMSGSIZE means packet too large for path MTU
    match socket.send_to(&payload, dest) {
        Ok(_) => {
            let mut buf = [0u8; 1024];
            match socket.recv_from(&mut buf) {
                Ok(_) => Ok(true),  // Got a reply
                Err(e) => {
                    if e.raw_os_error() == Some(libc::EMSGSIZE) {
                        Ok(false)  // MTU exceeded
                    } else {
                        // Timeout or other error - assume packet was delivered
                        Ok(true)
                    }
                }
            }
        }
        Err(e) => {
            if e.raw_os_error() == Some(libc::EMSGSIZE) {
                Ok(false)  // MTU exceeded
            } else {
                Err(e)
            }
        }
    }
}

pub fn probe_tcp_mss(target: &str, timeout_ms: u64) -> Option<usize> {
    let addr: SocketAddr = target.to_socket_addrs().ok()?.next()?;
    let timeout = Duration::from_millis(timeout_ms);
    
    let mut stream = TcpStream::connect_timeout(&addr, timeout).ok()?;
    stream.set_nodelay(true).ok();
    
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        
        let mut mss: libc::c_int = 0;
        let mut len: libc::socklen_t = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        
        unsafe {
            let ret = libc::getsockopt(
                stream.as_raw_fd(),
                libc::IPPROTO_TCP,
                libc::TCP_MAXSEG,
                &mut mss as *mut _ as *mut libc::c_void,
                &mut len,
            );
            
            if ret == 0 && mss > 0 {
                if addr.port() == 443 {
                    let test_data = vec![0u8; 1000];
                    if stream.write_all(&test_data).is_ok() {
                        drop(stream);
                        return Some(mss as usize);
                    }
                }
                
                drop(stream);
                return Some(mss as usize);
            }
        }
    }
    
    drop(stream);
    None
}

pub fn probe_quic_mtu(target: &str, port: u16, timeout_ms: u64) -> Option<usize> {
    let ip = if let Ok(ip) = target.parse::<IpAddr>() {
        ip
    } else {
        resolve_hostname(target).ok()?
    };
    
    let timeout = Duration::from_millis(timeout_ms);
    
    let mut low = 1200;  // QUIC minimum
    let mut high = 1500;
    let mut best = 1200;
    
    while low <= high {
        let mid = (low + high) / 2;
        
        if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") {
            socket.set_read_timeout(Some(timeout)).ok();
            socket.set_write_timeout(Some(timeout)).ok();
            
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
            
            let payload = vec![0xc0u8; mid];
            let dest = std::net::SocketAddr::new(ip, port);
            
            match socket.send_to(&payload, dest) {
                Ok(_) => {
                    best = mid;
                    low = mid + 1;
                }
                Err(e) => {
                    if e.raw_os_error() == Some(libc::EMSGSIZE) {
                        high = mid - 1;
                    } else {
                        high = mid - 1;
                    }
                }
            }
        } else {
            return None;
        }
    }
    
    if best > 1200 {
        Some(best)
    } else {
        None
    }
}

fn icmp_checksum(data: &[u8]) -> u16 {
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

pub fn load_targets() -> Vec<(String, String, u16)> {
    let default_targets = vec![
        ("8.8.8.8", "Google DNS", 0),
        ("1.1.1.1", "Cloudflare DNS", 0),
        ("9.9.9.9", "Quad9 DNS", 0),
        ("github.com", "GitHub", 443),
        ("outlook.office365.com", "M365 Outlook", 443),
        ("teams.microsoft.com", "MS Teams", 443),
        ("login.microsoftonline.com", "M365 Auth", 443),
        ("aws.amazon.com", "AWS", 443),
        ("azure.microsoft.com", "Azure", 443),
        ("mail.google.com", "Gmail", 443),
    ];

    let targets_file = std::path::Path::new("targets.txt");
    if targets_file.exists() {
        if let Ok(content) = std::fs::read_to_string(targets_file) {
            let mut targets = Vec::new();
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let parts: Vec<&str> = line.split(',').collect();
                if parts.len() >= 2 {
                    let target = parts[0].trim().to_string();
                    let desc = parts[1].trim().to_string();
                    let port: u16 = parts.get(2).and_then(|p| p.trim().parse().ok()).unwrap_or(443);
                    targets.push((target, desc, port));
                }
            }
            if !targets.is_empty() {
                return targets;
            }
        }
    }

    default_targets.iter().map(|(t, d, p)| (t.to_string(), d.to_string(), *p)).collect()
}

pub fn test_single_target(target: &str, desc: &str, port: u16, min_mtu: usize, max_mtu: usize, timeout_ms: u64, retries: usize) -> TestResult {
    let mut result = TestResult {
        target: target.to_string(),
        desc: desc.to_string(),
        icmp_mtu: None,
        tcp_mtu: None,
        udp_mtu: None,
        quic_mtu: None,
        tcp_mss: None,
        error: None,
    };

    let ip = if let Ok(ip) = target.parse::<IpAddr>() {
        ip
    } else {
        match resolve_hostname(target) {
            Ok(ip) => ip,
            Err(e) => {
                result.error = Some(format!("DNS resolution failed: {}", e));
                return result;
            }
        }
    };

    let (tx, rx) = mpsc::channel();
    
    let ip_clone = ip;
    let tx_icmp = tx.clone();
    thread::spawn(move || {
        if probe_icmp(ip_clone, 64, timeout_ms, 1) {
            let mtu = binary_search_mtu_icmp(ip_clone, min_mtu, max_mtu, timeout_ms, retries);
            let _ = tx_icmp.send(("icmp", Some(mtu)));
        } else {
            let _ = tx_icmp.send(("icmp", None));
        }
    });
    
    let ip_clone = ip;
    let tx_udp = tx.clone();
    thread::spawn(move || {
        let mtu = binary_search_mtu_udp(ip_clone, min_mtu, max_mtu, timeout_ms, retries);
        let _ = tx_udp.send(("udp", mtu));
    });
    
    if port > 0 {
        let tcp_target = format!("{}:{}", target, port);
        let tcp_target_clone = tcp_target.clone();
        let tx_tcp = tx.clone();
        thread::spawn(move || {
            let mtu = binary_search_mtu_tcp(&tcp_target_clone, min_mtu, max_mtu, timeout_ms);
            let _ = tx_tcp.send(("tcp", mtu));
        });
        
        let tcp_target_clone = tcp_target.clone();
        let tx_mss = tx.clone();
        thread::spawn(move || {
            let mss = probe_tcp_mss(&tcp_target_clone, timeout_ms);
            let _ = tx_mss.send(("mss", mss));
        });
        
        if port == 443 {
            let target_clone = target.to_string();
            let tx_quic = tx.clone();
            thread::spawn(move || {
                let mtu = probe_quic_mtu(&target_clone, port, timeout_ms);
                let _ = tx_quic.send(("quic", mtu));
            });
        }
    }
    
    drop(tx);
    let expected = if port > 0 && port == 443 { 5 } else if port > 0 { 4 } else { 2 };
    let mut received = 0;
    let deadline = Instant::now() + Duration::from_secs(60);
    
    while received < expected && Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok((proto, value)) => {
                match proto {
                    "icmp" => result.icmp_mtu = value,
                    "udp" => result.udp_mtu = value,
                    "tcp" => result.tcp_mtu = value,
                    "mss" => result.tcp_mss = value,
                    "quic" => result.quic_mtu = value,
                    _ => {}
                }
                received += 1;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                continue;
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                break;
            }
        }
    }

    result
}
