//! PCAP Replay Engine
//!
//! Rust-native replacement for `tcpreplay`. Reads a PCAP (any file the fuzzers
//! produce), optionally rewrites source/destination MAC or IP addresses, and
//! writes each packet to a raw socket.
//!
//! Backends:
//!   * Linux uses AF_PACKET (SOCK_RAW, ETH_P_ALL) for L2 send.
//!   * macOS/BSD use IP_HDRINCL raw sockets for L3 send (Ethernet header is
//!     stripped before sending since BSD raw sockets speak at layer 3).
//!   * Unsupported platforms return `ReplayError::Unsupported`.

use pcap_file::pcap::PcapReader;
use std::fs::File;
use std::net::Ipv4Addr;
use std::path::Path;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Default)]
pub struct ReplayOptions {
    pub iface: Option<String>,
    pub pps: Option<u32>,
    pub loop_count: u32,
    pub rewrite_src_mac: Option<[u8; 6]>,
    pub rewrite_dst_mac: Option<[u8; 6]>,
    pub rewrite_src_ip: Option<Ipv4Addr>,
    pub rewrite_dst_ip: Option<Ipv4Addr>,
    pub preserve_timing: bool,
}

impl ReplayOptions {
    pub fn new() -> Self {
        Self {
            loop_count: 1,
            ..Default::default()
        }
    }
    pub fn iface(mut self, iface: impl Into<String>) -> Self {
        self.iface = Some(iface.into());
        self
    }
    pub fn pps(mut self, pps: u32) -> Self {
        self.pps = Some(pps);
        self
    }
    pub fn loop_count(mut self, n: u32) -> Self {
        self.loop_count = n.max(1);
        self
    }
    pub fn rewrite_src_ip(mut self, ip: Ipv4Addr) -> Self {
        self.rewrite_src_ip = Some(ip);
        self
    }
    pub fn rewrite_dst_ip(mut self, ip: Ipv4Addr) -> Self {
        self.rewrite_dst_ip = Some(ip);
        self
    }
    pub fn rewrite_src_mac(mut self, mac: [u8; 6]) -> Self {
        self.rewrite_src_mac = Some(mac);
        self
    }
    pub fn rewrite_dst_mac(mut self, mac: [u8; 6]) -> Self {
        self.rewrite_dst_mac = Some(mac);
        self
    }
}

#[derive(Debug, Clone, Default)]
pub struct ReplayReport {
    pub packets_sent: u64,
    pub bytes_sent: u64,
    pub packets_dropped: u64,
    pub duration_ms: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum ReplayError {
    #[error("IO: {0}")]
    Io(#[from] std::io::Error),
    #[error("PCAP read: {0}")]
    Pcap(String),
    #[error("Root/admin privileges required to open raw socket")]
    NeedsRoot,
    #[error("Interface '{0}' not found")]
    InterfaceNotFound(String),
    #[error("Platform unsupported for raw sending")]
    Unsupported,
    #[error("Send error: {0}")]
    Send(String),
    #[error("Missing interface name (ReplayOptions.iface is required on this platform)")]
    MissingInterface,
}

/// High-level entry point: replay a PCAP file with the given options.
pub fn replay_pcap<P: AsRef<Path>>(
    path: P,
    opts: &ReplayOptions,
) -> Result<ReplayReport, ReplayError> {
    let mut report = ReplayReport::default();
    let start = Instant::now();

    let mut packets: Vec<(Duration, Vec<u8>)> = Vec::new();
    {
        let file = File::open(path.as_ref())?;
        let mut reader = PcapReader::new(file).map_err(|e| ReplayError::Pcap(e.to_string()))?;
        while let Some(pkt) = reader.next_packet() {
            let pkt = pkt.map_err(|e| ReplayError::Pcap(e.to_string()))?;
            packets.push((pkt.timestamp, pkt.data.to_vec()));
        }
    }

    if packets.is_empty() {
        report.duration_ms = start.elapsed().as_millis() as u64;
        return Ok(report);
    }

    let mut sender = build_sender(opts)?;
    let interval = opts
        .pps
        .map(|r| Duration::from_secs_f64(1.0 / r as f64))
        .unwrap_or(Duration::ZERO);

    for _ in 0..opts.loop_count {
        let mut last_tick = Instant::now();
        for (_, data) in &packets {
            let mut bytes = data.clone();
            apply_rewrites(&mut bytes, opts);
            match sender.send(&bytes) {
                Ok(n) => {
                    report.packets_sent += 1;
                    report.bytes_sent += n as u64;
                }
                Err(e) => {
                    report.packets_dropped += 1;
                    log::warn!("replay send failed: {}", e);
                }
            }
            if interval > Duration::ZERO {
                let elapsed = last_tick.elapsed();
                if interval > elapsed {
                    std::thread::sleep(interval - elapsed);
                }
                last_tick = Instant::now();
            }
        }
    }

    report.duration_ms = start.elapsed().as_millis() as u64;
    Ok(report)
}

fn apply_rewrites(bytes: &mut [u8], opts: &ReplayOptions) {
    if bytes.len() < 14 {
        return;
    }
    if let Some(mac) = opts.rewrite_dst_mac {
        bytes[0..6].copy_from_slice(&mac);
    }
    if let Some(mac) = opts.rewrite_src_mac {
        bytes[6..12].copy_from_slice(&mac);
    }
    let ethertype = u16::from_be_bytes([bytes[12], bytes[13]]);
    if ethertype != 0x0800 {
        return;
    }
    let ip_start = 14;
    if bytes.len() < ip_start + 20 {
        return;
    }
    if let Some(ip) = opts.rewrite_src_ip {
        bytes[ip_start + 12..ip_start + 16].copy_from_slice(&ip.octets());
    }
    if let Some(ip) = opts.rewrite_dst_ip {
        bytes[ip_start + 16..ip_start + 20].copy_from_slice(&ip.octets());
    }
    if opts.rewrite_src_ip.is_some() || opts.rewrite_dst_ip.is_some() {
        recompute_ipv4_checksum(&mut bytes[ip_start..]);
    }
}

fn recompute_ipv4_checksum(ip_bytes: &mut [u8]) {
    if ip_bytes.len() < 20 {
        return;
    }
    let ihl = (ip_bytes[0] & 0x0F) as usize * 4;
    if ip_bytes.len() < ihl {
        return;
    }
    ip_bytes[10] = 0;
    ip_bytes[11] = 0;
    let mut sum: u32 = 0;
    for i in (0..ihl).step_by(2) {
        let w = ((ip_bytes[i] as u32) << 8) | (ip_bytes[i + 1] as u32);
        sum = sum.wrapping_add(w);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    let cs = !(sum as u16);
    ip_bytes[10] = (cs >> 8) as u8;
    ip_bytes[11] = (cs & 0xFF) as u8;
}

trait RawSender {
    fn send(&mut self, bytes: &[u8]) -> Result<usize, ReplayError>;
}

#[cfg(target_os = "linux")]
fn build_sender(opts: &ReplayOptions) -> Result<Box<dyn RawSender>, ReplayError> {
    
    let iface = opts.iface.as_deref().ok_or(ReplayError::MissingInterface)?;
    let sock = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            (libc::ETH_P_ALL as u16).to_be() as i32,
        )
    };
    if sock < 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EPERM) {
            return Err(ReplayError::NeedsRoot);
        }
        return Err(ReplayError::Io(err));
    }
    let ifindex = unsafe {
        let c_iface = std::ffi::CString::new(iface).unwrap();
        libc::if_nametoindex(c_iface.as_ptr())
    } as i32;
    if ifindex == 0 {
        unsafe { libc::close(sock) };
        return Err(ReplayError::InterfaceNotFound(iface.to_string()));
    }
    let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    addr.sll_family = libc::AF_PACKET as u16;
    addr.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
    addr.sll_ifindex = ifindex;
    let bind_ret = unsafe {
        libc::bind(
            sock,
            &addr as *const libc::sockaddr_ll as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as u32,
        )
    };
    if bind_ret < 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(sock) };
        return Err(ReplayError::Io(err));
    }
    struct Linux {
        fd: i32,
    }
    impl Drop for Linux {
        fn drop(&mut self) {
            unsafe { libc::close(self.fd) };
        }
    }
    impl RawSender for Linux {
        fn send(&mut self, bytes: &[u8]) -> Result<usize, ReplayError> {
            let n = unsafe {
                libc::send(
                    self.fd,
                    bytes.as_ptr() as *const libc::c_void,
                    bytes.len(),
                    0,
                )
            };
            if n < 0 {
                Err(ReplayError::Send(
                    std::io::Error::last_os_error().to_string(),
                ))
            } else {
                Ok(n as usize)
            }
        }
    }
    let _ = <std::fs::File as std::os::unix::io::AsRawFd>::as_raw_fd;
    Ok(Box::new(Linux { fd: sock }))
}

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
fn build_sender(_opts: &ReplayOptions) -> Result<Box<dyn RawSender>, ReplayError> {
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW) };
    if sock < 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EPERM) {
            return Err(ReplayError::NeedsRoot);
        }
        return Err(ReplayError::Io(err));
    }
    let one: libc::c_int = 1;
    let ret = unsafe {
        libc::setsockopt(
            sock,
            libc::IPPROTO_IP,
            libc::IP_HDRINCL,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as u32,
        )
    };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(sock) };
        return Err(ReplayError::Io(err));
    }
    struct Bsd {
        fd: i32,
    }
    impl Drop for Bsd {
        fn drop(&mut self) {
            unsafe { libc::close(self.fd) };
        }
    }
    impl RawSender for Bsd {
        fn send(&mut self, frame: &[u8]) -> Result<usize, ReplayError> {
            if frame.len() < 14 {
                return Err(ReplayError::Send("frame too short".into()));
            }
            let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
            if ethertype != 0x0800 {
                return Err(ReplayError::Send(
                    "BSD raw send only supports IPv4 frames".into(),
                ));
            }
            let ip = &frame[14..];
            if ip.len() < 20 {
                return Err(ReplayError::Send("ip header too short".into()));
            }
            let dst = Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]);
            let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            addr.sin_family = libc::AF_INET as u8;
            addr.sin_port = 0;
            addr.sin_addr = libc::in_addr {
                s_addr: u32::from(dst).to_be(),
            };
            let n = unsafe {
                libc::sendto(
                    self.fd,
                    ip.as_ptr() as *const libc::c_void,
                    ip.len(),
                    0,
                    &addr as *const libc::sockaddr_in as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as u32,
                )
            };
            if n < 0 {
                Err(ReplayError::Send(
                    std::io::Error::last_os_error().to_string(),
                ))
            } else {
                Ok(n as usize)
            }
        }
    }
    Ok(Box::new(Bsd { fd: sock }))
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "freebsd")))]
fn build_sender(_opts: &ReplayOptions) -> Result<Box<dyn RawSender>, ReplayError> {
    Err(ReplayError::Unsupported)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrite_ipv4_src_dst() {
        let mut frame = vec![0u8; 14 + 20];
        frame[12] = 0x08;
        frame[13] = 0x00;
        frame[14] = 0x45;
        frame[14 + 12..14 + 16].copy_from_slice(&[10, 0, 0, 1]);
        frame[14 + 16..14 + 20].copy_from_slice(&[10, 0, 0, 2]);
        let opts = ReplayOptions::new()
            .rewrite_src_ip(Ipv4Addr::new(1, 2, 3, 4))
            .rewrite_dst_ip(Ipv4Addr::new(5, 6, 7, 8));
        apply_rewrites(&mut frame, &opts);
        assert_eq!(&frame[14 + 12..14 + 16], &[1, 2, 3, 4]);
        assert_eq!(&frame[14 + 16..14 + 20], &[5, 6, 7, 8]);
    }
}
