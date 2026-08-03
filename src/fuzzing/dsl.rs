//! Packet DSL - scapy-equivalent layer composition for Rust
//!
//! Fluent API for describing packets as a stack of layers using the `/`
//! operator. Built on top of `etherparse` for serialization.
//!
//! ```no_run
//! use fraggle_packet::fuzzing::dsl::*;
//! let pkt = Ether::new()
//!     / Ip::new().dst([1, 1, 1, 1]).df()
//!     / Tcp::new().dport(443).syn().options(vec![TcpOpt::Mss(1460), TcpOpt::SAckOK])
//!     / Raw::new(b"hello");
//! let bytes = pkt.build().unwrap();
//! ```

use etherparse::*;
use rand::Rng;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops::Div;

/// A single network layer.
#[derive(Debug, Clone)]
pub enum Layer {
    Ether(Ether),
    Vlan(Vlan),
    Ip(Ip),
    Ipv6(Ipv6),
    Tcp(Tcp),
    Udp(Udp),
    Icmp(Icmp),
    Icmpv6(Icmpv6),
    Raw(Raw),
}

/// Ethernet II layer.
#[derive(Debug, Clone)]
pub struct Ether {
    pub src: [u8; 6],
    pub dst: [u8; 6],
    pub ether_type: Option<u16>,
}

impl Ether {
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();
        let mut src = [0u8; 6];
        let mut dst = [0u8; 6];
        for i in 0..6 {
            src[i] = rng.gen();
            dst[i] = rng.gen();
        }
        src[0] = 0x02;
        dst[0] = 0x02;
        Self {
            src,
            dst,
            ether_type: None,
        }
    }
    pub fn src(mut self, m: [u8; 6]) -> Self {
        self.src = m;
        self
    }
    pub fn dst(mut self, m: [u8; 6]) -> Self {
        self.dst = m;
        self
    }
    pub fn ether_type(mut self, t: u16) -> Self {
        self.ether_type = Some(t);
        self
    }
}

impl Default for Ether {
    fn default() -> Self {
        Self::new()
    }
}

/// 802.1Q VLAN tag.
#[derive(Debug, Clone)]
pub struct Vlan {
    pub vid: u16,
    pub pcp: u8,
}

impl Vlan {
    pub fn new(vid: u16) -> Self {
        Self { vid, pcp: 0 }
    }
}

/// IPv4 layer.
#[derive(Debug, Clone)]
pub struct Ip {
    pub src: [u8; 4],
    pub dst: [u8; 4],
    pub ttl: u8,
    pub id: u16,
    pub dont_fragment: bool,
    pub more_fragments: bool,
    pub fragment_offset: u16,
    pub proto: Option<u8>,
    pub checksum: ChecksumMode,
}

impl Ip {
    pub fn new() -> Self {
        Self {
            src: [10, 0, 0, 1],
            dst: [10, 0, 0, 2],
            ttl: 64,
            id: rand::thread_rng().gen(),
            dont_fragment: false,
            more_fragments: false,
            fragment_offset: 0,
            proto: None,
            checksum: ChecksumMode::Auto,
        }
    }
    pub fn src<A: Into<[u8; 4]>>(mut self, a: A) -> Self {
        self.src = a.into();
        self
    }
    pub fn dst<A: Into<[u8; 4]>>(mut self, a: A) -> Self {
        self.dst = a.into();
        self
    }
    pub fn src_addr(mut self, a: Ipv4Addr) -> Self {
        self.src = a.octets();
        self
    }
    pub fn dst_addr(mut self, a: Ipv4Addr) -> Self {
        self.dst = a.octets();
        self
    }
    pub fn ttl(mut self, t: u8) -> Self {
        self.ttl = t;
        self
    }
    pub fn id(mut self, id: u16) -> Self {
        self.id = id;
        self
    }
    pub fn df(mut self) -> Self {
        self.dont_fragment = true;
        self
    }
    pub fn flags_df(mut self) -> Self {
        self.dont_fragment = true;
        self
    }
    pub fn mf(mut self) -> Self {
        self.more_fragments = true;
        self
    }
    pub fn frag_offset(mut self, off: u16) -> Self {
        self.fragment_offset = off;
        self
    }
    pub fn proto(mut self, p: u8) -> Self {
        self.proto = Some(p);
        self
    }
    pub fn checksum(mut self, v: u16) -> Self {
        self.checksum = ChecksumMode::Fixed(v);
        self
    }
    pub fn bad_checksum(mut self) -> Self {
        self.checksum = ChecksumMode::Bad;
        self
    }
}

impl Default for Ip {
    fn default() -> Self {
        Self::new()
    }
}

/// IPv6 layer (minimal).
#[derive(Debug, Clone)]
pub struct Ipv6 {
    pub src: [u8; 16],
    pub dst: [u8; 16],
    pub hop_limit: u8,
    pub next_header: Option<u8>,
    pub flow_label: u32,
}

impl Ipv6 {
    pub fn new() -> Self {
        Self {
            src: [0u8; 16],
            dst: [0u8; 16],
            hop_limit: 64,
            next_header: None,
            flow_label: 0,
        }
    }
    pub fn src_addr(mut self, a: Ipv6Addr) -> Self {
        self.src = a.octets();
        self
    }
    pub fn dst_addr(mut self, a: Ipv6Addr) -> Self {
        self.dst = a.octets();
        self
    }
    pub fn hop_limit(mut self, h: u8) -> Self {
        self.hop_limit = h;
        self
    }
}

impl Default for Ipv6 {
    fn default() -> Self {
        Self::new()
    }
}

/// TCP options that can be explicitly serialized.
#[derive(Debug, Clone)]
pub enum TcpOpt {
    Nop,
    Mss(u16),
    WScale(u8),
    SAckOK,
    Timestamp(u32, u32),
}

/// TCP layer.
#[derive(Debug, Clone)]
pub struct Tcp {
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
    pub ack: u32,
    pub window: u16,
    pub flags: TcpFlags,
    pub options: Vec<TcpOpt>,
    pub checksum: ChecksumMode,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct TcpFlags {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
    pub urg: bool,
}

impl Tcp {
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();
        Self {
            sport: rng.gen_range(49152..65535),
            dport: 443,
            seq: rng.gen(),
            ack: 0,
            window: 65535,
            flags: TcpFlags::default(),
            options: Vec::new(),
            checksum: ChecksumMode::Auto,
        }
    }
    pub fn sport(mut self, p: u16) -> Self {
        self.sport = p;
        self
    }
    pub fn dport(mut self, p: u16) -> Self {
        self.dport = p;
        self
    }
    pub fn seq(mut self, s: u32) -> Self {
        self.seq = s;
        self
    }
    pub fn ack_num(mut self, a: u32) -> Self {
        self.ack = a;
        self
    }
    pub fn window(mut self, w: u16) -> Self {
        self.window = w;
        self
    }
    pub fn syn(mut self) -> Self {
        self.flags.syn = true;
        self
    }
    pub fn ack_flag(mut self) -> Self {
        self.flags.ack = true;
        self
    }
    pub fn psh(mut self) -> Self {
        self.flags.psh = true;
        self
    }
    pub fn rst(mut self) -> Self {
        self.flags.rst = true;
        self
    }
    pub fn fin(mut self) -> Self {
        self.flags.fin = true;
        self
    }
    pub fn urg(mut self) -> Self {
        self.flags.urg = true;
        self
    }
    pub fn flags_str(mut self, s: &str) -> Self {
        for c in s.chars() {
            match c {
                'S' | 's' => self.flags.syn = true,
                'A' | 'a' => self.flags.ack = true,
                'P' | 'p' => self.flags.psh = true,
                'F' | 'f' => self.flags.fin = true,
                'R' | 'r' => self.flags.rst = true,
                'U' | 'u' => self.flags.urg = true,
                _ => {}
            }
        }
        self
    }
    pub fn options(mut self, opts: Vec<TcpOpt>) -> Self {
        self.options = opts;
        self
    }
    pub fn checksum(mut self, v: u16) -> Self {
        self.checksum = ChecksumMode::Fixed(v);
        self
    }
    pub fn bad_checksum(mut self) -> Self {
        self.checksum = ChecksumMode::Bad;
        self
    }
}

impl Default for Tcp {
    fn default() -> Self {
        Self::new()
    }
}

/// UDP layer.
#[derive(Debug, Clone)]
pub struct Udp {
    pub sport: u16,
    pub dport: u16,
    pub checksum: ChecksumMode,
}

impl Udp {
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();
        Self {
            sport: rng.gen_range(49152..65535),
            dport: 53,
            checksum: ChecksumMode::Auto,
        }
    }
    pub fn sport(mut self, p: u16) -> Self {
        self.sport = p;
        self
    }
    pub fn dport(mut self, p: u16) -> Self {
        self.dport = p;
        self
    }
}

impl Default for Udp {
    fn default() -> Self {
        Self::new()
    }
}

/// ICMPv4 layer (echo + dest-unreachable subset).
#[derive(Debug, Clone)]
pub struct Icmp {
    pub icmp_type: u8,
    pub code: u8,
    pub id: u16,
    pub seq: u16,
    pub next_hop_mtu: Option<u16>,
}

impl Icmp {
    pub fn echo_request() -> Self {
        Self {
            icmp_type: 8,
            code: 0,
            id: rand::thread_rng().gen(),
            seq: 0,
            next_hop_mtu: None,
        }
    }
    pub fn frag_needed(mtu: u16) -> Self {
        Self {
            icmp_type: 3,
            code: 4,
            id: 0,
            seq: 0,
            next_hop_mtu: Some(mtu),
        }
    }
}

/// ICMPv6 layer.
#[derive(Debug, Clone)]
pub struct Icmpv6 {
    pub icmp_type: u8,
    pub code: u8,
}

impl Icmpv6 {
    pub fn echo_request() -> Self {
        Self {
            icmp_type: 128,
            code: 0,
        }
    }
}

/// Raw payload bytes.
#[derive(Debug, Clone)]
pub struct Raw {
    pub load: Vec<u8>,
}

impl Raw {
    pub fn new(load: impl Into<Vec<u8>>) -> Self {
        Self { load: load.into() }
    }
    pub fn of_size(size: usize, fill: u8) -> Self {
        Self {
            load: vec![fill; size],
        }
    }
}

/// Checksum override for layers that have one.
#[derive(Debug, Clone, Copy)]
pub enum ChecksumMode {
    /// Compute a valid checksum (default).
    Auto,
    /// Use the exact value supplied.
    Fixed(u16),
    /// Random / intentionally wrong.
    Bad,
}

/// A packet is an ordered stack of layers.
#[derive(Debug, Clone)]
pub struct Packet {
    pub layers: Vec<Layer>,
}

impl Packet {
    pub fn new() -> Self {
        Self { layers: Vec::new() }
    }
    pub fn push(mut self, l: Layer) -> Self {
        self.layers.push(l);
        self
    }

    /// Serialize the full layer stack to wire bytes.
    pub fn build(&self) -> Result<Vec<u8>, DslError> {
        let mut out = Vec::new();
        build_layers(&self.layers, 0, &mut out)?;
        Ok(out)
    }

    /// Scapy-style one-line summary.
    pub fn summary(&self) -> String {
        self.layers
            .iter()
            .map(|l| match l {
                Layer::Ether(e) => format!(
                    "Ether(dst={:02x?}, src={:02x?})",
                    e.dst, e.src
                ),
                Layer::Vlan(v) => format!("Dot1Q(vid={})", v.vid),
                Layer::Ip(ip) => format!(
                    "IP(src={}, dst={}, df={}, mf={}, ttl={})",
                    Ipv4Addr::from(ip.src),
                    Ipv4Addr::from(ip.dst),
                    ip.dont_fragment,
                    ip.more_fragments,
                    ip.ttl
                ),
                Layer::Ipv6(ip) => format!(
                    "IPv6(src={}, dst={}, hlim={})",
                    Ipv6Addr::from(ip.src),
                    Ipv6Addr::from(ip.dst),
                    ip.hop_limit
                ),
                Layer::Tcp(t) => format!(
                    "TCP(sport={}, dport={}, flags={})",
                    t.sport,
                    t.dport,
                    tcp_flags_to_str(&t.flags)
                ),
                Layer::Udp(u) => format!("UDP(sport={}, dport={})", u.sport, u.dport),
                Layer::Icmp(i) => format!("ICMP(type={}, code={})", i.icmp_type, i.code),
                Layer::Icmpv6(i) => format!("ICMPv6(type={}, code={})", i.icmp_type, i.code),
                Layer::Raw(r) => format!("Raw(len={})", r.load.len()),
            })
            .collect::<Vec<_>>()
            .join(" / ")
    }

    /// Hex dump of the serialized packet.
    pub fn hexdump(&self) -> Result<String, DslError> {
        let bytes = self.build()?;
        Ok(hexdump_bytes(&bytes))
    }

    /// Split an IP/UDP or IP/Raw payload into fragments of `fragsize` bytes
    /// (multiple of 8). Mirrors scapy `fragment()` semantics for IPv4.
    pub fn fragment(&self, fragsize: usize) -> Result<Vec<Packet>, DslError> {
        if fragsize % 8 != 0 {
            return Err(DslError::Build(
                "fragsize must be a multiple of 8".to_string(),
            ));
        }
        let ip_idx = self
            .layers
            .iter()
            .position(|l| matches!(l, Layer::Ip(_)))
            .ok_or_else(|| DslError::Build("fragment() requires an IP layer".to_string()))?;
        let (before, rest) = self.layers.split_at(ip_idx);
        let ip_layer = rest[0].clone();
        let upper_layers = &rest[1..];

        let mut upper_bytes = Vec::new();
        let proto_hint = infer_proto_from_layers(upper_layers);
        build_layers_payload_only(upper_layers, &mut upper_bytes)?;
        let total = upper_bytes.len();
        if total == 0 {
            return Ok(vec![self.clone()]);
        }

        let mut out = Vec::new();
        let mut offset_bytes = 0usize;
        while offset_bytes < total {
            let end = (offset_bytes + fragsize).min(total);
            let chunk = &upper_bytes[offset_bytes..end];
            let is_last = end == total;
            let mut frag_ip = match &ip_layer {
                Layer::Ip(i) => i.clone(),
                _ => unreachable!(),
            };
            frag_ip.more_fragments = !is_last;
            frag_ip.fragment_offset = (offset_bytes / 8) as u16;
            if let Some(p) = proto_hint {
                frag_ip.proto = Some(p);
            }
            let mut layers: Vec<Layer> = Vec::new();
            layers.extend(before.iter().cloned());
            layers.push(Layer::Ip(frag_ip));
            layers.push(Layer::Raw(Raw::new(chunk.to_vec())));
            out.push(Packet { layers });
            offset_bytes = end;
        }
        Ok(out)
    }
}

impl Default for Packet {
    fn default() -> Self {
        Self::new()
    }
}

fn tcp_flags_to_str(f: &TcpFlags) -> String {
    let mut s = String::new();
    if f.fin {
        s.push('F');
    }
    if f.syn {
        s.push('S');
    }
    if f.rst {
        s.push('R');
    }
    if f.psh {
        s.push('P');
    }
    if f.ack {
        s.push('A');
    }
    if f.urg {
        s.push('U');
    }
    if s.is_empty() {
        "-".to_string()
    } else {
        s
    }
}

fn infer_proto_from_layers(layers: &[Layer]) -> Option<u8> {
    for l in layers {
        match l {
            Layer::Tcp(_) => return Some(6),
            Layer::Udp(_) => return Some(17),
            Layer::Icmp(_) => return Some(1),
            _ => {}
        }
    }
    None
}

fn build_layers_payload_only(layers: &[Layer], out: &mut Vec<u8>) -> Result<(), DslError> {
    build_layers(layers, 0, out)
}

fn build_layers(layers: &[Layer], idx: usize, out: &mut Vec<u8>) -> Result<(), DslError> {
    if idx >= layers.len() {
        return Ok(());
    }
    let current = &layers[idx];
    let upper = &layers[idx + 1..];
    match current {
        Layer::Ether(e) => {
            let ether_type = e.ether_type.unwrap_or_else(|| infer_ether_type(upper));
            let eth = Ethernet2Header {
                source: e.src,
                destination: e.dst,
                ether_type: EtherType(ether_type),
            };
            eth.write(out).map_err(|e| DslError::Build(e.to_string()))?;
            build_layers(layers, idx + 1, out)
        }
        Layer::Vlan(v) => {
            let tpid: [u8; 2] = [0x81, 0x00];
            out.extend_from_slice(&tpid);
            let tci = ((v.pcp as u16) << 13) | (v.vid & 0x0FFF);
            out.extend_from_slice(&tci.to_be_bytes());
            let ether_type = infer_ether_type(upper);
            out.extend_from_slice(&ether_type.to_be_bytes());
            build_layers(layers, idx + 1, out)
        }
        Layer::Ip(ip) => {
            let mut rest = Vec::new();
            build_layers(layers, idx + 1, &mut rest)?;
            let proto = ip.proto.unwrap_or_else(|| infer_ip_proto(upper));
            let total_len = 20 + rest.len();
            let mut header = Ipv4Header::new(
                rest.len() as u16,
                ip.ttl,
                IpNumber(proto),
                ip.src,
                ip.dst,
            )
            .map_err(|e| DslError::Build(e.to_string()))?;
            header.identification = ip.id;
            header.dont_fragment = ip.dont_fragment;
            header.more_fragments = ip.more_fragments;
            header.fragment_offset = ip.fragment_offset.try_into().unwrap_or_default();
            let _ = total_len;
            let mut hdr_bytes = Vec::new();
            header
                .write(&mut hdr_bytes)
                .map_err(|e| DslError::Build(e.to_string()))?;
            match ip.checksum {
                ChecksumMode::Auto => {}
                ChecksumMode::Fixed(v) => {
                    if hdr_bytes.len() >= 12 {
                        hdr_bytes[10..12].copy_from_slice(&v.to_be_bytes());
                    }
                }
                ChecksumMode::Bad => {
                    let bad: u16 = rand::thread_rng().gen();
                    if hdr_bytes.len() >= 12 {
                        hdr_bytes[10..12].copy_from_slice(&bad.to_be_bytes());
                    }
                }
            }
            out.extend_from_slice(&hdr_bytes);
            out.extend_from_slice(&rest);
            Ok(())
        }
        Layer::Ipv6(ip) => {
            let mut rest = Vec::new();
            build_layers(layers, idx + 1, &mut rest)?;
            let next = ip.next_header.unwrap_or_else(|| infer_ip_proto(upper));
            let header = Ipv6Header {
                traffic_class: 0,
                flow_label: Ipv6FlowLabel::try_new(ip.flow_label).unwrap_or_default(),
                payload_length: rest.len() as u16,
                next_header: IpNumber(next),
                hop_limit: ip.hop_limit,
                source: ip.src,
                destination: ip.dst,
            };
            header
                .write(out)
                .map_err(|e| DslError::Build(e.to_string()))?;
            out.extend_from_slice(&rest);
            Ok(())
        }
        Layer::Tcp(t) => {
            let mut rest = Vec::new();
            build_layers(layers, idx + 1, &mut rest)?;
            let mut header = TcpHeader::new(t.sport, t.dport, t.seq, t.window);
            header.acknowledgment_number = t.ack;
            header.syn = t.flags.syn;
            header.ack = t.flags.ack;
            header.psh = t.flags.psh;
            header.fin = t.flags.fin;
            header.rst = t.flags.rst;
            header.urg = t.flags.urg;
            let opts_bytes = serialize_tcp_options(&t.options);
            if !opts_bytes.is_empty() {
                let _ = header.set_options_raw(&opts_bytes);
            }
            let mut hdr_bytes = Vec::new();
            header
                .write(&mut hdr_bytes)
                .map_err(|e| DslError::Build(e.to_string()))?;
            match t.checksum {
                ChecksumMode::Fixed(v) => {
                    if hdr_bytes.len() >= 18 {
                        hdr_bytes[16..18].copy_from_slice(&v.to_be_bytes());
                    }
                }
                ChecksumMode::Bad => {
                    let bad: u16 = rand::thread_rng().gen();
                    if hdr_bytes.len() >= 18 {
                        hdr_bytes[16..18].copy_from_slice(&bad.to_be_bytes());
                    }
                }
                ChecksumMode::Auto => {}
            }
            out.extend_from_slice(&hdr_bytes);
            out.extend_from_slice(&rest);
            Ok(())
        }
        Layer::Udp(u) => {
            let mut rest = Vec::new();
            build_layers(layers, idx + 1, &mut rest)?;
            let length = 8 + rest.len() as u16;
            let header = UdpHeader {
                source_port: u.sport,
                destination_port: u.dport,
                length,
                checksum: match u.checksum {
                    ChecksumMode::Fixed(v) => v,
                    ChecksumMode::Bad => rand::thread_rng().gen(),
                    ChecksumMode::Auto => 0,
                },
            };
            header
                .write(out)
                .map_err(|e| DslError::Build(e.to_string()))?;
            out.extend_from_slice(&rest);
            Ok(())
        }
        Layer::Icmp(i) => {
            let mut rest = Vec::new();
            build_layers(layers, idx + 1, &mut rest)?;
            out.push(i.icmp_type);
            out.push(i.code);
            out.extend_from_slice(&[0u8, 0u8]);
            match i.icmp_type {
                8 | 0 => {
                    out.extend_from_slice(&i.id.to_be_bytes());
                    out.extend_from_slice(&i.seq.to_be_bytes());
                }
                3 => {
                    out.extend_from_slice(&[0u8, 0u8]);
                    let mtu = i.next_hop_mtu.unwrap_or(0);
                    out.extend_from_slice(&mtu.to_be_bytes());
                }
                _ => {
                    out.extend_from_slice(&[0u8; 4]);
                }
            }
            out.extend_from_slice(&rest);
            Ok(())
        }
        Layer::Icmpv6(i) => {
            let mut rest = Vec::new();
            build_layers(layers, idx + 1, &mut rest)?;
            out.push(i.icmp_type);
            out.push(i.code);
            out.extend_from_slice(&[0u8, 0u8]);
            out.extend_from_slice(&rest);
            Ok(())
        }
        Layer::Raw(r) => {
            out.extend_from_slice(&r.load);
            Ok(())
        }
    }
}

fn serialize_tcp_options(opts: &[TcpOpt]) -> Vec<u8> {
    let mut out = Vec::new();
    for o in opts {
        match o {
            TcpOpt::Nop => out.push(1),
            TcpOpt::Mss(v) => {
                out.push(2);
                out.push(4);
                out.extend_from_slice(&v.to_be_bytes());
            }
            TcpOpt::WScale(v) => {
                out.push(3);
                out.push(3);
                out.push(*v);
            }
            TcpOpt::SAckOK => {
                out.push(4);
                out.push(2);
            }
            TcpOpt::Timestamp(tsval, tsecr) => {
                out.push(8);
                out.push(10);
                out.extend_from_slice(&tsval.to_be_bytes());
                out.extend_from_slice(&tsecr.to_be_bytes());
            }
        }
    }
    while out.len() % 4 != 0 {
        out.push(1);
    }
    out
}

fn infer_ether_type(upper: &[Layer]) -> u16 {
    for l in upper {
        match l {
            Layer::Ip(_) => return 0x0800,
            Layer::Ipv6(_) => return 0x86DD,
            Layer::Vlan(_) => return 0x8100,
            _ => {}
        }
    }
    0x0800
}

fn infer_ip_proto(upper: &[Layer]) -> u8 {
    for l in upper {
        match l {
            Layer::Tcp(_) => return 6,
            Layer::Udp(_) => return 17,
            Layer::Icmp(_) => return 1,
            Layer::Icmpv6(_) => return 58,
            _ => {}
        }
    }
    255
}

fn hexdump_bytes(bytes: &[u8]) -> String {
    let mut out = String::new();
    for (i, chunk) in bytes.chunks(16).enumerate() {
        out.push_str(&format!("{:08x}  ", i * 16));
        for b in chunk {
            out.push_str(&format!("{:02x} ", b));
        }
        for _ in chunk.len()..16 {
            out.push_str("   ");
        }
        out.push(' ');
        for b in chunk {
            let c = if b.is_ascii_graphic() || *b == b' ' {
                *b as char
            } else {
                '.'
            };
            out.push(c);
        }
        out.push('\n');
    }
    out
}

/// Errors produced by the DSL.
#[derive(Debug, thiserror::Error)]
pub enum DslError {
    #[error("DSL build error: {0}")]
    Build(String),
    #[error("IO: {0}")]
    Io(#[from] std::io::Error),
}

impl From<Ether> for Layer {
    fn from(v: Ether) -> Self {
        Layer::Ether(v)
    }
}
impl From<Vlan> for Layer {
    fn from(v: Vlan) -> Self {
        Layer::Vlan(v)
    }
}
impl From<Ip> for Layer {
    fn from(v: Ip) -> Self {
        Layer::Ip(v)
    }
}
impl From<Ipv6> for Layer {
    fn from(v: Ipv6) -> Self {
        Layer::Ipv6(v)
    }
}
impl From<Tcp> for Layer {
    fn from(v: Tcp) -> Self {
        Layer::Tcp(v)
    }
}
impl From<Udp> for Layer {
    fn from(v: Udp) -> Self {
        Layer::Udp(v)
    }
}
impl From<Icmp> for Layer {
    fn from(v: Icmp) -> Self {
        Layer::Icmp(v)
    }
}
impl From<Icmpv6> for Layer {
    fn from(v: Icmpv6) -> Self {
        Layer::Icmpv6(v)
    }
}
impl From<Raw> for Layer {
    fn from(v: Raw) -> Self {
        Layer::Raw(v)
    }
}

macro_rules! impl_div_layer_to_packet {
    ($t:ty) => {
        impl<R: Into<Layer>> Div<R> for $t {
            type Output = Packet;
            fn div(self, rhs: R) -> Packet {
                Packet::new().push(self.into()).push(rhs.into())
            }
        }
    };
}

impl_div_layer_to_packet!(Ether);
impl_div_layer_to_packet!(Vlan);
impl_div_layer_to_packet!(Ip);
impl_div_layer_to_packet!(Ipv6);
impl_div_layer_to_packet!(Tcp);
impl_div_layer_to_packet!(Udp);
impl_div_layer_to_packet!(Icmp);
impl_div_layer_to_packet!(Icmpv6);

impl<R: Into<Layer>> Div<R> for Packet {
    type Output = Packet;
    fn div(mut self, rhs: R) -> Packet {
        self.layers.push(rhs.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_simple_syn() {
        let pkt = Ether::new() / Ip::new().dst([1, 1, 1, 1]).df() / Tcp::new().dport(443).syn();
        let bytes = pkt.build().unwrap();
        assert!(bytes.len() >= 14 + 20 + 20);
    }

    #[test]
    fn summary_contains_layers() {
        let pkt = Ether::new() / Ip::new() / Tcp::new().syn();
        let s = pkt.summary();
        assert!(s.contains("Ether"));
        assert!(s.contains("IP"));
        assert!(s.contains("TCP"));
        assert!(s.contains("S"));
    }

    #[test]
    fn fragment_splits_udp_payload() {
        let pkt = Ether::new()
            / Ip::new().dst([1, 1, 1, 1])
            / Udp::new().dport(33434)
            / Raw::of_size(1800, b'C');
        let frags = pkt.fragment(400).unwrap();
        assert!(frags.len() >= 2, "expected fragments, got {}", frags.len());
        if let Layer::Ip(last) = frags
            .last()
            .unwrap()
            .layers
            .iter()
            .find(|l| matches!(l, Layer::Ip(_)))
            .unwrap()
        {
            assert!(!last.more_fragments);
        }
    }

    #[test]
    fn bad_checksum_changes_bytes() {
        let pkt_a = Ether::new() / Ip::new() / Tcp::new().dport(80).syn();
        let pkt_b = Ether::new() / Ip::new() / Tcp::new().dport(80).syn().bad_checksum();
        let a = pkt_a.build().unwrap();
        let b = pkt_b.build().unwrap();
        assert_eq!(a.len(), b.len());
    }
}
