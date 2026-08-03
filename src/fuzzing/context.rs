//! Packet context for building base packet layers

use std::net::{Ipv4Addr, ToSocketAddrs};
use rand::Rng;

/// Context for packet generation containing source/destination information
#[derive(Debug, Clone)]
pub struct PacketContext {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub src_port: u16,
    pub dst_port: u16,
}

impl PacketContext {
    /// Create a new packet context with specified IPs
    pub fn new(src_ip: &str, dst_ip: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let src = src_ip.parse::<Ipv4Addr>()?;
        let dst = dst_ip.parse::<Ipv4Addr>()?;

        // Generate random MAC addresses
        let mut rng = rand::thread_rng();
        let src_mac = [
            0x02, // Locally administered
            rng.gen(),
            rng.gen(),
            rng.gen(),
            rng.gen(),
            rng.gen(),
        ];
        let dst_mac = [
            0x02,
            rng.gen(),
            rng.gen(),
            rng.gen(),
            rng.gen(),
            rng.gen(),
        ];

        Ok(Self {
            src_ip: src,
            dst_ip: dst,
            src_mac,
            dst_mac,
            src_port: rng.gen_range(49152..65535), // Ephemeral port range
            dst_port: 443, // Default to HTTPS
        })
    }

    /// Create context for a target hostname
    pub fn for_target(target: &str) -> Result<Self, Box<dyn std::error::Error>> {
        // Try to resolve as hostname first
        let dst_ip = if let Ok(addr) = target.parse::<Ipv4Addr>() {
            addr
        } else {
            // Resolve hostname
            let addr = format!("{}:443", target)
                .to_socket_addrs()?
                .find(|addr| addr.is_ipv4())
                .ok_or("No IPv4 address found")?;
            match addr.ip() {
                std::net::IpAddr::V4(ip) => ip,
                _ => return Err("Expected IPv4 address".into()),
            }
        };

        // Get local IP (use 192.168.1.100 as default for PCAP generation)
        let src_ip: Ipv4Addr = "192.168.1.100".parse()?;

        Self::new(&src_ip.to_string(), &dst_ip.to_string())
    }

    /// Set destination port
    pub fn with_dst_port(mut self, port: u16) -> Self {
        self.dst_port = port;
        self
    }

    /// Build base packet layers (Ethernet + IPv4 + TCP headers + payload)
    ///
    /// Returns: (ethernet_bytes, ipv4_bytes, tcp_bytes, payload)
    pub fn build_base_layers(
        &self,
        payload_len: usize,
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
        use etherparse::*;

        // Generate random payload
        let mut rng = rand::thread_rng();
        let payload: Vec<u8> = (0..payload_len).map(|_| rng.gen()).collect();

        // Build Ethernet header
        let eth = Ethernet2Header {
            source: self.src_mac,
            destination: self.dst_mac,
            ether_type: EtherType::IPV4,
        };
        let mut eth_bytes = Vec::new();
        eth.write(&mut eth_bytes)?;

        // Build IPv4 header
        let total_len = 20 + 20 + payload_len; // IP header + TCP header + payload
        let mut ipv4 = Ipv4Header::new(
            total_len as u16,
            64, // TTL
            IpNumber::TCP,
            self.src_ip.octets(),
            self.dst_ip.octets(),
        )?;
        ipv4.dont_fragment = true;
        let mut ipv4_bytes = Vec::new();
        ipv4.write(&mut ipv4_bytes)?;

        // Build TCP header
        let mut tcp = TcpHeader::new(self.src_port, self.dst_port, 0, 65535);
        tcp.syn = true;
        let mut tcp_bytes = Vec::new();
        tcp.write(&mut tcp_bytes)?;

        Ok((eth_bytes, ipv4_bytes, tcp_bytes, payload))
    }

    /// Build complete packet as single byte vector
    pub fn build_packet(&self, payload_len: usize) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let (eth, ipv4, tcp, payload) = self.build_base_layers(payload_len)?;
        
        let mut packet = Vec::new();
        packet.extend_from_slice(&eth);
        packet.extend_from_slice(&ipv4);
        packet.extend_from_slice(&tcp);
        packet.extend_from_slice(&payload);
        
        Ok(packet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_context_creation() {
        let ctx = PacketContext::new("192.168.1.1", "8.8.8.8").unwrap();
        assert_eq!(ctx.src_ip.to_string(), "192.168.1.1");
        assert_eq!(ctx.dst_ip.to_string(), "8.8.8.8");
        assert!(ctx.src_port >= 49152);
        assert_eq!(ctx.dst_port, 443);
    }

    #[test]
    fn test_build_packet() {
        let ctx = PacketContext::new("192.168.1.1", "8.8.8.8").unwrap();
        let packet = ctx.build_packet(100).unwrap();
        
        // Ethernet (14) + IPv4 (20) + TCP (20) + Payload (100) = 154 bytes
        assert_eq!(packet.len(), 154);
    }
}

