//! Packet building utilities

use etherparse::*;

/// Helper function to serialize packet layers into bytes
pub fn serialize_packet(
    eth: &Ethernet2Header,
    ipv4: &Ipv4Header,
    tcp: &TcpHeader,
    payload: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut packet = Vec::new();

    eth.write(&mut packet)?;
    ipv4.write(&mut packet)?;
    tcp.write(&mut packet)?;
    packet.extend_from_slice(payload);

    Ok(packet)
}

/// Calculate IP checksum
pub fn calculate_ip_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    for i in (0..header.len()).step_by(2) {
        if i + 1 < header.len() {
            let word = ((header[i] as u32) << 8) | (header[i + 1] as u32);
            sum += word;
        } else {
            sum += (header[i] as u32) << 8;
        }
    }

    while (sum >> 16) > 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !sum as u16
}

/// Corrupt a checksum value
pub fn corrupt_checksum(_original: u16) -> u16 {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    rng.gen()
}
