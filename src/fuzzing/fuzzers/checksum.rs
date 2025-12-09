//! Checksum Validation Fuzzing
//!
//! Tests parsers with valid and invalid checksums to detect validation bypass vulnerabilities.

use crate::fuzzing::{FuzzError, PacketContext, PcapWriter};

/// Run checksum fuzzing campaign
pub fn fuzz(ctx: &PacketContext, output_path: &str) -> Result<usize, FuzzError> {
    let mut writer = PcapWriter::new(output_path)?;
    let mut count = 0;

    // Scenario 1: Valid checksum (baseline)
    {
        let packet = ctx
            .build_packet(100)
            .map_err(|e| FuzzError::PacketBuild(e.to_string()))?;
        writer.write_packet(&packet)?;
        count += 1;
    }

    // Scenario 2: Zero checksum
    {
        let (eth_bytes, mut ipv4_bytes, tcp_bytes, payload) = ctx
            .build_base_layers(100)
            .map_err(|e| FuzzError::PacketBuild(e.to_string()))?;
        
        // Zero out IP checksum (bytes 10-11)
        ipv4_bytes[10] = 0;
        ipv4_bytes[11] = 0;
        
        let mut packet = Vec::new();
        packet.extend_from_slice(&eth_bytes);
        packet.extend_from_slice(&ipv4_bytes);
        packet.extend_from_slice(&tcp_bytes);
        packet.extend_from_slice(&payload);
        
        writer.write_packet(&packet)?;
        count += 1;
    }

    // Scenario 3: Random corrupt checksum
    {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        
        let (eth_bytes, mut ipv4_bytes, tcp_bytes, payload) = ctx
            .build_base_layers(100)
            .map_err(|e| FuzzError::PacketBuild(e.to_string()))?;
        
        // Set random checksum
        ipv4_bytes[10] = rng.gen();
        ipv4_bytes[11] = rng.gen();
        
        let mut packet = Vec::new();
        packet.extend_from_slice(&eth_bytes);
        packet.extend_from_slice(&ipv4_bytes);
        packet.extend_from_slice(&tcp_bytes);
        packet.extend_from_slice(&payload);
        
        writer.write_packet(&packet)?;
        count += 1;
    }

    // Scenario 4: Off-by-one checksum
    {
        let (eth_bytes, mut ipv4_bytes, tcp_bytes, payload) = ctx
            .build_base_layers(100)
            .map_err(|e| FuzzError::PacketBuild(e.to_string()))?;
        
        // Get current checksum and increment by 1
        let checksum = ((ipv4_bytes[10] as u16) << 8) | (ipv4_bytes[11] as u16);
        let bad_checksum = checksum.wrapping_add(1);
        
        ipv4_bytes[10] = (bad_checksum >> 8) as u8;
        ipv4_bytes[11] = (bad_checksum & 0xFF) as u8;
        
        let mut packet = Vec::new();
        packet.extend_from_slice(&eth_bytes);
        packet.extend_from_slice(&ipv4_bytes);
        packet.extend_from_slice(&tcp_bytes);
        packet.extend_from_slice(&payload);
        
        writer.write_packet(&packet)?;
        count += 1;
    }

    // Scenario 5: Max value checksum (0xFFFF)
    {
        let (eth_bytes, mut ipv4_bytes, tcp_bytes, payload) = ctx
            .build_base_layers(100)
            .map_err(|e| FuzzError::PacketBuild(e.to_string()))?;
        
        ipv4_bytes[10] = 0xFF;
        ipv4_bytes[11] = 0xFF;
        
        let mut packet = Vec::new();
        packet.extend_from_slice(&eth_bytes);
        packet.extend_from_slice(&ipv4_bytes);
        packet.extend_from_slice(&tcp_bytes);
        packet.extend_from_slice(&payload);
        
        writer.write_packet(&packet)?;
        count += 1;
    }

    // Scenario 6: Multiple packets with various corrupt checksums
    for _ in 0..5 {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        
        let (eth_bytes, mut ipv4_bytes, tcp_bytes, payload) = ctx
            .build_base_layers(rng.gen_range(50..500))
            .map_err(|e| FuzzError::PacketBuild(e.to_string()))?;
        
        // Corrupt checksum
        ipv4_bytes[10] = rng.gen();
        ipv4_bytes[11] = rng.gen();
        
        let mut packet = Vec::new();
        packet.extend_from_slice(&eth_bytes);
        packet.extend_from_slice(&ipv4_bytes);
        packet.extend_from_slice(&tcp_bytes);
        packet.extend_from_slice(&payload);
        
        writer.write_packet(&packet)?;
        count += 1;
    }

    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checksum_fuzzer() {
        let ctx = PacketContext::new("192.168.1.1", "8.8.8.8").unwrap();
        let output = "/tmp/test_checksum.pcap";
        
        let packets = fuzz(&ctx, output).unwrap();
        assert_eq!(packets, 10); // 5 main + 5 variations
        
        std::fs::remove_file(output).ok();
    }
}

