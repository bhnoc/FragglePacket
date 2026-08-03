//! IP Header Length Mismatch Fuzzing
//!
//! Tests parsers that trust the IP header's total_len field vs actual buffer size.
//! This can lead to Heartbleed-style buffer over-reads.

use crate::fuzzing::{FuzzError, PacketContext, PcapWriter};

/// Run length mismatch fuzzing campaign to a provided writer
pub fn fuzz_to_writer(ctx: &PacketContext, writer: &mut PcapWriter) -> Result<usize, FuzzError> {
    let mut count = 0;

    // Scenario 1: Normal packet (baseline)
    {
        let packet = ctx
            .build_packet(100)
            .map_err(|e| FuzzError::PacketBuild(e.to_string()))?;
        writer.write_packet(&packet)?;
        count += 1;
    }

    // Scenario 2: Header claims 50 bytes, actual is 100 bytes
    {
        let (eth_bytes, mut ipv4_bytes, tcp_bytes, payload) = ctx
            .build_base_layers(100)
            .map_err(|e| FuzzError::PacketBuild(e.to_string()))?;

        // Lie: Set total_len to 50 (should be 140)
        // IPv4 header bytes 2-3 are total_len (big-endian)
        ipv4_bytes[2] = 0;
        ipv4_bytes[3] = 50;

        // Zero out checksum (bytes 10-11)
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

    // Scenario 3: Header claims 200 bytes, actual is 100 bytes
    {
        let (eth_bytes, mut ipv4_bytes, tcp_bytes, payload) = ctx
            .build_base_layers(100)
            .map_err(|e| FuzzError::PacketBuild(e.to_string()))?;

        // Lie: Set total_len to 200
        ipv4_bytes[2] = 0;
        ipv4_bytes[3] = 200;

        // Zero out checksum
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

    // Scenario 4: Multiple sizes with mismatches
    for (actual_size, claimed_size) in vec![(50, 25), (50, 100), (200, 100), (200, 300)] {
        let (eth_bytes, mut ipv4_bytes, tcp_bytes, payload) = ctx
            .build_base_layers(actual_size)
            .map_err(|e| FuzzError::PacketBuild(e.to_string()))?;

        // Set claimed total_len
        let claimed_total = (20 + 20 + claimed_size) as u16;
        ipv4_bytes[2] = (claimed_total >> 8) as u8;
        ipv4_bytes[3] = (claimed_total & 0xFF) as u8;

        // Zero out checksum
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

    Ok(count)
}

/// Run length mismatch fuzzing campaign to a file path
pub fn fuzz(ctx: &PacketContext, output_path: &str) -> Result<usize, FuzzError> {
    let mut writer = PcapWriter::new(output_path)?;
    fuzz_to_writer(ctx, &mut writer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_length_mismatch_fuzzer() {
        let ctx = PacketContext::new("192.168.1.1", "8.8.8.8").unwrap();
        let output = "/tmp/test_length_mismatch.pcap";
        
        let packets = fuzz(&ctx, output).unwrap();
        assert_eq!(packets, 7); // 1 baseline + 2 main + 4 variations
        
        std::fs::remove_file(output).ok();
    }
}

