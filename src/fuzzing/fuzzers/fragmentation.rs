//! IP Fragmentation Fuzzing
//!
//! Tests IP fragment reassembly with edge cases like overlapping fragments,
//! missing fragments, and timeout scenarios.

use crate::fuzzing::{FuzzError, PacketContext, PcapWriter};

/// Run IP fragmentation fuzzing campaign
pub fn fuzz(ctx: &PacketContext, output_path: &str) -> Result<usize, FuzzError> {
    let mut writer = PcapWriter::new(output_path)?;
    let mut count = 0;

    // Scenario 1: Normal fragmented packet (baseline)
    {
        // Fragment 1 (offset 0, more fragments)
        let (eth_bytes, mut ipv4_bytes, tcp_bytes, payload) = ctx
            .build_base_layers(100)
            .map_err(|e| FuzzError::PacketBuild(e.to_string()))?;
        
        // Set More Fragments flag and offset 0
        ipv4_bytes[6] = 0x20; // Flags: More Fragments
        ipv4_bytes[7] = 0x00; // Offset: 0
        
        let mut packet = Vec::new();
        packet.extend_from_slice(&eth_bytes);
        packet.extend_from_slice(&ipv4_bytes);
        packet.extend_from_slice(&tcp_bytes);
        packet.extend_from_slice(&payload[..50]); // First 50 bytes
        
        writer.write_packet(&packet)?;
        count += 1;

        // Fragment 2 (offset 50, no more fragments)
        let (eth_bytes, mut ipv4_bytes, _, _) = ctx
            .build_base_layers(100)
            .map_err(|e| FuzzError::PacketBuild(e.to_string()))?;
        
        ipv4_bytes[6] = 0x00; // Flags: No More Fragments
        ipv4_bytes[7] = 0x06; // Offset: 50/8 = 6.25 → 6
        
        let mut packet = Vec::new();
        packet.extend_from_slice(&eth_bytes);
        packet.extend_from_slice(&ipv4_bytes);
        packet.extend_from_slice(&payload[50..]); // Last 50 bytes
        
        writer.write_packet(&packet)?;
        count += 1;
    }

    // Scenario 2: Overlapping fragments
    {
        // Fragment 1: bytes 0-60
        let (eth_bytes, mut ipv4_bytes, tcp_bytes, payload) = ctx
            .build_base_layers(100)
            .map_err(|e| FuzzError::PacketBuild(e.to_string()))?;
        
        ipv4_bytes[6] = 0x20; // More Fragments
        ipv4_bytes[7] = 0x00; // Offset: 0
        
        let mut packet = Vec::new();
        packet.extend_from_slice(&eth_bytes);
        packet.extend_from_slice(&ipv4_bytes);
        packet.extend_from_slice(&tcp_bytes);
        packet.extend_from_slice(&payload[..60]);
        
        writer.write_packet(&packet)?;
        count += 1;

        // Fragment 2: bytes 50-100 (overlaps with fragment 1)
        let (eth_bytes, mut ipv4_bytes, _, _) = ctx
            .build_base_layers(100)
            .map_err(|e| FuzzError::PacketBuild(e.to_string()))?;
        
        ipv4_bytes[6] = 0x00; // No More Fragments
        ipv4_bytes[7] = 0x06; // Offset: 50/8 = 6.25 → 6
        
        let mut packet = Vec::new();
        packet.extend_from_slice(&eth_bytes);
        packet.extend_from_slice(&ipv4_bytes);
        packet.extend_from_slice(&payload[50..]);
        
        writer.write_packet(&packet)?;
        count += 1;
    }

    // Scenario 3: Missing middle fragment (1, 3 but no 2)
    {
        // Fragment 1
        let (eth_bytes, mut ipv4_bytes, tcp_bytes, payload) = ctx
            .build_base_layers(120)
            .map_err(|e| FuzzError::PacketBuild(e.to_string()))?;
        
        ipv4_bytes[6] = 0x20;
        ipv4_bytes[7] = 0x00;
        
        let mut packet = Vec::new();
        packet.extend_from_slice(&eth_bytes);
        packet.extend_from_slice(&ipv4_bytes);
        packet.extend_from_slice(&tcp_bytes);
        packet.extend_from_slice(&payload[..40]);
        
        writer.write_packet(&packet)?;
        count += 1;

        // Fragment 3 (skip fragment 2)
        let (eth_bytes, mut ipv4_bytes, _, _) = ctx
            .build_base_layers(120)
            .map_err(|e| FuzzError::PacketBuild(e.to_string()))?;
        
        ipv4_bytes[6] = 0x00;
        ipv4_bytes[7] = 0x0A; // Offset: 80/8 = 10
        
        let mut packet = Vec::new();
        packet.extend_from_slice(&eth_bytes);
        packet.extend_from_slice(&ipv4_bytes);
        packet.extend_from_slice(&payload[80..]);
        
        writer.write_packet(&packet)?;
        count += 1;
    }

    // Scenario 4: Out-of-order fragments
    {
        let (eth_bytes, ipv4_bytes, tcp_bytes, payload) = ctx
            .build_base_layers(90)
            .map_err(|e| FuzzError::PacketBuild(e.to_string()))?;

        // Send fragment 2 first
        let (eth, mut ipv4, _, _) = ctx
            .build_base_layers(90)
            .map_err(|e| FuzzError::PacketBuild(e.to_string()))?;
        
        ipv4[6] = 0x20;
        ipv4[7] = 0x05; // Offset: 40/8 = 5
        
        let mut packet = Vec::new();
        packet.extend_from_slice(&eth);
        packet.extend_from_slice(&ipv4);
        packet.extend_from_slice(&payload[40..80]);
        
        writer.write_packet(&packet)?;
        count += 1;

        // Then send fragment 1
        let (eth, mut ipv4, tcp, _) = ctx
            .build_base_layers(90)
            .map_err(|e| FuzzError::PacketBuild(e.to_string()))?;
        
        ipv4[6] = 0x20;
        ipv4[7] = 0x00;
        
        let mut packet = Vec::new();
        packet.extend_from_slice(&eth);
        packet.extend_from_slice(&ipv4);
        packet.extend_from_slice(&tcp);
        packet.extend_from_slice(&payload[..40]);
        
        writer.write_packet(&packet)?;
        count += 1;

        // Finally fragment 3
        let (eth, mut ipv4, _, _) = ctx
            .build_base_layers(90)
            .map_err(|e| FuzzError::PacketBuild(e.to_string()))?;
        
        ipv4[6] = 0x00;
        ipv4[7] = 0x0A; // Offset: 80/8 = 10
        
        let mut packet = Vec::new();
        packet.extend_from_slice(&eth);
        packet.extend_from_slice(&ipv4);
        packet.extend_from_slice(&payload[80..]);
        
        writer.write_packet(&packet)?;
        count += 1;
    }

    // Scenario 5: Tiny fragments (8 bytes each - minimum fragment size)
    {
        let payload_size = 32;
        let (eth_bytes, ipv4_bytes, tcp_bytes, payload) = ctx
            .build_base_layers(payload_size)
            .map_err(|e| FuzzError::PacketBuild(e.to_string()))?;
        
        for i in 0..4 {
            let (eth, mut ipv4, tcp, _) = ctx
                .build_base_layers(payload_size)
                .map_err(|e| FuzzError::PacketBuild(e.to_string()))?;
            
            if i < 3 {
                ipv4[6] = 0x20; // More Fragments
            } else {
                ipv4[6] = 0x00; // Last fragment
            }
            ipv4[7] = i as u8; // Offset: i*8/8 = i
            
            let mut packet = Vec::new();
            packet.extend_from_slice(&eth);
            packet.extend_from_slice(&ipv4);
            if i == 0 {
                packet.extend_from_slice(&tcp);
            }
            packet.extend_from_slice(&payload[i*8..(i+1)*8]);
            
            writer.write_packet(&packet)?;
            count += 1;
        }
    }

    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fragmentation_fuzzer() {
        let ctx = PacketContext::new("192.168.1.1", "8.8.8.8").unwrap();
        let output = "/tmp/test_fragmentation.pcap";
        
        let packets = fuzz(&ctx, output).unwrap();
        assert!(packets >= 13, "Expected at least 13 packets, got {}", packets); // Multiple fragmentation scenarios
        
        std::fs::remove_file(output).ok();
    }
}

