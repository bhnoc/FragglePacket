//! TCP Options Fuzzing
//!
//! Tests TCP option parser robustness with corrupted MSS, SACK, Window Scale options.

use crate::fuzzing::{FuzzError, PacketContext, PcapWriter};

/// Run TCP options fuzzing campaign to a provided writer
pub fn fuzz_to_writer(ctx: &PacketContext, writer: &mut PcapWriter) -> Result<usize, FuzzError> {
    let mut count = 0;

    // Scenario 1: Normal MSS (baseline)
    {
        let (eth_bytes, ipv4_bytes, tcp_bytes, payload) = ctx
            .build_base_layers(0)
            .map_err(|e| FuzzError::PacketBuild(e.to_string()))?;

        // Add MSS option manually after base TCP header
        let mut packet = Vec::new();
        packet.extend_from_slice(&eth_bytes);
        packet.extend_from_slice(&ipv4_bytes);
        packet.extend_from_slice(&tcp_bytes);

        // TCP options: MSS = 1460 (kind=2, len=4, value=1460)
        packet.push(2); // Kind: MSS
        packet.push(4); // Length: 4 bytes
        packet.push((1460 >> 8) as u8);
        packet.push((1460 & 0xFF) as u8);

        // End of options
        packet.push(0); // Kind: End

        // Padding to 4-byte boundary
        while packet.len() % 4 != 0 {
            packet.push(0);
        }

        packet.extend_from_slice(&payload);

        writer.write_packet(&packet)?;
        count += 1;
    }

    // Scenario 2: MSS = 0 (invalid)
    {
        let (eth_bytes, ipv4_bytes, tcp_bytes, payload) = ctx
            .build_base_layers(0)
            .map_err(|e| FuzzError::PacketBuild(e.to_string()))?;

        let mut packet = Vec::new();
        packet.extend_from_slice(&eth_bytes);
        packet.extend_from_slice(&ipv4_bytes);
        packet.extend_from_slice(&tcp_bytes);

        // MSS = 0
        packet.push(2);
        packet.push(4);
        packet.push(0);
        packet.push(0);
        packet.push(0); // End

        packet.extend_from_slice(&payload);
        writer.write_packet(&packet)?;
        count += 1;
    }

    // Scenario 3: MSS = 65535 (max u16)
    {
        let (eth_bytes, ipv4_bytes, tcp_bytes, payload) = ctx
            .build_base_layers(0)
            .map_err(|e| FuzzError::PacketBuild(e.to_string()))?;

        let mut packet = Vec::new();
        packet.extend_from_slice(&eth_bytes);
        packet.extend_from_slice(&ipv4_bytes);
        packet.extend_from_slice(&tcp_bytes);

        // MSS = 65535
        packet.push(2);
        packet.push(4);
        packet.push(0xFF);
        packet.push(0xFF);
        packet.push(0); // End

        packet.extend_from_slice(&payload);
        writer.write_packet(&packet)?;
        count += 1;
    }

    // Scenario 4: Malformed MSS (wrong length field)
    {
        let (eth_bytes, ipv4_bytes, tcp_bytes, payload) = ctx
            .build_base_layers(0)
            .map_err(|e| FuzzError::PacketBuild(e.to_string()))?;

        let mut packet = Vec::new();
        packet.extend_from_slice(&eth_bytes);
        packet.extend_from_slice(&ipv4_bytes);
        packet.extend_from_slice(&tcp_bytes);

        // MSS with wrong length (kind=2, len=2 instead of 4)
        packet.push(2);
        packet.push(2); // WRONG: should be 4
        packet.push(0); // End

        packet.extend_from_slice(&payload);
        writer.write_packet(&packet)?;
        count += 1;
    }

    // Scenario 5: Multiple malformed options
    {
        let (eth_bytes, ipv4_bytes, tcp_bytes, payload) = ctx
            .build_base_layers(0)
            .map_err(|e| FuzzError::PacketBuild(e.to_string()))?;

        let mut packet = Vec::new();
        packet.extend_from_slice(&eth_bytes);
        packet.extend_from_slice(&ipv4_bytes);
        packet.extend_from_slice(&tcp_bytes);

        // Window Scale with wrong length
        packet.push(3); // Kind: Window Scale
        packet.push(1); // WRONG: should be 3

        // SACK Permitted with wrong length
        packet.push(4); // Kind: SACK Permitted
        packet.push(5); // WRONG: should be 2

        packet.push(0); // End

        packet.extend_from_slice(&payload);
        writer.write_packet(&packet)?;
        count += 1;
    }

    // Scenario 6: Invalid kind values
    for kind in vec![255, 254, 200, 150, 100] {
        let (eth_bytes, ipv4_bytes, tcp_bytes, payload) = ctx
            .build_base_layers(0)
            .map_err(|e| FuzzError::PacketBuild(e.to_string()))?;

        let mut packet = Vec::new();
        packet.extend_from_slice(&eth_bytes);
        packet.extend_from_slice(&ipv4_bytes);
        packet.extend_from_slice(&tcp_bytes);

        // Invalid kind
        packet.push(kind);
        packet.push(4);
        packet.push(0);
        packet.push(0);
        packet.push(0); // End

        packet.extend_from_slice(&payload);
        writer.write_packet(&packet)?;
        count += 1;
    }

    Ok(count)
}

/// Run TCP options fuzzing campaign to a file path
pub fn fuzz(ctx: &PacketContext, output_path: &str) -> Result<usize, FuzzError> {
    let mut writer = PcapWriter::new(output_path)?;
    fuzz_to_writer(ctx, &mut writer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_options_fuzzer() {
        let ctx = PacketContext::new("192.168.1.1", "8.8.8.8").unwrap();
        let output = "/tmp/test_tcp_options.pcap";

        let packets = fuzz(&ctx, output).unwrap();
        assert_eq!(packets, 10); // 5 main scenarios + 5 invalid kinds

        std::fs::remove_file(output).ok();
    }
}
