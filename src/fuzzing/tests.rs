//! Unit tests for RustPacketFuzz

#[cfg(test)]
mod tests {
    use crate::fuzzing::{PacketContext, PcapWriter};
    use crate::fuzzing::fuzzers::{segment_size, length_mismatch, tcp_options, fragmentation, checksum};
    use std::net::Ipv4Addr;
    use std::fs;

    fn create_test_context() -> PacketContext {
        PacketContext {
            src_ip: "192.168.1.1".parse::<Ipv4Addr>().unwrap(),
            dst_ip: "8.8.8.8".parse::<Ipv4Addr>().unwrap(),
            src_port: 12345,
            dst_port: 80,
        }
    }

    #[test]
    fn test_packet_context_creation() {
        let ctx = create_test_context();
        assert_eq!(ctx.src_ip.to_string(), "192.168.1.1");
        assert_eq!(ctx.dst_ip.to_string(), "8.8.8.8");
        assert_eq!(ctx.src_port, 12345);
        assert_eq!(ctx.dst_port, 80);
    }

    #[test]
    fn test_pcap_writer_creation() {
        let path = "/tmp/test_pcap_writer.pcap";
        let writer = PcapWriter::new(path);
        assert!(writer.is_ok());
        
        // Cleanup
        fs::remove_file(path).ok();
    }

    #[test]
    fn test_pcap_writer_write_packet() {
        let path = "/tmp/test_pcap_write.pcap";
        let mut writer = PcapWriter::new(path).unwrap();
        
        let packet = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05];
        assert!(writer.write_packet(&packet).is_ok());
        assert_eq!(writer.packets_written(), 1);
        
        // Cleanup
        drop(writer);
        fs::remove_file(path).ok();
    }

    #[test]
    fn test_segment_size_fuzzer() {
        let ctx = create_test_context();
        let output_path = "/tmp/test_segment_size.pcap";
        
        let result = segment_size::fuzz(&ctx, output_path);
        assert!(result.is_ok());
        
        let count = result.unwrap();
        assert!(count > 0, "Should generate at least one packet");
        assert!(count >= 14, "Should generate at least 14 packets for segment size fuzzing");
        
        // Verify file exists
        assert!(fs::metadata(output_path).is_ok());
        
        // Cleanup
        fs::remove_file(output_path).ok();
    }

    #[test]
    fn test_length_mismatch_fuzzer() {
        let ctx = create_test_context();
        let output_path = "/tmp/test_length_mismatch.pcap";
        
        let result = length_mismatch::fuzz(&ctx, output_path);
        assert!(result.is_ok());
        
        let count = result.unwrap();
        assert!(count > 0, "Should generate at least one packet");
        
        // Verify file exists
        assert!(fs::metadata(output_path).is_ok());
        
        // Cleanup
        fs::remove_file(output_path).ok();
    }

    #[test]
    fn test_tcp_options_fuzzer() {
        let ctx = create_test_context();
        let output_path = "/tmp/test_tcp_options.pcap";
        
        let result = tcp_options::fuzz(&ctx, output_path);
        assert!(result.is_ok());
        
        let count = result.unwrap();
        assert!(count > 0, "Should generate at least one packet");
        
        // Verify file exists
        assert!(fs::metadata(output_path).is_ok());
        
        // Cleanup
        fs::remove_file(output_path).ok();
    }

    #[test]
    fn test_fragmentation_fuzzer() {
        let ctx = create_test_context();
        let output_path = "/tmp/test_fragmentation.pcap";
        
        let result = fragmentation::fuzz(&ctx, output_path);
        assert!(result.is_ok());
        
        let count = result.unwrap();
        assert!(count > 0, "Should generate at least one packet");
        
        // Verify file exists
        assert!(fs::metadata(output_path).is_ok());
        
        // Cleanup
        fs::remove_file(output_path).ok();
    }

    #[test]
    fn test_checksum_fuzzer() {
        let ctx = create_test_context();
        let output_path = "/tmp/test_checksum.pcap";
        
        let result = checksum::fuzz(&ctx, output_path);
        assert!(result.is_ok());
        
        let count = result.unwrap();
        assert!(count > 0, "Should generate at least one packet");
        
        // Verify file exists
        assert!(fs::metadata(output_path).is_ok());
        
        // Cleanup
        fs::remove_file(output_path).ok();
    }

    #[test]
    fn test_all_fuzzers_generate_valid_pcap_files() {
        let ctx = create_test_context();
        
        let fuzzers = vec![
            ("segment_size", "/tmp/test_all_seg.pcap"),
            ("length_mismatch", "/tmp/test_all_len.pcap"),
            ("tcp_options", "/tmp/test_all_tcp.pcap"),
            ("fragmentation", "/tmp/test_all_frag.pcap"),
            ("checksum", "/tmp/test_all_check.pcap"),
        ];
        
        for (name, path) in fuzzers {
            let result = match name {
                "segment_size" => segment_size::fuzz(&ctx, path),
                "length_mismatch" => length_mismatch::fuzz(&ctx, path),
                "tcp_options" => tcp_options::fuzz(&ctx, path),
                "fragmentation" => fragmentation::fuzz(&ctx, path),
                "checksum" => checksum::fuzz(&ctx, path),
                _ => panic!("Unknown fuzzer"),
            };
            
            assert!(result.is_ok(), "{} fuzzer failed", name);
            assert!(fs::metadata(path).is_ok(), "{} fuzzer didn't create file", name);
            
            // Verify file has content
            let metadata = fs::metadata(path).unwrap();
            assert!(metadata.len() > 0, "{} created empty file", name);
            
            // Cleanup
            fs::remove_file(path).ok();
        }
    }

    #[test]
    fn test_packet_context_build_base_layers() {
        let ctx = create_test_context();
        let (eth, ipv4, tcp, payload) = ctx.build_base_layers(100);
        
        // Verify Ethernet header
        assert!(eth.destination.len() == 6);
        assert!(eth.source.len() == 6);
        
        // Verify IPv4 header
        assert_eq!(ipv4.source, [192, 168, 1, 1]);
        assert_eq!(ipv4.destination, [8, 8, 8, 8]);
        
        // Verify TCP header
        assert_eq!(tcp.source_port, 12345);
        assert_eq!(tcp.destination_port, 80);
        
        // Verify payload
        assert_eq!(payload.len(), 100);
    }
}

