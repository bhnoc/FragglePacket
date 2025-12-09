//! Fuzzing implementations for different attack vectors

pub mod segment_size;
pub mod length_mismatch;
pub mod tcp_options;
pub mod fragmentation;
pub mod checksum;

use crate::fuzzing::{PacketContext, PcapWriter, FuzzError};

/// Trait for fuzzing strategies
pub trait Fuzzer {
    /// Get the name of this fuzzer
    fn name(&self) -> &str;
    
    /// Get a description of what this fuzzer tests
    fn description(&self) -> &str;
    
    /// Run the fuzzing campaign
    fn fuzz(
        &self,
        ctx: &PacketContext,
        writer: &mut PcapWriter,
    ) -> Result<usize, FuzzError>;
}

/// Segment size fuzzer struct
pub struct SegmentSizeFuzzer;

impl Fuzzer for SegmentSizeFuzzer {
    fn name(&self) -> &str {
        "Segment Size Fuzzing"
    }
    
    fn description(&self) -> &str {
        "Tests TCP segment sizes from 0 to jumbo frames (9000+ bytes)"
    }
    
    fn fuzz(&self, ctx: &PacketContext, writer: &mut PcapWriter) -> Result<usize, FuzzError> {
        let output_path = "/tmp/segment_size_temp.pcap";
        segment_size::fuzz(ctx, output_path)
    }
}

/// Length mismatch fuzzer struct
pub struct LengthMismatchFuzzer;

impl Fuzzer for LengthMismatchFuzzer {
    fn name(&self) -> &str {
        "Length Mismatch"
    }
    
    fn description(&self) -> &str {
        "IP header length field doesn't match actual packet size (Heartbleed-style)"
    }
    
    fn fuzz(&self, ctx: &PacketContext, writer: &mut PcapWriter) -> Result<usize, FuzzError> {
        let output_path = "/tmp/length_mismatch_temp.pcap";
        length_mismatch::fuzz(ctx, output_path)
    }
}

/// TCP options fuzzer struct
pub struct TcpOptionsFuzzer;

impl Fuzzer for TcpOptionsFuzzer {
    fn name(&self) -> &str {
        "TCP Options Corruption"
    }
    
    fn description(&self) -> &str {
        "Malformed TCP options (MSS, SACK, Window Scale)"
    }
    
    fn fuzz(&self, ctx: &PacketContext, writer: &mut PcapWriter) -> Result<usize, FuzzError> {
        let output_path = "/tmp/tcp_options_temp.pcap";
        tcp_options::fuzz(ctx, output_path)
    }
}

/// Fragmentation fuzzer struct
pub struct FragmentationFuzzer;

impl Fuzzer for FragmentationFuzzer {
    fn name(&self) -> &str {
        "IP Fragmentation"
    }
    
    fn description(&self) -> &str {
        "Overlapping fragments, missing fragments, out-of-order reassembly"
    }
    
    fn fuzz(&self, ctx: &PacketContext, writer: &mut PcapWriter) -> Result<usize, FuzzError> {
        let output_path = "/tmp/fragmentation_temp.pcap";
        fragmentation::fuzz(ctx, output_path)
    }
}

/// Checksum fuzzer struct
pub struct ChecksumFuzzer;

impl Fuzzer for ChecksumFuzzer {
    fn name(&self) -> &str {
        "Checksum Validation"
    }
    
    fn description(&self) -> &str {
        "Valid and invalid checksums to test validation bypass"
    }
    
    fn fuzz(&self, ctx: &PacketContext, writer: &mut PcapWriter) -> Result<usize, FuzzError> {
        let output_path = "/tmp/checksum_temp.pcap";
        checksum::fuzz(ctx, output_path)
    }
}

