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
        segment_size::fuzz_to_writer(ctx, writer)
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
        length_mismatch::fuzz_to_writer(ctx, writer)
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
        tcp_options::fuzz_to_writer(ctx, writer)
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
        fragmentation::fuzz_to_writer(ctx, writer)
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
        checksum::fuzz_to_writer(ctx, writer)
    }
}

