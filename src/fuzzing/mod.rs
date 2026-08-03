//! RustPacketFuzz - Packet Crafting and Security Testing Module
//!
//! This module provides functionality for generating malformed and edge-case packets
//! to test network parsers, firewalls, and IDS/IPS systems.
//!
//! # Architecture
//!
//! - `context`: PacketContext for building base packet layers
//! - `builder`: Utilities for packet construction
//! - `writer`: PCAP file writing
//! - `fuzzers`: Individual fuzzing strategies
//! - `cli`: Command-line interface integration
//!
//! # Example
//!
//! ```ignore
//! use fraggle_packet::fuzzing::{PacketContext, FuzzMode, run_campaign};
//!
//! let ctx = PacketContext::new("192.168.1.1", "8.8.8.8").unwrap();
//! run_campaign(&ctx, FuzzMode::SegmentSize, "output.pcap").unwrap();
//! ```

use std::path::PathBuf;
use thiserror::Error;

pub mod builder;
pub mod capture;
pub mod cli;
pub mod context;
pub mod dsl;
pub mod fuzzers;
pub mod probe;
pub mod replay;
pub mod writer;

pub use context::PacketContext;
pub use writer::PcapWriter;

/// Utility: detect whether the process is running as root/admin.
pub fn is_root() -> bool {
    #[cfg(unix)]
    unsafe {
        libc::geteuid() == 0
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// Fuzzing modes available
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FuzzMode {
    /// Test various TCP segment sizes (0-65535 bytes)
    SegmentSize,
    /// IP header length mismatches (Heartbleed-style)
    LengthMismatch,
    /// Corrupt TCP options (MSS, SACK, Window Scale)
    TcpOptions,
    /// IP fragmentation edge cases
    Fragmentation,
    /// Valid and invalid checksums
    Checksum,
}

impl FuzzMode {
    /// Parse fuzzing mode from string
    pub fn from_str(s: &str) -> Result<Self, FuzzError> {
        match s.to_lowercase().as_str() {
            "segment-size" | "segment" => Ok(FuzzMode::SegmentSize),
            "length-mismatch" | "length" => Ok(FuzzMode::LengthMismatch),
            "tcp-options" | "options" => Ok(FuzzMode::TcpOptions),
            "fragmentation" | "frag" => Ok(FuzzMode::Fragmentation),
            "checksum" => Ok(FuzzMode::Checksum),
            _ => Err(FuzzError::InvalidMode(s.to_string())),
        }
    }

    /// Get human-readable name
    pub fn name(&self) -> &str {
        match self {
            FuzzMode::SegmentSize => "Segment Size Fuzzing",
            FuzzMode::LengthMismatch => "Length Mismatch",
            FuzzMode::TcpOptions => "TCP Options Corruption",
            FuzzMode::Fragmentation => "IP Fragmentation",
            FuzzMode::Checksum => "Checksum Validation",
        }
    }
}

/// Result of a fuzzing campaign
#[derive(Debug, Clone)]
pub struct FuzzResult {
    /// Number of packets generated
    pub packets_generated: usize,
    /// Path to output PCAP file
    pub pcap_path: PathBuf,
    /// File size in bytes
    pub file_size_bytes: u64,
    /// Fuzzing mode used
    pub mode: FuzzMode,
    /// Duration in milliseconds
    pub duration_ms: u64,
}

/// Fuzzing errors
#[derive(Error, Debug)]
pub enum FuzzError {
    #[error("Invalid fuzzing mode: {0}")]
    InvalidMode(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("PCAP write error: {0}")]
    PcapWrite(String),

    #[error("Packet build error: {0}")]
    PacketBuild(String),

    #[error("Address parse error: {0}")]
    AddrParse(#[from] std::net::AddrParseError),
}

/// Run a complete fuzzing campaign
pub fn run_campaign(
    ctx: &PacketContext,
    mode: FuzzMode,
    output_path: &str,
) -> Result<FuzzResult, FuzzError> {
    use std::time::Instant;
    let start = Instant::now();

    let packets = match mode {
        FuzzMode::SegmentSize => fuzzers::segment_size::fuzz(ctx, output_path)?,
        FuzzMode::LengthMismatch => fuzzers::length_mismatch::fuzz(ctx, output_path)?,
        FuzzMode::TcpOptions => fuzzers::tcp_options::fuzz(ctx, output_path)?,
        FuzzMode::Fragmentation => fuzzers::fragmentation::fuzz(ctx, output_path)?,
        FuzzMode::Checksum => fuzzers::checksum::fuzz(ctx, output_path)?,
    };

    let duration_ms = start.elapsed().as_millis() as u64;
    let file_size = std::fs::metadata(output_path)?.len();

    Ok(FuzzResult {
        packets_generated: packets,
        pcap_path: PathBuf::from(output_path),
        file_size_bytes: file_size,
        mode,
        duration_ms,
    })
}
