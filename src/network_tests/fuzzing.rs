//! Fuzzing Test Wrapper - wraps RustPacketFuzz in NetworkTest trait

use crate::framework::{
    Diagnosis, DiagnosisSeverity, NetworkTest, TestCategory, TestResult, TestStatus,
};
use crate::fuzzing::context::PacketContext;
use crate::fuzzing::fuzzers::{
    ChecksumFuzzer, FragmentationFuzzer, Fuzzer, LengthMismatchFuzzer, SegmentSizeFuzzer,
    TcpOptionsFuzzer,
};
use crate::fuzzing::writer::PcapWriter;
use std::error::Error;
use std::net::Ipv4Addr;

/// Fuzzing test modes
#[derive(Debug, Clone, Copy)]
pub enum FuzzMode {
    SegmentSize,
    LengthMismatch,
    TcpOptions,
    Fragmentation,
    Checksum,
    All,
}

impl FuzzMode {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "segment" | "segment-size" => Some(FuzzMode::SegmentSize),
            "length" | "length-mismatch" => Some(FuzzMode::LengthMismatch),
            "options" | "tcp-options" => Some(FuzzMode::TcpOptions),
            "fragment" | "fragmentation" => Some(FuzzMode::Fragmentation),
            "checksum" => Some(FuzzMode::Checksum),
            "all" => Some(FuzzMode::All),
            _ => None,
        }
    }
}

/// Packet fuzzing test
pub struct FuzzingTest {
    mode: FuzzMode,
    output_path: String,
}

impl FuzzingTest {
    pub fn new(mode: FuzzMode) -> Self {
        Self {
            mode,
            output_path: "reports/fuzz.pcap".to_string(),
        }
    }

    pub fn with_output(mut self, path: String) -> Self {
        self.output_path = path;
        self
    }
}

impl NetworkTest for FuzzingTest {
    fn name(&self) -> &str {
        match self.mode {
            FuzzMode::SegmentSize => "Fuzzing: Segment Size",
            FuzzMode::LengthMismatch => "Fuzzing: Length Mismatch",
            FuzzMode::TcpOptions => "Fuzzing: TCP Options",
            FuzzMode::Fragmentation => "Fuzzing: Fragmentation",
            FuzzMode::Checksum => "Fuzzing: Checksum",
            FuzzMode::All => "Fuzzing: All Modes",
        }
    }

    fn category(&self) -> TestCategory {
        TestCategory::Fuzzing
    }

    fn run(&self, target: &str) -> Result<TestResult, Box<dyn Error>> {
        let mut result =
            TestResult::new(self.name().to_string(), self.category(), target.to_string());

        // Parse target IP
        let target_ip: Ipv4Addr = target.parse().or_else(|_| {
            // Try DNS resolution
            use std::net::ToSocketAddrs;
            format!("{}:80", target)
                .to_socket_addrs()
                .ok()
                .and_then(|mut addrs| addrs.next())
                .and_then(|addr| {
                    if let std::net::IpAddr::V4(ipv4) = addr.ip() {
                        Some(ipv4)
                    } else {
                        None
                    }
                })
                .ok_or("Could not resolve target")
        })?;

        // Create packet context
        let ctx = PacketContext::new("192.168.1.100", &target_ip.to_string())?;

        // Create PCAP writer
        let mut writer = PcapWriter::new(&self.output_path)?;

        // Run fuzzing based on mode
        let packet_count = match self.mode {
            FuzzMode::SegmentSize => {
                let fuzzer = SegmentSizeFuzzer;
                fuzzer.fuzz(&ctx, &mut writer)?
            }
            FuzzMode::LengthMismatch => {
                let fuzzer = LengthMismatchFuzzer;
                fuzzer.fuzz(&ctx, &mut writer)?
            }
            FuzzMode::TcpOptions => {
                let fuzzer = TcpOptionsFuzzer;
                fuzzer.fuzz(&ctx, &mut writer)?
            }
            FuzzMode::Fragmentation => {
                let fuzzer = FragmentationFuzzer;
                fuzzer.fuzz(&ctx, &mut writer)?
            }
            FuzzMode::Checksum => {
                let fuzzer = ChecksumFuzzer;
                fuzzer.fuzz(&ctx, &mut writer)?
            }
            FuzzMode::All => {
                let mut total = 0;
                total += SegmentSizeFuzzer.fuzz(&ctx, &mut writer)?;
                total += LengthMismatchFuzzer.fuzz(&ctx, &mut writer)?;
                total += TcpOptionsFuzzer.fuzz(&ctx, &mut writer)?;
                total += FragmentationFuzzer.fuzz(&ctx, &mut writer)?;
                total += ChecksumFuzzer.fuzz(&ctx, &mut writer)?;
                total
            }
        };

        // Writer auto-finalizes on drop
        drop(writer);

        // Add metrics
        result.add_metric("packets_generated", packet_count as f64);
        result.add_metadata("output_file", self.output_path.clone());
        result.add_metadata("mode", format!("{:?}", self.mode));
        result.add_metadata("target_ip", target_ip.to_string());

        result.set_status(TestStatus::Success);

        // Add diagnosis with recommendations
        result.add_diagnosis(
            Diagnosis::new(
                DiagnosisSeverity::Info,
                "Fuzzing Campaign Complete".to_string(),
                format!(
                    "Generated {} test packets in {}",
                    packet_count, self.output_path
                ),
            )
            .with_recommendation("Analyze PCAP with: wireshark reports/fuzz.pcap")
            .with_recommendation("Test against IDS: suricata -r reports/fuzz.pcap")
            .with_recommendation("Replay packets: tcpreplay -i eth0 reports/fuzz.pcap"),
        );

        Ok(result)
    }

    fn estimated_duration(&self) -> u64 {
        // Fuzzing is very fast (milliseconds)
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fuzzing_struct() {
        let test = FuzzingTest::new(FuzzMode::SegmentSize);
        assert_eq!(test.name(), "Fuzzing: Segment Size");
        assert_eq!(test.category(), TestCategory::Fuzzing);
    }

    #[test]
    fn test_fuzz_mode_from_str() {
        assert!(matches!(
            FuzzMode::from_str("segment"),
            Some(FuzzMode::SegmentSize)
        ));
        assert!(matches!(
            FuzzMode::from_str("length"),
            Some(FuzzMode::LengthMismatch)
        ));
        assert!(matches!(FuzzMode::from_str("all"), Some(FuzzMode::All)));
        assert!(FuzzMode::from_str("invalid").is_none());
    }
}
