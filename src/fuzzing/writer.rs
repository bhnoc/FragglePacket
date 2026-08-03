//! PCAP file writer wrapper

use pcap_file::pcap::{PcapHeader, PcapPacket, PcapWriter as RawPcapWriter};
use pcap_file::DataLink;
use std::fs::File;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::fuzzing::FuzzError;

/// Wrapper around pcap-file crate for writing packets
pub struct PcapWriter {
    writer: RawPcapWriter<File>,
    packets_written: usize,
}

impl PcapWriter {
    /// Create a new PCAP writer
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, FuzzError> {
        // Ensure parent directory exists
        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent)?;
        }

        let file = File::create(path)?;

        // pcap-file 3.0 API - simpler header
        let header = PcapHeader {
            datalink: DataLink::ETHERNET,
            snaplen: 262144, // 256KB for jumbo frames
            ..Default::default()
        };

        let writer = RawPcapWriter::with_header(file, header)
            .map_err(|e| FuzzError::PcapWrite(e.to_string()))?;

        Ok(Self {
            writer,
            packets_written: 0,
        })
    }

    /// Write a packet to the PCAP file
    pub fn write_packet(&mut self, data: &[u8]) -> Result<(), FuzzError> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();

        // pcap-file 3.0 API
        let packet = PcapPacket::new(now, data.len() as u32, data);

        self.writer
            .write_packet(&packet)
            .map_err(|e| FuzzError::PcapWrite(e.to_string()))?;

        self.packets_written += 1;

        Ok(())
    }

    /// Get the number of packets written
    pub fn packets_written(&self) -> usize {
        self.packets_written
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn test_pcap_writer() {
        let path = "/tmp/test_fuzz.pcap";
        let mut writer = PcapWriter::new(path).unwrap();

        // Write a dummy packet
        let packet = vec![0x42; 100];
        writer.write_packet(&packet).unwrap();

        assert_eq!(writer.packets_written(), 1);

        // Verify file exists and has content
        let mut file = File::open(path).unwrap();
        let mut contents = Vec::new();
        file.read_to_end(&mut contents).unwrap();
        assert!(contents.len() > 100); // Header + packet

        std::fs::remove_file(path).ok();
    }
}
