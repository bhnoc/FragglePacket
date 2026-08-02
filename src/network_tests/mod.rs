//! Network testing module - Tools to test network connectivity
//! 
//! Not to be confused with tests/ (which tests our code)

pub mod https;
pub mod tcp_segmentation;
pub mod tcp_health;
pub mod rtt;
pub mod dns;
pub mod packet_loss;
pub mod mtu;
pub mod tunnel_mss;
pub mod path_analysis;
pub mod ipv6;
pub mod application;
pub mod fuzzing;
pub mod upload_sweep;
pub mod ssh_path;
pub mod printer_raw;
pub mod tcp_options_echo;
pub mod quic_pmtud;
pub mod dns_secure;
pub mod scenario;
pub mod pcap_report;
pub mod probe_rate;
pub mod firsthop;
pub mod bufferbloat;
pub mod protocol_compare;
pub mod gateway_bracket;
pub mod capture;
pub mod burst_analysis;
pub mod mss_evidence;
pub mod iperf;
pub mod iperf_summary;
pub mod size_rate_matrix;
pub mod flow_dscp_matrix;
pub mod listener_admission;
pub mod listener_lease;
pub mod throughput_tuner;

pub use https::{test_https_stages, HttpsTestResult, HttpsDiagnosis, diagnose_mtu_blackhole, CertInfo};
pub use upload_sweep::{UploadSizeSweepTest, DEFAULT_SIZES as UPLOAD_SWEEP_DEFAULT_SIZES};
pub use ssh_path::SshDataPathTest;
pub use printer_raw::Raw9100BulkTest;
pub use tcp_options_echo::TcpOptionsEchoTest;
pub use quic_pmtud::QuicPmtudTest;
pub use dns_secure::DnsSecureCompareTest;

