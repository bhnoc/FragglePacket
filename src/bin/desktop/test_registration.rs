//! Test registration for FragglePacket Desktop
//!
//! Registers all available network tests with the TestOrchestrator.

use fraggle_packet::framework::TestOrchestrator;
use fraggle_packet::network_tests::{
    application::ApplicationTest,
    dns::DnsTest,
    fuzzing::{FuzzMode, FuzzingTest},
    https::HttpsTest,
    ipv6::Ipv6Test,
    mtu::{IcmpMtuTest, TcpMtuTest},
    packet_loss::PacketLossTest,
    path_analysis::PathAnalysisTest,
    rtt::RttTest,
    tcp_health::TcpHealthTest,
    tcp_segmentation::TcpSegmentationTest,
    tunnel_mss::TunnelMssClampingTest,
    DnsSecureCompareTest, QuicPmtudTest, Raw9100BulkTest, SshDataPathTest, TcpOptionsEchoTest,
    UploadSizeSweepTest,
};

/// Register all tests with the orchestrator
pub fn register_all_tests(orchestrator: &mut TestOrchestrator) {
    // DNS tests
    orchestrator.register(Box::new(DnsTest::new()));

    // MTU discovery tests
    orchestrator.register(Box::new(IcmpMtuTest::new()));
    orchestrator.register(Box::new(TcpMtuTest::new()));
    orchestrator.register(Box::new(TunnelMssClampingTest::new()));

    // HTTPS stage-by-stage
    orchestrator.register(Box::new(HttpsTest::new()));

    // TCP tests
    orchestrator.register(Box::new(TcpSegmentationTest::new()));
    orchestrator.register(Box::new(TcpHealthTest::new()));

    // Latency and loss tests
    orchestrator.register(Box::new(RttTest::new().with_count(10)));
    orchestrator.register(Box::new(PacketLossTest::new().with_count(10)));

    // Path analysis
    orchestrator.register(Box::new(PathAnalysisTest::new()));

    // IPv6 comparison
    orchestrator.register(Box::new(Ipv6Test::new()));

    // Application protocol tests
    orchestrator.register(Box::new(ApplicationTest::new()));

    // Fuzzing (default to All mode)
    orchestrator.register(Box::new(
        FuzzingTest::new(FuzzMode::All).with_output("reports/desktop_fuzz.pcap".to_string()),
    ));

    // Shell script parity + comprehensive-tester extras
    orchestrator.register(Box::new(UploadSizeSweepTest::new()));
    orchestrator.register(Box::new(SshDataPathTest::new()));
    orchestrator.register(Box::new(Raw9100BulkTest::new()));
    orchestrator.register(Box::new(TcpOptionsEchoTest::new()));
    orchestrator.register(Box::new(QuicPmtudTest::new()));
    orchestrator.register(Box::new(DnsSecureCompareTest::new()));
}
