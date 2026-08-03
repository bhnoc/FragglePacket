// Helper function to register all tests with orchestrator
use fraggle_packet::framework::TestOrchestrator;
use fraggle_packet::network_tests::{
    dns::DnsTest,
    https::HttpsTest,
    tcp_segmentation::TcpSegmentationTest,
    tcp_health::TcpHealthTest,
    rtt::RttTest,
    packet_loss::PacketLossTest,
    mtu::{IcmpMtuTest, TcpMtuTest},
    tunnel_mss::TunnelMssClampingTest,
    path_analysis::PathAnalysisTest,
    ipv6::Ipv6Test,
    application::ApplicationTest,
    fuzzing::{FuzzingTest, FuzzMode},
    DnsSecureCompareTest, QuicPmtudTest, Raw9100BulkTest, SshDataPathTest, TcpOptionsEchoTest,
    UploadSizeSweepTest,
};

pub fn register_all_tests(orchestrator: &mut TestOrchestrator) {
    orchestrator.register(Box::new(DnsTest::new()));
    orchestrator.register(Box::new(IcmpMtuTest::new()));
    orchestrator.register(Box::new(TcpMtuTest::new()));
    orchestrator.register(Box::new(TunnelMssClampingTest::new()));
    orchestrator.register(Box::new(HttpsTest::new()));
    orchestrator.register(Box::new(TcpSegmentationTest::new()));
    orchestrator.register(Box::new(TcpHealthTest::new()));
    orchestrator.register(Box::new(RttTest::new().with_count(20)));
    orchestrator.register(Box::new(PacketLossTest::new().with_count(20)));
    orchestrator.register(Box::new(PathAnalysisTest::new()));
    orchestrator.register(Box::new(Ipv6Test::new()));
    orchestrator.register(Box::new(ApplicationTest::new()));
    orchestrator.register(Box::new(FuzzingTest::new(FuzzMode::All).with_output("reports/tui_fuzz.pcap".to_string())));
    orchestrator.register(Box::new(UploadSizeSweepTest::new()));
    orchestrator.register(Box::new(SshDataPathTest::new()));
    orchestrator.register(Box::new(Raw9100BulkTest::new()));
    orchestrator.register(Box::new(TcpOptionsEchoTest::new()));
    orchestrator.register(Box::new(QuicPmtudTest::new()));
    orchestrator.register(Box::new(DnsSecureCompareTest::new()));
}

