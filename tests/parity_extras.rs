//! Integration tests for the shell-script-parity additions and extras.
//!
//! These tests avoid real network I/O so they can run in any CI sandbox.

use fraggle_packet::diagnosis::{
    render_unified_report, BlackholeScoreRule, DiagnosisEngine, DiagnosisEvidence, DiagnosisIssue,
    Severity,
};
use fraggle_packet::framework::{MetricsRegistry, NetworkTest, TestCategory};
use fraggle_packet::fuzzing::dsl::*;
use fraggle_packet::fuzzing::replay::ReplayOptions;
use fraggle_packet::network_tests::{
    DnsSecureCompareTest, QuicPmtudTest, Raw9100BulkTest, SshDataPathTest, TcpOptionsEchoTest,
    UploadSizeSweepTest,
};
use std::net::Ipv4Addr;

#[test]
fn score_rule_flags_classic_blackhole_shape() {
    let mut ev = DiagnosisEvidence::default();
    ev.icmp_mtu = Some(1380);
    ev.upload_fail_sizes = vec![16384, 65536];
    ev.ssh_banner_ok = Some(true);
    ev.ssh_exec_ok = Some(false);
    ev.printer_fail_sizes = vec![32768];
    let (score, findings) = BlackholeScoreRule::score(&ev);
    assert!(score >= 6, "expected strong score, got {}", score);
    assert!(!findings.is_empty());
    assert_eq!(
        BlackholeScoreRule::severity_for_score(score),
        Severity::Critical
    );
}

#[test]
fn unified_report_rendering_is_stable() {
    let mut ev = DiagnosisEvidence::default();
    ev.icmp_mtu = Some(1400);
    ev.upload_fail_sizes = vec![65536];
    let engine = DiagnosisEngine::new();
    let diagnoses = engine.diagnose(&ev);
    let report = render_unified_report(&diagnoses, &ev);
    assert!(report.contains("=== Findings ==="));
    assert!(report.contains("SUGGESTED_BASE_MSS_IPV4"));
    assert!(report.contains("SUGGESTED_CONSERVATIVE_CLAMP"));
}

#[test]
fn diagnosis_engine_picks_up_blackhole_score() {
    let mut ev = DiagnosisEvidence::default();
    ev.upload_fail_sizes = vec![65536];
    ev.ssh_banner_ok = Some(true);
    ev.ssh_exec_ok = Some(false);
    let engine = DiagnosisEngine::new();
    let diagnoses = engine.diagnose(&ev);
    assert!(diagnoses
        .iter()
        .any(|d| d.issue == DiagnosisIssue::BlackholeScore));
}

#[test]
fn dsl_round_trip_layers_have_expected_bytes() {
    let pkt = Ether::new()
        / Ip::new().dst([8, 8, 8, 8]).df()
        / Tcp::new()
            .dport(443)
            .sport(54321)
            .syn()
            .options(vec![TcpOpt::Mss(1460), TcpOpt::SAckOK])
        / Raw::of_size(64, b'Z');
    let bytes = pkt.build().expect("build");
    assert!(bytes.len() >= 14 + 20 + 20 + 64);
    assert_eq!(u16::from_be_bytes([bytes[12], bytes[13]]), 0x0800);
    let df_flags = bytes[14 + 6];
    assert!(df_flags & 0x40 != 0, "DF flag should be set");
    assert_eq!(bytes[14 + 9], 6, "protocol should be TCP");
}

#[test]
fn dsl_fragment_returns_more_than_one_fragment() {
    let pkt = Ether::new()
        / Ip::new().dst([1, 1, 1, 1])
        / Udp::new().dport(33434)
        / Raw::of_size(2400, b'F');
    let frags = pkt.fragment(400).expect("fragment");
    assert!(frags.len() >= 2);
}

#[test]
fn dsl_hexdump_contains_hex_digits() {
    let pkt = Ether::new() / Ip::new() / Tcp::new().dport(80).syn();
    let dump = pkt.hexdump().expect("dump");
    assert!(dump.contains("00000000"));
}

#[test]
fn replay_options_builder_sets_fields() {
    let opts = ReplayOptions::new()
        .iface("lo0")
        .loop_count(3)
        .rewrite_dst_ip(Ipv4Addr::new(5, 6, 7, 8));
    assert_eq!(opts.iface.as_deref(), Some("lo0"));
    assert_eq!(opts.loop_count, 3);
    assert_eq!(opts.rewrite_dst_ip, Some(Ipv4Addr::new(5, 6, 7, 8)));
}

#[test]
fn new_tests_expose_correct_category() {
    let t = UploadSizeSweepTest::new();
    assert_eq!(t.category(), TestCategory::HTTPS);
    let t = SshDataPathTest::new();
    assert_eq!(t.category(), TestCategory::Application);
    let t = Raw9100BulkTest::new();
    assert_eq!(t.category(), TestCategory::Application);
    let t = TcpOptionsEchoTest::new();
    assert_eq!(t.category(), TestCategory::TCPHealth);
    let t = QuicPmtudTest::new();
    assert_eq!(t.category(), TestCategory::MTU);
    let t = DnsSecureCompareTest::new();
    assert_eq!(t.category(), TestCategory::DNS);
}

#[test]
fn metrics_registry_renders_prometheus_text() {
    let reg = MetricsRegistry::new();
    reg.set_help("fraggle_fake_seconds", "fake metric for tests");
    reg.set_gauge("fraggle_fake_seconds", 1.25);
    let s = reg.render();
    assert!(s.contains("# HELP fraggle_fake_seconds"));
    assert!(s.contains("fraggle_fake_seconds 1.25"));
}

#[test]
fn scenario_parser_round_trips_kinds() {
    use fraggle_packet::network_tests::scenario::Scenario;
    let text = "# step: one\nkind: https\ntarget: example.com\n\n# step: two\nkind: quic\ntarget: example.com\nport: 443\n";
    let s = Scenario::parse(text).unwrap();
    assert_eq!(s.steps.len(), 2);
    assert_eq!(s.steps[0].kind, "https");
    assert_eq!(s.steps[1].port, Some(443));
}
