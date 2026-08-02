use clap::{Parser, Subcommand};
use colored::*;

pub mod commands;
pub mod common;

#[derive(Parser, Debug)]
#[command(name = "fraggle-packet")]
#[command(author, version, about = "FragglePacket - Comprehensive MTU and Path Discovery Tool")]
pub struct Args {
    #[command(subcommand)]
    pub command: Option<Commands>,

    #[command(flatten)]
    pub global: GlobalArgs,
}

#[derive(clap::Args, Debug)]
pub struct GlobalArgs {
    /// Target IP address (for quick ICMP test)
    #[arg(short, long)]
    pub target: Option<String>,

    /// Starting minimum MTU (default: 576 - minimum IPv4)
    #[arg(long, default_value_t = 576)]
    pub min: usize,

    /// Starting maximum MTU (default: 1500, use 9000 for jumbo frames)
    #[arg(long, default_value_t = 1500)]
    pub max: usize,

    /// Timeout in milliseconds
    #[arg(short = 'T', long, default_value_t = 2000)]
    pub timeout_ms: u64,

    /// Retries per probe
    #[arg(short, long, default_value_t = 2)]
    pub retries: usize,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Launch interactive TUI
    Tui,
    /// Full diagnostic against a hostname (DNS, TCP, HTTP, ICMP comparison)
    Diagnose(commands::diagnose::DiagnoseArgs),
    /// Test HTTPS connectivity with stage-by-stage analysis (MTU blackhole detection)
    Https(commands::https::HttpsArgs),
    /// Test multiple targets and compare path MTUs
    Multi(commands::multi::MultiArgs),
    /// Calculate safe MTU for VPN/SASE/Zero-Trust usage
    Vpn(commands::vpn::VpnArgs),
    /// Quick ICMP-only MTU test
    Quick(commands::quick::QuickArgs),
    /// Packet fuzzing for security testing
    Fuzz(commands::fuzz::FuzzArgs),
    /// Run test framework tests (DNS, HTTPS, TCP, RTT, Loss)
    Test(commands::test::TestArgs),
    /// TCP-based MTU discovery (no ICMP required)
    Tcp(commands::tcp::TcpArgs),
    /// Run all tests against common targets and give final verdict
    KitchenSink(commands::kitchen_sink::KitchenSinkArgs),
    /// HTTP(S) upload size sweep (detects data-stall blackholes)
    UploadSweep(commands::upload_sweep::UploadSweepArgs),
    /// SSH banner + optional authenticated echo data-path test
    SshPath(commands::ssh_path::SshPathArgs),
    /// Raw JetDirect port 9100 PJL + bulk size sweep
    PrinterRaw(commands::printer_raw::PrinterRawArgs),
    /// Query actual negotiated TCP MSS and detect middlebox rewriting
    TcpOptions(commands::tcp_options::TcpOptionsArgs),
    /// QUIC/UDP PMTUD probe
    Quic(commands::quic::QuicArgs),
    /// DoH/DoT vs plain DNS comparison
    DnsSecure(commands::dns_secure::DnsSecureArgs),
    /// Render a unified README_FIRST-style diagnosis of a target
    Report(commands::report::ReportArgs),
    /// Replay a PCAP file onto the wire (requires root)
    Replay(commands::replay::ReplayArgs),
    /// Active MTU probe using the native DSL + send-and-capture engine
    Probe(commands::probe::ProbeArgs),
    /// Run a declarative scenario from a file or stdin
    Scenario(commands::scenario::ScenarioArgs),
    /// Expose a Prometheus metrics scrape endpoint
    Serve(commands::serve::ServeArgs),
    /// Print a hexdump of a packet described by our DSL (demo helper)
    DslDemo(commands::dsl_demo::DslDemoArgs),
    /// Run a budget-guarded, radio-monitored load phase (GAP-027/GAP-047)
    LoadGuard(commands::load_guard::LoadGuardArgs),
    /// Preflight ALPN/Alt-Svc + real handshake capability across endpoints (GAP-025)
    Preflight(commands::preflight::PreflightArgs),
    /// Analyze a PCAP/pcapng capture: vantage point, capture health, qualified MTU/loss verdicts (GAP-019)
    PcapReport(commands::pcap_report::PcapReportArgs),
    /// Detect ICMP rate-limiting/batching artifacts by comparing normal vs elevated probe cadence (GAP-021)
    ProbeRate(commands::probe_rate::ProbeRateArgs),
    /// First-hop gateway isolation with non-ICMP fallback when echo is suppressed (GAP-022)
    FirstHop(commands::firsthop::FirstHopArgs),
    /// Bounded packet capture with duration/size caps and safe privilege handoff (GAP-007)
    Capture(commands::capture::CaptureArgs),
    /// Pair idle/upload/download/simultaneous load phases with a first-hop gateway RTT/loss bracket (GAP-044)
    GatewayBracket(commands::gateway_bracket::GatewayBracketArgs),
    /// Bounded burst-loss/reordering/duplication/jitter probe with queue-delay correlation (GAP-066)
    BurstAnalysis(commands::burst_analysis::BurstAnalysisArgs),
    /// SYN/SYN-ACK MSS evidence (local/peer/middlebox) and multi-destination MSS clustering vs route MTU (GAP-010/GAP-026)
    MssEvidence(commands::mss_evidence::MssEvidenceArgs),
    /// Idle/upload-loaded/download-loaded/simultaneous latency via networkQuality (GAP-002)
    Bufferbloat(commands::bufferbloat::BufferbloatArgs),
    /// Controlled H1/H2/H3 comparison with directional vs simultaneous isolation (GAP-003/GAP-004)
    ProtocolCompare(commands::protocol_compare::ProtocolCompareArgs),
    /// Datagram-size/packet-rate pressure matrix distinguishing packet-rate ceilings from byte-rate policing (GAP-033)
    SizeRateMatrix(commands::size_rate_matrix::SizeRateMatrixArgs),
    /// Constant-aggregate flow-count sweep with DSCP marking-survival qualification (GAP-034)
    FlowDscpMatrix(commands::flow_dscp_matrix::FlowDscpMatrixArgs),
    /// Normalized, qualified per-phase interface-counter deltas (GAP-031)
    CounterDeltas(commands::counter_deltas::CounterDeltasArgs),
    /// Independently rate-controlled, time-aligned simultaneous upload/download sweep (GAP-032)
    IndependentRates(commands::independent_rates::IndependentRatesArgs),
    /// Controlled TCP-versus-UDP throughput/loss comparison against a user-supplied endpoint (GAP-006)
    TcpVsUdp(commands::tcp_vs_udp::TcpVsUdpArgs),
    /// Barrier-synchronized public-listener admission fanout: never reports a listener that never admitted as zero throughput (GAP-045)
    AdmissionFanout(commands::admission_fanout::AdmissionFanoutArgs),
    /// Authorized-only listener leasing with per-transport capacity/duration qualification and endpoint loss-floor declaration (GAP-040)
    ListenerLease(commands::listener_lease::ListenerLeaseArgs),
    /// Version-aware maximum-throughput tuner: randomized trials, duration validation, synthetic-max vs representative-application split (GAP-046)
    ThroughputTuner(commands::throughput_tuner::ThroughputTunerArgs),
    /// Version/direction-aware iperf3 JSON parsing and explicit-allowlist endpoint capability discovery (GAP-039/GAP-036)
    IperfAnalyze(commands::iperf_analyze::IperfAnalyzeArgs),
}

pub fn dispatch(args: Args) {
    println!("{}", "=".repeat(60).blue());
    println!("{}", " FragglePacket v0.2 ".white().on_blue().bold());
    println!("{}", "=".repeat(60).blue());
    println!();

    let global = &args.global;

    match args.command {
        Some(Commands::Tui) => {
            let _ = crate::tui_app::run_tui();
        }
        Some(Commands::Diagnose(a)) => commands::diagnose::run(&a, global),
        Some(Commands::Https(a)) => commands::https::run(&a),
        Some(Commands::Multi(a)) => commands::multi::run(&a, global),
        Some(Commands::Vpn(a)) => commands::vpn::run(&a, global),
        Some(Commands::Quick(a)) => commands::quick::run(&a, global),
        Some(Commands::Fuzz(a)) => commands::fuzz::run(&a),
        Some(Commands::Test(a)) => commands::test::run(&a),
        Some(Commands::Tcp(a)) => commands::tcp::run(&a, global),
        Some(Commands::KitchenSink(a)) => commands::kitchen_sink::run(&a, global),
        Some(Commands::UploadSweep(a)) => commands::upload_sweep::run(&a),
        Some(Commands::SshPath(a)) => commands::ssh_path::run(&a),
        Some(Commands::PrinterRaw(a)) => commands::printer_raw::run(&a),
        Some(Commands::TcpOptions(a)) => commands::tcp_options::run(&a),
        Some(Commands::Quic(a)) => commands::quic::run(&a),
        Some(Commands::DnsSecure(a)) => commands::dns_secure::run(&a),
        Some(Commands::Report(a)) => commands::report::run(&a),
        Some(Commands::Replay(a)) => commands::replay::run(&a),
        Some(Commands::Probe(a)) => commands::probe::run(&a),
        Some(Commands::Scenario(a)) => commands::scenario::run(&a),
        Some(Commands::Serve(a)) => commands::serve::run(&a),
        Some(Commands::DslDemo(a)) => commands::dsl_demo::run(&a),
        Some(Commands::LoadGuard(a)) => commands::load_guard::run(&a),
        Some(Commands::Preflight(a)) => commands::preflight::run(&a),
        Some(Commands::PcapReport(a)) => commands::pcap_report::run(&a),
        Some(Commands::ProbeRate(a)) => commands::probe_rate::run(&a),
        Some(Commands::FirstHop(a)) => commands::firsthop::run(&a),
        Some(Commands::Capture(a)) => commands::capture::run(&a),
        Some(Commands::GatewayBracket(a)) => commands::gateway_bracket::run(&a),
        Some(Commands::BurstAnalysis(a)) => commands::burst_analysis::run(&a),
        Some(Commands::MssEvidence(a)) => commands::mss_evidence::run(&a),
        Some(Commands::Bufferbloat(a)) => commands::bufferbloat::run(&a),
        Some(Commands::ProtocolCompare(a)) => commands::protocol_compare::run(&a),
        Some(Commands::SizeRateMatrix(a)) => commands::size_rate_matrix::run(&a),
        Some(Commands::FlowDscpMatrix(a)) => commands::flow_dscp_matrix::run(&a),
        Some(Commands::CounterDeltas(a)) => commands::counter_deltas::run(&a),
        Some(Commands::IndependentRates(a)) => commands::independent_rates::run(&a),
        Some(Commands::TcpVsUdp(a)) => commands::tcp_vs_udp::run(&a),
        Some(Commands::AdmissionFanout(a)) => commands::admission_fanout::run(&a),
        Some(Commands::ListenerLease(a)) => commands::listener_lease::run(&a),
        Some(Commands::ThroughputTuner(a)) => commands::throughput_tuner::run(&a),
        Some(Commands::IperfAnalyze(a)) => commands::iperf_analyze::run(&a),
        None => {
            let _ = crate::tui_app::run_tui();
        }
    }
}
