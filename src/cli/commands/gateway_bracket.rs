//! GAP-044: local-gateway latency-under-load bracket (`gateway-bracket`).

use colored::*;
use std::net::IpAddr;
use std::time::Duration;

use fraggle_packet::load_guard::LoadBudget;
use fraggle_packet::network_tests::firsthop::resolve_probe_interface;
use fraggle_packet::network_tests::gateway_bracket::{
    run_phase, GatewayBracketReport, GatewayPhaseResult, PhaseKind, QUEUE_LOCALIZATION_CAVEAT,
    SMALL_ICMP_PACKET_CAVEAT,
};
use fraggle_packet::network_tests::firsthop::IcmpState;

#[derive(clap::Args, Debug)]
pub struct GatewayBracketArgs {
    /// Gateway IP to probe. Required: no default-route guessing, since the
    /// default route on this class of machine is frequently a VPN tunnel
    /// whose "gateway" is not the physical first hop.
    #[arg(long)]
    pub gateway: Option<IpAddr>,

    /// Interface whose first hop is under test (e.g. en0).
    #[arg(long)]
    pub interface: Option<String>,

    /// Duration of each of the four phases, in seconds. Kept short by
    /// default -- GAP-047 forbids generating heavy/long load by default.
    #[arg(long, default_value_t = 2)]
    pub phase_duration_secs: u64,

    /// Gateway probe cadence in Hz during each phase.
    #[arg(long, default_value_t = 5.0)]
    pub cadence_hz: f64,

    /// Synthetic target rate for the upload/download/simultaneous phases, in
    /// Mbps. Small on purpose: this command demonstrates the bracket
    /// mechanism, not a real load generator (that's GAP-031-034's job).
    #[arg(long, default_value_t = 1.0)]
    pub rate_mbps: f64,

    #[arg(long, default_value_t = 1000)]
    pub icmp_timeout_ms: u64,

    #[arg(long, default_value_t = 80)]
    pub tcp_fallback_port: u16,

    /// For the demo/test harness only: inject a synthetic gateway RTT/loss
    /// pattern instead of probing a real gateway, so the correlation and
    /// caveat paths are exercisable offline and deterministically.
    #[arg(long)]
    pub inject_synthetic: bool,

    #[arg(long)]
    pub json: bool,
}

fn synthetic_report(interface: Option<String>, interface_is_tunnel: bool, gateway: IpAddr) -> GatewayBracketReport {
    use fraggle_packet::network_tests::gateway_bracket::GatewaySample;
    let idle = GatewayPhaseResult {
        phase: PhaseKind::Idle,
        icmp_state: IcmpState::Responding,
        icmp_sent: 10,
        icmp_received: 10,
        avg_rtt_ms: Some(1.6),
        max_rtt_ms: Some(3.3),
        samples: vec![GatewaySample { elapsed_secs: 0.0, rtt_ms: Some(1.6) }],
        fallback: None,
        bytes_transferred: Some(0),
        throughput_loss_pct: None,
    };
    let upload = GatewayPhaseResult {
        phase: PhaseKind::Upload,
        icmp_state: IcmpState::Responding,
        icmp_sent: 10,
        icmp_received: 10,
        avg_rtt_ms: Some(2.6),
        max_rtt_ms: Some(11.0),
        samples: vec![GatewaySample { elapsed_secs: 0.5, rtt_ms: Some(2.6) }],
        fallback: None,
        bytes_transferred: Some(120_000),
        throughput_loss_pct: Some(0.002),
    };
    let download = GatewayPhaseResult {
        phase: PhaseKind::Download,
        icmp_state: IcmpState::Responding,
        icmp_sent: 10,
        icmp_received: 10,
        avg_rtt_ms: Some(4.1),
        max_rtt_ms: Some(13.8),
        samples: vec![GatewaySample { elapsed_secs: 0.5, rtt_ms: Some(4.1) }],
        fallback: None,
        bytes_transferred: Some(115_000),
        throughput_loss_pct: Some(5.5),
    };
    let simultaneous = GatewayPhaseResult {
        phase: PhaseKind::Simultaneous,
        icmp_state: IcmpState::Responding,
        icmp_sent: 10,
        icmp_received: 10,
        avg_rtt_ms: Some(7.1),
        max_rtt_ms: Some(22.7),
        samples: vec![GatewaySample { elapsed_secs: 0.5, rtt_ms: Some(7.1) }],
        fallback: None,
        bytes_transferred: Some(70_000),
        throughput_loss_pct: Some(23.5),
    };
    GatewayBracketReport {
        interface,
        interface_is_tunnel,
        gateway: gateway.to_string(),
        phases: vec![idle, upload, download, simultaneous],
        small_icmp_packet_caveat: SMALL_ICMP_PACKET_CAVEAT.to_string(),
        queue_localization_caveat: QUEUE_LOCALIZATION_CAVEAT.to_string(),
        data_source: "synthetic",
    }
}

pub fn run(args: &GatewayBracketArgs) {
    let (interface, is_tunnel) = resolve_probe_interface(args.interface.as_deref());

    let gateway = match args.gateway {
        Some(ip) => ip,
        None => {
            eprintln!(
                "{} --gateway is required; pass the interface's actual first hop \
                 (e.g. from `route -n get default` on --interface, not the tunnel default route).",
                "✗".red()
            );
            std::process::exit(1);
        }
    };

    if is_tunnel {
        eprintln!(
            "{} interface '{}' resolves through a tunnel; the gateway you pass must be the physical first hop, not the tunnel's peer.",
            "⚠".yellow(),
            interface.as_deref().unwrap_or("?")
        );
    }

    let report = if args.inject_synthetic {
        synthetic_report(interface, is_tunnel, gateway)
    } else {
        run_real(args, interface, is_tunnel, gateway)
    };

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
        return;
    }
    print_human(&report);
}

fn run_real(args: &GatewayBracketArgs, interface: Option<String>, is_tunnel: bool, gateway: IpAddr) -> GatewayBracketReport {
    let phase_duration = Duration::from_secs(args.phase_duration_secs.max(1));
    let bytes_per_tick: u64 = 512;

    let idle = run_phase(
        PhaseKind::Idle,
        gateway,
        None,
        phase_duration,
        args.cadence_hz,
        args.icmp_timeout_ms,
        args.tcp_fallback_port,
        0,
    );

    let upload_budget = LoadBudget::maintenance(args.rate_mbps, args.phase_duration_secs.max(1), 1);
    let upload = run_phase(
        PhaseKind::Upload,
        gateway,
        Some(upload_budget),
        phase_duration,
        args.cadence_hz,
        args.icmp_timeout_ms,
        args.tcp_fallback_port,
        bytes_per_tick,
    );

    let download_budget = LoadBudget::maintenance(args.rate_mbps, args.phase_duration_secs.max(1), 1);
    let download = run_phase(
        PhaseKind::Download,
        gateway,
        Some(download_budget),
        phase_duration,
        args.cadence_hz,
        args.icmp_timeout_ms,
        args.tcp_fallback_port,
        bytes_per_tick,
    );

    let simultaneous_budget = LoadBudget::maintenance(args.rate_mbps * 2.0, args.phase_duration_secs.max(1), 2);
    let simultaneous = run_phase(
        PhaseKind::Simultaneous,
        gateway,
        Some(simultaneous_budget),
        phase_duration,
        args.cadence_hz,
        args.icmp_timeout_ms,
        args.tcp_fallback_port,
        bytes_per_tick * 2,
    );

    GatewayBracketReport {
        interface,
        interface_is_tunnel: is_tunnel,
        gateway: gateway.to_string(),
        phases: vec![idle, upload, download, simultaneous],
        small_icmp_packet_caveat: SMALL_ICMP_PACKET_CAVEAT.to_string(),
        queue_localization_caveat: QUEUE_LOCALIZATION_CAVEAT.to_string(),
        data_source: "live",
    }
}

fn fmt_ms(v: Option<f64>) -> String {
    v.map(|v| format!("{v:.2}ms")).unwrap_or_else(|| "unavailable".to_string())
}

fn fmt_pct(v: Option<f64>) -> String {
    v.map(|v| format!("{v:.3}%")).unwrap_or_else(|| "unavailable".to_string())
}

fn print_human(report: &GatewayBracketReport) {
    println!();
    println!("{}", "== Gateway Latency-Under-Load Bracket ==".cyan().bold());
    println!(
        "  interface: {}{}",
        report.interface.as_deref().unwrap_or("?"),
        if report.interface_is_tunnel { " (tunnel)".yellow().to_string() } else { String::new() }
    );
    println!("  gateway:   {}", report.gateway);
    if report.data_source == "synthetic" {
        println!("  {} this report is SYNTHETIC (--inject-synthetic), not a real probed run", "⚠".yellow());
    }
    println!();

    let idle_baseline = report
        .phases
        .iter()
        .find(|p| p.phase == PhaseKind::Idle)
        .and_then(|p| p.avg_rtt_ms);

    for phase in &report.phases {
        println!("  [{}]", phase.phase.label().to_uppercase());
        match phase.icmp_state {
            IcmpState::Responding => println!("    icmp: {}/{} received", phase.icmp_received, phase.icmp_sent),
            IcmpState::Suppressed => println!(
                "    icmp: {} (fallback confirmed reachable)",
                "SUPPRESSED".yellow().bold()
            ),
            IcmpState::Lost => println!("    icmp: {}", "LOST".red().bold()),
        }
        println!("    rtt avg={} max={}", fmt_ms(phase.avg_rtt_ms), fmt_ms(phase.max_rtt_ms));
        if phase.phase != PhaseKind::Idle {
            let delta = phase.rtt_delta_ms(idle_baseline);
            println!("    rtt delta vs idle: {}", fmt_ms(delta));
            println!(
                "    throughput: bytes_transferred={} loss={}",
                phase.bytes_transferred.map(|b| b.to_string()).unwrap_or_else(|| "unavailable".to_string()),
                fmt_pct(phase.throughput_loss_pct)
            );
        }
        if let Some(fb) = &phase.fallback {
            println!("    fallback: method={:?} succeeded={}", fb.method, fb.succeeded);
        }
        println!();
    }

    println!("  {} {}", "caveat:".dimmed(), SMALL_ICMP_PACKET_CAVEAT);
    println!("  {} {}", "caveat:".dimmed(), QUEUE_LOCALIZATION_CAVEAT);
    println!();
}
