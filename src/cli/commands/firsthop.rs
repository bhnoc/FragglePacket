//! GAP-022: first-hop isolation without depending solely on ICMP echo
//! (`first-hop`).

use colored::*;
use std::net::IpAddr;

use fraggle_packet::network_tests::firsthop::{
    classify, probe_icmp_n, resolve_probe_interface, tcp_syn_timing, FirstHopReport, IcmpState,
};

#[derive(clap::Args, Debug)]
pub struct FirstHopArgs {
    /// Gateway IP to probe. If omitted, detected from `route -n get
    /// default` on the given --interface (or the system default route,
    /// which may be a VPN tunnel -- this is reported explicitly).
    #[arg(long)]
    pub gateway: Option<IpAddr>,

    /// Interface whose default gateway should be probed (e.g. en0). Without
    /// this, the system default route is used, which on this class of
    /// machine is frequently a VPN tunnel rather than Wi-Fi/Ethernet.
    #[arg(long)]
    pub interface: Option<String>,

    /// Number of ICMP echo probes to send.
    #[arg(long, default_value_t = 10)]
    pub count: usize,

    /// TCP port used for the SYN-timing fallback when ICMP is suppressed.
    #[arg(long, default_value_t = 80)]
    pub tcp_port: u16,

    #[arg(long, default_value_t = 1000)]
    pub timeout_ms: u64,

    #[arg(long)]
    pub json: bool,
}

pub fn run(args: &FirstHopArgs) {
    let (interface, is_tunnel) = resolve_probe_interface(args.interface.as_deref());

    let gateway = match args.gateway {
        Some(ip) => ip,
        None => {
            eprintln!(
                "{} --gateway is required (no ARP-table gateway discovery implemented yet); \
                 pass the gateway IP explicitly, e.g. from `route -n get default`",
                "✗".red()
            );
            std::process::exit(1);
        }
    };

    if !args.json {
        println!(
            "Probing gateway={} via interface={}{}",
            gateway,
            interface.as_deref().unwrap_or("(unknown)"),
            if is_tunnel { " [TUNNEL -- this is not a physical L2 gateway]".yellow() } else { "".normal() }
        );
    }

    let icmp_raw = probe_icmp_n(gateway, args.count, args.timeout_ms);
    let fallback = if icmp_raw.1 == 0 {
        // ICMP got nothing back at all: before calling this "loss", try a
        // non-ICMP method to see if the host is actually reachable.
        Some(tcp_syn_timing(gateway, args.tcp_port, args.timeout_ms))
    } else {
        None
    };
    let (icmp, fallback) = classify(icmp_raw, fallback);

    let report = FirstHopReport {
        interface,
        interface_is_tunnel: is_tunnel,
        gateway: gateway.to_string(),
        icmp,
        fallback,
    };

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
        return;
    }

    print_human(&report);
}

fn print_human(report: &FirstHopReport) {
    println!();
    println!("{}", "== First-Hop Isolation ==".cyan().bold());
    println!("  interface: {}{}", report.interface.as_deref().unwrap_or("?"),
        if report.interface_is_tunnel { " (tunnel)".yellow().to_string() } else { "".to_string() });
    println!("  gateway:   {}", report.gateway);
    println!(
        "  icmp:      {}/{} received, loss={:.1}%",
        report.icmp.received, report.icmp.sent, report.icmp.loss_percent()
    );
    match report.icmp.state {
        IcmpState::Responding => println!("  state:     {}", "RESPONDING".green().bold()),
        IcmpState::Suppressed => println!(
            "  state:     {}",
            "ICMP SUPPRESSED (policy, not packet loss -- confirmed reachable by non-ICMP fallback)".yellow().bold()
        ),
        IcmpState::Lost => println!("  state:     {}", "LOST (no ICMP reply, no fallback corroboration)".red().bold()),
    }
    if let Some(fb) = &report.fallback {
        println!();
        println!("  fallback method:  {:?}", fb.method);
        println!("  fallback attempted: {}", fb.attempted);
        println!("  fallback succeeded: {}", fb.succeeded);
        if let Some(ms) = fb.rtt_ms {
            println!("  fallback rtt_ms:    {:.2}", ms);
        }
        if let Some(reason) = &fb.unavailable_reason {
            println!("  {} {}", "unavailable:".dimmed(), reason);
        }
    }
    println!();
}
