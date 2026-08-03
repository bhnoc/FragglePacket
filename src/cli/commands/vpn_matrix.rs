//! GAP-060: VPN/encapsulation compatibility matrix CLI (`vpn-matrix`).

use colored::*;
use std::net::IpAddr;
use std::time::Duration;

use fraggle_packet::network_tests::vpn_matrix::{
    interface_mtu_hint, measure_effective_mss_via_tcp, probe_protocol_reachability,
    EffectiveMtuResult, VpnProtocol,
};

#[derive(clap::Args, Debug)]
pub struct VpnMatrixArgs {
    /// Target host/IP to probe protocol reachability and MSS against.
    #[arg(long)]
    pub target: IpAddr,

    /// Interface to bind effective-MTU/MSS measurement to, e.g. utun6.
    /// Required for the MTU/MSS half -- unbound measurement describes
    /// whichever interface the OS happens to route through.
    #[arg(long)]
    pub interface: Option<String>,

    /// Port to use for the effective-MSS TCP handshake measurement.
    #[arg(long, default_value_t = 443)]
    pub mss_probe_port: u16,

    #[arg(long, default_value_t = 500)]
    pub timeout_ms: u64,

    /// Never prints the local egress-facing IP unless explicitly requested
    /// (GAP-018 treats it like a BSSID).
    #[arg(long)]
    pub show_local_ip: bool,

    #[arg(long)]
    pub json: bool,
}

pub fn run(args: &VpnMatrixArgs) {
    let timeout = Duration::from_millis(args.timeout_ms);
    let protocols = [
        VpnProtocol::WireGuard,
        VpnProtocol::IpsecIke,
        VpnProtocol::IpsecNatT,
        VpnProtocol::OpenVpnUdp,
        VpnProtocol::OpenVpnTcp,
    ];

    let probes: Vec<_> = protocols
        .iter()
        .map(|p| probe_protocol_reachability(*p, args.target, p.default_port(), timeout))
        .collect();

    let interface_mtu = args.interface.as_deref().and_then(interface_mtu_hint);
    let bind_ip = if args.show_local_ip {
        local_bind_ip(args.interface.as_deref())
    } else {
        None
    };
    let effective_mss =
        measure_effective_mss_via_tcp(args.target, args.mss_probe_port, bind_ip, timeout);

    let effective_mtu = EffectiveMtuResult {
        interface: args
            .interface
            .clone()
            .unwrap_or_else(|| "unspecified".to_string()),
        interface_mtu_reported: interface_mtu,
        measured_effective_mtu: effective_mss.as_ref().ok().map(|mss| mss + 40),
        overhead_hint_bytes: None,
        protocol_hint: None,
    };

    if args.json {
        let report = serde_json::json!({
            "protocol_probes": probes,
            "effective_mss_bytes": effective_mss.as_ref().ok(),
            "effective_mss_error": effective_mss.as_ref().err(),
            "effective_mtu": effective_mtu,
        });
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
        return;
    }

    println!(
        "{}",
        "== VPN/Encapsulation Compatibility Matrix ==".cyan().bold()
    );
    println!(
        "  {}",
        "(never requests, reads, or logs a VPN credential)".dimmed()
    );
    for probe in &probes {
        println!(
            "  {} port {}: {:?} ({}ms)",
            probe.protocol.label(),
            probe.port,
            probe.outcome,
            probe.elapsed_ms
        );
    }
    println!();
    println!("  interface: {}", effective_mtu.interface);
    println!(
        "  interface-reported MTU: {}",
        interface_mtu
            .map(|m| m.to_string())
            .unwrap_or_else(|| "unavailable".to_string())
    );
    match &effective_mss {
        Ok(mss) => println!(
            "  measured effective TCP MSS (real handshake): {} bytes",
            mss
        ),
        Err(e) => println!(
            "  {}",
            format!("measured effective TCP MSS: unavailable ({})", e).yellow()
        ),
    }
}

fn local_bind_ip(interface: Option<&str>) -> Option<IpAddr> {
    let iface = interface?;
    let out = std::process::Command::new("ifconfig")
        .arg(iface)
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("inet ") {
            return rest.split_whitespace().next()?.parse().ok();
        }
    }
    None
}
