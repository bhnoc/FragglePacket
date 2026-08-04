use colored::*;
use fraggle_packet::probe::{binary_search_mtu_icmp, probe_icmp};
use std::net::IpAddr;

use crate::cli::common::*;
use crate::cli::GlobalArgs;

#[derive(clap::Args, Debug)]
pub struct VpnArgs {
    /// VPN type (see --help for full list)
    pub vpn_type: String,
    /// Base MTU to calculate from (default: auto-detect)
    #[arg(short, long)]
    pub base_mtu: Option<usize>,

    /// Emit the calculation as JSON
    #[arg(long)]
    pub json: bool,
}

pub fn run(args: &VpnArgs, global: &GlobalArgs) {
    run_vpn_calculator(&args.vpn_type, args.base_mtu, global.timeout_ms, global.min, global.max, global.retries, args.json);
}

fn run_vpn_calculator(vpn_type: &str, base_mtu: Option<usize>, timeout_ms: u64, min_mtu: usize, max_mtu: usize, retries: usize, json: bool) {
    let (overhead, proto_desc) = match vpn_type.to_lowercase().as_str() {
        // Traditional VPNs
        "wireguard" | "wg" => (VPN_OVERHEAD_WIREGUARD, "WireGuard (UDP)"),
        "openvpn-udp" | "ovpn-udp" => (VPN_OVERHEAD_OPENVPN_UDP, "OpenVPN over UDP"),
        "openvpn-tcp" | "ovpn-tcp" => (VPN_OVERHEAD_OPENVPN_TCP, "OpenVPN over TCP"),
        "ipsec" | "ipsec-udp" => (VPN_OVERHEAD_IPSEC_UDP, "IPsec with NAT-T (UDP)"),
        "ipsec-tunnel" => (VPN_OVERHEAD_IPSEC_TUNNEL, "IPsec tunnel mode"),
        "ikev2" => (VPN_OVERHEAD_IKEV2, "IKEv2/IPsec"),
        "pptp" => (VPN_OVERHEAD_PPTP, "PPTP (GRE+PPP)"),
        "l2tp" => (VPN_OVERHEAD_L2TP, "L2TP/IPsec"),

        // Zero Trust / SASE
        "zscaler" | "zia" | "zpa" => (VPN_OVERHEAD_ZSCALER, "Zscaler ZIA/ZPA"),
        "netskope" => (VPN_OVERHEAD_NETSKOPE, "Netskope SASE"),
        "cloudflare" | "warp" => (VPN_OVERHEAD_CLOUDFLARE_WARP, "Cloudflare WARP"),
        "globalprotect" | "paloalto" => (VPN_OVERHEAD_GLOBAL_PROTECT, "Palo Alto GlobalProtect"),
        "anyconnect" | "cisco" => (VPN_OVERHEAD_CISCO_ANYCONNECT, "Cisco AnyConnect"),
        "forticlient" | "fortinet" => (VPN_OVERHEAD_FORTINET, "FortiClient"),

        // Overlay protocols
        "gre" => (VPN_OVERHEAD_GRE, "GRE tunnel"),
        "vxlan" => (VPN_OVERHEAD_VXLAN, "VXLAN overlay"),
        "geneve" => (VPN_OVERHEAD_GENEVE, "Geneve overlay"),

        "list" => {
            println!("{}", "Supported VPN/Tunnel Types:".cyan().bold());
            println!();
            println!("{}", "Traditional VPNs:".yellow());
            println!("  wireguard, wg          WireGuard (UDP)              ~60 bytes");
            println!("  openvpn-udp            OpenVPN over UDP             ~70 bytes");
            println!("  openvpn-tcp            OpenVPN over TCP             ~90 bytes");
            println!("  ipsec, ipsec-udp       IPsec with NAT-T             ~72 bytes");
            println!("  ipsec-tunnel           IPsec tunnel mode            ~80 bytes");
            println!("  ikev2                  IKEv2/IPsec                  ~80 bytes");
            println!("  pptp                   PPTP                         ~48 bytes");
            println!("  l2tp                   L2TP/IPsec                   ~76 bytes");
            println!();
            println!("{}", "Zero Trust / SASE:".yellow());
            println!("  zscaler, zia, zpa      Zscaler ZIA/ZPA             ~100 bytes");
            println!("  netskope               Netskope                     ~90 bytes");
            println!("  cloudflare, warp       Cloudflare WARP              ~60 bytes");
            println!("  globalprotect          Palo Alto GlobalProtect      ~80 bytes");
            println!("  anyconnect, cisco      Cisco AnyConnect             ~80 bytes");
            println!("  forticlient            FortiClient                  ~76 bytes");
            println!();
            println!("{}", "Overlay Protocols:".yellow());
            println!("  gre                    GRE tunnel                   ~24 bytes");
            println!("  vxlan                  VXLAN overlay                ~50 bytes");
            println!("  geneve                 Geneve overlay               ~50 bytes");
            return;
        }

        _ => {
            eprintln!("{}: Unknown VPN type '{}'. Run 'fraggle-packet vpn list' for options", "Error".red(), vpn_type);
            return;
        }
    };

    let base = match base_mtu {
        Some(m) => m,
        None => {
            // Auto-detect by testing common DNS server
            println!("Auto-detecting base MTU via 8.8.8.8...");
            let ip: IpAddr = "8.8.8.8".parse().unwrap();
            if !probe_icmp(ip, 64, timeout_ms, 1) {
                println!("{}: Cannot reach 8.8.8.8, using default 1500", "Warning".yellow());
                1500
            } else {
                binary_search_mtu_icmp(ip, min_mtu, max_mtu, timeout_ms, retries)
            }
        }
    };

    println!();
    let tunnel_mtu_early = base.saturating_sub(overhead);
    if json {
        let inner = tunnel_mtu_early.saturating_sub(40);
        let safe = if overhead >= 80 { tunnel_mtu_early.saturating_sub(20) } else { tunnel_mtu_early };
        let doc = serde_json::json!({
            "vpn_type": vpn_type,
            "solution": proto_desc,
            "protocol_overhead_bytes": overhead,
            "base_path_mtu": base,
            "tunnel_interface_mtu": tunnel_mtu_early,
            "safe_conservative_mtu": safe,
            "inner_tcp_mss": inner,
            // An inner MTU below the IPv6 minimum breaks paths that look fine in
            // a calculator, so it is flagged rather than left for the reader.
            "below_ipv6_minimum": tunnel_mtu_early < 1280,
        });
        match serde_json::to_string_pretty(&doc) {
            Ok(s) => println!("{s}"),
            Err(e) => eprintln!("failed to serialize calculation: {e}"),
        }
        return;
    }

    println!("{}", "=".repeat(60).blue());
    println!("{}", " VPN/TUNNEL MTU CALCULATOR ".white().on_blue().bold());
    println!("{}", "=".repeat(60).blue());
    println!();
    println!("  Solution:          {}", proto_desc.green());
    println!("  Protocol Overhead: {} bytes", overhead);
    println!("  Base Path MTU:     {} bytes", base);
    println!();

    let tunnel_mtu = base.saturating_sub(overhead);
    let inner_mss = tunnel_mtu.saturating_sub(40);

    // For extra safety with SASE/Zero Trust, recommend slightly lower
    let safe_tunnel_mtu = if overhead >= 80 {
        tunnel_mtu.saturating_sub(20) // Extra buffer for SASE solutions
    } else {
        tunnel_mtu
    };

    println!("{}", "RECOMMENDATIONS:".cyan().bold());
    println!("  Tunnel interface MTU: {} bytes", tunnel_mtu.to_string().green().bold());
    println!("  Safe/conservative:    {} bytes", safe_tunnel_mtu.to_string().yellow());
    println!("  Inner TCP MSS:        {} bytes", inner_mss.to_string().green());
    println!();

    println!("{}", "CONFIGURATION:".cyan());
    match vpn_type.to_lowercase().as_str() {
        "wireguard" | "wg" | "cloudflare" | "warp" => {
            println!("  [Interface]");
            println!("  MTU = {}", tunnel_mtu);
        }
        "openvpn-udp" | "openvpn-tcp" | "ovpn-udp" | "ovpn-tcp" => {
            println!("  # In server/client config:");
            println!("  tun-mtu {}", tunnel_mtu);
            println!("  mssfix {}", inner_mss);
        }
        "zscaler" | "zia" | "zpa" => {
            println!("  # Zscaler ZCC / tunnel interface:");
            println!("  MTU = {}", safe_tunnel_mtu);
        }
        "globalprotect" | "paloalto" => {
            println!("  # GlobalProtect portal/gateway config:");
            println!("  tunnel-mtu {}", tunnel_mtu);
            println!("  # Or in agent settings");
        }
        "anyconnect" | "cisco" => {
            println!("  # AnyConnect profile XML:");
            println!("  <MTU>{}</MTU>", tunnel_mtu);
        }
        _ => {
            println!("  # Set interface MTU to {}", tunnel_mtu);
        }
    }

}
