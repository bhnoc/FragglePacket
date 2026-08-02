// VPN/Tunnel overheads (bytes added to each packet)
// Traditional VPNs
pub const VPN_OVERHEAD_WIREGUARD: usize = 60;      // UDP + WG header
pub const VPN_OVERHEAD_OPENVPN_UDP: usize = 70;    // UDP + OpenVPN header + encryption
pub const VPN_OVERHEAD_OPENVPN_TCP: usize = 90;    // TCP + OpenVPN + encryption (avoid TCP-over-TCP)
pub const VPN_OVERHEAD_IPSEC_UDP: usize = 72;      // ESP + UDP encap (NAT-T)
pub const VPN_OVERHEAD_IPSEC_TUNNEL: usize = 80;   // ESP tunnel mode
pub const VPN_OVERHEAD_IKEV2: usize = 80;          // IKEv2/IPsec
pub const VPN_OVERHEAD_PPTP: usize = 48;           // GRE + PPP
pub const VPN_OVERHEAD_L2TP: usize = 76;           // L2TP + IPsec

// Zero Trust / SASE solutions (conservative estimates)
pub const VPN_OVERHEAD_ZSCALER: usize = 100;       // Zscaler ZIA/ZPA tunnel overhead
pub const VPN_OVERHEAD_NETSKOPE: usize = 90;       // Netskope SASE
pub const VPN_OVERHEAD_CLOUDFLARE_WARP: usize = 60; // WARP uses WireGuard
pub const VPN_OVERHEAD_GLOBAL_PROTECT: usize = 80; // Palo Alto GlobalProtect
pub const VPN_OVERHEAD_CISCO_ANYCONNECT: usize = 80;
pub const VPN_OVERHEAD_FORTINET: usize = 76;       // FortiClient

// Overlay/Tunnel protocols
pub const VPN_OVERHEAD_GRE: usize = 24;            // Basic GRE
pub const VPN_OVERHEAD_VXLAN: usize = 50;          // VXLAN encap
pub const VPN_OVERHEAD_GENEVE: usize = 50;         // Geneve (similar to VXLAN)

pub fn print_test_result(res: &fraggle_packet::framework::TestResult) {
    use colored::*;
    use fraggle_packet::framework::TestStatus;
    let status = match res.status {
        TestStatus::Success => "PASS".green().bold().to_string(),
        TestStatus::Warning => "WARN".yellow().bold().to_string(),
        TestStatus::Failed => "FAIL".red().bold().to_string(),
        TestStatus::Running => "RUN ".cyan().to_string(),
        TestStatus::Pending => "PEND".to_string(),
        TestStatus::Skipped => "SKIP".dimmed().to_string(),
    };
    println!("[{}] {} ({}) target={}", status, res.name, res.category.as_str(), res.target);
    for (k, v) in &res.metrics {
        println!("  metric {} = {}", k, v);
    }
    for (k, v) in &res.metadata {
        println!("  meta   {} = {}", k, v);
    }
    for d in &res.diagnoses {
        println!("  {:?}: {}", d.severity, d.title);
        for r in &d.recommendations {
            println!("    - {}", r);
        }
    }
}
