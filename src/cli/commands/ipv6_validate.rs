use colored::*;
use std::time::Duration;

use fraggle_packet::network_tests::ipv6_validation::{happy_eyeballs, validate, LayerState};

#[derive(clap::Args, Debug)]
pub struct Ipv6ValidateArgs {
    /// Interface to validate. Required: the default route on this class of
    /// machine is frequently a VPN tunnel that carries no IPv6, so an implicit
    /// choice would report the tunnel's absence as the network's.
    #[arg(long)]
    pub interface: String,

    /// Dual-stack host used to test DNS answers and reachability per family.
    #[arg(long, default_value = "cloudflare.com")]
    pub probe_host: String,

    /// Also run the Happy Eyeballs comparison (GAP-015).
    #[arg(long)]
    pub happy_eyeballs: bool,

    #[arg(long, default_value_t = 3000)]
    pub timeout_ms: u64,

    #[arg(long)]
    pub json: bool,
}

fn render(label: &str, state: &LayerState) {
    let tag = match state {
        LayerState::Ok(_) => "ok".green(),
        LayerState::Failed(_) => "FAILED".red(),
        LayerState::Unavailable { .. } => "unavailable".yellow(),
    };
    println!("    {:<22} {} — {}", label, tag, state.detail());
}

pub fn run(args: &Ipv6ValidateArgs) {
    let timeout = Duration::from_millis(args.timeout_ms);
    let v = validate(&args.interface, &args.probe_host, timeout);
    let he = if args.happy_eyeballs {
        Some(happy_eyeballs(&args.probe_host, 443, timeout))
    } else {
        None
    };

    if args.json {
        let out = serde_json::json!({ "ipv6_validation": v, "happy_eyeballs": he });
        println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
        return;
    }

    println!("\n== IPv6 Validation ==");
    println!("  interface: {}", v.interface);
    if v.interface_is_tunnel {
        println!("  {}", "interface is a tunnel".yellow());
    }
    println!("  layers:");
    render("link_local_address", &v.link_local_address);
    render("global_address", &v.global_address);
    render("router_advertisement", &v.router_advertisement);
    render("dhcpv6", &v.dhcpv6);
    render("default_route", &v.default_route);
    render("neighbor_discovery", &v.neighbor_discovery);
    render("dns_aaaa", &v.dns_aaaa);
    render("native_reachability", &v.native_reachability);
    render("ipv6_pmtu", &v.ipv6_pmtu);
    render("nat64_prefix", &v.nat64_prefix);
    render("dns64", &v.dns64);

    println!();
    println!("  {}", v.ipv4_verdict);
    println!("  {}", v.ipv6_verdict);
    let unavailable = v.unavailable_layers();
    if !unavailable.is_empty() {
        println!(
            "  not evaluated (absence of a check is not a finding): {}",
            unavailable.join(", ")
        );
    }
    for n in &v.notes {
        println!("  note: {}", n);
    }

    if let Some(he) = he {
        println!("\n== Happy Eyeballs ==");
        println!(
            "  host: {}  v6_offered={} v4_offered={}",
            he.host, he.v6_offered, he.v4_offered
        );
        let fmt = |v: Option<f64>| match v {
            Some(x) => format!("{:.2}ms", x),
            None => "unavailable".to_string(),
        };
        println!("  v6 connect: {}", fmt(he.v6_connect_ms));
        println!("  v4 connect: {}", fmt(he.v4_connect_ms));
        println!(
            "  measured fallback delta: {}",
            match he.fallback_delay_ms {
                Some(d) => format!("{:.2}ms", d),
                None =>
                    "unavailable (only one family was attempted; not an RFC constant)".to_string(),
            }
        );
        println!(
            "  winning family: {}",
            he.winning_family.unwrap_or_else(|| "none".to_string())
        );
        if let Some(f) = he.family_specific_failure {
            println!("  {} {}", "family-specific failure:".yellow(), f);
        }
    }
}
