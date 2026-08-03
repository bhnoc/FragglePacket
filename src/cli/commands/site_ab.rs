//! GAP-012: affected-site vs known-good-control A/B workflow CLI
//! (`site-ab`). Drives `protocol_compare::run_comparison` twice (affected,
//! control) and produces one side-by-side verdict per protocol.

use std::net::IpAddr;

use colored::*;

use fraggle_packet::network_tests::site_ab::{compare_sites, run_site_samples, CompareConfigInput, SiteAbVerdict};

#[derive(clap::Args, Debug)]
pub struct SiteAbArgs {
    #[arg(long)]
    pub affected_host: String,
    #[arg(long, default_value_t = 443)]
    pub affected_port: u16,
    #[arg(long, default_value = "/")]
    pub affected_path: String,
    #[arg(long)]
    pub affected_force_ip: Option<IpAddr>,

    #[arg(long)]
    pub control_host: String,
    #[arg(long, default_value_t = 443)]
    pub control_port: u16,
    #[arg(long, default_value = "/")]
    pub control_path: String,
    #[arg(long)]
    pub control_force_ip: Option<IpAddr>,

    /// Protocols to compare. Repeatable. Defaults to http1,http2,http3.
    #[arg(long = "protocol", value_parser = ["http1", "http2", "http3"])]
    pub protocols: Vec<String>,

    #[arg(long)]
    pub interface: Option<String>,

    #[arg(long, default_value_t = 10)]
    pub timeout_secs: u64,

    #[arg(long, default_value_t = 2_000_000)]
    pub upload_bytes: usize,

    #[arg(long)]
    pub simultaneous: bool,

    /// Repeated samples per site for a comparison sturdier than one shot
    /// each.
    #[arg(long, default_value_t = 3)]
    pub repeat_samples: u32,

    #[arg(long)]
    pub json: bool,
}

pub fn run(args: &SiteAbArgs) {
    let protocols = if args.protocols.is_empty() {
        vec!["http1".to_string(), "http2".to_string(), "http3".to_string()]
    } else {
        args.protocols.clone()
    };

    let affected_cfg = CompareConfigInput {
        host: args.affected_host.clone(),
        port: args.affected_port,
        path: args.affected_path.clone(),
        interface: args.interface.clone(),
        forced_ip: args.affected_force_ip,
        timeout_secs: args.timeout_secs,
        upload_bytes: args.upload_bytes,
        protocols: protocols.clone(),
        run_simultaneous: args.simultaneous,
    };
    let control_cfg = CompareConfigInput {
        host: args.control_host.clone(),
        port: args.control_port,
        path: args.control_path.clone(),
        interface: args.interface.clone(),
        forced_ip: args.control_force_ip,
        timeout_secs: args.timeout_secs,
        upload_bytes: args.upload_bytes,
        protocols: protocols.clone(),
        run_simultaneous: args.simultaneous,
    };

    let affected = match run_site_samples(&affected_cfg, args.repeat_samples) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{} affected-site config error: {}", "✗".red(), e);
            std::process::exit(1);
        }
    };
    let control = match run_site_samples(&control_cfg, args.repeat_samples) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{} control-site config error: {}", "✗".red(), e);
            std::process::exit(1);
        }
    };

    let reports = compare_sites(&affected, &control, &protocols);

    if args.json {
        let out = serde_json::json!({
            "affected_host": args.affected_host,
            "control_host": args.control_host,
            "reports": reports,
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
        return;
    }

    println!();
    println!("{}", "== Site A/B ==".cyan().bold());
    println!("  affected: {}", args.affected_host);
    println!("  control:  {}", args.control_host);
    println!();
    for r in &reports {
        println!("  protocol: {}", r.protocol);
        match &r.verdict {
            SiteAbVerdict::Compared { affected_mbps, control_mbps, ratio } => {
                println!(
                    "    {} affected={:.2} Mbps control={:.2} Mbps ratio={:.3}",
                    "COMPARED".green(),
                    affected_mbps,
                    control_mbps,
                    ratio
                );
            }
            SiteAbVerdict::RedirectedRatherThanCompared { detail, .. } => {
                println!("    {} {}", "REDIRECTED:".yellow().bold(), detail);
            }
            SiteAbVerdict::Withheld { reason } => {
                println!("    {} {}", "WITHHELD:".yellow(), reason);
            }
        }
    }
    println!();
}
