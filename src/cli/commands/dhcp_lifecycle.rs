//! GAP-048: DHCP/address-lifecycle/pool-capacity CLI (`dhcp-lifecycle`).

use colored::*;
use std::time::Duration;

use fraggle_packet::network_tests::dhcp_lifecycle::{
    evaluate_pool_headroom, read_existing_lease, request_fresh_lease, PoolHeadroomVerdict,
    PoolTelemetry,
};

#[derive(clap::Args, Debug)]
pub struct DhcpLifecycleArgs {
    #[arg(long)]
    pub interface: String,

    /// Enables the disruptive fresh-lease test (release + renew). Requires
    /// --authorized; refuses to run without it. Safe-by-default: omitting
    /// this flag only reads the existing cached lease.
    #[arg(long)]
    pub fresh_lease: bool,

    #[arg(long)]
    pub authorized: Option<String>,

    #[arg(long, default_value_t = 15)]
    pub fresh_lease_timeout_secs: u64,

    /// Operator-supplied pool headroom JSON: {"scope_label":..,
    /// "addresses_total":.., "addresses_in_use":..}.
    #[arg(long)]
    pub pool_telemetry: Option<String>,

    #[arg(long)]
    pub json: bool,
}

pub fn run(args: &DhcpLifecycleArgs) {
    let existing = read_existing_lease(&args.interface);

    let fresh = if args.fresh_lease {
        match request_fresh_lease(
            &args.interface,
            args.authorized.as_deref(),
            Duration::from_secs(args.fresh_lease_timeout_secs),
        ) {
            Ok(t) => Some(Ok(t)),
            Err(e) if e.contains("--authorized") => {
                eprintln!("{} {}", "✗".red(), e);
                std::process::exit(1);
            }
            Err(e) => Some(Err(e)),
        }
    } else {
        None
    };

    let pool_telemetry: Option<PoolTelemetry> = args.pool_telemetry.as_ref().and_then(|path| {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
    });
    let headroom = evaluate_pool_headroom(&pool_telemetry);

    if args.json {
        let report = serde_json::json!({
            "existing_lease": existing.as_ref().ok(),
            "existing_lease_error": existing.as_ref().err().map(|e| e.to_string()),
            "fresh_lease": fresh.as_ref().and_then(|r| r.as_ref().ok()),
            "fresh_lease_error": fresh.as_ref().and_then(|r| r.as_ref().err()),
            "pool_headroom": headroom,
        });
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
        return;
    }

    println!("{}", "== DHCP Lifecycle ==".cyan().bold());
    match &existing {
        Ok(lease) => {
            println!("  existing lease on {}:", args.interface);
            println!("    message_type: {:?}", lease.message_type);
            println!(
                "    lease_seconds: {}",
                lease
                    .lease_seconds
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "unavailable".to_string())
            );
            println!(
                "    server_identifier: {}",
                lease.server_identifier.as_deref().unwrap_or("unavailable")
            );
            println!(
                "    router: {}",
                lease.router.as_deref().unwrap_or("unavailable")
            );
            println!(
                "    dns: {}",
                if lease.domain_name_servers.is_empty() {
                    "unavailable".to_string()
                } else {
                    lease.domain_name_servers.join(", ")
                }
            );
        }
        Err(e) => println!(
            "  existing lease: {}",
            format!("unavailable ({})", e).yellow()
        ),
    }

    if !args.fresh_lease {
        println!(
            "  {}",
            "fresh-lease test not run (safe default); pass --fresh-lease --authorized \"...\" to enable".yellow()
        );
    } else {
        match fresh {
            Some(Ok(t)) => {
                println!(
                    "  fresh lease: discover-to-address {}ms",
                    t.discover_to_address_ms
                );
                println!(
                    "    lease_seconds: {}",
                    t.lease
                        .lease_seconds
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "unavailable".to_string())
                );
            }
            Some(Err(e)) => println!("  fresh lease error: {}", e),
            None => {}
        }
    }

    match headroom {
        PoolHeadroomVerdict::Headroom { free, total } => {
            println!("  pool headroom: {}/{} free", free, total)
        }
        PoolHeadroomVerdict::Unavailable { reason } => {
            println!(
                "  {}",
                format!("pool headroom: unavailable ({})", reason).yellow()
            )
        }
    }
}
