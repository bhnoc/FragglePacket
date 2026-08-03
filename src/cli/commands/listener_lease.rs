//! GAP-040: authorized-only listener allocation and baseline-floor control
//! CLI (`listener-lease`).

use colored::*;

use fraggle_packet::network_tests::iperf::{run_iperf_client, IperfParseError};
use fraggle_packet::network_tests::listener_lease::{
    estimate_loss_floor, is_busy_or_rate_limited, qualify_capacity, AuthorizedListener,
    CapacityCheck, CapacityVerdict, ListenerPool, Transport,
};

#[derive(clap::Args, Debug)]
pub struct ListenerLeaseArgs {
    /// host:port pairs this operator has explicitly authorized. Never
    /// discovered or scanned -- only ports named here are ever contacted.
    #[arg(long, required = true, num_args = 1..)]
    pub allow: Vec<String>,

    /// host:port to actually run this session against; must be present in
    /// --allow or the lease is refused before any network contact.
    #[arg(long)]
    pub use_listener: String,

    #[arg(long, default_value_t = 1)]
    pub max_concurrency: usize,

    #[arg(long, value_enum, default_value = "tcp")]
    pub transport: TransportArg,

    #[arg(long, default_value_t = 5)]
    pub duration_secs: u32,

    #[arg(long)]
    pub reverse: bool,

    #[arg(long)]
    pub json: bool,
}

#[derive(clap::ValueEnum, Debug, Clone, Copy)]
pub enum TransportArg {
    Tcp,
    Udp,
}

fn parse_authorized(raw: &[String]) -> Result<Vec<AuthorizedListener>, String> {
    raw.iter()
        .map(|s| {
            let (host, port) = s
                .rsplit_once(':')
                .ok_or_else(|| format!("expected host:port, got '{s}'"))?;
            let port: u16 = port.parse().map_err(|_| format!("invalid port in '{s}'"))?;
            Ok(AuthorizedListener {
                host: host.to_string(),
                port,
            })
        })
        .collect()
}

pub fn run(args: &ListenerLeaseArgs) {
    let allowlist = match parse_authorized(&args.allow) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{} {}", "✗".red(), e);
            std::process::exit(1);
        }
    };

    let (use_host, use_port) = match args.use_listener.rsplit_once(':') {
        Some((h, p)) => match p.parse::<u16>() {
            Ok(p) => (h.to_string(), p),
            Err(_) => {
                eprintln!("{} invalid port in --use-listener", "✗".red());
                std::process::exit(1);
            }
        },
        None => {
            eprintln!("{} --use-listener must be host:port", "✗".red());
            std::process::exit(1);
        }
    };

    let pool = ListenerPool::new(allowlist, args.max_concurrency);
    let lease = match pool.lease_specific(use_port) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("{} {}", "✗".red(), e);
            std::process::exit(1);
        }
    };
    if lease.listener.host != use_host {
        eprintln!(
            "{} --use-listener host '{}' does not match authorized host '{}' for port {}",
            "✗".red(),
            use_host,
            lease.listener.host,
            use_port
        );
        std::process::exit(1);
    }

    let udp = matches!(args.transport, TransportArg::Udp);
    let result = run_iperf_client(
        &lease.listener.host,
        lease.listener.port,
        args.duration_secs,
        args.reverse,
        false,
        udp,
        None,
        None,
    );

    let parsed = match result {
        Ok(r) => r,
        Err(IperfParseError::ServerError(e)) => {
            if is_busy_or_rate_limited(&e) {
                eprintln!("{} listener busy/rate-limited: {}", "✗".red(), e);
            } else {
                eprintln!("{} session error: {}", "✗".red(), e);
            }
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("{} {}", "✗".red(), e);
            std::process::exit(1);
        }
    };

    let transport = match args.transport {
        TransportArg::Tcp => Transport::Tcp,
        TransportArg::Udp => Transport::Udp,
    };
    let received = parsed.forward.received;
    let capacity_verdict = received.map(|r| {
        qualify_capacity(&CapacityCheck {
            transport,
            requested_duration_secs: args.duration_secs as f64,
            reported_duration_secs: r.seconds,
            receiver_bits_per_second: r.bits_per_second,
        })
    });

    let iperf_version = parsed
        .version
        .map(|v| format!("iperf {}.{}", v.major, v.minor))
        .unwrap_or_default();
    let loss_floor = estimate_loss_floor(&iperf_version);

    if args.json {
        let report = serde_json::json!({
            "listener": {"host": lease.listener.host, "port": lease.listener.port},
            "result": parsed,
            "capacity_verdict": capacity_verdict,
            "endpoint_loss_floor": loss_floor,
        });
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
        return;
    }

    println!("{}", "== Listener Lease Session ==".cyan().bold());
    println!(
        "  listener: {}:{}",
        lease.listener.host, lease.listener.port
    );
    match capacity_verdict {
        Some(CapacityVerdict::Consistent) => {
            let r = received.unwrap();
            println!(
                "  receiver: {:.1} Mbps over {:.2}s (requested {}s) -- duration-consistent",
                r.bits_per_second / 1_000_000.0,
                r.seconds,
                args.duration_secs
            );
        }
        Some(CapacityVerdict::DurationInconsistent {
            requested_secs,
            reported_secs,
        }) => {
            println!(
                "  {}",
                format!(
                    "receiver result WITHHELD: reported duration {:.2}s inconsistent with requested {:.2}s",
                    reported_secs, requested_secs
                )
                .yellow()
            );
        }
        None => println!("  receiver: no throughput figure available"),
    }
    if let Some(r) = received {
        if let Some(pct) = r.lost_percent {
            println!(
                "  loss: {:.2}% (endpoint floor for {}: {:.1}-{:.1}%)",
                pct,
                loss_floor.client_version_family,
                loss_floor.floor_pct_low,
                loss_floor.floor_pct_high
            );
        }
    }
    println!("  iperf version: {}", iperf_version);
}
