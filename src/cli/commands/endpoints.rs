use colored::*;

use fraggle_packet::network_tests::endpoint_registry::EndpointRegistry;

/// Bundled registry, so the command works with no arguments.
const BUNDLED: &str = include_str!("../../../harness/fixtures/endpoints/public-iperf.json");

#[derive(clap::Args, Debug)]
pub struct EndpointsArgs {
    /// Registry JSON to read instead of the bundled one.
    #[arg(long)]
    pub registry: Option<String>,

    /// Provider to select from. Omit to list everything known.
    #[arg(long)]
    pub provider: Option<String>,

    /// Select a verified listener for a direction, e.g. "upload" or "download".
    /// Refuses a listener recorded as known-bad.
    #[arg(long)]
    pub purpose: Option<String>,

    /// Print the allowlist for this provider in a form listener-lease accepts,
    /// with known-bad ports already excluded.
    #[arg(long)]
    pub allowlist: bool,

    /// Check one host:port against the known-bad record before using it.
    #[arg(long)]
    pub check: Option<String>,

    #[arg(long)]
    pub json: bool,
}

pub fn run(args: &EndpointsArgs) {
    let registry = match &args.registry {
        Some(p) => match EndpointRegistry::load(p) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("{} {}", "✗".red(), e);
                std::process::exit(1);
            }
        },
        None => match EndpointRegistry::from_json(BUNDLED) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("{} bundled registry is corrupt: {}", "✗".red(), e);
                std::process::exit(1);
            }
        },
    };

    // --check: is this endpoint already known to fail?
    if let Some(spec) = &args.check {
        let (host, port) = match spec.rsplit_once(':') {
            Some((h, p)) => match p.parse::<u16>() {
                Ok(p) => (h.to_string(), p),
                Err(_) => {
                    eprintln!("{} --check expects host:port", "✗".red());
                    std::process::exit(2);
                }
            },
            None => {
                eprintln!("{} --check expects host:port", "✗".red());
                std::process::exit(2);
            }
        };
        match registry.is_known_bad(&host, port) {
            Some(bad) => {
                if args.json {
                    println!(
                        "{}",
                        serde_json::json!({ "known_bad": true, "outcome": bad.outcome })
                    );
                } else {
                    println!("{} {}:{} is known bad", "REFUSE".red(), host, port);
                    println!("  outcome: {}", bad.outcome);
                    if let Some(n) = &bad.must_not_be_recorded_as {
                        println!("  must not be recorded as: {}", n);
                    }
                    if let Some(w) = &bad.why_it_matters {
                        println!("  why: {}", w);
                    }
                }
                std::process::exit(1);
            }
            None => {
                if args.json {
                    println!("{}", serde_json::json!({ "known_bad": false }));
                } else {
                    println!("{} {}:{} has no recorded failure", "OK".green(), host, port);
                }
                return;
            }
        }
    }

    // --allowlist: hand listener-lease a set with known-bad ports removed.
    if args.allowlist {
        let provider = match &args.provider {
            Some(p) => p.clone(),
            None => {
                eprintln!("{} --allowlist requires --provider", "✗".red());
                std::process::exit(2);
            }
        };
        match registry.allowlist_for(&provider) {
            Ok(list) => {
                if args.json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&list).unwrap_or_default()
                    );
                } else {
                    println!("\n== Allowlist for {} ==", provider);
                    for l in &list {
                        println!("  {}:{}", l.host, l.port);
                    }
                    println!(
                        "\n  {} known-bad port(s) excluded by construction, so the lease layer \
                         cannot be handed one by accident.",
                        registry
                            .provider(&provider)
                            .map(|p| p
                                .known_bad_ports
                                .iter()
                                .map(|b| b.all_ports().len())
                                .sum::<usize>())
                            .unwrap_or(0)
                    );
                }
            }
            Err(e) => {
                eprintln!("{} {}", "✗".red(), e.message());
                std::process::exit(1);
            }
        }
        return;
    }

    // --purpose: select a verified listener for a direction.
    if let (Some(provider), Some(purpose)) = (&args.provider, &args.purpose) {
        match registry.select(provider, purpose) {
            Ok(l) => {
                if args.json {
                    println!("{}", serde_json::to_string_pretty(l).unwrap_or_default());
                } else {
                    println!("\n== {} / {} ==", provider, purpose);
                    println!("  endpoint: {}:{}", l.host, l.port);
                    if let Some(v) = &l.verified {
                        println!("  verified: {}", v);
                    }
                    if let Some(o) = &l.observed {
                        println!("  observed: {}", o);
                    }
                    for c in registry.caveats_for(provider) {
                        println!("  caveat: {}", c);
                    }
                }
            }
            Err(e) => {
                eprintln!("{} {}", "✗".red(), e.message());
                std::process::exit(1);
            }
        }
        return;
    }

    // Default: show what is known, failures included.
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&registry).unwrap_or_default()
        );
        return;
    }

    println!("\n== Known iperf3 endpoints ==");
    for p in &registry.providers {
        println!("\n  {}", p.provider.bold());
        if let Some(a) = &p.authorization {
            println!("    authorization: {}", a);
        }
        for l in &p.listeners {
            println!(
                "    {} {}:{}{}",
                "verified".green(),
                l.host,
                l.port,
                l.purpose
                    .as_deref()
                    .map(|s| format!("  ({})", s))
                    .unwrap_or_default()
            );
        }
        for b in &p.known_bad_ports {
            let ports: Vec<String> = b.all_ports().iter().map(|p| p.to_string()).collect();
            println!(
                "    {} {}:{}  {}",
                "known bad".red(),
                b.host,
                ports.join(","),
                b.outcome
            );
        }
        if !p.caveats.is_empty() {
            println!("    caveats:");
            for c in &p.caveats {
                println!("      - {}", c);
            }
        }
    }
    println!(
        "\n  Known-bad ports are listed on purpose. An endpoint that never admitted a connection \
         is an admission failure, not a zero-throughput measurement."
    );
}
