//! GAP-014: DNS steering comparison (`dns-steering`).

use colored::*;

use fraggle_packet::network_tests::dns_steering::{compare_steering, SteeringVerdict};

#[derive(clap::Args, Debug)]
pub struct DnsSteeringArgs {
    /// Name to query.
    pub name: String,

    /// Resolver IPs to compare, e.g. --resolver 1.1.1.1 --resolver 8.8.8.8.
    /// At least two are required to assess divergence.
    #[arg(long = "resolver", required = true, num_args = 1)]
    pub resolvers: Vec<String>,

    #[arg(long, default_value_t = 3)]
    pub timeout_secs: u64,

    #[arg(long)]
    pub json: bool,
}

pub fn run(args: &DnsSteeringArgs) {
    let comparison = compare_steering(&args.name, &args.resolvers, args.timeout_secs);

    if args.json {
        println!("{}", serde_json::to_string_pretty(&comparison).unwrap());
        return;
    }

    println!("{}", format!("== DNS steering comparison: {} ==", comparison.name).cyan().bold());
    for (resolver, results) in args.resolvers.iter().zip(comparison.per_resolver.iter()) {
        println!("  resolver {}:", resolver);
        for r in results {
            match &r.error {
                Some(e) => println!("    {:?}: error -- {}", "?".yellow(), e),
                None => {
                    if r.answers.is_empty() {
                        println!("    (no records of this type)");
                    } else {
                        for a in &r.answers {
                            println!(
                                "    {:?} {} ttl={}",
                                a.record_type,
                                a.value,
                                a.ttl_secs.map(|t| t.to_string()).unwrap_or_else(|| "unavailable".to_string())
                            );
                        }
                    }
                }
            }
        }
        if let Some(t) = results.iter().find_map(|r| r.query_time_ms) {
            println!("    query_time_ms (per-resolver, not averaged): {}", t);
        }
    }

    let verdict_str = match comparison.verdict {
        SteeringVerdict::Consistent => "Consistent".green(),
        SteeringVerdict::Diverges => "Diverges".yellow().bold(),
        SteeringVerdict::Inconclusive => "Inconclusive".yellow(),
    };
    println!("{}", "-- Verdict --".white().bold());
    println!("  {}", verdict_str);
    println!("  {}", comparison.explanation.dimmed());
}
