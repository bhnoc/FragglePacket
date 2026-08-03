//! GAP-014: DNS steering comparison (`dns-steering`).

use colored::*;

use fraggle_packet::network_tests::dns_steering::{compare_steering, SteeringVerdict};
use fraggle_packet::redact::RedactionPolicy;

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

    /// GAP-018: by default, resolved A/AAAA addresses are redacted in
    /// human-readable output. Pass this to see raw values.
    #[arg(long)]
    pub retain_identifiers: bool,
}

pub fn run(args: &DnsSteeringArgs) {
    let comparison = compare_steering(&args.name, &args.resolvers, args.timeout_secs);
    let policy = RedactionPolicy::from_retain_flag(args.retain_identifiers);

    if args.json {
        println!("{}", serde_json::to_string_pretty(&comparison).unwrap());
        return;
    }

    let mut buf = String::new();
    buf.push_str(&format!("== DNS steering comparison: {} ==\n", comparison.name));
    for (resolver, results) in args.resolvers.iter().zip(comparison.per_resolver.iter()) {
        buf.push_str(&format!("  resolver {}:\n", resolver));
        for r in results {
            match &r.error {
                Some(e) => buf.push_str(&format!("    error -- {}\n", e)),
                None => {
                    if r.answers.is_empty() {
                        buf.push_str("    (no records of this type)\n");
                    } else {
                        for a in &r.answers {
                            buf.push_str(&format!(
                                "    {:?} {} ttl={}\n",
                                a.record_type,
                                a.value,
                                a.ttl_secs.map(|t| t.to_string()).unwrap_or_else(|| "unavailable".to_string())
                            ));
                        }
                    }
                }
            }
        }
        if let Some(t) = results.iter().find_map(|r| r.query_time_ms) {
            buf.push_str(&format!("    query_time_ms (per-resolver, not averaged): {}\n", t));
        }
    }

    let verdict_str = match comparison.verdict {
        SteeringVerdict::Consistent => "Consistent",
        SteeringVerdict::Diverges => "Diverges",
        SteeringVerdict::Inconclusive => "Inconclusive",
    };
    buf.push_str("-- Verdict --\n");
    buf.push_str(&format!("  {}\n", verdict_str));
    buf.push_str(&format!("  {}\n", comparison.explanation));
    print!("{}", policy.apply(&buf));
}
