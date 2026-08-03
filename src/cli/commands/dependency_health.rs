//! GAP-059: infrastructure dependency health bundle CLI
//! (`dependency-health`).

use colored::*;
use std::time::Duration;

use fraggle_packet::network_tests::dependency_health::{
    check_tcp_dependency, measure_ntp_offset, DependencyBundle, DependencyCheck, Verdict,
};

#[derive(clap::Args, Debug)]
pub struct DependencyHealthArgs {
    #[arg(long, default_value_t = 5)]
    pub timeout_secs: u64,

    #[arg(long, default_value = "time.apple.com")]
    pub ntp_server: String,

    /// Additional NTP servers to sample.
    #[arg(long, num_args = 0..)]
    pub ntp_server_extra: Vec<String>,

    /// OCSP responder host:port pairs to probe. Many networks block these
    /// deliberately -- that is why this check exists, to tell that apart
    /// from an actually-broken responder.
    #[arg(long, num_args = 0.., default_values_t = ["ocsp.digicert.com:80".to_string(), "ocsp.pki.goog:80".to_string()])]
    pub ocsp_targets: Vec<String>,

    /// Controller/cloud dependency host:port pairs, operator-supplied.
    #[arg(long, num_args = 0..)]
    pub controller_targets: Vec<String>,

    #[arg(long)]
    pub json: bool,
}

fn parse_host_port(s: &str) -> Option<(String, u16)> {
    let (h, p) = s.rsplit_once(':')?;
    Some((h.to_string(), p.parse().ok()?))
}

pub fn run(args: &DependencyHealthArgs) {
    let timeout = Duration::from_secs(args.timeout_secs);

    let mut ntp = vec![measure_ntp_offset(&args.ntp_server, timeout)];
    for s in &args.ntp_server_extra {
        ntp.push(measure_ntp_offset(s, timeout));
    }

    let ocsp_checks: Vec<DependencyCheck> = args
        .ocsp_targets
        .iter()
        .filter_map(|t| parse_host_port(t))
        .map(|(h, p)| check_tcp_dependency(&format!("ocsp:{h}"), &h, p, timeout))
        .collect();

    let controller_checks: Vec<DependencyCheck> = args
        .controller_targets
        .iter()
        .filter_map(|t| parse_host_port(t))
        .map(|(h, p)| check_tcp_dependency(&format!("controller:{h}"), &h, p, timeout))
        .collect();

    let bundle = DependencyBundle {
        dns_checks: vec![],
        ntp,
        cert_checks: vec![],
        ocsp_checks,
        portal_checks: vec![],
        controller_checks,
    };

    if args.json {
        println!("{}", serde_json::to_string_pretty(&bundle).unwrap());
        return;
    }

    println!("{}", "== Infrastructure Dependency Health ==".cyan().bold());
    println!("  NTP offset:");
    for n in &bundle.ntp {
        match n.offset_ms {
            Some(ms) => println!("    {}: offset={:.3}ms delay={:.3}ms", n.server, ms, n.round_trip_delay_ms.unwrap_or(0.0)),
            None => println!("    {}: {}", n.server, "offset unavailable (never defaulted to 0)".yellow()),
        }
    }

    print_checks("OCSP", &bundle.ocsp_checks);
    print_checks("Controller/cloud", &bundle.controller_checks);

    println!();
    println!(
        "  blocked-by-policy: {}   unhealthy: {}",
        bundle.blocked_by_policy_count(),
        bundle.unhealthy_count()
    );
}

fn print_checks(label: &str, checks: &[DependencyCheck]) {
    if checks.is_empty() {
        return;
    }
    println!("  {}:", label);
    for c in checks {
        let verdict_str = match &c.verdict {
            Verdict::Healthy => "healthy".green().to_string(),
            Verdict::BlockedByPolicy { detail_kind } => format!("{}", format!("blocked-by-policy ({:?})", detail_kind).yellow()),
            Verdict::Unhealthy { detail_kind } => format!("{}", format!("unhealthy ({:?})", detail_kind).red()),
            Verdict::NotApplicable => "not applicable".to_string(),
        };
        println!("    {}: {} ({}ms)", c.label, verdict_str, c.elapsed_ms);
    }
}
