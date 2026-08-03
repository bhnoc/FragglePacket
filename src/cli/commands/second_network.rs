//! GAP-013: second-network control workflow CLI (`second-network`).

use colored::*;

use fraggle_packet::load_guard::ap_identity::{label_for_bssid, load_or_create_salt, ApIdentity};
use fraggle_packet::network_tests::second_network::{
    compare_bundles, load_bundle, save_bundle, BundleMetric, NetworkFingerprint, TestBundle,
};

#[derive(clap::Args, Debug)]
pub struct SecondNetworkArgs {
    #[arg(long)]
    pub save: Option<String>,

    /// Two saved bundle paths to compare. Requires exactly 2.
    #[arg(long = "compare", num_args = 2)]
    pub compare: Vec<String>,

    /// BSSID to derive a salted AP identity from, when saving. Read once
    /// in memory and never written anywhere raw -- only
    /// `label_for_bssid`'s salted output is stored.
    #[arg(long)]
    pub bssid: Option<String>,

    #[arg(long)]
    pub band: Option<String>,

    #[arg(long)]
    pub channel: Option<u32>,

    #[arg(long)]
    pub interface: Option<String>,

    /// Explicit opt-in to retain a human network label (which may contain
    /// SSID-shaped text) in the saved bundle. Omitting this never stores
    /// one -- there is no default that captures it.
    #[arg(long)]
    pub retain_network_label: Option<String>,

    #[arg(long)]
    pub capture_tag: Option<String>,

    /// name=value metric pairs, e.g. --metric download_mbps=320.5
    #[arg(long = "metric")]
    pub metrics: Vec<String>,

    #[arg(long)]
    pub json: bool,
}

pub fn run(args: &SecondNetworkArgs) {
    if let Some(path) = &args.save {
        let ap_identity = args.bssid.as_deref().map(|bssid| {
            let salt = load_or_create_salt().unwrap_or_else(|e| {
                eprintln!("{} {}", "✗".red(), e);
                std::process::exit(1);
            });
            ApIdentity {
                label: label_for_bssid(bssid, &salt),
                band: args.band.clone(),
                channel: args.channel,
            }
        });

        let metrics: Vec<BundleMetric> = args
            .metrics
            .iter()
            .filter_map(|kv| {
                let (name, value) = kv.split_once('=')?;
                Some(BundleMetric {
                    name: name.to_string(),
                    value: value.parse().ok(),
                    unit: "".to_string(),
                })
            })
            .collect();

        let bundle = TestBundle {
            fingerprint: NetworkFingerprint {
                ap_identity,
                interface: args.interface.clone(),
                interface_is_tunnel: false,
                operator_label: args.retain_network_label.clone(),
            },
            metrics,
            capture_tag: args
                .capture_tag
                .clone()
                .unwrap_or_else(|| "unlabeled".to_string()),
        };

        if let Err(e) = save_bundle(path, &bundle) {
            eprintln!("{} could not save bundle: {}", "✗".red(), e);
            std::process::exit(1);
        }
        println!("{} saved bundle to {}", "✓".green(), path);
        return;
    }

    if args.compare.len() == 2 {
        let before = match load_bundle(&args.compare[0]) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("{} could not load {}: {}", "✗".red(), args.compare[0], e);
                std::process::exit(1);
            }
        };
        let after = match load_bundle(&args.compare[1]) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("{} could not load {}: {}", "✗".red(), args.compare[1], e);
                std::process::exit(1);
            }
        };

        let cmp = compare_bundles(&before, &after);

        if args.json {
            println!("{}", serde_json::to_string_pretty(&cmp).unwrap_or_default());
            return;
        }

        println!();
        println!("{}", "== Second-Network Comparison ==".cyan().bold());
        println!("  relationship: {}", cmp.network_relationship);
        println!();
        for m in &cmp.metrics {
            println!(
                "  {:<20} before={:?} after={:?} delta={:?}",
                m.name, m.before, m.after, m.delta
            );
        }
        println!();
        return;
    }

    eprintln!(
        "{} pass either --save <path> or --compare <path1> <path2>",
        "✗".red()
    );
    std::process::exit(1);
}
