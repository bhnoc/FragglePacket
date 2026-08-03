//! GAP-024: stable, privacy-safe AP/radio identity (`ap-identity`).

use colored::*;
use fraggle_packet::load_guard::ap_identity::{
    compare, label_for_bssid, load_or_create_salt, ApIdentity,
};
use fraggle_packet::load_guard::wdutil::{self, WdutilError};

#[derive(clap::Args, Debug)]
pub struct ApIdentityArgs {
    /// Sample twice with a pause between, to demonstrate same-AP-vs-roam
    /// comparison in one run. Without this, prints one identity only.
    #[arg(long)]
    pub compare_before_after: bool,

    /// For the demo/test harness only: two fixed synthetic BSSIDs simulate
    /// two samples without needing real root or a real roam.
    #[arg(long)]
    pub inject_fixture: bool,

    /// For the demo/test harness only, used with --inject-fixture: selects
    /// which of the four distinguishable cases the second sample simulates.
    /// "same" (default): identical BSSID+band -- same AP, same radio.
    /// "same-radio-change": identical BSSID, different band -- same AP,
    /// different radio. "different-ap": a different BSSID entirely.
    #[arg(long, default_value = "same")]
    pub inject_second_sample: String,

    #[arg(long)]
    pub json: bool,
}

fn sample_once(
    fixture_bssid: Option<&str>,
    fixture_band: Option<&str>,
    fixture_channel: Option<u32>,
) -> (Option<ApIdentity>, Option<String>) {
    let salt = match load_or_create_salt() {
        Ok(s) => s,
        Err(e) => {
            return (
                None,
                Some(format!("could not load/create AP-identity salt: {e}")),
            )
        }
    };

    let (bssid, band, channel) = if let Some(b) = fixture_bssid {
        (
            Some(b.to_string()),
            fixture_band.map(|s| s.to_string()),
            fixture_channel,
        )
    } else {
        match wdutil::snapshot_live() {
            Ok(fields) => (fields.bssid, fields.band, fields.channel),
            Err(WdutilError::PrivilegeRequired { command }) => {
                return (
                    None,
                    Some(format!(
                        "AP identity requires elevated wdutil access; re-run as: {command}"
                    )),
                );
            }
            Err(e) => return (None, Some(e.to_string())),
        }
    };

    let Some(bssid) = bssid else {
        return (
            None,
            Some("wdutil info did not report a BSSID for the current association".to_string()),
        );
    };
    // label_for_bssid is called and `bssid` (the local variable) is dropped
    // at the end of this function's scope -- it is never passed to println!,
    // serde_json, or any logging call anywhere in this file.
    let label = label_for_bssid(&bssid, &salt);
    (
        Some(ApIdentity {
            label,
            band,
            channel,
        }),
        None,
    )
}

pub fn run(args: &ApIdentityArgs) {
    if args.compare_before_after {
        let (before, before_err) = if args.inject_fixture {
            sample_once(Some("02:00:00:00:00:01"), Some("6GHz"), Some(37))
        } else {
            sample_once(None, None, None)
        };

        // Give the operator a window to physically move/roam between the
        // two samples in a real (non-fixture) run.
        if !args.inject_fixture {
            eprintln!(
                "{} sampling again in 2 seconds -- move now to test roam detection",
                "i".cyan()
            );
            std::thread::sleep(std::time::Duration::from_secs(2));
        }

        let (after, after_err) = if args.inject_fixture {
            match args.inject_second_sample.as_str() {
                "same-radio-change" => {
                    sample_once(Some("02:00:00:00:00:01"), Some("2GHz"), Some(6))
                }
                "different-ap" => sample_once(Some("02:00:00:00:00:02"), Some("6GHz"), Some(37)),
                _ => sample_once(Some("02:00:00:00:00:01"), Some("6GHz"), Some(37)),
            }
        } else {
            sample_once(None, None, None)
        };

        let comparison = compare(&before, &after);

        if args.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "before": before,
                    "before_error": before_err,
                    "after": after,
                    "after_error": after_err,
                    "comparison": comparison,
                }))
                .unwrap()
            );
            return;
        }

        println!();
        println!("{}", "== AP Identity Comparison ==".cyan().bold());
        print_identity("before", &before, &before_err);
        print_identity("after ", &after, &after_err);
        println!("  comparison: {comparison:?}");
        println!();
        return;
    }

    let (identity, err) = if args.inject_fixture {
        sample_once(Some("02:00:00:00:00:01"), Some("6GHz"), Some(37))
    } else {
        sample_once(None, None, None)
    };

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({"identity": identity, "error": err}))
                .unwrap()
        );
        return;
    }
    println!();
    println!("{}", "== AP Identity ==".cyan().bold());
    print_identity("current", &identity, &err);
    println!();
}

fn print_identity(label: &str, identity: &Option<ApIdentity>, err: &Option<String>) {
    match identity {
        Some(id) => println!(
            "  {label}: label={} band={} channel={}",
            id.label,
            id.band.as_deref().unwrap_or("unavailable"),
            id.channel
                .map(|c| c.to_string())
                .unwrap_or_else(|| "unavailable".to_string())
        ),
        None => println!(
            "  {label}: {} {}",
            "unavailable".yellow(),
            err.as_deref().unwrap_or("no reason given")
        ),
    }
}
