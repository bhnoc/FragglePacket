//! GAP-050: controlled roaming/session-continuity test (`roaming`).

use colored::*;
use std::time::{Duration, Instant};

use fraggle_packet::load_guard::ap_identity::{label_for_bssid, load_or_create_salt};
use fraggle_packet::load_guard::wdutil::{self, WdutilError};
use fraggle_packet::load_guard::{build_transition, ApIdentity, IdentityContinuity, RoamTransition, TransitionKind};

#[derive(clap::Args, Debug)]
pub struct RoamingArgs {
    /// Seconds to wait between the before/after samples, giving the
    /// operator a window to physically move.
    #[arg(long, default_value_t = 5)]
    pub wait_secs: u64,

    /// For the demo/test harness only: two fixed synthetic BSSIDs/bands
    /// simulate a transition without needing a real walk or real root.
    #[arg(long)]
    pub inject_fixture: Option<String>,

    #[arg(long)]
    pub json: bool,
}

fn sample_identity(fixture: Option<(&str, &str, u32)>) -> (Option<ApIdentity>, Option<String>) {
    let salt = match load_or_create_salt() {
        Ok(s) => s,
        Err(e) => return (None, Some(format!("could not load/create salt: {e}"))),
    };
    let (bssid, band, channel) = if let Some((b, band, ch)) = fixture {
        (Some(b.to_string()), Some(band.to_string()), Some(ch))
    } else {
        match wdutil::snapshot_live() {
            Ok(f) => (f.bssid, f.band, f.channel),
            Err(WdutilError::PrivilegeRequired { command }) => {
                return (None, Some(format!("requires elevated wdutil access; re-run as: {command}")))
            }
            Err(e) => return (None, Some(e.to_string())),
        }
    };
    let Some(bssid) = bssid else {
        return (None, Some("no BSSID reported for the current association".to_string()));
    };
    let label = label_for_bssid(&bssid, &salt);
    (Some(ApIdentity { label, band, channel }), None)
}

pub fn run(args: &RoamingArgs) {
    let (before, before_err, after, after_err, handoff_ms, lost, reset, id_before, id_after) =
        if let Some(seed) = &args.inject_fixture {
            match seed.as_str() {
                "roam-clean" => (
                    sample_identity(Some(("02:00:00:00:00:01", "6GHz", 37))).0,
                    None,
                    sample_identity(Some(("02:00:00:00:00:02", "6GHz", 37))).0,
                    None,
                    Some(38.0),
                    Some(0u64),
                    false,
                    Some("198.51.100.5:1000".to_string()),
                    Some("198.51.100.5:1000".to_string()),
                ),
                "roam-identity-change" => (
                    sample_identity(Some(("02:00:00:00:00:01", "6GHz", 37))).0,
                    None,
                    sample_identity(Some(("02:00:00:00:00:02", "6GHz", 37))).0,
                    None,
                    Some(60.0),
                    Some(3u64),
                    true,
                    Some("198.51.100.5:1000".to_string()),
                    Some("203.0.113.9:2000".to_string()),
                ),
                "roam-never-completed" => (
                    sample_identity(Some(("02:00:00:00:00:01", "6GHz", 37))).0,
                    None,
                    None,
                    Some("association never re-established within the observation window".to_string()),
                    None,
                    None,
                    false,
                    Some("198.51.100.5:1000".to_string()),
                    None,
                ),
                _ => (
                    sample_identity(Some(("02:00:00:00:00:01", "6GHz", 37))).0,
                    None,
                    sample_identity(Some(("02:00:00:00:00:01", "6GHz", 37))).0,
                    None,
                    Some(0.5),
                    Some(0u64),
                    false,
                    Some("198.51.100.5:1000".to_string()),
                    Some("198.51.100.5:1000".to_string()),
                ),
            }
        } else {
            let (before, before_err) = sample_identity(None);
            eprintln!(
                "{} sampling again in {}s -- move now to test roam detection",
                "i".cyan(),
                args.wait_secs
            );
            let start = Instant::now();
            std::thread::sleep(Duration::from_secs(args.wait_secs));
            let (after, after_err) = sample_identity(None);
            let handoff_ms = Some(start.elapsed().as_secs_f64() * 1000.0);
            (before, before_err, after, after_err, handoff_ms, None, false, None, None)
        };

    let transition: RoamTransition = build_transition(
        before,
        after,
        handoff_ms,
        lost,
        reset,
        id_before.as_deref(),
        id_after.as_deref(),
    );

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "transition": transition,
                "before_error": before_err,
                "after_error": after_err,
            }))
            .unwrap()
        );
        return;
    }

    println!();
    println!("{}", "== Roaming / Session Continuity ==".cyan().bold());
    println!(
        "  transition: {} -> {}",
        transition.before_label.as_deref().unwrap_or("unavailable"),
        transition.after_label.as_deref().unwrap_or("unavailable")
    );
    println!("  kind: {}", format_kind(transition.kind));
    println!(
        "  handoff duration: {}",
        transition.handoff_duration_ms.map(|v| format!("{v:.1}ms")).unwrap_or_else(|| "unavailable (handoff not observed to complete)".to_string())
    );
    println!(
        "  packets lost during handoff: {}",
        transition.packets_lost_during_handoff.map(|v| v.to_string()).unwrap_or_else(|| "unavailable".to_string())
    );
    println!("  session reset detected: {}", transition.session_reset_detected);
    println!("  identity (VLAN/public) continuity: {}", format_continuity(transition.identity_continuity));
    if let Some(e) = &before_err {
        println!("  {} before-sample: {}", "note:".dimmed(), e);
    }
    if let Some(e) = &after_err {
        println!("  {} after-sample: {}", "note:".dimmed(), e);
    }
    println!();
}

fn format_kind(k: TransitionKind) -> String {
    match k {
        TransitionKind::SameApSameRadio => "same AP, same radio".to_string(),
        TransitionKind::SameApDifferentRadio => "same AP, different radio".to_string(),
        TransitionKind::DifferentAp => "different AP".yellow().bold().to_string(),
        TransitionKind::Undetermined => "undetermined (identity unavailable on one or both sides)".to_string(),
    }
}

fn format_continuity(c: IdentityContinuity) -> String {
    match c {
        IdentityContinuity::Unchanged => "unchanged".green().to_string(),
        IdentityContinuity::Changed => "CHANGED".red().bold().to_string(),
        IdentityContinuity::Unavailable => "unavailable".dimmed().to_string(),
    }
}
