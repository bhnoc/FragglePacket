//! GAP-030: matched wired-versus-Wi-Fi fault-domain control (`wired-control`).

use colored::*;

use fraggle_packet::load_guard::{attribute_wired_vs_wifi, FaultAttribution, PathResult};

#[derive(clap::Args, Debug)]
pub struct WiredControlArgs {
    #[arg(long)]
    pub wired_mbps: Option<f64>,

    #[arg(long)]
    pub wired_loss_pct: Option<f64>,

    /// Wired path's observed public egress identity (e.g. from a STUN
    /// mapped address). Omit to report attribution withheld.
    #[arg(long)]
    pub wired_egress: Option<String>,

    #[arg(long)]
    pub wifi_mbps: Option<f64>,

    #[arg(long)]
    pub wifi_loss_pct: Option<f64>,

    #[arg(long)]
    pub wifi_egress: Option<String>,

    #[arg(long)]
    pub inject_fixture: Option<String>,

    #[arg(long)]
    pub json: bool,
}

fn synthetic_pair(seed: &str) -> (PathResult, PathResult) {
    match seed {
        "different-egress" => (
            PathResult { label: "wired", achieved_mbps: Some(350.0), loss_pct: Some(0.0), egress_identity: Some("203.0.113.5".to_string()) },
            PathResult { label: "wifi", achieved_mbps: Some(300.0), loss_pct: Some(20.0), egress_identity: Some("198.51.100.9".to_string()) },
        ),
        "shared-edge" => (
            PathResult { label: "wired", achieved_mbps: Some(350.0), loss_pct: Some(5.0), egress_identity: Some("203.0.113.5".to_string()) },
            PathResult { label: "wifi", achieved_mbps: Some(300.0), loss_pct: Some(20.0), egress_identity: Some("203.0.113.5".to_string()) },
        ),
        "missing-egress" => (
            PathResult { label: "wired", achieved_mbps: Some(350.0), loss_pct: Some(0.0), egress_identity: None },
            PathResult { label: "wifi", achieved_mbps: Some(300.0), loss_pct: Some(20.0), egress_identity: Some("203.0.113.5".to_string()) },
        ),
        _ => (
            PathResult { label: "wired", achieved_mbps: Some(350.0), loss_pct: Some(0.0), egress_identity: Some("203.0.113.5".to_string()) },
            PathResult { label: "wifi", achieved_mbps: Some(300.0), loss_pct: Some(20.0), egress_identity: Some("203.0.113.5".to_string()) },
        ),
    }
}

pub fn run(args: &WiredControlArgs) {
    let (wired, wifi) = if let Some(seed) = &args.inject_fixture {
        synthetic_pair(seed)
    } else {
        (
            PathResult { label: "wired", achieved_mbps: args.wired_mbps, loss_pct: args.wired_loss_pct, egress_identity: args.wired_egress.clone() },
            PathResult { label: "wifi", achieved_mbps: args.wifi_mbps, loss_pct: args.wifi_loss_pct, egress_identity: args.wifi_egress.clone() },
        )
    };

    let attribution = attribute_wired_vs_wifi(&wired, &wifi);

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "wired": wired,
                "wifi": wifi,
                "attribution": attribution,
            }))
            .unwrap()
        );
        return;
    }

    println!();
    println!("{}", "== Wired-vs-Wi-Fi Fault-Domain Control ==".cyan().bold());
    println!(
        "  wired: achieved={} loss={}",
        fmt_mbps(wired.achieved_mbps),
        fmt_pct(wired.loss_pct)
    );
    println!(
        "  wifi:  achieved={} loss={}",
        fmt_mbps(wifi.achieved_mbps),
        fmt_pct(wifi.loss_pct)
    );
    match &attribution {
        FaultAttribution::Wlan { detail } => println!("  attribution: {} {}", "WLAN".yellow().bold(), detail),
        FaultAttribution::SharedEdgeOrWan { detail } => println!("  attribution: {} {}", "SHARED EDGE/WAN".yellow().bold(), detail),
        FaultAttribution::Withheld { reason } => println!("  attribution: {} {}", "WITHHELD".red().bold(), reason),
    }
    println!();
}

fn fmt_mbps(v: Option<f64>) -> String {
    v.map(|v| format!("{v:.1} Mbps")).unwrap_or_else(|| "unavailable".to_string())
}

fn fmt_pct(v: Option<f64>) -> String {
    v.map(|v| format!("{v:.2}%")).unwrap_or_else(|| "unavailable".to_string())
}
