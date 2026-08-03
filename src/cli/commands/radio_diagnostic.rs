//! GAP-011: Wi-Fi radio/retry diagnostic with safe elevation (`radio-diagnostic`).

use colored::*;
use fraggle_packet::load_guard::radio::RadioSnapshot;
use fraggle_packet::load_guard::radio_diagnostic::{build_diagnostic, RadioDiagnostic};
use fraggle_packet::load_guard::wdutil::{self, WdutilError};

#[derive(clap::Args, Debug)]
pub struct RadioDiagnosticArgs {
    /// For the demo/test harness only: use the captured wdutil/system_profiler
    /// fixtures instead of sampling this machine's real radio.
    #[arg(long)]
    pub inject_fixture: bool,

    /// For the demo/test harness only: simulate `wdutil info` failing due to
    /// missing privilege, to exercise the safe-elevation path deterministically.
    #[arg(long)]
    pub inject_privilege_denied: bool,

    #[arg(long)]
    pub json: bool,
}

pub fn run(args: &RadioDiagnosticArgs) {
    let diag = if args.inject_fixture {
        let base = fraggle_packet::load_guard::radio::parse_airport_text(include_str!(
            "../../../harness/fixtures/wifi/system_profiler-airport.txt"
        ));
        let privileged = if args.inject_privilege_denied {
            Err(WdutilError::PrivilegeRequired {
                command: wdutil::suggested_privileged_command(),
            })
        } else {
            Ok(wdutil::parse_wdutil_info(include_str!(
                "../../../harness/fixtures/wifi/wdutil-info.txt"
            )))
        };
        build_diagnostic(base, privileged)
    } else {
        let base = fraggle_packet::load_guard::radio::snapshot_live()
            .unwrap_or_else(|_| RadioSnapshot::unavailable());
        let privileged = wdutil::snapshot_live();
        build_diagnostic(base, privileged)
    };

    if args.json {
        println!("{}", serde_json::to_string_pretty(&diag).unwrap());
        return;
    }
    print_human(&diag);
}

fn fmt_dbm(v: Option<i32>) -> String {
    v.map(|v| format!("{v}dBm"))
        .unwrap_or_else(|| "unavailable".to_string())
}

fn fmt_pct(v: Option<f64>) -> String {
    v.map(|v| format!("{v:.1}%"))
        .unwrap_or_else(|| "unavailable".to_string())
}

fn print_human(diag: &RadioDiagnostic) {
    println!();
    println!("{}", "== Wi-Fi Radio Diagnostic ==".cyan().bold());
    println!("  associated: {}", diag.associated);
    println!(
        "  band={} channel={} width={}",
        diag.band.as_deref().unwrap_or("unavailable"),
        diag.channel
            .map(|c| c.to_string())
            .unwrap_or_else(|| "unavailable".to_string()),
        diag.width_mhz
            .map(|w| format!("{w}MHz"))
            .unwrap_or_else(|| "unavailable".to_string())
    );
    println!(
        "  rssi={} noise={} snr={}",
        fmt_dbm(diag.rssi_dbm),
        fmt_dbm(diag.noise_dbm),
        diag.snr_db
            .map(|s| format!("{s}dB"))
            .unwrap_or_else(|| "unavailable".to_string())
    );
    println!(
        "  mcs={} phy_rate={}",
        diag.mcs_index
            .map(|m| m.to_string())
            .unwrap_or_else(|| "unavailable".to_string()),
        diag.tx_rate_mbps
            .map(|r| format!("{r}Mbps"))
            .unwrap_or_else(|| "unavailable".to_string())
    );
    println!("  rf_quality: {:?}", diag.rf_quality);
    println!(
        "  channel_utilization: {}",
        fmt_pct(diag.channel_utilization_pct)
    );
    println!(
        "  retries: {} (see platform limitations below)",
        diag.retries
            .map(|r| r.to_string())
            .unwrap_or_else(|| "unavailable".to_string())
    );
    println!(
        "  wmm_access_category: {} (see platform limitations below)",
        diag.wmm_access_category.as_deref().unwrap_or("unavailable")
    );
    if let Some(note) = &diag.privilege_note {
        println!("  {} {}", "privilege:".yellow(), note);
    }
    println!("  {}", "platform limitations:".dimmed());
    for l in &diag.platform_limitations {
        println!("    - {l}");
    }
    println!();
}
