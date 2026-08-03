//! GAP-063: cross-platform and power-save client matrix (`platform-matrix`).
//!
//! Records this local client's own capability class and, when a second
//! result is supplied via `--compare-in`, compares the two and either
//! attributes a difference to a single varying axis or explicitly withholds
//! attribution when multiple capability axes differ at once (the field
//! evidence's VHT/5.10/iperf3-3.9 vs HE/6.1/iperf3-3.16 shape). This
//! command does not itself run a cross-machine test bundle -- collecting
//! comparable local results and feeding both in is the operator's job;
//! this is the analysis step that keeps correlation and causation separate.

use colored::*;
use std::io::Read;

use fraggle_packet::network_tests::platform_matrix::{
    attribute_difference, power_save_observability, Attribution, ClientCapability, MatrixResult, PhyGeneration, PowerSaveState,
};

#[derive(clap::Args, Debug)]
pub struct PlatformMatrixArgs {
    /// Coarse OS family (e.g. "macos", "linux", "windows"). Never a
    /// hostname.
    #[arg(long, default_value = "macos")]
    pub os_family: String,

    /// Coarse driver family (e.g. "iwlwifi", "ath10k", "wl"). Never a
    /// firmware build string.
    #[arg(long)]
    pub driver_family: Option<String>,

    /// Coarse kernel major version (e.g. "6", "25"). Never a full build
    /// string.
    #[arg(long)]
    pub kernel_major: Option<String>,

    /// PHY generation: wifi4, wifi5, wifi6, wifi6e, wifi7, unknown.
    #[arg(long, default_value = "unknown")]
    pub phy_generation: String,

    #[arg(long)]
    pub iperf_version: Option<String>,

    /// Measured throughput for this client's run of the representative
    /// bundle, if already known.
    #[arg(long)]
    pub throughput_mbps: Option<f64>,

    #[arg(long)]
    pub loss_percent: Option<f64>,

    /// Path to a JSON file (or "-" for stdin) containing a second
    /// `MatrixResult` to compare against this run.
    #[arg(long)]
    pub compare_in: Option<String>,

    #[arg(long)]
    pub json: bool,
}

fn parse_phy(s: &str) -> PhyGeneration {
    match s.to_lowercase().as_str() {
        "wifi4" => PhyGeneration::Wifi4,
        "wifi5" => PhyGeneration::Wifi5,
        "wifi6" => PhyGeneration::Wifi6,
        "wifi6e" => PhyGeneration::Wifi6E,
        "wifi7" => PhyGeneration::Wifi7,
        _ => PhyGeneration::Unknown,
    }
}

fn load_compare(path: &str) -> Result<MatrixResult, String> {
    let text = if path == "-" {
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf).map_err(|e| e.to_string())?;
        buf
    } else {
        std::fs::read_to_string(path).map_err(|e| e.to_string())?
    };
    serde_json::from_str(&text).map_err(|e| e.to_string())
}

pub fn run(args: &PlatformMatrixArgs) {
    let capability = ClientCapability {
        os_family: args.os_family.clone(),
        driver_family: args.driver_family.clone(),
        kernel_major: args.kernel_major.clone(),
        phy_generation: parse_phy(&args.phy_generation),
        power_save: power_save_observability(),
        iperf_version: args.iperf_version.clone(),
    };
    let local = MatrixResult {
        capability,
        power_save_during_test: PowerSaveState::Unknown,
        throughput_mbps: args.throughput_mbps,
        loss_percent: args.loss_percent,
    };

    let comparison = args.compare_in.as_ref().map(|p| load_compare(p));

    if args.json {
        let attribution = match &comparison {
            Some(Ok(other)) => Some(attribute_difference(&local, other)),
            _ => None,
        };
        let out = serde_json::json!({
            "local": local,
            "compared_against": comparison.as_ref().and_then(|c| c.as_ref().ok()),
            "compare_error": comparison.as_ref().and_then(|c| c.as_ref().err()),
            "attribution": attribution,
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
        return;
    }

    println!();
    println!("{}", "== Local client capability ==".cyan().bold());
    println!(
        "  os_family={} driver_family={} kernel_major={} phy_generation={:?} iperf_version={} power_save={}",
        local.capability.os_family,
        local.capability.driver_family.as_deref().unwrap_or("unavailable"),
        local.capability.kernel_major.as_deref().unwrap_or("unavailable"),
        local.capability.phy_generation,
        local.capability.iperf_version.as_deref().unwrap_or("unavailable"),
        if local.capability.power_save.value.is_none() {
            "platform-limited (client-side TWT/U-APSD state is not observable here)".dimmed().to_string()
        } else {
            format!("{:?}", local.capability.power_save.value)
        }
    );

    match comparison {
        None => println!("\n(no --compare-in supplied; nothing to attribute)"),
        Some(Err(e)) => println!("\n{} failed to load --compare-in: {}", "✗".red(), e),
        Some(Ok(other)) => {
            let attribution = attribute_difference(&local, &other);
            println!();
            println!("{}", "== Attribution ==".cyan().bold());
            match attribution {
                Attribution::SinglePlatformFactor { axis, delta_mbps } => {
                    println!(
                        "  {} attributable to single varying axis: {} (delta {})",
                        "OK".green().bold(),
                        axis,
                        delta_mbps.map(|d| format!("{:.1} Mbps", d)).unwrap_or_else(|| "unavailable".to_string())
                    );
                }
                Attribution::ConfoundedEntangled { varying_axes, reason } => {
                    println!("  {} {}", "CONFOUNDED -- attribution withheld:".red().bold(), reason);
                    println!("  varying axes: {}", varying_axes.join(", "));
                }
                Attribution::NoVariation => {
                    println!("  no capability axis varied between these two results");
                }
            }
        }
    }
}
