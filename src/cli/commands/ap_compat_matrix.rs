//! GAP-037: AP compatibility matrix CLI (`ap-compat-matrix`).

use colored::*;

use fraggle_packet::load_guard::radio::snapshot_live;
use fraggle_packet::load_guard::{ap_identity, wdutil};
use fraggle_packet::network_tests::ap_compat_matrix::{
    client_association_from_snapshot, run_descriptor_digest, verdict, ApContext, ClientHardwareGeneration,
    CompatibilityMatrix, CompatibilityVerdict, MatrixCell,
};

#[derive(clap::Args, Debug)]
pub struct ApCompatMatrixArgs {
    /// Sample this machine's own current Wi-Fi association (unprivileged
    /// `system_profiler`) and print it as one client-only cell. Never reads
    /// or stores SSID/BSSID/MAC.
    #[arg(long)]
    pub sample_client: bool,

    /// Attempt the privileged BSSID read (`wdutil info`, needs root) solely
    /// to compute this machine's stable AP-identity label via GAP-024's
    /// salted hash. The BSSID itself is discarded immediately after
    /// hashing and never printed. Without this flag, ap_identity is None.
    #[arg(long)]
    pub with_ap_identity: bool,

    /// One or more JSON files, each an array of `MatrixCell` objects
    /// (client association + AP context + client hardware generation),
    /// ingested and merged into one matrix for the verdict check.
    #[arg(long, num_args = 1..)]
    pub ingest_cells: Vec<String>,

    /// Label for the sampled client-only cell.
    #[arg(long, default_value = "client-self-sample")]
    pub label: String,

    #[arg(long, value_enum)]
    pub client_hardware_generation: Option<ClientHardwareGenerationArg>,

    #[arg(long)]
    pub json: bool,
}

#[derive(clap::ValueEnum, Debug, Clone, Copy)]
pub enum ClientHardwareGenerationArg {
    Wifi7,
    Wifi6e,
    Other,
}

fn empty_ap_context() -> ApContext {
    ApContext {
        ap_identity: None,
        model: None,
        firmware_version: None,
        power_mode_raw: None,
        low_power_supply: None,
        radio_mode: None,
        mlo_supported: None,
        band_advertised: None,
        width_advertised_mhz: None,
        nss_advertised: None,
    }
}

pub fn run(args: &ApCompatMatrixArgs) {
    let mut cells: Vec<MatrixCell> = Vec::new();

    if args.sample_client {
        let snap = match snapshot_live() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("{} failed to sample Wi-Fi association: {}", "✗".red(), e);
                std::process::exit(1);
            }
        };

        let ap_identity = if args.with_ap_identity {
            match (wdutil::snapshot_live(), ap_identity::load_or_create_salt()) {
                (Ok(fields), Ok(salt)) => fields.bssid.as_deref().map(|b| ap_identity::ApIdentity {
                    label: ap_identity::label_for_bssid(b, &salt),
                    band: snap.band.clone(),
                    channel: snap.channel,
                }),
                (Err(e), _) => {
                    eprintln!(
                        "{} ap identity unavailable: {} (proceeding without it)",
                        "note:".yellow(),
                        e
                    );
                    None
                }
                (_, Err(e)) => {
                    eprintln!("{} ap identity salt unavailable: {} (proceeding without it)", "note:".yellow(), e);
                    None
                }
            }
        } else {
            None
        };

        let client = client_association_from_snapshot(&snap, ap_identity);
        let generation = args.client_hardware_generation.map(|g| match g {
            ClientHardwareGenerationArg::Wifi7 => ClientHardwareGeneration::Wifi7,
            ClientHardwareGenerationArg::Wifi6e => ClientHardwareGeneration::Wifi6e,
            ClientHardwareGenerationArg::Other => ClientHardwareGeneration::Other,
        });

        cells.push(MatrixCell {
            label: args.label.clone(),
            client,
            ap: empty_ap_context(),
            client_hardware_generation: generation,
        });
    }

    for path in &args.ingest_cells {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("{} {}: {}", "✗".red(), path, e);
                std::process::exit(1);
            }
        };
        match serde_json::from_str::<Vec<MatrixCell>>(&text) {
            Ok(mut ingested) => cells.append(&mut ingested),
            Err(e) => {
                eprintln!("{} {}: invalid MatrixCell array: {}", "✗".red(), path, e);
                std::process::exit(1);
            }
        }
    }

    if cells.is_empty() {
        eprintln!(
            "{} nothing to do: pass --sample-client and/or --ingest-cells <file.json>",
            "✗".red()
        );
        std::process::exit(1);
    }

    let digests: Vec<u64> = cells.iter().map(run_descriptor_digest).collect();
    let matrix = CompatibilityMatrix { cells };
    let result = verdict(&matrix);

    if args.json {
        let report = serde_json::json!({
            "matrix": matrix,
            "run_descriptor_digests": digests,
            "verdict": result,
        });
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
        return;
    }

    println!("{}", "== AP Compatibility Matrix ==".cyan().bold());
    for (cell, digest) in matrix.cells.iter().zip(digests.iter()) {
        println!("  cell: {}", cell.label);
        println!(
            "    client negotiated: {:?} (raw phy_mode: {})",
            cell.client.negotiated_generation,
            cell.client.phy_mode_raw.as_deref().unwrap_or("unavailable")
        );
        println!(
            "    client band/channel/width: {}/{}/{}",
            cell.client.band.as_deref().unwrap_or("?"),
            cell.client.channel.map(|c| c.to_string()).unwrap_or_else(|| "?".to_string()),
            cell.client.width_mhz.map(|w| w.to_string()).unwrap_or_else(|| "?".to_string()),
        );
        if !cell.client.platform_limitations.is_empty() {
            for l in &cell.client.platform_limitations {
                println!("    {} {}", "platform-limited:".yellow(), l);
            }
        }
        println!(
            "    AP context: model={} firmware={} radio_mode={:?} power_mode={}",
            cell.ap.model.as_deref().unwrap_or("unavailable"),
            cell.ap.firmware_version.as_deref().unwrap_or("unavailable"),
            cell.ap.radio_mode,
            cell.ap.power_mode_raw.as_deref().unwrap_or("unavailable"),
        );
        println!("    run descriptor digest: {:016x}", digest);
    }
    println!();
    match result {
        CompatibilityVerdict::Comparable { present_cells } => {
            println!("{}", "verdict: COMPARABLE".green().bold());
            for c in present_cells {
                println!("  present: {}", c);
            }
        }
        CompatibilityVerdict::InsufficientCells { missing } => {
            println!("{}", "verdict: INSUFFICIENT CELLS FOR A VERDICT".yellow().bold());
            for m in missing {
                println!("  missing: {}", m);
            }
        }
    }
}
