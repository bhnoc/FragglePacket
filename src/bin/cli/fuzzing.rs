//! CLI command handlers for fuzzing

use crate::fuzzing::{run_campaign, FuzzError, FuzzMode, PacketContext};
use colored::*;

/// Handle the fuzz command from CLI
pub fn handle_fuzz_command(
    target: &str,
    output: &str,
    mode_str: &str,
) -> Result<(), FuzzError> {
    println!("{}", "╔════════════════════════════════════════╗".green());
    println!("{}", "║      RustPacketFuzz - Packet Fuzzer    ║".green());
    println!("{}", "╚════════════════════════════════════════╝".green());
    println!();

    // Parse fuzzing mode
    let mode = FuzzMode::from_str(mode_str)?;

    println!("{} {}", "Target:".cyan(), target);
    println!("{} {}", "Mode:".cyan(), mode.name());
    println!("{} {}", "Output:".cyan(), output);
    println!();

    // Create packet context
    let ctx = PacketContext::for_target(target)
        .map_err(|e| FuzzError::PacketBuild(e.to_string()))?;

    println!("{}", "Generating packets...".yellow());

    // Run fuzzing campaign
    let result = run_campaign(&ctx, mode, output)?;

    println!();
    println!("{}", "✓ Fuzzing complete!".green().bold());
    println!();
    println!("{} {}", "Packets generated:".cyan(), result.packets_generated);
    println!("{} {}", "PCAP file:".cyan(), result.pcap_path.display());
    println!("{} {} bytes", "File size:".cyan(), result.file_size_bytes);
    println!("{} {} ms", "Duration:".cyan(), result.duration_ms);
    println!();
    println!("{}", "Next steps:".yellow().bold());
    println!("  1. Open in Wireshark:");
    println!("     {}", format!("wireshark {}", output).bright_black());
    println!("  2. Analyze with Suricata:");
    println!("     {}", format!("suricata -r {} -l ./logs/", output).bright_black());
    println!("  3. Replay to network:");
    println!("     {}", format!("tcpreplay -i eth0 {}", output).bright_black());
    println!();

    Ok(())
}
