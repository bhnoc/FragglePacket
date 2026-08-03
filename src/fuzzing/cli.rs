//! CLI command handlers for fuzzing

use crate::fuzzing::{FuzzError, FuzzMode, PacketContext, run_campaign};
use colored::*;

/// Handle the fuzz command from CLI
pub fn handle_fuzz_command(
    target: &str,
    output: &str,
    mode_str: &str,
) -> Result<(), FuzzError> {
    println!("{}", "╔════════════════════════════════════════╗".green());
    println!("{}", "║     RustPacketFuzz - Packet Fuzzer    ║".green());
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

/// Print available fuzzing modes
pub fn print_modes() {
    println!("{}", "Available Fuzzing Modes:".yellow().bold());
    println!();
    println!("  {} - Test TCP segment sizes (0-65535 bytes)", "segment-size".cyan());
    println!("    Detects: Buffer underruns, integer overflows");
    println!();
    println!("  {} - IP header length mismatches", "length-mismatch".cyan());
    println!("    Detects: Heartbleed-style buffer over-reads");
    println!();
    println!("  {} - Corrupt TCP options", "tcp-options".cyan());
    println!("    Detects: Option parser bugs, division by zero");
    println!();
    println!("  {} - IP fragmentation edge cases", "fragmentation".cyan());
    println!("    Detects: Reassembly bugs, resource exhaustion");
    println!();
    println!("  {} - Valid and invalid checksums", "checksum".cyan());
    println!("    Detects: Validation bypass vulnerabilities");
    println!();
}

