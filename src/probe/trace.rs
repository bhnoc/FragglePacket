use std::io::BufRead;
use std::io::BufReader;
use std::process::{Command, Stdio};

#[derive(Debug, Clone)]
pub struct HopInfo {
    pub hop: u8,
    pub addr: String,
    pub mtu: Option<usize>,
}

pub fn run_tracepath(target: &str) -> Vec<HopInfo> {
    let mut hops = Vec::new();

    // Try tracepath first (Linux)
    let output = Command::new("tracepath")
        .arg("-n") // No DNS lookups (faster)
        .arg("-m")
        .arg("15") // Max 15 hops
        .arg(target)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output();

    if let Ok(output) = output {
        if output.status.success() {
            let reader = BufReader::new(&output.stdout[..]);
            for line in reader.lines().map_while(Result::ok) {
                // Parse tracepath output:
                // " 1:  192.168.1.1    0.5ms pmtu 1500"
                // " 2:  10.0.0.1      5.2ms pmtu 1400"
                if let Some(hop_info) = parse_tracepath_line(&line) {
                    hops.push(hop_info);
                }
            }
        }
    }

    hops
}

pub fn parse_tracepath_line(line: &str) -> Option<HopInfo> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }

    // Format: " N:  ADDRESS  TIMEms [pmtu MTU]"
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.is_empty() {
        return None;
    }

    // Extract hop number
    let hop_str = parts[0].trim_end_matches(':');
    let hop: u8 = hop_str.parse().ok()?;

    // Extract address (second element if exists)
    let addr = if parts.len() > 1 && !parts[1].ends_with("ms") {
        parts[1].to_string()
    } else {
        "???".to_string()
    };

    // Look for "pmtu" in the line
    let mtu = if let Some(pos) = parts.iter().position(|&p| p == "pmtu") {
        parts.get(pos + 1).and_then(|m| m.parse().ok())
    } else {
        None
    };

    Some(HopInfo { hop, addr, mtu })
}

pub fn check_tracepath_available() -> bool {
    Command::new("tracepath")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}
