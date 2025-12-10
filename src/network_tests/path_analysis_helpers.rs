use std::collections::HashMap;
use std::process::Command;

#[derive(Debug, Clone)]
struct HopLatencyData {
    min: f64,
    max: f64,
    avg: f64,
    loss_percent: f64,
}

/// MTR-style: measure per-hop latency with multiple probes
fn measure_per_hop_latency(target: &str, max_hops: usize, probe_count: usize) -> HashMap<usize, HopLatencyData> {
    let mut hop_data: HashMap<usize, Vec<f64>> = HashMap::new();
    
    // Send multiple probes to build statistics (simplified mtr approach)
    for _ in 0..probe_count {
        // Use traceroute with ICMP to get per-hop timing
        let output = Command::new("traceroute")
            .arg("-m")
            .arg(max_hops.to_string())
            .arg("-q")
            .arg("1")  // 1 query per hop per iteration
            .arg(target)
            .output();
        
        if let Ok(output) = output {
            let stdout = String::from_utf8_lossy(&output.stdout);
            
            // Parse each hop's latency
            for (hop_num, line) in stdout.lines().enumerate().skip(1) {
                if line.is_empty() || line.starts_with("traceroute") {
                    continue;
                }
                
                // Extract RTT from line
                if let Some(rtt) = extract_rtt_from_line(line) {
                    hop_data.entry(hop_num).or_insert_with(Vec::new).push(rtt);
                }
            }
        }
        
        // Small delay between probes
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    
    // Calculate statistics for each hop
    let mut result = HashMap::new();
    for (hop_num, rtts) in hop_data {
        if rtts.is_empty() {
            continue;
        }
        
        let min = rtts.iter().copied().fold(f64::INFINITY, f64::min);
        let max = rtts.iter().copied().fold(f64::NEG_INFINITY, f64::max);
        let avg = rtts.iter().sum::<f64>() / rtts.len() as f64;
        let loss_percent = ((probe_count - rtts.len()) as f64 / probe_count as f64) * 100.0;
        
        result.insert(hop_num, HopLatencyData {
            min,
            max,
            avg,
            loss_percent,
        });
    }
    
    result
}

fn extract_rtt_from_line(line: &str) -> Option<f64> {
    // Look for patterns like "14.5 ms" or "14.5ms"
    for part in line.split_whitespace() {
        if part.ends_with("ms") {
            if let Ok(rtt) = part.trim_end_matches("ms").parse::<f64>() {
                return Some(rtt);
            }
        }
        // Also check next word
        if part == "ms" {
            // Previous word should be the number
            continue;
        }
    }
    None
}


