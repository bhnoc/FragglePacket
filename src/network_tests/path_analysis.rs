//! Path Analysis - Traceroute with MTR-style per-hop latency

use crate::framework::{
    Diagnosis, DiagnosisSeverity, NetworkTest, TestCategory, TestResult, TestStatus,
};
use std::collections::HashMap;
use std::error::Error;
use std::process::Command;

#[derive(Debug, Clone)]
struct HopLatencyData {
    min: f64,
    max: f64,
    avg: f64,
    loss_percent: f64,
}

/// MTR-style: measure per-hop latency with multiple probes
fn measure_per_hop_latency(
    target: &str,
    max_hops: usize,
    probe_count: usize,
) -> HashMap<usize, HopLatencyData> {
    let mut hop_data: HashMap<usize, Vec<f64>> = HashMap::new();

    for _ in 0..probe_count {
        let output = Command::new("traceroute")
            .arg("-m")
            .arg(max_hops.to_string())
            .arg("-q")
            .arg("1")
            .arg(target)
            .output();

        if let Ok(output) = output {
            let stdout = String::from_utf8_lossy(&output.stdout);

            for (hop_num, line) in stdout.lines().enumerate().skip(1) {
                if line.is_empty() || line.starts_with("traceroute") {
                    continue;
                }

                if let Some(rtt) = extract_rtt_from_line(line) {
                    hop_data.entry(hop_num).or_insert_with(Vec::new).push(rtt);
                }
            }
        }

        std::thread::sleep(std::time::Duration::from_millis(200));
    }

    let mut result = HashMap::new();
    for (hop_num, rtts) in hop_data {
        if rtts.is_empty() {
            continue;
        }

        let min = rtts.iter().copied().fold(f64::INFINITY, f64::min);
        let max = rtts.iter().copied().fold(f64::NEG_INFINITY, f64::max);
        let avg = rtts.iter().sum::<f64>() / rtts.len() as f64;
        let loss_percent = ((probe_count - rtts.len()) as f64 / probe_count as f64) * 100.0;

        result.insert(
            hop_num,
            HopLatencyData {
                min,
                max,
                avg,
                loss_percent,
            },
        );
    }

    result
}

fn extract_rtt_from_line(line: &str) -> Option<f64> {
    for part in line.split_whitespace() {
        if part.ends_with("ms") {
            if let Ok(rtt) = part.trim_end_matches("ms").parse::<f64>() {
                return Some(rtt);
            }
        }
    }
    None
}

/// Traceroute-based path analysis with per-hop latency
pub struct PathAnalysisTest {
    max_hops: u8,
    timeout_secs: u64,
    probe_count: usize, // Number of probes per hop (mtr-style)
}

impl PathAnalysisTest {
    pub fn new() -> Self {
        Self {
            max_hops: 30,
            timeout_secs: 5,
            probe_count: 3,
        }
    }

    pub fn with_max_hops(mut self, hops: u8) -> Self {
        self.max_hops = hops;
        self
    }

    pub fn with_probe_count(mut self, count: usize) -> Self {
        self.probe_count = count;
        self
    }
}

impl Default for PathAnalysisTest {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkTest for PathAnalysisTest {
    fn name(&self) -> &str {
        "Path Analysis (Traceroute)"
    }

    fn category(&self) -> TestCategory {
        TestCategory::PathAnalysis
    }

    fn run(&self, target: &str) -> Result<TestResult, Box<dyn Error>> {
        let mut result =
            TestResult::new(self.name().to_string(), self.category(), target.to_string());

        // Add CLI equivalent commands for transparency
        result.add_metadata(
            "cli_command",
            format!("traceroute -m {} {}", self.max_hops, target),
        );
        result.add_metadata("cli_mtr", format!("mtr -r -c 10 {}", target));
        result.add_metadata(
            "cli_note",
            "Per-hop latency measured with multiple probes like mtr",
        );

        // Run traceroute
        let output = Command::new("traceroute")
            .arg("-m")
            .arg(self.max_hops.to_string())
            .arg("-w")
            .arg(self.timeout_secs.to_string())
            .arg(target)
            .output();

        let output = match output {
            Ok(o) => o,
            Err(_) => {
                // Try tracepath as fallback
                match Command::new("tracepath").arg(target).output() {
                    Ok(o) => o,
                    Err(e) => {
                        result.set_status(TestStatus::Failed);
                        result.add_metadata(
                            "error",
                            format!("traceroute/tracepath not available: {}", e),
                        );
                        return Ok(result);
                    }
                }
            }
        };

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse hops
        let hops = parse_traceroute(&stdout);

        result.add_metric("hop_count", hops.len() as f64);

        if hops.is_empty() {
            result.set_status(TestStatus::Failed);
            result.add_metadata("error", "No hops detected");
            return Ok(result);
        }

        // MTR-style: measure per-hop latency with multiple probes
        let hop_latencies = measure_per_hop_latency(target, hops.len().min(15), self.probe_count);

        // Analyze path with latency data
        let mut hop_details = Vec::new();
        let mut has_timeouts = false;
        let mut has_high_latency = false;
        let mut hop_latency_increase = Vec::new();

        for (i, hop) in hops.iter().enumerate() {
            let hop_num = i + 1;

            // Get latency stats for this hop from mtr-style probes
            let latency_data = hop_latencies.get(&hop_num);

            if hop.timeout {
                has_timeouts = true;
                hop_details.push(format!("Hop {}: * * * (timeout)", hop_num));
            } else {
                let latency_str = if let Some(data) = latency_data {
                    result.add_metric(&format!("hop{}_avg_ms", hop_num), data.avg);
                    result.add_metric(&format!("hop{}_min_ms", hop_num), data.min);
                    result.add_metric(&format!("hop{}_max_ms", hop_num), data.max);
                    result.add_metric(&format!("hop{}_loss_pct", hop_num), data.loss_percent);

                    // Track latency increase
                    if hop_num > 1 {
                        if let Some(prev_data) = hop_latencies.get(&(hop_num - 1)) {
                            let increase = data.avg - prev_data.avg;
                            hop_latency_increase.push((hop_num, increase));
                        }
                    }

                    format!(
                        "{} (avg {:.1}ms, loss {:.0}%)",
                        hop.addr, data.avg, data.loss_percent
                    )
                } else {
                    format!("{} ({:.1}ms)", hop.addr, hop.rtt_ms)
                };

                hop_details.push(format!("Hop {}: {}", hop_num, latency_str));

                if hop.rtt_ms > 200.0 {
                    has_high_latency = true;
                }
            }
        }

        result.add_metadata("path", hop_details.join(" → "));
        result.add_metadata(
            "final_hop",
            hops.last().map(|h| h.addr.clone()).unwrap_or_default(),
        );

        // TTL analysis
        let final_hop_count = hops.len();
        let _estimated_ttl_used = final_hop_count;

        result.add_metric("hops_to_target", final_hop_count as f64);
        result.add_metric(
            "estimated_initial_ttl",
            estimate_initial_ttl(final_hop_count) as f64,
        );

        // Check for unusual TTL patterns
        if final_hop_count > 25 {
            result.add_diagnosis(
                Diagnosis::new(
                    DiagnosisSeverity::Warning,
                    "Very Long Path".to_string(),
                    format!("Target is {} hops away (typical is <15)", final_hop_count),
                )
                .with_recommendation("May indicate suboptimal routing")
                .with_recommendation("Consider using closer mirror or CDN"),
            );
        }

        // Detect if we hit max hops without reaching target
        if final_hop_count >= (self.max_hops as usize)
            && hops.last().map(|h| h.timeout).unwrap_or(false)
        {
            result.add_diagnosis(
                Diagnosis::new(
                    DiagnosisSeverity::Error,
                    "Target Not Reached".to_string(),
                    format!(
                        "Reached max hops ({}) without finding target",
                        self.max_hops
                    ),
                )
                .with_recommendation("Target may be unreachable or beyond max hops")
                .with_recommendation("Increase max hops or check target reachability"),
            );
        }

        // Identify hops with significant latency contribution
        if !hop_latency_increase.is_empty() {
            hop_latency_increase.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
            if let Some((hop_num, increase)) = hop_latency_increase.first() {
                if *increase > 50.0 {
                    result.add_diagnosis(
                        Diagnosis::new(
                            DiagnosisSeverity::Info,
                            "High Latency Hop Identified".to_string(),
                            format!(
                                "Hop {} adds {:.1}ms latency (largest contributor)",
                                hop_num, increase
                            ),
                        )
                        .with_recommendation(format!(
                            "Investigate hop {} for congestion or routing issues",
                            hop_num
                        )),
                    );
                }
            }
        }

        // Calculate average RTT from all non-timeout hops
        let rtts: Vec<f64> = hops
            .iter()
            .filter(|h| !h.timeout)
            .map(|h| h.rtt_ms)
            .collect();
        if !rtts.is_empty() {
            let avg_rtt = rtts.iter().sum::<f64>() / rtts.len() as f64;
            result.add_metric("avg_hop_rtt_ms", avg_rtt);
        }

        // Status and diagnoses
        if has_timeouts {
            result.set_status(TestStatus::Warning);
            result.add_diagnosis(
                Diagnosis::new(
                    DiagnosisSeverity::Warning,
                    "Path Contains Timeouts".to_string(),
                    "Some hops in path did not respond (may be normal for filtered routers)"
                        .to_string(),
                )
                .with_recommendation("Verify target is reachable"),
            );
        } else if has_high_latency {
            result.set_status(TestStatus::Warning);
            result.add_diagnosis(
                Diagnosis::new(
                    DiagnosisSeverity::Info,
                    "High Latency Detected in Path".to_string(),
                    format!(
                        "Path has {} hops with high latency",
                        rtts.iter().filter(|&&r| r > 200.0).count()
                    ),
                )
                .with_recommendation("May indicate congestion or long-distance routing"),
            );
        } else {
            result.set_status(TestStatus::Success);
        }

        // Check for routing loops
        let unique_addrs: std::collections::HashSet<_> = hops
            .iter()
            .filter(|h| !h.timeout)
            .map(|h| &h.addr)
            .collect();

        if unique_addrs.len() < hops.iter().filter(|h| !h.timeout).count() {
            result.add_diagnosis(
                Diagnosis::new(
                    DiagnosisSeverity::Error,
                    "Possible Routing Loop Detected".to_string(),
                    "Same address appears multiple times in path".to_string(),
                )
                .with_recommendation("Check network routing configuration"),
            );
        }

        Ok(result)
    }

    fn requires_root(&self) -> bool {
        false // traceroute/tracepath usually work without root
    }

    fn estimated_duration(&self) -> u64 {
        (self.max_hops as u64) * self.timeout_secs
    }
}

#[derive(Debug)]
struct Hop {
    addr: String,
    rtt_ms: f64,
    timeout: bool,
}

fn estimate_initial_ttl(hops_used: usize) -> u8 {
    // Most operating systems use TTL of 64, 128, or 255
    // Estimate which was likely used based on hops
    if hops_used <= 64 {
        64
    } else if hops_used <= 128 {
        128
    } else {
        255
    }
}

fn parse_traceroute(output: &str) -> Vec<Hop> {
    let mut hops = Vec::new();

    for line in output.lines() {
        let line = line.trim();

        // Skip header lines
        if line.is_empty() || line.starts_with("traceroute") || line.starts_with("tracepath") {
            continue;
        }

        // Parse hop line (various formats)
        // Format: " 1  router.local (192.168.1.1)  1.234 ms"
        // Format: " 2  * * *"

        if line.contains("* * *") {
            hops.push(Hop {
                addr: "*".to_string(),
                rtt_ms: 0.0,
                timeout: true,
            });
            continue;
        }

        // Try to extract IP/hostname and RTT
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            continue;
        }

        // Look for address (hostname or IP in parens)
        let mut addr = String::new();
        let mut rtt = 0.0;

        for (i, part) in parts.iter().enumerate() {
            // Address might be like "router.local" or "(192.168.1.1)"
            if part.contains('.') && !part.ends_with("ms") {
                addr = part.trim_matches(|c| c == '(' || c == ')').to_string();
            }

            // RTT looks like "1.234"
            if i > 0 && parts.get(i + 1) == Some(&"ms") {
                rtt = part.parse().unwrap_or(0.0);
                break;
            }
        }

        if !addr.is_empty() {
            hops.push(Hop {
                addr,
                rtt_ms: rtt,
                timeout: false,
            });
        }
    }

    hops
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_analysis_struct() {
        let test = PathAnalysisTest::new();
        assert_eq!(test.name(), "Path Analysis (Traceroute)");
        assert_eq!(test.category(), TestCategory::PathAnalysis);
        assert_eq!(test.max_hops, 30);
    }

    #[test]
    fn test_parse_traceroute() {
        let output = r#"
traceroute to google.com (142.250.80.46)
 1  router.local (192.168.1.1)  1.234 ms
 2  * * *
 3  10.0.0.1 (10.0.0.1)  15.678 ms
"#;

        let hops = parse_traceroute(output);
        assert!(hops.len() >= 2); // At least timeout and one real hop

        // Check we found the timeout
        assert!(hops.iter().any(|h| h.timeout));

        // Check we found at least one real IP
        assert!(hops.iter().any(|h| !h.timeout && !h.addr.is_empty()));
    }
}
