//! RTT and Latency Testing
//! 
//! 100-packet ping statistics with jitter detection

use crate::framework::{NetworkTest, TestCategory, TestResult, TestStatus, Diagnosis, DiagnosisSeverity};
use std::error::Error;
use std::process::Command;
use std::time::Duration;

/// RTT and latency measurements
pub struct RttTest {
    count: usize,
    timeout_secs: u64,
}

impl RttTest {
    pub fn new() -> Self {
        Self {
            count: 100,
            timeout_secs: 10,
        }
    }
    
    pub fn with_count(mut self, count: usize) -> Self {
        self.count = count;
        self
    }
}

impl Default for RttTest {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkTest for RttTest {
    fn name(&self) -> &str {
        "RTT/Latency Test"
    }
    
    fn category(&self) -> TestCategory {
        TestCategory::RTT
    }
    
    fn run(&self, target: &str) -> Result<TestResult, Box<dyn Error>> {
        let mut result = TestResult::new(
            self.name().to_string(),
            self.category(),
            target.to_string(),
        );

        // Add CLI equivalent commands for transparency
        result.add_metadata("cli_command", format!("ping -c {} {}", self.count, target));
        result.add_metadata("cli_note", "Parses min/avg/max/stddev from ping statistics");

        // Use ping command
        let output = Command::new("ping")
            .arg("-c")
            .arg(self.count.to_string())
            .arg("-W")
            .arg(self.timeout_secs.to_string())
            .arg(target)
            .output()?;
        
        if !output.status.success() {
            result.set_status(TestStatus::Failed);
            result.add_metadata("error", "Ping command failed");
            return Ok(result);
        }
        
        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse ping output. Fields are Option<f64>: a missing/unrecognized
        // summary line must never be reported as a latency of 0.0 (GAP-009).
        let stats = parse_ping_stats(&stdout);

        let mut latency_available = false;
        if let Some(v) = stats.min { result.add_metric("min_ms", v); latency_available = true; }
        if let Some(v) = stats.avg { result.add_metric("avg_ms", v); latency_available = true; }
        if let Some(v) = stats.max { result.add_metric("max_ms", v); latency_available = true; }
        if let Some(v) = stats.stddev { result.add_metric("stddev_ms", v); latency_available = true; }
        if let Some(v) = stats.jitter { result.add_metric("jitter_ms", v); }
        if let Some(v) = stats.loss_percent { result.add_metric("loss_percent", v); }

        if !latency_available {
            result.add_metadata(
                "latency_unavailable",
                "no round-trip/rtt summary line was found or recognized in ping output; \
                 min/avg/max/stddev/jitter are unavailable, not zero",
            );
            result.add_diagnosis(Diagnosis::new(
                DiagnosisSeverity::Warning,
                "Latency Unavailable".to_string(),
                "Ping produced no parseable round-trip summary (total loss or unrecognized \
                 platform format). Latency is unknown, not zero.".to_string(),
            ).with_recommendation("Check packet loss below; total loss commonly means no summary line exists")
             .with_recommendation("If loss is low, this may be an unrecognized ping output format"));
        }

        // Bufferbloat detection (RTT variance under load) -- only meaningful
        // when both values were actually parsed.
        if let (Some(stddev), Some(avg)) = (stats.stddev, stats.avg) {
            if stddev > avg * 0.5 {
                result.add_diagnosis(Diagnosis::new(
                    DiagnosisSeverity::Warning,
                    "Possible Bufferbloat".to_string(),
                    format!("High RTT variance (stddev {:.1}ms vs avg {:.1}ms) may indicate bufferbloat", stddev, avg),
                ).with_recommendation("Test under load: ping during large download")
                 .with_recommendation("Check router queue management (consider fq_codel)")
                 .with_recommendation("May affect real-time applications"));
            }
        }

        // Analyze results
        let loss = stats.loss_percent;
        if loss.map(|l| l > 10.0).unwrap_or(false) {
            result.set_status(TestStatus::Warning);
            result.add_diagnosis(Diagnosis::new(
                DiagnosisSeverity::Warning,
                "High Packet Loss".to_string(),
                format!("Packet loss: {:.1}%", loss.unwrap()),
            ).with_recommendation("Investigate network congestion")
             .with_recommendation("Check for routing issues"));
        } else if stats.jitter.map(|j| j > 50.0).unwrap_or(false) {
            result.set_status(TestStatus::Warning);
            result.add_diagnosis(Diagnosis::new(
                DiagnosisSeverity::Warning,
                "High Jitter Detected".to_string(),
                format!("Jitter: {:.1}ms (stddev/avg ratio)", stats.jitter.unwrap()),
            ).with_recommendation("May affect real-time applications (VoIP, gaming)"));
        } else if stats.avg.map(|a| a > 200.0).unwrap_or(false) {
            result.set_status(TestStatus::Warning);
            result.add_diagnosis(Diagnosis::new(
                DiagnosisSeverity::Info,
                "High Latency".to_string(),
                format!("Average RTT: {:.1}ms", stats.avg.unwrap()),
            ).with_recommendation("Check routing path")
             .with_related_test("Path Analysis"));
        } else if !latency_available {
            // No round-trip summary and loss wasn't reported as high either
            // (e.g. loss line itself missing/unrecognized): can't call this
            // a success, but it's also not a command failure.
            result.set_status(TestStatus::Warning);
        } else {
            result.set_status(TestStatus::Success);
        }

        Ok(result)
    }
    
    fn estimated_duration(&self) -> u64 {
        // ping rate ~1/sec, plus overhead
        (self.count as u64) / 10 + 2
    }
}

/// Parsed ping statistics. Every field is `Option<f64>` on purpose: a
/// missing or unrecognized summary line must be structurally distinguishable
/// from a real measurement of 0.0 (GAP-009). `None` means "unavailable",
/// never "zero".
#[derive(Debug, Default, PartialEq)]
pub struct PingStats {
    pub min: Option<f64>,
    pub max: Option<f64>,
    pub avg: Option<f64>,
    pub stddev: Option<f64>,
    pub loss_percent: Option<f64>,
    pub jitter: Option<f64>,
}

/// Parses both Linux (`rtt min/avg/max/mdev = ...`) and Darwin
/// (`round-trip min/avg/max/stddev = ...`) ping summary lines from the same
/// code path -- not `#[cfg]`-gated, since a colleague's pasted output from
/// either OS must parse on any host. If no summary line is found or it
/// doesn't parse into 4 numbers, the latency fields stay `None`.
pub fn parse_ping_stats(output: &str) -> PingStats {
    let mut stats = PingStats::default();

    for line in output.lines() {
        let is_summary_line = line.contains("rtt min/avg/max") || line.contains("round-trip min/avg/max");
        if is_summary_line {
            if let Some(stats_part) = line.split('=').nth(1) {
                let nums: Vec<f64> = stats_part
                    .trim()
                    .split('/')
                    .filter_map(|s| s.trim().split_whitespace().next())
                    .filter_map(|s| s.parse().ok())
                    .collect();

                if nums.len() >= 4 {
                    stats.min = Some(nums[0]);
                    stats.avg = Some(nums[1]);
                    stats.max = Some(nums[2]);
                    stats.stddev = Some(nums[3]);
                }
            }
        }

        // Parse packet loss: "10 packets transmitted, 9 received, 10% packet loss"
        // (Linux) or "2 packets transmitted, 0 packets received, 100.0% packet loss" (Darwin).
        if line.contains("packet loss") {
            if let Some(percent_str) = line.split(',').nth(2) {
                if let Some(num_str) = percent_str.trim().split('%').next() {
                    if let Some(num) = num_str.split_whitespace().last() {
                        stats.loss_percent = num.parse().ok();
                    }
                }
            }
        }
    }

    // Jitter (stddev/avg ratio) is only meaningful once both inputs parsed.
    stats.jitter = match (stats.stddev, stats.avg) {
        (Some(stddev), Some(avg)) if avg > 0.0 => Some((stddev / avg) * 100.0),
        _ => None,
    };

    stats
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_rtt_struct() {
        let test = RttTest::new();
        assert_eq!(test.name(), "RTT/Latency Test");
        assert_eq!(test.category(), TestCategory::RTT);
        assert_eq!(test.count, 100);
    }
    
    #[test]
    fn test_parse_ping_output() {
        let output = r#"
PING google.com (142.250.80.46) 56(84) bytes of data.
64 bytes from 142.250.80.46: icmp_seq=1 ttl=117 time=14.2 ms
64 bytes from 142.250.80.46: icmp_seq=2 ttl=117 time=15.1 ms

--- google.com ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1001ms
rtt min/avg/max/mdev = 14.200/14.650/15.100/0.450 ms
"#;

        let stats = parse_ping_stats(output);
        assert!((stats.min.unwrap() - 14.2).abs() < 0.1);
        assert!((stats.avg.unwrap() - 14.65).abs() < 0.1);
        assert_eq!(stats.loss_percent, Some(0.0));
    }

    fn fixture(name: &str) -> String {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("harness/fixtures/ping")
            .join(name);
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {:?}: {}", path, e))
    }

    #[test]
    fn darwin_ok_fixture_parses_real_numbers() {
        let stats = parse_ping_stats(&fixture("darwin-ping-ok.txt"));
        assert_eq!(stats.min, Some(61.541));
        assert_eq!(stats.avg, Some(62.641));
        assert_eq!(stats.max, Some(65.020));
        assert_eq!(stats.stddev, Some(1.395));
        assert_eq!(stats.loss_percent, Some(0.0));
    }

    #[test]
    fn darwin_timeout_fixture_is_unavailable_not_zero() {
        let stats = parse_ping_stats(&fixture("darwin-ping-timeout.txt"));
        assert_eq!(stats.min, None);
        assert_eq!(stats.avg, None);
        assert_eq!(stats.max, None);
        assert_eq!(stats.stddev, None);
        assert_eq!(stats.jitter, None);
        assert_eq!(stats.loss_percent, Some(100.0));
    }

    #[test]
    fn darwin_df_toobig_fixture_reports_unavailable_despite_trailing_stats_block() {
        // Darwin prints a normal-looking "statistics" block even when the
        // probe itself failed with "sendto: Message too long". There is no
        // round-trip line in this fixture, so the parser must not fabricate
        // one from the trailing packet-loss line alone.
        let stats = parse_ping_stats(&fixture("darwin-ping-df-toobig.txt"));
        assert_eq!(stats.min, None);
        assert_eq!(stats.avg, None);
        assert_eq!(stats.loss_percent, Some(100.0));
    }

    #[test]
    fn no_summary_line_never_yields_zero() {
        let stats = parse_ping_stats("nothing recognizable here\n");
        assert_eq!(stats.min, None);
        assert_eq!(stats.avg, None);
        assert_eq!(stats.max, None);
        assert_eq!(stats.stddev, None);
        assert_eq!(stats.jitter, None);
        assert_eq!(stats.loss_percent, None);
    }
}

