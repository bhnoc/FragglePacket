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
        
        // Parse ping output
        let stats = parse_ping_stats(&stdout)?;
        
        result.add_metric("min_ms", stats.min);
        result.add_metric("max_ms", stats.max);
        result.add_metric("avg_ms", stats.avg);
        result.add_metric("stddev_ms", stats.stddev);
        result.add_metric("loss_percent", stats.loss_percent);
        result.add_metric("jitter_ms", stats.jitter);
        
        // Bufferbloat detection (RTT variance under load)
        if stats.stddev > stats.avg * 0.5 {
            result.add_diagnosis(Diagnosis::new(
                DiagnosisSeverity::Warning,
                "Possible Bufferbloat".to_string(),
                format!("High RTT variance (stddev {:.1}ms vs avg {:.1}ms) may indicate bufferbloat", stats.stddev, stats.avg),
            ).with_recommendation("Test under load: ping during large download")
             .with_recommendation("Check router queue management (consider fq_codel)")
             .with_recommendation("May affect real-time applications"));
        }
        
        // Analyze results
        if stats.loss_percent > 10.0 {
            result.set_status(TestStatus::Warning);
            result.add_diagnosis(Diagnosis::new(
                DiagnosisSeverity::Warning,
                "High Packet Loss".to_string(),
                format!("Packet loss: {:.1}%", stats.loss_percent),
            ).with_recommendation("Investigate network congestion")
             .with_recommendation("Check for routing issues"));
        } else if stats.jitter > 50.0 {
            result.set_status(TestStatus::Warning);
            result.add_diagnosis(Diagnosis::new(
                DiagnosisSeverity::Warning,
                "High Jitter Detected".to_string(),
                format!("Jitter: {:.1}ms (stddev/avg ratio)", stats.jitter),
            ).with_recommendation("May affect real-time applications (VoIP, gaming)"));
        } else if stats.avg > 200.0 {
            result.set_status(TestStatus::Warning);
            result.add_diagnosis(Diagnosis::new(
                DiagnosisSeverity::Info,
                "High Latency".to_string(),
                format!("Average RTT: {:.1}ms", stats.avg),
            ).with_recommendation("Check routing path")
             .with_related_test("Path Analysis"));
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

#[derive(Debug)]
struct PingStats {
    min: f64,
    max: f64,
    avg: f64,
    stddev: f64,
    loss_percent: f64,
    jitter: f64,
}

fn parse_ping_stats(output: &str) -> Result<PingStats, Box<dyn Error>> {
    let mut min = 0.0;
    let mut max = 0.0;
    let mut avg = 0.0;
    let mut stddev = 0.0;
    let mut loss_percent = 0.0;
    
    // Parse rtt line: "rtt min/avg/max/mdev = 14.123/20.456/45.789/8.234 ms"
    for line in output.lines() {
        if line.contains("rtt min/avg/max") {
            if let Some(stats_part) = line.split('=').nth(1) {
                let nums: Vec<f64> = stats_part
                    .trim()
                    .split('/')
                    .filter_map(|s| s.trim().split_whitespace().next())
                    .filter_map(|s| s.parse().ok())
                    .collect();
                
                if nums.len() >= 4 {
                    min = nums[0];
                    avg = nums[1];
                    max = nums[2];
                    stddev = nums[3];
                }
            }
        }
        
        // Parse packet loss: "10 packets transmitted, 9 received, 10% packet loss"
        if line.contains("packet loss") {
            if let Some(percent_str) = line.split(',').nth(2) {
                if let Some(num_str) = percent_str.trim().split('%').next() {
                    if let Some(num) = num_str.split_whitespace().last() {
                        loss_percent = num.parse().unwrap_or(0.0);
                    }
                }
            }
        }
    }
    
    // Calculate jitter (stddev/avg ratio)
    let jitter = if avg > 0.0 { (stddev / avg) * 100.0 } else { 0.0 };
    
    Ok(PingStats {
        min,
        max,
        avg,
        stddev,
        loss_percent,
        jitter,
    })
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
        
        let stats = parse_ping_stats(output).unwrap();
        assert!((stats.min - 14.2).abs() < 0.1);
        assert!((stats.avg - 14.65).abs() < 0.1);
        assert_eq!(stats.loss_percent, 0.0);
    }
}

