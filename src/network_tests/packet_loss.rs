//! Packet Loss Detection

use crate::framework::{
    Diagnosis, DiagnosisSeverity, NetworkTest, TestCategory, TestResult, TestStatus,
};
use std::error::Error;
use std::process::Command;

/// Packet loss testing
pub struct PacketLossTest {
    count: usize,
    timeout_secs: u64,
}

impl PacketLossTest {
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

impl Default for PacketLossTest {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkTest for PacketLossTest {
    fn name(&self) -> &str {
        "Packet Loss Analysis"
    }

    fn category(&self) -> TestCategory {
        TestCategory::PacketLoss
    }

    fn run(&self, target: &str) -> Result<TestResult, Box<dyn Error>> {
        let mut result =
            TestResult::new(self.name().to_string(), self.category(), target.to_string());

        // Add CLI equivalent commands for transparency
        result.add_metadata(
            "cli_command",
            format!("ping -c {} -i 0.2 {}", self.count, target),
        );
        result.add_metadata(
            "cli_note",
            "Fast interval (0.2s) to detect burst loss patterns",
        );

        // Use ping to measure packet loss
        let output = Command::new("ping")
            .arg("-c")
            .arg(self.count.to_string())
            .arg("-W")
            .arg(self.timeout_secs.to_string())
            .arg("-i")
            .arg("0.2") // Faster interval
            .arg(target)
            .output()?;

        if !output.status.success() {
            result.set_status(TestStatus::Failed);
            result.add_metadata("error", "Ping command failed");
            return Ok(result);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse packet loss
        let (transmitted, received, loss_percent) = parse_packet_loss(&stdout)?;

        result.add_metric("packets_transmitted", transmitted as f64);
        result.add_metric("packets_received", received as f64);
        result.add_metric("loss_percent", loss_percent);
        result.add_metric("packets_lost", (transmitted - received) as f64);

        // Analyze loss pattern if possible
        let pattern = analyze_loss_pattern(&stdout);
        result.add_metadata("pattern", pattern.clone());

        // Test TCP connection success rate
        let tcp_success_rate = test_tcp_connection_rate(target, 10);
        result.add_metric("tcp_success_rate", tcp_success_rate);

        if tcp_success_rate < 80.0 && loss_percent < 5.0 {
            result.add_diagnosis(
                Diagnosis::new(
                    DiagnosisSeverity::Warning,
                    "TCP Connection Issues".to_string(),
                    format!(
                        "TCP success rate {:.0}% lower than ICMP success",
                        tcp_success_rate
                    ),
                )
                .with_recommendation("May indicate firewall or TCP-specific issues")
                .with_related_test("TCP Health"),
            );
        }

        // Severity assessment
        if loss_percent >= 50.0 {
            result.set_status(TestStatus::Failed);
            result.add_diagnosis(
                Diagnosis::new(
                    DiagnosisSeverity::Critical,
                    "Severe Packet Loss".to_string(),
                    format!(
                        "Losing {:.1}% of packets ({}/{})",
                        loss_percent,
                        transmitted - received,
                        transmitted
                    ),
                )
                .with_recommendation("Network connection is severely degraded")
                .with_recommendation("Check physical connections and cables")
                .with_recommendation("Investigate network congestion")
                .with_recommendation("Check for hardware failures"),
            );
        } else if loss_percent >= 10.0 {
            result.set_status(TestStatus::Warning);
            result.add_diagnosis(
                Diagnosis::new(
                    DiagnosisSeverity::Warning,
                    "High Packet Loss".to_string(),
                    format!(
                        "Losing {:.1}% of packets ({}/{})",
                        loss_percent,
                        transmitted - received,
                        transmitted
                    ),
                )
                .with_recommendation("Network quality is degraded")
                .with_recommendation("May affect real-time applications")
                .with_recommendation("Check for congestion or routing issues"),
            );
        } else if loss_percent > 1.0 {
            result.set_status(TestStatus::Warning);
            result.add_diagnosis(
                Diagnosis::new(
                    DiagnosisSeverity::Info,
                    "Moderate Packet Loss".to_string(),
                    format!(
                        "Losing {:.1}% of packets ({}/{})",
                        loss_percent,
                        transmitted - received,
                        transmitted
                    ),
                )
                .with_recommendation("Monitor for increasing loss")
                .with_related_test("RTT/Latency Test"),
            );
        } else if loss_percent > 0.0 {
            result.set_status(TestStatus::Success);
            result.add_metadata("verdict", format!("Minimal loss ({:.1}%)", loss_percent));
        } else {
            result.set_status(TestStatus::Success);
            result.add_metadata("verdict", "No packet loss detected");
        }

        Ok(result)
    }

    fn estimated_duration(&self) -> u64 {
        // With interval 0.2, takes count * 0.2 seconds
        (self.count as u64) / 5 + 2
    }
}

fn parse_packet_loss(output: &str) -> Result<(usize, usize, f64), Box<dyn Error>> {
    // Parse: "10 packets transmitted, 9 received, 10% packet loss"
    for line in output.lines() {
        if line.contains("packets transmitted") && line.contains("received") {
            let parts: Vec<&str> = line.split(',').collect();

            let transmitted = parts
                .get(0)
                .and_then(|s| s.split_whitespace().next())
                .and_then(|s| s.parse().ok())
                .ok_or("Failed to parse transmitted count")?;

            let received = parts
                .get(1)
                .and_then(|s| s.split_whitespace().next())
                .and_then(|s| s.parse().ok())
                .ok_or("Failed to parse received count")?;

            let loss_percent = if transmitted > 0 {
                ((transmitted - received) as f64 / transmitted as f64) * 100.0
            } else {
                0.0
            };

            return Ok((transmitted, received, loss_percent));
        }
    }

    Err("Could not parse packet loss statistics".into())
}

fn analyze_loss_pattern(output: &str) -> String {
    // Simple pattern analysis - check if losses are clustered or random
    let mut sequence = Vec::new();

    for line in output.lines() {
        if line.contains("bytes from") {
            sequence.push(true); // Received
        } else if line.contains("timeout") || line.contains("no answer") {
            sequence.push(false); // Lost
        }
    }

    if sequence.is_empty() {
        return "Unknown".to_string();
    }

    // Detect burst loss (consecutive losses)
    let mut max_consecutive_loss = 0;
    let mut current_consecutive = 0;

    for &received in &sequence {
        if !received {
            current_consecutive += 1;
            max_consecutive_loss = max_consecutive_loss.max(current_consecutive);
        } else {
            current_consecutive = 0;
        }
    }

    if max_consecutive_loss >= 5 {
        "Burst Loss (consecutive drops)".to_string()
    } else if max_consecutive_loss >= 2 {
        "Mixed (some clustering)".to_string()
    } else {
        "Random (isolated drops)".to_string()
    }
}

fn test_tcp_connection_rate(target: &str, attempts: usize) -> f64 {
    use std::net::TcpStream;
    use std::time::Duration;

    let mut successes = 0;
    let ports = [80, 443];
    let attempts_per_port = attempts / 2;

    for &port in &ports {
        for _ in 0..attempts_per_port {
            let addr = format!("{}:{}", target, port);
            if let Ok(socket_addr) = addr.parse() {
                if TcpStream::connect_timeout(&socket_addr, Duration::from_secs(2)).is_ok() {
                    successes += 1;
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    (successes as f64 / attempts as f64) * 100.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_loss_struct() {
        let test = PacketLossTest::new();
        assert_eq!(test.name(), "Packet Loss Analysis");
        assert_eq!(test.category(), TestCategory::PacketLoss);
        assert_eq!(test.count, 100);
    }

    #[test]
    fn test_parse_packet_loss() {
        let output = "10 packets transmitted, 9 received, 10% packet loss, time 1001ms";
        let (tx, rx, loss) = parse_packet_loss(output).unwrap();
        assert_eq!(tx, 10);
        assert_eq!(rx, 9);
        assert!((loss - 10.0).abs() < 0.1);
    }

    #[test]
    fn test_pattern_analysis() {
        let pattern = analyze_loss_pattern("");
        assert_eq!(pattern, "Unknown");
    }
}
