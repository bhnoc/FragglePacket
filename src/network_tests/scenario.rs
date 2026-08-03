//! Declarative Scenario Runner
//!
//! Simple key=value step format so users can describe multi-step probes
//! without bringing in a YAML dependency. Each line is either a step header
//! `# step: <name>` or a `key: value` pair. Blank lines separate steps.
//!
//! Supported step kinds:
//!   * `kind: https` runs the staged HTTPS test
//!   * `kind: upload_sweep` runs the upload size sweep
//!   * `kind: ssh` runs the SSH data-path test
//!   * `kind: printer` runs the raw 9100 bulk sweep
//!   * `kind: quic` runs the QUIC PMTU probe
//!   * `kind: dns_secure` runs the DoH/DoT compare test
//!   * `kind: tcp_options` runs the TCP options echo test
//!
//! Each step may include `target: host` and `port: N`.

use crate::framework::{NetworkTest, TestResult};
use crate::network_tests::https::HttpsTest;
use crate::network_tests::{
    DnsSecureCompareTest, QuicPmtudTest, Raw9100BulkTest, SshDataPathTest, TcpOptionsEchoTest,
    UploadSizeSweepTest,
};
use std::collections::HashMap;
use std::error::Error;

#[derive(Debug, Clone)]
pub struct ScenarioStep {
    pub name: String,
    pub kind: String,
    pub target: String,
    pub port: Option<u16>,
    pub extra: HashMap<String, String>,
}

#[derive(Debug, Clone, Default)]
pub struct Scenario {
    pub steps: Vec<ScenarioStep>,
}

impl Scenario {
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut scenario = Scenario::default();
        let mut current: Option<ScenarioStep> = None;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                if let Some(step) = current.take() {
                    scenario.steps.push(step);
                }
                continue;
            }
            if line.starts_with('#') {
                if let Some(rest) = line
                    .strip_prefix("# step:")
                    .or_else(|| line.strip_prefix("#step:"))
                {
                    if let Some(step) = current.take() {
                        scenario.steps.push(step);
                    }
                    current = Some(ScenarioStep {
                        name: rest.trim().to_string(),
                        kind: String::new(),
                        target: String::new(),
                        port: None,
                        extra: HashMap::new(),
                    });
                }
                continue;
            }
            let Some(step) = current.as_mut() else {
                continue;
            };
            if let Some((k, v)) = line.split_once(':') {
                let k = k.trim();
                let v = v.trim();
                match k {
                    "kind" => step.kind = v.to_string(),
                    "target" => step.target = v.to_string(),
                    "port" => step.port = v.parse().ok(),
                    _ => {
                        step.extra.insert(k.to_string(), v.to_string());
                    }
                }
            }
        }
        if let Some(step) = current.take() {
            scenario.steps.push(step);
        }
        Ok(scenario)
    }

    pub fn run(&self) -> Vec<(String, Result<TestResult, String>)> {
        let mut out = Vec::with_capacity(self.steps.len());
        for step in &self.steps {
            let name = step.name.clone();
            let res = run_step(step);
            out.push((name, res));
        }
        out
    }
}

fn run_step(step: &ScenarioStep) -> Result<TestResult, String> {
    let target = &step.target;
    let result: Result<TestResult, Box<dyn Error>> = match step.kind.as_str() {
        "https" => HttpsTest::new().run(target),
        "upload_sweep" | "upload" => {
            let mut t = UploadSizeSweepTest::new();
            if let Some(p) = step.port {
                t = t.with_port(p);
            }
            t.run(target)
        }
        "ssh" => SshDataPathTest::new().run(target),
        "printer" | "raw9100" => Raw9100BulkTest::new().run(target),
        "quic" => QuicPmtudTest::new().run(target),
        "dns_secure" | "dns" => DnsSecureCompareTest::new().run(target),
        "tcp_options" => TcpOptionsEchoTest::new().run(target),
        other => return Err(format!("unknown kind '{}'", other)),
    };
    result.map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_scenario() {
        let text = r#"
# step: check-http
kind: https
target: example.com

# step: bulk-upload
kind: upload_sweep
target: example.com
port: 443
"#;
        let s = Scenario::parse(text).unwrap();
        assert_eq!(s.steps.len(), 2);
        assert_eq!(s.steps[0].kind, "https");
        assert_eq!(s.steps[1].port, Some(443));
    }
}
