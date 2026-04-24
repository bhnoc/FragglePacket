//! SSH Data-Path Test
//!
//! Two stages:
//!  1. Banner: raw TCP connect to port 22 and read the `SSH-` prefix.
//!  2. Exec (optional): when an `SSH_USER` is supplied, run a non-interactive
//!     ssh session that echoes `SSH_OK` then attempts to push 64KB of zeros
//!     through the server side shell. If the banner works but exec fails, the
//!     signature suggests a data-path blackhole (MTU/MSS) rather than an auth
//!     or reachability problem.

use crate::framework::{
    Diagnosis, DiagnosisSeverity, NetworkTest, TestCategory, TestResult, TestStatus,
};
use std::error::Error;
use std::io::Read;
use std::net::{TcpStream, ToSocketAddrs};
use std::process::Command;
use std::time::Duration;

/// SSH banner + optional data-path echo test.
pub struct SshDataPathTest {
    port: u16,
    connect_timeout_secs: u64,
    ssh_user: Option<String>,
    run_exec_stage: bool,
    bulk_bytes: usize,
}

impl SshDataPathTest {
    pub fn new() -> Self {
        let env_user = std::env::var("SSH_USER").ok().filter(|s| !s.is_empty());
        let exec = std::env::var("SSH_TEST")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        Self {
            port: 22,
            connect_timeout_secs: 5,
            ssh_user: env_user,
            run_exec_stage: exec,
            bulk_bytes: 65536,
        }
    }

    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    pub fn with_user(mut self, user: impl Into<String>) -> Self {
        self.ssh_user = Some(user.into());
        self.run_exec_stage = true;
        self
    }

    pub fn with_exec(mut self, run_exec: bool) -> Self {
        self.run_exec_stage = run_exec;
        self
    }

    pub fn with_bulk_bytes(mut self, bytes: usize) -> Self {
        self.bulk_bytes = bytes;
        self
    }
}

impl Default for SshDataPathTest {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkTest for SshDataPathTest {
    fn name(&self) -> &str {
        "SSH Data-Path"
    }

    fn category(&self) -> TestCategory {
        TestCategory::Application
    }

    fn run(&self, target: &str) -> Result<TestResult, Box<dyn Error>> {
        let mut result = TestResult::new(
            self.name().to_string(),
            self.category(),
            target.to_string(),
        );
        result.add_metadata(
            "cli_banner",
            format!("nc -w 5 {} {} </dev/null", target, self.port),
        );
        result.add_metadata(
            "cli_exec",
            format!(
                "ssh -p {} -o BatchMode=yes -o ConnectTimeout=5 -o ServerAliveInterval=5 -o ServerAliveCountMax=1 <user>@{} 'printf SSH_OK; head -c {} /dev/zero | wc -c'",
                self.port, target, self.bulk_bytes
            ),
        );

        let banner = read_banner(target, self.port, self.connect_timeout_secs);
        let banner_ok = banner
            .as_deref()
            .map(|b| b.starts_with("SSH-"))
            .unwrap_or(false);
        result.add_metadata("ssh_banner_ok", banner_ok.to_string());
        if let Some(ref b) = banner {
            result.add_metadata("ssh_banner", b.trim().to_string());
        }

        let mut exec_ok: Option<bool> = None;
        if self.run_exec_stage {
            if let Some(user) = &self.ssh_user {
                let out = run_ssh_exec(user, target, self.port, self.bulk_bytes);
                match out {
                    Ok(text) => {
                        let ok = text.contains("SSH_OK")
                            && text.contains(&self.bulk_bytes.to_string());
                        exec_ok = Some(ok);
                        result.add_metadata("ssh_exec_output", text);
                    }
                    Err(e) => {
                        exec_ok = Some(false);
                        result.add_metadata("ssh_exec_error", e);
                    }
                }
            } else {
                result.add_metadata("ssh_exec_skipped", "SSH_USER not set".to_string());
            }
        } else {
            result.add_metadata("ssh_exec_skipped", "exec stage not enabled".to_string());
        }

        if let Some(ok) = exec_ok {
            result.add_metadata("ssh_exec_ok", ok.to_string());
        }

        match (banner_ok, exec_ok) {
            (true, Some(true)) => result.set_status(TestStatus::Success),
            (true, Some(false)) => {
                result.set_status(TestStatus::Warning);
                let diag = Diagnosis::new(
                    DiagnosisSeverity::Critical,
                    "SSH Data-Path Failure".to_string(),
                    "SSH banner was readable but the authenticated echo test failed. \
                     Classic data-path blackhole signature: small control traffic works, \
                     larger data transfers stall."
                        .to_string(),
                )
                .with_recommendation("Compare with ICMP MTU result and lower MTU accordingly")
                .with_recommendation("Enable MSS clamping on the egress router")
                .with_recommendation("Retest with a smaller bulk_bytes to find the break point");
                result.add_diagnosis(diag);
            }
            (true, None) => result.set_status(TestStatus::Warning),
            (false, _) => {
                result.set_status(TestStatus::Failed);
                let diag = Diagnosis::new(
                    DiagnosisSeverity::Error,
                    "SSH Banner Not Reached".to_string(),
                    "Could not read an SSH banner from the target port. The server may not \
                     be running SSH, the port may be firewalled, or TCP is not reachable."
                        .to_string(),
                )
                .with_recommendation("Verify sshd is running and the port matches")
                .with_recommendation("Check firewall rules on port 22");
                result.add_diagnosis(diag);
            }
        }

        Ok(result)
    }
}

fn read_banner(target: &str, port: u16, timeout_secs: u64) -> Option<String> {
    let addr_str = format!("{}:{}", target, port);
    let addr = addr_str.to_socket_addrs().ok()?.next()?;
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(timeout_secs)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(timeout_secs)))
        .ok()?;
    let mut buf = [0u8; 256];
    match stream.read(&mut buf) {
        Ok(n) if n > 0 => Some(String::from_utf8_lossy(&buf[..n]).to_string()),
        _ => None,
    }
}

fn run_ssh_exec(
    user: &str,
    target: &str,
    port: u16,
    bulk_bytes: usize,
) -> Result<String, String> {
    let remote_cmd = format!(
        "printf 'SSH_OK\\n'; head -c {} /dev/zero | wc -c",
        bulk_bytes
    );
    let output = Command::new("ssh")
        .arg("-p")
        .arg(port.to_string())
        .arg("-o")
        .arg("BatchMode=yes")
        .arg("-o")
        .arg("ConnectTimeout=5")
        .arg("-o")
        .arg("ServerAliveInterval=5")
        .arg("-o")
        .arg("ServerAliveCountMax=1")
        .arg("-o")
        .arg("StrictHostKeyChecking=accept-new")
        .arg(format!("{}@{}", user, target))
        .arg(remote_cmd)
        .output()
        .map_err(|e| format!("spawn ssh: {}", e))?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    if !output.status.success() && stdout.is_empty() {
        return Err(format!("ssh exit {}: {}", output.status, stderr.trim()));
    }
    Ok(format!("{}\n{}", stdout.trim(), stderr.trim()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_port_22() {
        let t = SshDataPathTest::new();
        assert_eq!(t.port, 22);
    }

    #[test]
    fn with_user_enables_exec() {
        let t = SshDataPathTest::new().with_user("root");
        assert!(t.run_exec_stage);
        assert_eq!(t.ssh_user.as_deref(), Some("root"));
    }
}
