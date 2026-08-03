use std::process::{Command, Stdio};

/// Test DNS with EDNS0 buffer size to probe UDP MTU
pub fn probe_dns_edns(server: &str, bufsize: usize, _timeout_ms: u64) -> bool {
    // Use dig command if available
    let output = Command::new("dig")
        .args([
            &format!("+bufsize={}", bufsize),
            "+norecurse",
            "@",
            server,
            "google.com",
            "A",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output();

    match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            // Check if we got a response (not truncated)
            !stdout.contains("truncated") && stdout.contains("ANSWER")
        }
        Err(_) => false,
    }
}
