//! GAP-049: authentication/captive-portal/policy-assignment CLI
//! (`auth-portal`).

use colored::*;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use fraggle_packet::network_tests::auth_portal::{
    classify_portal_response, verify_role_assignment, PortalDetectionResult, PortalStatus,
};

#[derive(clap::Args, Debug)]
pub struct AuthPortalArgs {
    /// Detection URL. Defaults to Apple's, which returns a fixed 200 body
    /// containing "Success" when unblocked.
    #[arg(long, default_value = "http://captive.apple.com/hotspot-detect.html")]
    pub detection_url: String,

    #[arg(long, default_value = "Success")]
    pub expected_body_marker: String,

    #[arg(long, default_value_t = 5)]
    pub timeout_secs: u64,

    /// Expected subnet (CIDR) for role/VLAN verification, e.g. 10.1.0.0/24.
    #[arg(long)]
    pub expected_subnet: Option<String>,

    #[arg(long)]
    pub observed_subnet: Option<String>,

    #[arg(long, default_value = "unspecified-role")]
    pub expected_role_label: String,

    #[arg(long)]
    pub json: bool,
}

fn detect_portal(url: &str, expected_marker: &str, timeout: Duration) -> PortalDetectionResult {
    // curl only: this is a GET to read the detection response, never a
    // POST, and no credential field exists anywhere in this command.
    let output = Command::new("curl")
        .args([
            "-sS",
            "-D",
            "-",
            "-o",
            "-",
            "--max-time",
            &timeout.as_secs().to_string(),
            url,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output();

    let out = match output {
        Ok(o) => o,
        Err(e) => {
            return PortalDetectionResult {
                detection_url: url.to_string(),
                status: PortalStatus::ProbeFailed {
                    detail: e.to_string(),
                },
                http_status: None,
            }
        }
    };

    let text = String::from_utf8_lossy(&out.stdout);
    let mut status_code: Option<u16> = None;
    let mut location: Option<String> = None;
    let mut body_start = 0usize;
    for (i, line) in text.lines().enumerate() {
        if i == 0 {
            if let Some(code) = line.split_whitespace().nth(1) {
                status_code = code.parse().ok();
            }
        }
        if let Some(v) = line
            .strip_prefix("Location:")
            .or_else(|| line.strip_prefix("location:"))
        {
            location = Some(v.trim().to_string());
        }
        if line.is_empty() {
            body_start = text.lines().take(i + 1).map(|l| l.len() + 1).sum();
            break;
        }
    }
    let body = if body_start < text.len() {
        &text[body_start..]
    } else {
        ""
    };

    let Some(code) = status_code else {
        return PortalDetectionResult {
            detection_url: url.to_string(),
            status: PortalStatus::ProbeFailed {
                detail: "no HTTP status line observed".to_string(),
            },
            http_status: None,
        };
    };

    let portal_status =
        classify_portal_response(code, location.as_deref(), body, Some(expected_marker));
    PortalDetectionResult {
        detection_url: url.to_string(),
        status: portal_status,
        http_status: Some(code),
    }
}

pub fn run(args: &AuthPortalArgs) {
    let timeout = Duration::from_secs(args.timeout_secs);

    let start = Instant::now();
    let portal = detect_portal(&args.detection_url, &args.expected_body_marker, timeout);
    let portal_elapsed_ms = start.elapsed().as_millis() as u64;

    let role_check = verify_role_assignment(
        &args.expected_role_label,
        args.expected_subnet.as_deref(),
        args.observed_subnet.as_deref(),
    );

    if args.json {
        let report = serde_json::json!({
            "portal_detection": portal,
            "portal_detection_elapsed_ms": portal_elapsed_ms,
            "role_check": role_check,
        });
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
        return;
    }

    println!(
        "{}",
        "== Authentication / Captive-Portal Workflow =="
            .cyan()
            .bold()
    );
    println!(
        "  {}",
        "(never automates a portal login; never requests or logs credentials)".dimmed()
    );
    println!("  portal detection ({}ms):", portal_elapsed_ms);
    match &portal.status {
        PortalStatus::NoPortalDetected => println!("    {}", "no portal detected".green()),
        PortalStatus::PortalDetected { redirect_location } => {
            println!(
                "    {}",
                "PORTAL DETECTED -- hand off to the user, do not proceed"
                    .yellow()
                    .bold()
            );
            if let Some(loc) = redirect_location {
                println!("    redirect location: {}", loc);
            }
        }
        PortalStatus::ProbeFailed { detail } => println!("    probe failed: {}", detail),
    }

    println!("  role assignment check:");
    println!("    expected: {}", role_check.expected_label);
    match role_check.matches_expected {
        Some(true) => println!("    subnet match: {}", "yes".green()),
        Some(false) => println!(
            "    subnet match: {} (expected {}, observed {})",
            "no".red(),
            role_check.expected_subnet.as_deref().unwrap_or("?"),
            role_check.observed_subnet.as_deref().unwrap_or("?")
        ),
        None => println!(
            "    subnet match: {}",
            "unavailable (expected or observed subnet not supplied)".yellow()
        ),
    }
}
