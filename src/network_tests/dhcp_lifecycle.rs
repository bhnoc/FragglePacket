//! GAP-048: DHCP, address-lifecycle, and pool-capacity test.
//!
//! Field insight the whole design turns on: a client that already holds a
//! lease looks perfectly healthy while new arrivals to an exhausted or
//! slow pool fail outright. The one diagnostic that actually exercises
//! that failure mode -- requesting a brand new lease -- is also the one
//! that can drop the operator's own connectivity and consume a pool
//! address on a network that may already be short of them. So this module
//! draws the same authorization line `nat-capacity` draws: reading the
//! CURRENT lease (`ipconfig getpacket`/`getoption`, both unprivileged) is
//! the default and touches nothing; requesting a FRESH one is gated behind
//! `require_authorization`, reusing that exact function rather than a
//! second copy of the same rule.
//!
//! Pool headroom cannot be read from a client -- there is no unprivileged
//! or privileged macOS API that reports a DHCP server's free-address
//! count. It is ingested from operator-supplied telemetry only, and a
//! conclusion is withheld, not guessed from "I got a lease so there must
//! be room," when that telemetry is absent.
//!
//! The MAC address (`chaddr`) appears in raw `ipconfig getpacket` output;
//! this module never reads or forwards it into any parsed field, matching
//! the GAP-018 allowlist discipline already applied to Wi-Fi identifiers.

use serde::{Deserialize, Serialize};
use std::process::Command;
use std::time::Duration;

pub use crate::network_tests::nat_capacity::require_authorization_for;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DhcpMessageType {
    Offer,
    Ack,
    Nak,
    Unknown,
}

/// Fields read from a live `ipconfig getpacket <iface>` dump. Deliberately
/// excludes `chaddr` (MAC), `sname`, and `file` -- those carry identifying
/// or vendor-specific data this module has no use for and GAP-018 forbids
/// persisting by default.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DhcpLease {
    pub message_type: Option<DhcpMessageType>,
    pub lease_seconds: Option<u32>,
    pub server_identifier: Option<String>,
    pub router: Option<String>,
    pub domain_name_servers: Vec<String>,
    /// `domain_name` (e.g. an internal search domain) is retained because
    /// GAP-018's allowlist is about identifiers (SSID/BSSID/MAC/public IP),
    /// not DHCP-supplied network configuration -- but it is a candid
    /// naming risk on a real deployment, so callers rendering this for an
    /// attendee-facing report should treat it the same way.
    pub domain_name: Option<String>,
}

fn parse_ip_list(value: &str) -> Vec<String> {
    value
        .trim_matches(|c: char| c == '{' || c == '}')
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Parses `ipconfig getpacket` text. Kept separate from the live-command
/// path so it is unit-testable against a captured fixture.
pub fn parse_getpacket(text: &str) -> DhcpLease {
    let mut lease = DhcpLease::default();

    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("dhcp_message_type") {
            if let Some(v) = rest.split(':').nth(1) {
                let v = v.trim();
                lease.message_type = Some(if v.starts_with("OFFER") {
                    DhcpMessageType::Offer
                } else if v.starts_with("ACK") {
                    DhcpMessageType::Ack
                } else if v.starts_with("NAK") {
                    DhcpMessageType::Nak
                } else {
                    DhcpMessageType::Unknown
                });
            }
        } else if let Some(rest) = line.strip_prefix("lease_time") {
            if let Some(v) = rest.split(':').nth(1) {
                let v = v.trim();
                let hex = v.split_whitespace().last().unwrap_or("");
                lease.lease_seconds = hex.strip_prefix("0x").and_then(|h| u32::from_str_radix(h, 16).ok());
            }
        } else if let Some(rest) = line.strip_prefix("server_identifier") {
            if let Some(v) = rest.split(':').nth(1) {
                lease.server_identifier = Some(v.trim().to_string());
            }
        } else if let Some(rest) = line.strip_prefix("router") {
            if let Some(v) = rest.split(':').nth(1) {
                lease.router = parse_ip_list(v.trim()).into_iter().next();
            }
        } else if let Some(rest) = line.strip_prefix("domain_name_server") {
            if let Some(v) = rest.split(':').nth(1) {
                lease.domain_name_servers = parse_ip_list(v.trim());
            }
        } else if let Some(rest) = line.strip_prefix("domain_name ") {
            if let Some(v) = rest.split(':').nth(1) {
                let v = v.trim();
                if !v.is_empty() {
                    lease.domain_name = Some(v.to_string());
                }
            }
        }
    }

    lease
}

#[derive(Debug, thiserror::Error)]
pub enum DhcpReadError {
    #[error("failed to run ipconfig: {0}")]
    CommandFailed(String),
    #[error("no DHCP lease found on interface {0} (not DHCP-configured, or no lease currently held)")]
    NoLease(String),
}

/// Reads the CURRENT lease. Non-disruptive: `ipconfig getpacket` returns
/// cached state the OS already holds and never sends a packet.
pub fn read_existing_lease(interface: &str) -> Result<DhcpLease, DhcpReadError> {
    let out = Command::new("ipconfig")
        .args(["getpacket", interface])
        .output()
        .map_err(|e| DhcpReadError::CommandFailed(e.to_string()))?;
    let text = String::from_utf8_lossy(&out.stdout);
    if !out.status.success() || text.trim().is_empty() {
        return Err(DhcpReadError::NoLease(interface.to_string()));
    }
    Ok(parse_getpacket(&text))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FreshLeaseTiming {
    pub discover_to_address_ms: u64,
    pub lease: DhcpLease,
}

/// Disruptive: releases the interface's current lease and requests a new
/// one (`ipconfig set <iface> DHCP` after `ipconfig set <iface> NONE`, both
/// requiring no root but visibly interrupting connectivity on that
/// interface). Gated the same way `nat-capacity`'s session-rate probe is
/// gated -- there is no code path here that runs without a real
/// authorization statement.
pub fn request_fresh_lease(
    interface: &str,
    authorization: Option<&str>,
    timeout: Duration,
) -> Result<FreshLeaseTiming, String> {
    require_authorization_for(
        authorization,
        "release this host's lease and consume a fresh address from the DHCP pool",
    )?;

    let start = std::time::Instant::now();
    let release = Command::new("ipconfig")
        .args(["set", interface, "NONE"])
        .output()
        .map_err(|e| format!("failed to release lease: {e}"))?;
    if !release.status.success() {
        return Err(format!("ipconfig set {interface} NONE failed: {}", String::from_utf8_lossy(&release.stderr)));
    }

    let renew = Command::new("ipconfig")
        .args(["set", interface, "DHCP"])
        .output()
        .map_err(|e| format!("failed to request new lease: {e}"))?;
    if !renew.status.success() {
        return Err(format!("ipconfig set {interface} DHCP failed: {}", String::from_utf8_lossy(&renew.stderr)));
    }

    let deadline = std::time::Instant::now() + timeout;
    loop {
        if let Ok(lease) = read_existing_lease(interface) {
            if lease.message_type == Some(DhcpMessageType::Ack) {
                return Ok(FreshLeaseTiming { discover_to_address_ms: start.elapsed().as_millis() as u64, lease });
            }
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!("no ACK observed on {interface} within {:?}", timeout));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Operator-supplied pool telemetry -- never inferred from a successful
/// client-side lease, since a client obtaining a lease from a large pool
/// proves nothing about how much headroom remains.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PoolTelemetry {
    pub scope_label: Option<String>,
    pub addresses_total: Option<u32>,
    pub addresses_in_use: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PoolHeadroomVerdict {
    Headroom { free: u32, total: u32 },
    Unavailable { reason: String },
}

pub fn evaluate_pool_headroom(telemetry: &Option<PoolTelemetry>) -> PoolHeadroomVerdict {
    let Some(t) = telemetry else {
        return PoolHeadroomVerdict::Unavailable {
            reason: "no pool telemetry supplied; headroom cannot be inferred from a single client's lease".to_string(),
        };
    };
    match (t.addresses_total, t.addresses_in_use) {
        (Some(total), Some(in_use)) => PoolHeadroomVerdict::Headroom { free: total.saturating_sub(in_use), total },
        _ => PoolHeadroomVerdict::Unavailable {
            reason: "pool telemetry supplied but missing addresses_total/addresses_in_use".to_string(),
        },
    }
}

/// Renewal/rebind observation: samples the current lease's remaining time
/// across a short window (no active renewal is forced -- this only reads
/// what the OS already reports) to detect whether the reported lease
/// duration is internally consistent, e.g. a lease that never counts down.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseCountdownSample {
    pub sampled_lease_seconds: Vec<u32>,
}

impl LeaseCountdownSample {
    /// `None` when fewer than two samples exist. A constant reported value
    /// across samples means the OS is not counting down the lease (or the
    /// samples were too close together to observe a change), not that the
    /// lease is somehow permanent.
    pub fn appears_counting_down(&self) -> Option<bool> {
        if self.sampled_lease_seconds.len() < 2 {
            return None;
        }
        Some(self.sampled_lease_seconds.windows(2).any(|w| w[0] != w[1]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = "op = BOOTREPLY\n\
htype = 1\n\
hlen = 6\n\
hops = 0\n\
xid = 0x6ffec45c\n\
secs = 0\n\
ciaddr = 0.0.0.0\n\
yiaddr = 10.10.250.55\n\
siaddr = 0.0.0.0\n\
giaddr = 0.0.0.0\n\
chaddr = 20:7b:d2:72:35:80\n\
sname = \n\
file = \n\
options:\n\
Options count is 8\n\
dhcp_message_type (uint8): ACK 0x5\n\
lease_time (uint32): 0x3840\n\
server_identifier (ip): 10.10.250.1\n\
subnet_mask (ip): 255.255.255.0\n\
router (ip_mult): {10.10.250.1}\n\
domain_name (string): internal.example.com\n\
domain_name_server (ip_mult): {192.0.2.53, 192.0.2.54, 208.67.222.222}\n\
end (none):\n";

    #[test]
    fn parses_real_capture_fields() {
        let lease = parse_getpacket(FIXTURE);
        assert_eq!(lease.message_type, Some(DhcpMessageType::Ack));
        assert_eq!(lease.lease_seconds, Some(0x3840));
        assert_eq!(lease.server_identifier, Some("10.10.250.1".to_string()));
        assert_eq!(lease.router, Some("10.10.250.1".to_string()));
        assert_eq!(
            lease.domain_name_servers,
            vec!["192.0.2.53".to_string(), "192.0.2.54".to_string(), "208.67.222.222".to_string()]
        );
        assert_eq!(lease.domain_name, Some("internal.example.com".to_string()));
    }

    #[test]
    fn never_surfaces_the_mac_address() {
        let lease = parse_getpacket(FIXTURE);
        let debug = format!("{lease:?}");
        assert!(FIXTURE.contains("20:7b:d2:72:35:80"));
        assert!(!debug.contains("20:7b:d2:72:35:80"));
    }

    #[test]
    fn fresh_lease_refuses_without_authorization() {
        let result = request_fresh_lease("en0", None, Duration::from_millis(10));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("--authorized"));
    }

    #[test]
    fn fresh_lease_refuses_with_empty_authorization() {
        let result = request_fresh_lease("en0", Some(""), Duration::from_millis(10));
        assert!(result.is_err());
    }

    #[test]
    fn pool_headroom_unavailable_with_no_telemetry() {
        assert!(matches!(evaluate_pool_headroom(&None), PoolHeadroomVerdict::Unavailable { .. }));
    }

    #[test]
    fn pool_headroom_computed_from_full_telemetry() {
        let t = PoolTelemetry {
            scope_label: Some("vlan-100".to_string()),
            addresses_total: Some(254),
            addresses_in_use: Some(240),
        };
        assert_eq!(
            evaluate_pool_headroom(&Some(t)),
            PoolHeadroomVerdict::Headroom { free: 14, total: 254 }
        );
    }

    #[test]
    fn pool_headroom_unavailable_with_partial_telemetry() {
        let t = PoolTelemetry { scope_label: Some("vlan-100".to_string()), ..Default::default() };
        assert!(matches!(evaluate_pool_headroom(&Some(t)), PoolHeadroomVerdict::Unavailable { .. }));
    }

    #[test]
    fn single_sample_countdown_is_unknown_not_false() {
        let s = LeaseCountdownSample { sampled_lease_seconds: vec![3600] };
        assert_eq!(s.appears_counting_down(), None);
    }

    #[test]
    fn changing_samples_show_countdown() {
        let s = LeaseCountdownSample { sampled_lease_seconds: vec![3600, 3595] };
        assert_eq!(s.appears_counting_down(), Some(true));
    }

    #[test]
    fn nak_is_distinguished_from_ack() {
        let text = FIXTURE.replace("ACK 0x5", "NAK 0x6");
        let lease = parse_getpacket(&text);
        assert_eq!(lease.message_type, Some(DhcpMessageType::Nak));
    }
}
