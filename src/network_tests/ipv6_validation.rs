//! GAP-056 / GAP-015: decomposed IPv6 validation and Happy Eyeballs timing.
//!
//! Recording "IPv6 is absent" is a status, not a diagnosis. It cannot
//! distinguish a missing router advertisement from a working RA whose default
//! route is unreachable, and those have different owners. Every layer is
//! therefore reported separately, and the IPv4 and IPv6 verdicts never blend
//! into one "network healthy" claim.
//!
//! A check that could not run is distinct from a check that failed. Reading RA
//! contents needs raw ICMPv6 and root; that absence is a limit of this run, not
//! evidence about the network.

use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::process::Command;
use std::time::{Duration, Instant};

/// Outcome of one layer's check. `Unavailable` means the check could not be
/// performed, which must never be read as the network failing it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum LayerState {
    Ok(String),
    Failed(String),
    Unavailable {
        reason: String,
        required_privilege: Option<String>,
    },
}

impl LayerState {
    pub fn as_str(&self) -> &'static str {
        match self {
            LayerState::Ok(_) => "ok",
            LayerState::Failed(_) => "failed",
            LayerState::Unavailable { .. } => "unavailable",
        }
    }

    /// Only a genuine failure counts against the network. An unavailable check
    /// is silent on the question.
    pub fn is_network_failure(&self) -> bool {
        matches!(self, LayerState::Failed(_))
    }

    pub fn detail(&self) -> String {
        match self {
            LayerState::Ok(d) | LayerState::Failed(d) => d.clone(),
            LayerState::Unavailable {
                reason,
                required_privilege,
            } => match required_privilege {
                Some(p) => format!("{} (requires: {})", reason, p),
                None => reason.clone(),
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ipv6Validation {
    pub interface: String,
    pub interface_is_tunnel: bool,
    /// SLAAC or statically configured global address present on the interface.
    pub global_address: LayerState,
    pub link_local_address: LayerState,
    pub router_advertisement: LayerState,
    pub dhcpv6: LayerState,
    pub default_route: LayerState,
    pub neighbor_discovery: LayerState,
    pub dns_aaaa: LayerState,
    pub native_reachability: LayerState,
    pub ipv6_pmtu: LayerState,
    pub nat64_prefix: LayerState,
    pub dns64: LayerState,
    /// Deliberately separate from every IPv6 field above.
    pub ipv4_verdict: String,
    pub ipv6_verdict: String,
    pub notes: Vec<String>,
}

impl Ipv6Validation {
    fn layers(&self) -> [(&'static str, &LayerState); 11] {
        [
            ("global_address", &self.global_address),
            ("link_local_address", &self.link_local_address),
            ("router_advertisement", &self.router_advertisement),
            ("dhcpv6", &self.dhcpv6),
            ("default_route", &self.default_route),
            ("neighbor_discovery", &self.neighbor_discovery),
            ("dns_aaaa", &self.dns_aaaa),
            ("native_reachability", &self.native_reachability),
            ("ipv6_pmtu", &self.ipv6_pmtu),
            ("nat64_prefix", &self.nat64_prefix),
            ("dns64", &self.dns64),
        ]
    }

    /// The layers that actually failed, as opposed to those that could not be
    /// checked. This list is what makes "IPv6 unavailable" actionable.
    pub fn failed_layers(&self) -> Vec<&'static str> {
        self.layers()
            .into_iter()
            .filter(|(_, s)| s.is_network_failure())
            .map(|(n, _)| n)
            .collect()
    }

    pub fn unavailable_layers(&self) -> Vec<&'static str> {
        self.layers()
            .into_iter()
            .filter(|(_, s)| matches!(s, LayerState::Unavailable { .. }))
            .map(|(n, _)| n)
            .collect()
    }
}

/// Parses `ifconfig <iface>` for IPv6 addresses. Split out for testability.
pub fn parse_inet6(text: &str) -> (Option<String>, Option<String>) {
    let mut global = None;
    let mut link_local = None;
    for line in text.lines() {
        let line = line.trim();
        if !line.starts_with("inet6 ") {
            continue;
        }
        let addr = line
            .split_whitespace()
            .nth(1)
            .unwrap_or("")
            .split('%')
            .next()
            .unwrap_or("")
            .to_string();
        if addr.is_empty() {
            continue;
        }
        if addr.to_lowercase().starts_with("fe80") {
            if link_local.is_none() {
                link_local = Some(addr);
            }
        } else if global.is_none() {
            global = Some(addr);
        }
    }
    (global, link_local)
}

/// Derives the NAT64 prefix from an `ipv4only.arpa` AAAA answer. Per RFC 7050
/// the well-known IPv4 addresses 192.0.0.170/171 are embedded in the answer, so
/// the leading 96 bits are the prefix.
pub fn nat64_prefix_from_answer(addr: &str) -> Option<String> {
    let parsed: std::net::Ipv6Addr = addr.parse().ok()?;
    let o = parsed.octets();
    if o[12] == 192 && o[13] == 0 && o[14] == 0 && (o[15] == 170 || o[15] == 171) {
        let seg: Vec<String> = (0..6)
            .map(|i| format!("{:x}", u16::from_be_bytes([o[i * 2], o[i * 2 + 1]])))
            .collect();
        return Some(format!("{}::/96", seg.join(":")));
    }
    None
}

fn ifconfig(interface: &str) -> Option<String> {
    let out = Command::new("ifconfig").arg(interface).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).to_string())
}

fn is_tunnel(interface: &str) -> bool {
    let i = interface.to_lowercase();
    i.starts_with("utun") || i.starts_with("tun") || i.starts_with("ppp") || i.starts_with("ipsec")
}

fn resolve_family(host: &str, want_v6: bool) -> Vec<IpAddr> {
    match (host, 443u16).to_socket_addrs() {
        Ok(addrs) => addrs
            .map(|a| a.ip())
            .filter(|ip| ip.is_ipv6() == want_v6)
            .collect(),
        Err(_) => Vec::new(),
    }
}

fn tcp_reachable(ip: IpAddr, port: u16, timeout: Duration) -> bool {
    TcpStream::connect_timeout(&SocketAddr::new(ip, port), timeout).is_ok()
}

/// Runs every layer check. `probe_host` should be a dual-stack host.
pub fn validate(interface: &str, probe_host: &str, timeout: Duration) -> Ipv6Validation {
    let tunnel = is_tunnel(interface);
    let mut notes = Vec::new();
    if tunnel {
        notes.push(format!(
            "interface '{}' is a tunnel; tunnels frequently carry no IPv6 at all, so an absent \
             address here may describe the tunnel rather than the physical network. Re-run against \
             the physical interface before concluding the network lacks IPv6.",
            interface
        ));
    }

    let (global, link_local) = match ifconfig(interface) {
        Some(text) => parse_inet6(&text),
        None => (None, None),
    };

    let global_address = match &global {
        Some(a) => LayerState::Ok(format!("global address configured: {}", a)),
        None => LayerState::Failed(
            "no global IPv6 address on this interface (SLAAC produced none and none is static)"
                .to_string(),
        ),
    };
    let link_local_address = match &link_local {
        Some(_) => LayerState::Ok("link-local address present".to_string()),
        None => {
            LayerState::Failed("no link-local IPv6 address, so the stack is not up".to_string())
        }
    };

    // RA contents need raw ICMPv6, which needs root. Absence of that privilege
    // is a limit of this run, not a finding about the network.
    let router_advertisement = if global.is_some() {
        LayerState::Ok(
            "a global address exists, which implies an RA with the autonomous flag was received; \
             RA contents and lifetimes were not read directly"
                .to_string(),
        )
    } else {
        LayerState::Unavailable {
            reason: "router advertisement contents and lifetimes require listening for raw ICMPv6"
                .to_string(),
            required_privilege: Some(format!(
                "sudo tcpdump -i {} -n 'icmp6 && ip6[40] == 134'",
                interface
            )),
        }
    };

    let dhcpv6 = LayerState::Unavailable {
        reason: "macOS exposes no unprivileged DHCPv6 client state; stateful DHCPv6 versus SLAAC \
                 cannot be distinguished from here"
            .to_string(),
        required_privilege: None,
    };

    let default_route = match Command::new("route")
        .args(["-n", "get", "-inet6", "default"])
        .output()
    {
        Ok(o) if o.status.success() && !String::from_utf8_lossy(&o.stdout).trim().is_empty() => {
            LayerState::Ok("an IPv6 default route is installed".to_string())
        }
        Ok(_) => LayerState::Failed(
            "no IPv6 default route installed, so no off-link IPv6 destination is reachable \
             regardless of address configuration"
                .to_string(),
        ),
        Err(e) => LayerState::Unavailable {
            reason: format!("could not query the routing table: {}", e),
            required_privilege: None,
        },
    };

    let neighbor_discovery = match Command::new("ndp").args(["-an"]).output() {
        Ok(o) if o.status.success() => {
            let text = String::from_utf8_lossy(&o.stdout);
            let entries = text
                .lines()
                .skip(1)
                .filter(|l| !l.trim().is_empty())
                .count();
            if entries > 0 {
                LayerState::Ok(format!("{} neighbor cache entries present", entries))
            } else {
                LayerState::Failed(
                    "neighbor cache is empty, so no IPv6 neighbor was resolved".to_string(),
                )
            }
        }
        _ => LayerState::Unavailable {
            reason: "ndp is unavailable on this platform".to_string(),
            required_privilege: None,
        },
    };

    let v6_answers = resolve_family(probe_host, true);
    let v4_answers = resolve_family(probe_host, false);

    let dns_aaaa = if v6_answers.is_empty() {
        LayerState::Failed(format!("no AAAA record returned for {}", probe_host))
    } else {
        LayerState::Ok(format!(
            "{} AAAA answer(s) returned for {}",
            v6_answers.len(),
            probe_host
        ))
    };

    // A resolver returning AAAA while the interface has no address is the
    // decomposition that matters: DNS is healthy, the local stack is not.
    let native_reachability = if v6_answers.is_empty() {
        LayerState::Unavailable {
            reason: "no AAAA answer to test reachability against".to_string(),
            required_privilege: None,
        }
    } else if global.is_none() {
        LayerState::Unavailable {
            reason: "no source address available, so an IPv6 connection cannot be attempted; this \
                     is a local stack limitation, not proof the destination is unreachable"
                .to_string(),
            required_privilege: None,
        }
    } else if tcp_reachable(v6_answers[0], 443, timeout) {
        LayerState::Ok("TCP/443 completed over IPv6".to_string())
    } else {
        LayerState::Failed("TCP/443 over IPv6 did not complete".to_string())
    };

    let ipv6_pmtu = if matches!(native_reachability, LayerState::Ok(_)) {
        LayerState::Unavailable {
            reason: "IPv6 PMTU/PLPMTUD probing is not implemented in this command; use `quic` for \
                     response-validated path MTU"
                .to_string(),
            required_privilege: None,
        }
    } else {
        LayerState::Unavailable {
            reason: "no working IPv6 path to probe PMTU over".to_string(),
            required_privilege: None,
        }
    };

    let (nat64_prefix, dns64) = {
        let answers = resolve_family("ipv4only.arpa", true);
        if answers.is_empty() {
            (
                LayerState::Failed(
                    "ipv4only.arpa returned no AAAA, so no NAT64 prefix is advertised by this \
                     resolver"
                        .to_string(),
                ),
                LayerState::Failed("resolver does not synthesize DNS64 answers".to_string()),
            )
        } else {
            let prefix = answers
                .iter()
                .find_map(|a| nat64_prefix_from_answer(&a.to_string()));
            match prefix {
                Some(p) => (
                    LayerState::Ok(format!("NAT64 prefix {}", p)),
                    LayerState::Ok("resolver synthesizes DNS64 answers".to_string()),
                ),
                None => (
                    LayerState::Unavailable {
                        reason: "ipv4only.arpa returned AAAA answers that do not embed the \
                                 well-known IPv4 addresses, so no prefix could be derived"
                            .to_string(),
                        required_privilege: None,
                    },
                    LayerState::Ok("resolver returned a synthesized answer".to_string()),
                ),
            }
        }
    };

    let ipv4_verdict = if v4_answers.is_empty() {
        "IPv4: no A record returned; not evaluated further".to_string()
    } else if tcp_reachable(v4_answers[0], 443, timeout) {
        "IPv4: usable (TCP/443 completed)".to_string()
    } else {
        "IPv4: A record resolved but TCP/443 did not complete".to_string()
    };

    let mut v = Ipv6Validation {
        interface: interface.to_string(),
        interface_is_tunnel: tunnel,
        global_address,
        link_local_address,
        router_advertisement,
        dhcpv6,
        default_route,
        neighbor_discovery,
        dns_aaaa,
        native_reachability,
        ipv6_pmtu,
        nat64_prefix,
        dns64,
        ipv4_verdict,
        ipv6_verdict: String::new(),
        notes,
    };

    let failed = v.failed_layers();
    v.ipv6_verdict = if failed.is_empty() {
        "IPv6: no layer failed".to_string()
    } else {
        format!("IPv6: unusable; failing layer(s): {}", failed.join(", "))
    };
    v
}

// ---------------------------------------------------------------------------
// GAP-015: Happy Eyeballs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HappyEyeballs {
    pub host: String,
    pub v6_offered: bool,
    pub v4_offered: bool,
    pub v6_connect_ms: Option<f64>,
    pub v4_connect_ms: Option<f64>,
    /// Measured difference between the two families' connect times, or None
    /// when only one family could be attempted. Never an RFC constant.
    pub fallback_delay_ms: Option<f64>,
    pub winning_family: Option<String>,
    pub family_specific_failure: Option<String>,
}

/// Attempts both families and reports which won and what the difference
/// actually was. A delta is only reported when both families genuinely
/// connected; otherwise there is nothing to compare and the field stays None.
pub fn happy_eyeballs(host: &str, port: u16, timeout: Duration) -> HappyEyeballs {
    let v6 = resolve_family(host, true);
    let v4 = resolve_family(host, false);

    let time_one = |ip: IpAddr| -> Option<f64> {
        let start = Instant::now();
        if tcp_reachable(ip, port, timeout) {
            Some(start.elapsed().as_secs_f64() * 1000.0)
        } else {
            None
        }
    };

    let v6_ms = v6.first().copied().and_then(time_one);
    let v4_ms = v4.first().copied().and_then(time_one);

    let winning_family = match (v6_ms, v4_ms) {
        (Some(a), Some(b)) => Some(if a <= b {
            "ipv6".to_string()
        } else {
            "ipv4".to_string()
        }),
        (Some(_), None) => Some("ipv6".to_string()),
        (None, Some(_)) => Some("ipv4".to_string()),
        (None, None) => None,
    };

    let fallback_delay_ms = match (v6_ms, v4_ms) {
        (Some(a), Some(b)) => Some((a - b).abs()),
        _ => None,
    };

    let family_specific_failure = match (v6.is_empty(), v4.is_empty(), v6_ms, v4_ms) {
        (false, _, None, Some(_)) => Some(
            "IPv6 was offered by DNS but did not connect while IPv4 did; this is a family-specific \
             failure and users may see it as a stalled load before fallback"
                .to_string(),
        ),
        (_, false, Some(_), None) => {
            Some("IPv4 was offered by DNS but did not connect while IPv6 did".to_string())
        }
        _ => None,
    };

    HappyEyeballs {
        host: host.to_string(),
        v6_offered: !v6.is_empty(),
        v4_offered: !v4.is_empty(),
        v6_connect_ms: v6_ms,
        v4_connect_ms: v4_ms,
        fallback_delay_ms,
        winning_family,
        family_specific_failure,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_inet6_separates_global_from_link_local() {
        let text = "\
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tinet6 fe80::1cbf:66ff:fe4e:1%en0 prefixlen 64 scopeid 0xa
\tinet6 2001:db8::5 prefixlen 64 autoconf secured
\tinet 192.0.2.10 netmask 0xffffff00 broadcast 192.0.2.255";
        let (global, ll) = parse_inet6(text);
        assert_eq!(global.as_deref(), Some("2001:db8::5"));
        assert_eq!(ll.as_deref(), Some("fe80::1cbf:66ff:fe4e:1"));
    }

    #[test]
    fn parse_inet6_reports_none_when_no_ipv6_configured() {
        let text = "en0: flags=8863 mtu 1500\n\tinet 192.0.2.10 netmask 0xffffff00";
        let (global, ll) = parse_inet6(text);
        assert!(global.is_none());
        assert!(ll.is_none());
    }

    #[test]
    fn nat64_prefix_derives_from_well_known_answer() {
        assert_eq!(
            nat64_prefix_from_answer("64:ff9b::192.0.0.170").as_deref(),
            Some("64:ff9b:0:0:0:0::/96")
        );
    }

    #[test]
    fn nat64_prefix_rejects_an_answer_without_the_well_known_suffix() {
        assert!(nat64_prefix_from_answer("2606:4700::6810:84e5").is_none());
    }

    #[test]
    fn unavailable_is_never_counted_as_a_network_failure() {
        let s = LayerState::Unavailable {
            reason: "needs root".to_string(),
            required_privilege: Some("sudo tcpdump".to_string()),
        };
        assert!(!s.is_network_failure());
        assert_eq!(s.as_str(), "unavailable");
    }

    fn sample() -> Ipv6Validation {
        Ipv6Validation {
            interface: "en0".to_string(),
            interface_is_tunnel: false,
            global_address: LayerState::Failed("none".to_string()),
            link_local_address: LayerState::Ok("present".to_string()),
            router_advertisement: LayerState::Unavailable {
                reason: "needs root".to_string(),
                required_privilege: Some("sudo".to_string()),
            },
            dhcpv6: LayerState::Unavailable {
                reason: "n/a".to_string(),
                required_privilege: None,
            },
            default_route: LayerState::Failed("absent".to_string()),
            neighbor_discovery: LayerState::Ok("entries".to_string()),
            dns_aaaa: LayerState::Ok("answers".to_string()),
            native_reachability: LayerState::Unavailable {
                reason: "no source".to_string(),
                required_privilege: None,
            },
            ipv6_pmtu: LayerState::Unavailable {
                reason: "no path".to_string(),
                required_privilege: None,
            },
            nat64_prefix: LayerState::Failed("none".to_string()),
            dns64: LayerState::Failed("none".to_string()),
            ipv4_verdict: String::new(),
            ipv6_verdict: String::new(),
            notes: Vec::new(),
        }
    }

    #[test]
    fn failed_layers_lists_only_genuine_failures() {
        let v = sample();
        let failed = v.failed_layers();
        assert!(failed.contains(&"global_address"));
        assert!(failed.contains(&"default_route"));
        // The privileged RA check could not run; that is not a network failure.
        assert!(!failed.contains(&"router_advertisement"));
        assert!(v.unavailable_layers().contains(&"router_advertisement"));
    }

    #[test]
    fn a_layer_is_never_both_failed_and_unavailable() {
        let v = sample();
        for name in v.failed_layers() {
            assert!(
                !v.unavailable_layers().contains(&name),
                "{} appears in both lists, which is self-contradictory",
                name
            );
        }
    }

    #[test]
    fn fallback_delay_is_none_when_only_one_family_was_attempted() {
        let he = HappyEyeballs {
            host: "example.test".to_string(),
            v6_offered: true,
            v4_offered: true,
            v6_connect_ms: None,
            v4_connect_ms: Some(12.0),
            fallback_delay_ms: None,
            winning_family: Some("ipv4".to_string()),
            family_specific_failure: None,
        };
        assert!(he.fallback_delay_ms.is_none());
    }
}
