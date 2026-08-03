//! Default-route interface detection.
//!
//! On this class of machine the default route is frequently a VPN tunnel
//! (`utunN`), not the physical interface under test. Anything measuring "the
//! network" must bind explicitly and warn when the default route is a
//! tunnel, or it silently measures the tunnel instead.

pub struct RouteInfo {
    pub interface: String,
    pub is_tunnel: bool,
}

pub fn is_tunnel_interface(name: &str) -> bool {
    name.starts_with("utun")
        || name.starts_with("tun")
        || name.starts_with("ppp")
        || name.starts_with("ipsec")
}

/// Parses `route -n get default` output for the `interface:` line.
pub fn parse_default_route(text: &str) -> Option<RouteInfo> {
    for line in text.lines() {
        let line = line.trim();
        if let Some(v) = line.strip_prefix("interface:") {
            let iface = v.trim().to_string();
            return Some(RouteInfo {
                is_tunnel: is_tunnel_interface(&iface),
                interface: iface,
            });
        }
    }
    None
}

pub fn detect_live() -> Result<RouteInfo, String> {
    let out = std::process::Command::new("route")
        .args(["-n", "get", "default"])
        .output()
        .map_err(|e| format!("failed to run route: {e}"))?;
    if !out.status.success() {
        return Err(format!("route exited with {:?}", out.status.code()));
    }
    parse_default_route(&String::from_utf8_lossy(&out.stdout))
        .ok_or_else(|| "no interface line in route output".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TUNNEL_ROUTE: &str =
        "   route to: default\ndestination: default\n       mask: default\n  interface: utun6\n";
    const WIFI_ROUTE: &str =
        "   route to: default\ndestination: default\n       mask: default\n  interface: en0\n";

    #[test]
    fn detects_tunnel_default_route() {
        let info = parse_default_route(TUNNEL_ROUTE).unwrap();
        assert_eq!(info.interface, "utun6");
        assert!(info.is_tunnel);
    }

    #[test]
    fn detects_physical_default_route() {
        let info = parse_default_route(WIFI_ROUTE).unwrap();
        assert_eq!(info.interface, "en0");
        assert!(!info.is_tunnel);
    }
}
