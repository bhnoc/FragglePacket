use std::net::{IpAddr, ToSocketAddrs};

pub fn resolve_hostname(host: &str) -> Result<IpAddr, String> {
    // If it's already an IP, just parse it
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ip);
    }

    // Try system resolver
    let addr = format!("{}:80", host);
    match addr.to_socket_addrs() {
        Ok(mut addrs) => {
            if let Some(addr) = addrs.next() {
                Ok(addr.ip())
            } else {
                Err("No addresses returned".into())
            }
        }
        Err(e) => Err(e.to_string()),
    }
}
