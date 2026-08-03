//! Interface counter snapshots (GAP-027/GAP-031 evidence retention).

use serde::{Deserialize, Serialize};
use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct InterfaceCounters {
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
}

impl InterfaceCounters {
    pub fn zero() -> Self {
        Self {
            rx_packets: 0,
            tx_packets: 0,
            rx_bytes: 0,
            tx_bytes: 0,
            rx_errors: 0,
            tx_errors: 0,
        }
    }

    /// A counter set is unusable as evidence if it went backwards, which on
    /// this platform means a wrap or an interface reset mid-phase rather than
    /// real traffic (see GAP-043's frozen/reset-counter concern, shared here).
    pub fn usable_delta_from(&self, before: &InterfaceCounters) -> bool {
        self.rx_packets >= before.rx_packets
            && self.tx_packets >= before.tx_packets
            && self.rx_bytes >= before.rx_bytes
            && self.tx_bytes >= before.tx_bytes
    }
}

pub fn snapshot_live(interface: &str) -> Result<InterfaceCounters, String> {
    let out = Command::new("netstat")
        .args(["-I", interface, "-b"])
        .output()
        .map_err(|e| format!("failed to run netstat: {e}"))?;
    if !out.status.success() {
        return Err(format!("netstat exited with {:?}", out.status.code()));
    }
    parse_netstat_ib(&String::from_utf8_lossy(&out.stdout), interface)
        .ok_or_else(|| format!("no netstat row for interface {interface}"))
}

/// Parses `netstat -I <iface> -b` Darwin output. Picks the `<Link#N>` row,
/// which carries byte counters; the address rows repeat packet counts but
/// print `-` for bytes.
pub fn parse_netstat_ib(text: &str, interface: &str) -> Option<InterfaceCounters> {
    let mut lines = text.lines();
    let header = lines.next()?;
    let cols: Vec<&str> = header.split_whitespace().collect();
    let idx = |name: &str| cols.iter().position(|c| *c == name);
    let (ipkts_i, ierrs_i, ibytes_i, opkts_i, oerrs_i, obytes_i) = (
        idx("Ipkts")?,
        idx("Ierrs")?,
        idx("Ibytes")?,
        idx("Opkts")?,
        idx("Oerrs")?,
        idx("Obytes")?,
    );

    for line in lines {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.is_empty() || fields[0] != interface {
            continue;
        }
        let max_i = *[ipkts_i, ierrs_i, ibytes_i, opkts_i, oerrs_i, obytes_i]
            .iter()
            .max()
            .unwrap();
        if fields.len() <= max_i {
            continue;
        }
        let parse = |s: &str| -> Option<u64> { s.parse::<u64>().ok() };
        if let (Some(ip), Some(ib), Some(op), Some(ob)) = (
            parse(fields[ipkts_i]),
            parse(fields[ibytes_i]),
            parse(fields[opkts_i]),
            parse(fields[obytes_i]),
        ) {
            return Some(InterfaceCounters {
                rx_packets: ip,
                tx_packets: op,
                rx_bytes: ib,
                tx_bytes: ob,
                rx_errors: parse(fields[ierrs_i]).unwrap_or(0),
                tx_errors: parse(fields[oerrs_i]).unwrap_or(0),
            });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "Name       Mtu   Network       Address            Ipkts Ierrs     Ibytes    Opkts Oerrs     Obytes  Coll\nen0        1500  <Link#14>   02:00:00:00:00:01 21869567     0 27949362788 22461432     0 29723901148     0\nen0        1500  10.10.251/24 10.10.251.27   21869567     - 27949362788 22461432     - 29723901148     -\n";

    #[test]
    fn parses_link_row_bytes() {
        let c = parse_netstat_ib(SAMPLE, "en0").expect("row");
        assert_eq!(c.rx_packets, 21869567);
        assert_eq!(c.tx_bytes, 29723901148);
    }

    #[test]
    fn missing_interface_returns_none() {
        assert!(parse_netstat_ib(SAMPLE, "en1").is_none());
    }

    #[test]
    fn detects_unusable_backwards_delta() {
        let before = InterfaceCounters {
            rx_packets: 100,
            ..InterfaceCounters::zero()
        };
        let after = InterfaceCounters {
            rx_packets: 50,
            ..InterfaceCounters::zero()
        };
        assert!(!after.usable_delta_from(&before));
    }
}
