//! Response-validated path MTU probing.
//!
//! A successful `send_to()` proves only that the local kernel accepted the
//! buffer. It says nothing about whether the datagram crossed the path. This
//! module only ever credits a size when a peer's protocol response proves the
//! padded datagram arrived intact.

use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::quic::SkipServerVerification;

/// quinn refuses a `min_mtu`/`initial_mtu` below this, so smaller sizes cannot
/// be tested through a QUIC handshake.
pub const QUIC_MIN_TESTABLE_MTU: u16 = 1200;

/// What was actually learned about one tested size.
///
/// The distinction between `Confirmed` and everything else is the whole point:
/// only `Confirmed` may contribute to a path MTU conclusion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SizeOutcome {
    /// A protocol-valid response came back for a datagram padded to this size.
    /// The only state that proves the path carries it.
    Confirmed,
    /// The local stack refused to send it (typically EMSGSIZE with DF set).
    /// Bounds the MTU from local evidence; proves nothing about the wider path.
    SendFailedLocally,
    /// An ICMP fragmentation-needed / packet-too-big was observed for this size.
    IcmpTooBig,
    /// Sent without local error, nothing came back. Ambiguous: could be path
    /// MTU, a filtered response, or a peer that does not answer. Never success.
    NoResponse,
    /// Below the floor this probe method can test at all.
    NotTestable,
}

impl SizeOutcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            SizeOutcome::Confirmed => "confirmed",
            SizeOutcome::SendFailedLocally => "send-failed-locally",
            SizeOutcome::IcmpTooBig => "icmp-too-big",
            SizeOutcome::NoResponse => "no-response",
            SizeOutcome::NotTestable => "not-testable",
        }
    }

    /// True only when a peer response proved the datagram traversed the path.
    pub fn is_path_evidence(&self) -> bool {
        matches!(self, SizeOutcome::Confirmed)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SizeResult {
    pub size: usize,
    pub outcome: SizeOutcome,
    pub detail: String,
    pub elapsed_ms: u64,
}

/// Whether the don't-fragment bit could actually be set. Without DF the kernel
/// may fragment an oversize datagram and a "confirmed" response would describe
/// reassembly rather than path MTU, so a failure here invalidates the run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DfStatus {
    pub requested: bool,
    pub applied: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PmtuEvidence {
    pub target: String,
    pub resolved_ip: Option<String>,
    pub port: u16,
    pub df: DfStatus,
    pub sizes: Vec<SizeResult>,
    /// Largest size a peer response confirmed. `None` means undetermined; it is
    /// never derived from a send-only result.
    pub confirmed_pmtu: Option<usize>,
    pub verdict: String,
}

impl PmtuEvidence {
    pub fn largest_confirmed(&self) -> Option<usize> {
        self.sizes
            .iter()
            .filter(|s| s.outcome.is_path_evidence())
            .map(|s| s.size)
            .max()
        }

    /// Smallest size that produced no response, which bounds where the path
    /// ceiling may lie once something below it is confirmed.
    pub fn smallest_unanswered(&self) -> Option<usize> {
        self.sizes
            .iter()
            .filter(|s| matches!(s.outcome, SizeOutcome::NoResponse | SizeOutcome::IcmpTooBig))
            .map(|s| s.size)
            .min()
    }
}

/// Sets DF on a UDP socket and reports whether it took effect.
///
/// The previous implementation discarded the `setsockopt` return value and was
/// a no-op off Linux entirely, so on macOS every probe silently ran without DF.
pub fn set_dont_fragment(socket: &UdpSocket, is_ipv4: bool) -> DfStatus {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let fd = socket.as_raw_fd();
        let (level, name, val) = if is_ipv4 {
            (libc::IPPROTO_IP, libc::IP_MTU_DISCOVER, libc::IP_PMTUDISC_DO)
        } else {
            (
                libc::IPPROTO_IPV6,
                libc::IPV6_MTU_DISCOVER,
                libc::IP_PMTUDISC_DO,
            )
        };
        let v: libc::c_int = val;
        let rc = unsafe {
            libc::setsockopt(
                fd,
                level,
                name,
                &v as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rc == 0 {
            DfStatus { requested: true, applied: true, detail: "IP_MTU_DISCOVER=IP_PMTUDISC_DO".to_string() }
        } else {
            DfStatus {
                requested: true,
                applied: false,
                detail: format!("setsockopt IP_MTU_DISCOVER failed: {}", std::io::Error::last_os_error()),
            }
        }
    }

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        use std::os::fd::AsRawFd;
        let fd = socket.as_raw_fd();
        let (level, name) = if is_ipv4 {
            (libc::IPPROTO_IP, libc::IP_DONTFRAG)
        } else {
            (libc::IPPROTO_IPV6, libc::IPV6_DONTFRAG)
        };
        let v: libc::c_int = 1;
        let rc = unsafe {
            libc::setsockopt(
                fd,
                level,
                name,
                &v as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rc == 0 {
            DfStatus { requested: true, applied: true, detail: "IP_DONTFRAG=1".to_string() }
        } else {
            DfStatus {
                requested: true,
                applied: false,
                detail: format!("setsockopt IP_DONTFRAG failed: {}", std::io::Error::last_os_error()),
            }
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "ios")))]
    {
        let _ = (socket, is_ipv4);
        DfStatus {
            requested: true,
            applied: false,
            detail: "no DF socket option known for this platform".to_string(),
        }
    }
}

/// Confirms `size` by forcing real stream data through datagrams of that size
/// and requiring the peer to acknowledge it.
///
/// The QUIC handshake alone cannot confirm a size: Initial packets are padded
/// only to 1200 bytes, so a handshake completes on any path that carries 1200
/// regardless of the configured maximum. An earlier version of this probe
/// checked only the handshake and consequently "confirmed" 8972 bytes across a
/// 1412-byte tunnel.
///
/// Pinning `min_mtu` and `initial_mtu` to `size` with discovery disabled means
/// post-handshake packets are emitted at `size` and quinn may not back off. If
/// the path cannot carry that size, the stream write is never acknowledged and
/// stalls. A completed write therefore proves datagrams of that size crossed
/// the path and came back acknowledged.
pub async fn confirm_size_via_quic(
    host: &str,
    ip: IpAddr,
    port: u16,
    size: u16,
    timeout: Duration,
) -> (SizeOutcome, String) {
    use quinn::{ClientConfig, Endpoint, TransportConfig};

    if size < QUIC_MIN_TESTABLE_MTU {
        return (
            SizeOutcome::NotTestable,
            format!("below quinn's {}-byte floor", QUIC_MIN_TESTABLE_MTU),
        );
    }

    let mut crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();
    crypto.alpn_protocols = vec![b"h3".to_vec()];

    let quic_crypto = match quinn::crypto::rustls::QuicClientConfig::try_from(crypto) {
        Ok(c) => c,
        Err(e) => return (SizeOutcome::NoResponse, format!("quic tls config: {}", e)),
    };

    let mut transport = TransportConfig::default();
    let idle: quinn::IdleTimeout = match Duration::from_millis(timeout.as_millis() as u64).try_into()
    {
        Ok(v) => v,
        Err(_) => return (SizeOutcome::NoResponse, "invalid idle timeout".to_string()),
    };
    transport.max_idle_timeout(Some(idle));
    transport.min_mtu(size);
    transport.initial_mtu(size);
    transport.mtu_discovery_config(None);

    let mut client_config = ClientConfig::new(Arc::new(quic_crypto));
    client_config.transport_config(Arc::new(transport));

    let bind_addr = if ip.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let mut endpoint = match Endpoint::client(match bind_addr.parse() {
        Ok(a) => a,
        Err(e) => return (SizeOutcome::NoResponse, format!("bind parse: {}", e)),
    }) {
        Ok(e) => e,
        Err(e) => return (SizeOutcome::SendFailedLocally, format!("endpoint bind: {}", e)),
    };
    endpoint.set_default_client_config(client_config);

    let connecting = match endpoint.connect(SocketAddr::new(ip, port), host) {
        Ok(c) => c,
        Err(e) => return (SizeOutcome::SendFailedLocally, format!("connect setup: {}", e)),
    };

    match tokio::time::timeout(timeout, connecting).await {
        Ok(Ok(conn)) => {
            let alpn = conn
                .handshake_data()
                .and_then(|d| d.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
                .and_then(|d| d.protocol)
                .map(|p| String::from_utf8_lossy(&p).to_string())
                .unwrap_or_default();

            // The handshake proves only that 1200-byte Initials crossed. Push
            // enough stream data to require several full-size datagrams and
            // wait for the peer to acknowledge them.
            let outcome = match tokio::time::timeout(timeout, conn.open_uni()).await {
                Ok(Ok(mut stream)) => {
                    let payload = vec![0x41u8; (size as usize) * 4];
                    let wrote = tokio::time::timeout(timeout, async {
                        stream.write_all(&payload).await.map_err(|e| e.to_string())?;
                        stream.finish().map_err(|e| e.to_string())?;
                        stream.stopped().await.map(|_| ()).map_err(|e| e.to_string())
                    })
                    .await;

                    match wrote {
                        Ok(Ok(())) => (
                            SizeOutcome::Confirmed,
                            format!(
                                "{} bytes of stream data acknowledged with {}-byte datagrams (alpn={})",
                                payload.len(), size, alpn
                            ),
                        ),
                        Ok(Err(e)) => (
                            SizeOutcome::NoResponse,
                            format!("stream write with {}-byte datagrams failed: {}", size, e),
                        ),
                        Err(_) => (
                            SizeOutcome::NoResponse,
                            format!(
                                "stream write stalled with {}-byte datagrams: no acknowledgement \
                                 within {:?}, consistent with the path not carrying this size",
                                size, timeout
                            ),
                        ),
                    }
                }
                Ok(Err(e)) => (
                    SizeOutcome::NoResponse,
                    format!("peer refused a stream ({}), size unconfirmed", e),
                ),
                Err(_) => (
                    SizeOutcome::NoResponse,
                    format!("opening a stream stalled at {}-byte datagrams", size),
                ),
            };

            let observed = conn.max_datagram_size();
            conn.close(0u32.into(), b"pmtu probe complete");
            endpoint.wait_idle().await;

            match (outcome.0, observed) {
                // quinn's own path estimate contradicting a confirmation means
                // the write was carried by smaller datagrams than requested.
                (SizeOutcome::Confirmed, Some(obs)) if (obs as u16) < size => (
                    SizeOutcome::NoResponse,
                    format!(
                        "write succeeded but quinn's path estimate stayed at {} bytes, below the \
                         requested {}; not treated as confirmation of {}",
                        obs, size, size
                    ),
                ),
                _ => outcome,
            }
        }
        Ok(Err(e)) => {
            let msg = e.to_string();
            // A local EMSGSIZE surfaces as a transport write error rather than
            // a peer refusal, so it is local evidence, not path evidence.
            if msg.contains("too long") || msg.contains("message size") {
                (SizeOutcome::SendFailedLocally, msg)
            } else {
                (SizeOutcome::NoResponse, msg)
            }
        }
        Err(_) => (
            SizeOutcome::NoResponse,
            format!("no handshake response within {:?}", timeout),
        ),
    }
}

/// Probes a bare UDP datagram to detect a local send refusal (EMSGSIZE).
///
/// This is deliberately NOT used to confirm a size. It only distinguishes "the
/// local stack would not even send this" from "it went out and we heard
/// nothing", which the old code conflated into success.
pub fn local_send_check(ip: IpAddr, port: u16, size: usize) -> (SizeOutcome, String, DfStatus) {
    let bind = if ip.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let socket = match UdpSocket::bind(bind) {
        Ok(s) => s,
        Err(e) => {
            return (
                SizeOutcome::SendFailedLocally,
                format!("bind: {}", e),
                DfStatus { requested: false, applied: false, detail: "socket bind failed".to_string() },
            )
        }
    };
    let df = set_dont_fragment(&socket, ip.is_ipv4());
    let payload = vec![0u8; size];
    match socket.send_to(&payload, SocketAddr::new(ip, port)) {
        Ok(n) if n == size => (
            SizeOutcome::NoResponse,
            "local stack accepted the datagram; no path evidence".to_string(),
            df,
        ),
        Ok(n) => (
            SizeOutcome::SendFailedLocally,
            format!("short send: {} of {} bytes", n, size),
            df,
        ),
        Err(e) => (SizeOutcome::SendFailedLocally, e.to_string(), df),
    }
}

/// Runs the full evidence-based sweep for one target.
pub fn probe_pmtu_evidence(
    host: &str,
    ip: IpAddr,
    port: u16,
    sizes: &[usize],
    timeout: Duration,
) -> PmtuEvidence {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build();

    let mut results: Vec<SizeResult> = Vec::new();
    let mut df_status = DfStatus {
        requested: true,
        applied: false,
        detail: "not yet attempted".to_string(),
    };

    for &size in sizes {
        let start = Instant::now();
        let (local_outcome, local_detail, df) = local_send_check(ip, port, size);
        df_status = df;

        // A local refusal is conclusive for this size; no point handshaking.
        let (outcome, detail) = if local_outcome == SizeOutcome::SendFailedLocally {
            (local_outcome, local_detail)
        } else {
            match &rt {
                Ok(rt) => {
                    let s16 = if size > u16::MAX as usize { u16::MAX } else { size as u16 };
                    rt.block_on(confirm_size_via_quic(host, ip, port, s16, timeout))
                }
                Err(e) => (SizeOutcome::NoResponse, format!("runtime: {}", e)),
            }
        };

        results.push(SizeResult {
            size,
            outcome,
            detail,
            elapsed_ms: start.elapsed().as_millis() as u64,
        });
    }

    let mut evidence = PmtuEvidence {
        target: host.to_string(),
        resolved_ip: Some(ip.to_string()),
        port,
        df: df_status,
        sizes: results,
        confirmed_pmtu: None,
        verdict: String::new(),
    };
    evidence.confirmed_pmtu = evidence.largest_confirmed();
    evidence.verdict = build_verdict(&evidence);
    evidence
}

/// Wording is load-bearing here: with nothing confirmed the tool must say the
/// path MTU is undetermined rather than print a number it cannot support.
pub fn build_verdict(e: &PmtuEvidence) -> String {
    let mut parts: Vec<String> = Vec::new();

    match e.confirmed_pmtu {
        Some(c) => {
            parts.push(format!(
                "largest response-confirmed UDP payload: {} bytes",
                c
            ));
            if let Some(u) = e.smallest_unanswered() {
                if u > c {
                    parts.push(format!(
                        "path ceiling lies between {} and {} bytes",
                        c, u
                    ));
                }
            }
        }
        None => {
            parts.push(
                "path MTU undetermined: no tested size produced a protocol-valid response"
                    .to_string(),
            );
            let unanswered = e
                .sizes
                .iter()
                .filter(|s| s.outcome == SizeOutcome::NoResponse)
                .count();
            let local = e
                .sizes
                .iter()
                .filter(|s| s.outcome == SizeOutcome::SendFailedLocally)
                .count();
            if unanswered > 0 {
                parts.push(format!(
                    "{} size(s) sent without a reply, which is ambiguous between path MTU, \
                     response filtering, and an endpoint that does not answer",
                    unanswered
                ));
            }
            if local > 0 {
                parts.push(format!(
                    "{} size(s) refused by the local stack (local evidence only)",
                    local
                ));
            }
        }
    }

    if !e.df.applied {
        parts.push(format!(
            "WARNING: don't-fragment could not be set ({}), so any confirmation may describe \
             fragmented delivery rather than path MTU",
            e.df.detail
        ));
    }

    parts.join("; ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(sizes: Vec<(usize, SizeOutcome)>, df_applied: bool) -> PmtuEvidence {
        let mut e = PmtuEvidence {
            target: "example.test".to_string(),
            resolved_ip: Some("192.0.2.1".to_string()),
            port: 443,
            df: DfStatus {
                requested: true,
                applied: df_applied,
                detail: "test".to_string(),
            },
            sizes: sizes
                .into_iter()
                .map(|(size, outcome)| SizeResult {
                    size,
                    outcome,
                    detail: String::new(),
                    elapsed_ms: 0,
                })
                .collect(),
            confirmed_pmtu: None,
            verdict: String::new(),
        };
        e.confirmed_pmtu = e.largest_confirmed();
        e.verdict = build_verdict(&e);
        e
    }

    #[test]
    fn send_only_success_is_never_path_evidence() {
        // The GAP-001 regression: every size "sent" fine, nothing answered.
        let e = ev(
            vec![
                (1200, SizeOutcome::NoResponse),
                (1500, SizeOutcome::NoResponse),
                (8972, SizeOutcome::NoResponse),
            ],
            true,
        );
        assert_eq!(e.confirmed_pmtu, None);
        assert!(e.verdict.contains("undetermined"));
        assert!(!e.verdict.contains("8972"));
    }

    #[test]
    fn only_confirmed_sizes_count() {
        let e = ev(
            vec![
                (1200, SizeOutcome::Confirmed),
                (1400, SizeOutcome::NoResponse),
                (8972, SizeOutcome::NoResponse),
            ],
            true,
        );
        assert_eq!(e.confirmed_pmtu, Some(1200));
        assert!(e.verdict.contains("1200"));
        assert!(e.verdict.contains("between 1200 and 1400"));
    }

    #[test]
    fn local_send_failure_is_not_path_evidence() {
        let e = ev(
            vec![
                (1200, SizeOutcome::Confirmed),
                (9000, SizeOutcome::SendFailedLocally),
            ],
            true,
        );
        assert_eq!(e.confirmed_pmtu, Some(1200));
        assert!(!SizeOutcome::SendFailedLocally.is_path_evidence());
    }

    #[test]
    fn unset_df_warns_that_confirmation_may_be_fragmented() {
        let e = ev(vec![(1500, SizeOutcome::Confirmed)], false);
        assert!(e.verdict.contains("don't-fragment could not be set"));
    }

    #[test]
    fn icmp_too_big_is_not_success() {
        assert!(!SizeOutcome::IcmpTooBig.is_path_evidence());
        let e = ev(vec![(1500, SizeOutcome::IcmpTooBig)], true);
        assert_eq!(e.confirmed_pmtu, None);
    }
}
