//! GAP-003/GAP-004: controlled H1/H2/H3 protocol comparison with directional
//! vs simultaneous load isolation.
//!
//! Field evidence this formalizes (2026-08-02 investigation notes): HTTP/3
//! was healthy directionally (679 Mbps down) and collapsed to 41 Mbps under
//! simultaneous load (6.1% retained) on the same radio where HTTP/2 stayed
//! balanced (44.5% retained). A single blended number would have read as
//! "QUIC is being shaped"; the actual trigger was bidirectional contention.
//! Directional and simultaneous results are therefore kept as separate
//! fields all the way through this module -- there is no code path that
//! averages them into one figure.
//!
//! Two more field lessons drive this design:
//! - Native protocol runs silently selected different CDN edge IPs between
//!   protocols, which invalidates a cross-protocol comparison without
//!   anyone noticing (GAP-017). Every leg here records the IP curl actually
//!   connected to (`%{remote_ip}`), and the comparison warns loudly when
//!   legs disagree.
//! - HTTP/3 failed against two real endpoints that simply don't offer it
//!   (GAP-025). This module calls `crate::probe::preflight` before running
//!   an H3 leg and reports `Unsupported` rather than measuring garbage
//!   against an incapable endpoint.

use std::net::IpAddr;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::network_tests::pcap_report::Confidence;
use crate::probe::preflight::{self, EndpointVerdict};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HttpProtocol {
    Http1,
    Http2,
    Http3,
}

impl HttpProtocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            HttpProtocol::Http1 => "http1",
            HttpProtocol::Http2 => "http2",
            HttpProtocol::Http3 => "http3",
        }
    }

    fn curl_flag(&self) -> &'static str {
        match self {
            HttpProtocol::Http1 => "--http1.1",
            HttpProtocol::Http2 => "--http2",
            HttpProtocol::Http3 => "--http3-only",
        }
    }

    /// H3 needs a curl build linked against a QUIC backend. The system
    /// `/usr/bin/curl` on this platform (LibreSSL/SecureTransport build)
    /// does not have it; verified separately that Homebrew's curl does. We
    /// probe for HTTP3 in `curl --version` output at call time rather than
    /// hardcoding a path, so this degrades honestly on a machine where
    /// neither curl build supports H3.
    fn requires_h3_capable_curl(&self) -> bool {
        matches!(self, HttpProtocol::Http3)
    }
}

/// Candidate curl binaries to search, in preference order. The system curl
/// is preferred when it's sufficient (H1/H2); H3 legs additionally require
/// whichever candidate actually reports the `HTTP3` feature.
const CURL_CANDIDATES: &[&str] = &["curl", "/opt/homebrew/opt/curl/bin/curl", "/usr/local/opt/curl/bin/curl"];

#[derive(Debug, Clone)]
struct CurlBinary {
    path: String,
    supports_h3: bool,
}

fn probe_curl_binary(path: &str) -> Option<CurlBinary> {
    let out = Command::new(path).arg("--version").output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    Some(CurlBinary {
        path: path.to_string(),
        supports_h3: text.lines().next().map(|_| ()).is_some() && text.contains("HTTP3"),
    })
}

/// Picks a curl binary able to run `protocol`. Returns `None` (rather than
/// silently downgrading to a protocol-incapable binary) when nothing on the
/// candidate list can do it -- callers must report this as unavailable, not
/// substitute a different protocol's result under the requested one's name.
fn select_curl_for(protocol: HttpProtocol) -> Option<CurlBinary> {
    let mut first_working: Option<CurlBinary> = None;
    for candidate in CURL_CANDIDATES {
        if let Some(bin) = probe_curl_binary(candidate) {
            if !protocol.requires_h3_capable_curl() {
                return Some(bin);
            }
            if bin.supports_h3 {
                return Some(bin);
            }
            first_working.get_or_insert(bin);
        }
    }
    if protocol.requires_h3_capable_curl() {
        None
    } else {
        first_working
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegResult {
    pub protocol: String,
    pub direction: String,
    pub host: String,
    pub connected_ip: Option<String>,
    pub http_status: Option<u32>,
    pub throughput_bps: Option<f64>,
    pub bytes_transferred: Option<u64>,
    pub time_total_secs: Option<f64>,
    pub loss_indicator: LossIndicator,
    pub error: Option<String>,
    /// The URL curl actually finished on, after following redirects
    /// (`-L`). `None` when equal to the requested URL (no redirect chain).
    pub final_url: Option<String>,
    /// How many redirect hops curl followed to get there.
    pub redirect_count: u32,
}

/// A leg's transfer either completed cleanly against a real body of at
/// least `MIN_VALID_TRANSFER_BYTES`, completed with a non-2xx final status
/// (still timed, but confidence-reducing), completed 2xx but with a body
/// too small to trust as a capacity measurement, or never completed at
/// all. Kept distinct from a bare `bool` so "ran but the server object
/// itself was unhappy" is visibly different from "never even connected".
///
/// There is deliberately no `Redirected` variant: redirects are now
/// followed (`-L`) and judged on their FINAL status/body, matching what an
/// operator asking about a redirecting hostname actually wants measured.
/// `http_status`/`final_url` still record that a redirect happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LossIndicator {
    Clean,
    /// The transfer completed (2xx final status) but the body was smaller
    /// than `MIN_VALID_TRANSFER_BYTES`, so a rate computed from it would
    /// measure TLS/connection setup overhead, not capacity. This is the
    /// field bug this module was built to avoid repeating: a redirect
    /// stub's few hundred bytes silently became "0.02 Mbps, loss=Clean".
    BodyTooSmall,
    NonSuccessStatus,
    TransferFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Direction {
    DownloadOnly,
    UploadOnly,
    Simultaneous,
}

impl Direction {
    fn as_str(&self) -> &'static str {
        match self {
            Direction::DownloadOnly => "download-only",
            Direction::UploadOnly => "upload-only",
            Direction::Simultaneous => "simultaneous",
        }
    }
}

const KILL_GRACE_SECS: u64 = 5;

/// Runs `curl` to completion or force-kills it at `timeout_secs +
/// KILL_GRACE_SECS`, mirroring the watchdog in `bufferbloat.rs` -- curl
/// itself has its own `-m` timeout, but a hung DNS/TLS stack underneath it
/// is not something curl's own timeout is guaranteed to interrupt cleanly on
/// every platform, so this tool owns a second, independent deadline.
fn run_curl_watched(curl_path: &str, args: &[String], timeout_secs: u64) -> Result<std::process::Output, String> {
    // curl's `-w` write-out format prints to stdout even though the actual
    // transfer body is separately discarded via `-o /dev/null` in `args` --
    // stdout must stay piped here, or the write-out fields (status/speed/IP)
    // are lost along with the body.
    let mut child: Child = Command::new(curl_path)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("failed to spawn curl: {e}"))?;

    let deadline = Instant::now() + Duration::from_secs(timeout_secs + KILL_GRACE_SECS);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("curl exceeded watchdog deadline ({}s) and was killed", timeout_secs + KILL_GRACE_SECS));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(format!("failed to poll curl: {e}")),
        }
    }
    child.wait_with_output().map_err(|e| format!("failed to collect curl output: {e}"))
}

// Positional, `\x1f`-delimited (ASCII unit separator) rather than a `key=value|...`
// format: `%{url_effective}` can legitimately contain both `=` (query strings)
// and, in principle, other punctuation, so a delimiter that can never appear
// in a URL or these numeric fields is required for this to parse reliably.
const WRITE_OUT_FIELDS: &[&str] = &[
    "code", "proto", "speed_dl", "speed_up", "size_dl", "size_up", "time_total", "remote_ip", "url_effective", "num_redirects",
];
const WRITE_OUT_FORMAT: &str = "%{http_code}\x1f%{http_version}\x1f%{speed_download}\x1f%{speed_upload}\x1f%{size_download}\x1f%{size_upload}\x1f%{time_total}\x1f%{remote_ip}\x1f%{url_effective}\x1f%{num_redirects}";

fn parse_write_out(text: &str) -> std::collections::HashMap<String, String> {
    text.trim_end_matches(['\n', '\r'])
        .split('\x1f')
        .zip(WRITE_OUT_FIELDS.iter())
        .map(|(v, k)| (k.to_string(), v.to_string()))
        .collect()
}

#[derive(Debug, Clone)]
pub struct LegConfig {
    pub host: String,
    pub port: u16,
    pub path: String,
    pub interface: Option<String>,
    pub forced_ip: Option<IpAddr>,
    pub timeout_secs: u64,
    pub upload_bytes: usize,
}

/// Runs one download leg (GET) or upload leg (POST with a generated body)
/// over `protocol`. Never runs both in the same curl invocation -- the
/// "simultaneous" mode composes two of these run in parallel from the
/// caller, not a single dual-direction curl request, so each leg's own
/// timing/status/IP stays individually attributable.
/// A GET/POST that transfers less than this many bytes cannot be trusted as
/// a capacity measurement -- it measures TLS/connection setup overhead, not
/// throughput. Chosen well above typical redirect-stub/error-page sizes
/// (usually under 1 KB) and well below the smallest real payload this
/// module requests (`--upload-bytes` defaults to 2,000,000; download bodies
/// used in practice are hundreds of KB or more).
const MIN_VALID_TRANSFER_BYTES: u64 = 16_384;

/// Curl caps redirect following at this many hops. Large enough for any
/// legitimate redirect chain, small enough that a redirect loop still fails
/// fast rather than hanging until the outer watchdog deadline.
const MAX_REDIRECTS: u32 = 10;

fn failed_leg(protocol: HttpProtocol, direction: Direction, host: &str, error: String) -> LegResult {
    LegResult {
        protocol: protocol.as_str().to_string(),
        direction: direction.as_str().to_string(),
        host: host.to_string(),
        connected_ip: None,
        http_status: None,
        throughput_bps: None,
        bytes_transferred: None,
        time_total_secs: None,
        loss_indicator: LossIndicator::TransferFailed,
        error: Some(error),
        final_url: None,
        redirect_count: 0,
    }
}

fn run_leg(protocol: HttpProtocol, direction: Direction, cfg: &LegConfig, upload_body: Option<&std::path::Path>) -> LegResult {
    let curl = match select_curl_for(protocol) {
        Some(c) => c,
        None => {
            return failed_leg(
                protocol,
                direction,
                &cfg.host,
                format!(
                    "no curl binary on this system supports {}; measurement unavailable, not substituted",
                    protocol.as_str()
                ),
            );
        }
    };

    let url = format!("https://{}:{}{}", cfg.host, cfg.port, cfg.path);
    let mut args: Vec<String> = vec![
        protocol.curl_flag().to_string(),
        "-sS".to_string(),
        // Follow redirects rather than measuring a redirect stub: an
        // operator asking about `cloudflare.com` (which 301s to
        // www.cloudflare.com) wants the real resource's throughput, not the
        // 301 body's. `--max-redirs` bounds a redirect loop; the final
        // status/URL/body still govern the loss_indicator and whether a
        // throughput figure gets reported at all (see below).
        "-L".to_string(),
        "--max-redirs".to_string(),
        MAX_REDIRECTS.to_string(),
        "-o".to_string(),
        "/dev/null".to_string(),
        "-w".to_string(),
        WRITE_OUT_FORMAT.to_string(),
        "-m".to_string(),
        cfg.timeout_secs.to_string(),
    ];
    if let Some(ip) = cfg.forced_ip {
        args.push("--resolve".to_string());
        args.push(format!("{}:{}:{}", cfg.host, cfg.port, ip));
    }
    if let Some(iface) = &cfg.interface {
        args.push("--interface".to_string());
        args.push(iface.clone());
    }
    if let Some(body_path) = upload_body {
        args.push("-X".to_string());
        args.push("POST".to_string());
        args.push("--data-binary".to_string());
        args.push(format!("@{}", body_path.display()));
    }
    args.push(url);

    let output = match run_curl_watched(&curl.path, &args, cfg.timeout_secs) {
        Ok(o) => o,
        Err(e) => return failed_leg(protocol, direction, &cfg.host, e),
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let msg = if stderr.is_empty() { format!("curl exited with {:?}", output.status.code()) } else { stderr };
        return failed_leg(protocol, direction, &cfg.host, msg);
    }

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let fields = parse_write_out(&stdout);

    let status: Option<u32> = fields.get("code").and_then(|s| s.parse().ok());
    let speed_dl: Option<f64> = fields.get("speed_dl").and_then(|s| s.parse().ok());
    let speed_up: Option<f64> = fields.get("speed_up").and_then(|s| s.parse().ok());
    let size_dl: Option<u64> = fields.get("size_dl").and_then(|s| s.parse().ok());
    let size_up: Option<u64> = fields.get("size_up").and_then(|s| s.parse().ok());
    let time_total: Option<f64> = fields.get("time_total").and_then(|s| s.parse().ok());
    let remote_ip = fields.get("remote_ip").filter(|s| !s.is_empty()).cloned();
    let redirect_count: u32 = fields.get("num_redirects").and_then(|s| s.parse().ok()).unwrap_or(0);
    let requested_url = format!("https://{}:{}{}", cfg.host, cfg.port, cfg.path);
    let final_url = fields
        .get("url_effective")
        .filter(|u| !u.is_empty() && *u != &requested_url)
        .cloned();

    let transferred_bytes = match direction {
        Direction::UploadOnly => size_up,
        _ => size_dl,
    };

    // Only a genuine final 2xx (after following any redirects) with a body
    // at or above MIN_VALID_TRANSFER_BYTES counts as a real capacity
    // measurement. A redirect that never resolves to 2xx, any 4xx/5xx, or a
    // body too small to trust all withhold the derived figure entirely
    // rather than printing it with a caveat -- this is the exact bug this
    // module was built to avoid repeating: a redirect stub's few hundred
    // bytes silently became "0.02 Mbps, loss=Clean".
    let is_success_status = matches!(status, Some(s) if (200..300).contains(&s));
    let body_large_enough = transferred_bytes.map(|b| b >= MIN_VALID_TRANSFER_BYTES).unwrap_or(false);
    let is_real_transfer = is_success_status && body_large_enough;

    let (throughput_bps, bytes_transferred) = if is_real_transfer {
        match direction {
            Direction::UploadOnly => (speed_up.map(|b| b * 8.0), size_up),
            _ => (speed_dl.map(|b| b * 8.0), size_dl),
        }
    } else {
        (None, None)
    };

    // `-L` means `status` is already the final status after following any
    // redirect chain; a 3xx here means curl stopped following (redirect
    // loop, --max-redirs exhausted, or a redirect with no Location), which
    // is exactly as much a non-success as a 4xx/5xx -- it is grouped with
    // NonSuccessStatus rather than kept as a separate case.
    let loss_indicator = match status {
        Some(s) if (200..300).contains(&s) && body_large_enough => LossIndicator::Clean,
        Some(s) if (200..300).contains(&s) => LossIndicator::BodyTooSmall,
        Some(_) => LossIndicator::NonSuccessStatus,
        None => LossIndicator::TransferFailed,
    };

    LegResult {
        protocol: protocol.as_str().to_string(),
        direction: direction.as_str().to_string(),
        host: cfg.host.clone(),
        connected_ip: remote_ip,
        http_status: status,
        throughput_bps,
        bytes_transferred,
        time_total_secs: time_total,
        loss_indicator,
        error: None,
        final_url,
        redirect_count,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolComparisonResult {
    pub protocol: String,
    pub preflight_verdict: Option<String>,
    /// `None` when preflight determined the endpoint doesn't support this
    /// protocol -- no legs are run against a known-incapable endpoint, so a
    /// collapsed/absent number here is never misread as network shaping.
    pub download_only: Option<LegResult>,
    pub upload_only: Option<LegResult>,
    pub simultaneous_download: Option<LegResult>,
    pub simultaneous_upload: Option<LegResult>,
    pub confidence: Confidence,
    pub confidence_reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparisonReport {
    pub host: String,
    pub interface: Option<String>,
    pub protocols: Vec<ProtocolComparisonResult>,
    /// `true` when any two protocols' legs connected to different IPs --
    /// GAP-017's endpoint-normalization warning. A comparison across
    /// different CDN edges is not comparing the same path.
    pub endpoint_mismatch: bool,
    pub endpoint_mismatch_detail: Option<String>,
    /// `true` when the requested host redirected to a different hostname
    /// (e.g. `cloudflare.com` -> `www.cloudflare.com`). Same class of
    /// problem as `endpoint_mismatch`: the measured resource lives at a
    /// different name than the one requested, and that final host may
    /// itself resolve to a different edge than the requested one would
    /// have -- worth surfacing even though every leg here still measures
    /// the same (final) resource consistently.
    pub redirected_to_different_host: bool,
    pub redirect_detail: Option<String>,
}

fn confidence_for(legs: &[Option<&LegResult>]) -> (Confidence, Vec<String>) {
    let mut reasons = Vec::new();
    let present: Vec<&LegResult> = legs.iter().filter_map(|l| *l).collect();
    if present.is_empty() {
        reasons.push("no legs completed".to_string());
        return (Confidence::Low, reasons);
    }
    let clean_count = present.iter().filter(|l| l.loss_indicator == LossIndicator::Clean).count();
    let total = present.len();
    if clean_count < total {
        reasons.push(format!("{}/{} legs did not complete cleanly", total - clean_count, total));
    }
    // Every leg here is one sample, not repeated/averaged -- never claim
    // more than Medium confidence off a single sample per leg.
    reasons.push("single sample per leg; repeat runs for statistical confidence".to_string());
    let confidence = if clean_count == total { Confidence::Medium } else { Confidence::Low };
    (confidence, reasons)
}

pub struct CompareConfig {
    pub host: String,
    pub port: u16,
    pub path: String,
    pub interface: Option<String>,
    pub forced_ip: Option<IpAddr>,
    pub timeout_secs: u64,
    pub upload_bytes: usize,
    pub protocols: Vec<HttpProtocol>,
    pub run_simultaneous: bool,
}

fn write_upload_body(bytes: usize) -> std::io::Result<tempfile_like::TempBody> {
    tempfile_like::TempBody::random(bytes)
}

/// Minimal scratch-file helper so we don't add a `tempfile` dependency for
/// one generated upload payload; cleans itself up on drop.
mod tempfile_like {
    use std::io::Write;

    pub struct TempBody {
        pub path: std::path::PathBuf,
    }

    impl TempBody {
        pub fn random(bytes: usize) -> std::io::Result<Self> {
            let mut path = std::env::temp_dir();
            path.push(format!("fraggle-packet-protocol-compare-upload-{}.bin", std::process::id()));
            let mut f = std::fs::File::create(&path)?;
            // Deterministic filler is fine here -- we need bytes on the
            // wire to time upload throughput, not entropy.
            let chunk = vec![0x5Au8; 65536];
            let mut written = 0;
            while written < bytes {
                let take = chunk.len().min(bytes - written);
                f.write_all(&chunk[..take])?;
                written += take;
            }
            Ok(Self { path })
        }
    }

    impl Drop for TempBody {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Runs the full comparison across every requested protocol: preflight,
/// download-only, upload-only, and (if requested) a simultaneous phase
/// where the up and down legs for that protocol run concurrently in their
/// own threads. Simultaneous results are stored in dedicated fields
/// (`simultaneous_download`/`simultaneous_upload`) and are never merged
/// with `download_only`/`upload_only` -- GAP-004's entire point.
pub fn run_comparison(cfg: &CompareConfig) -> ComparisonReport {
    let upload_body = write_upload_body(cfg.upload_bytes).ok();

    let mut results = Vec::new();
    let mut all_ips: Vec<(String, String)> = Vec::new(); // (protocol, ip)
    let mut final_urls: Vec<String> = Vec::new();

    for protocol in &cfg.protocols {
        let leg_cfg = LegConfig {
            host: cfg.host.clone(),
            port: cfg.port,
            path: cfg.path.clone(),
            interface: cfg.interface.clone(),
            forced_ip: cfg.forced_ip,
            timeout_secs: cfg.timeout_secs,
            upload_bytes: cfg.upload_bytes,
        };

        // Preflight gate for H3 only -- H1/H2 have no capability-advertisement
        // concept the way H3's Alt-Svc does, and both are near-universally
        // supported, so gating them the same way would just add noise.
        let preflight_verdict = if matches!(protocol, HttpProtocol::Http3) {
            let ip = preflight::resolve_for_preflight(&cfg.host, cfg.forced_ip);
            let result = preflight::preflight_one(&cfg.host, ip, preflight::Protocol::Http3, cfg.port, Duration::from_secs(cfg.timeout_secs));
            Some(result)
        } else {
            None
        };

        // An endpoint preflight determined does not support this protocol:
        // do not run legs against it at all. Running them anyway and
        // reporting a collapsed/zero number would be indistinguishable from
        // network shaping, exactly the GAP-025 false-diagnosis this reuses
        // preflight to prevent.
        if let Some(pf) = &preflight_verdict {
            if pf.verdict == EndpointVerdict::Unsupported {
                results.push(ProtocolComparisonResult {
                    protocol: protocol.as_str().to_string(),
                    preflight_verdict: Some(pf.verdict.as_str().to_string()),
                    download_only: None,
                    upload_only: None,
                    simultaneous_download: None,
                    simultaneous_upload: None,
                    confidence: Confidence::Low,
                    confidence_reasons: vec![format!(
                        "endpoint does not support {}: {}",
                        protocol.as_str(),
                        pf.detail
                    )],
                });
                continue;
            }
        }

        let download_only = run_leg(*protocol, Direction::DownloadOnly, &leg_cfg, None);
        let upload_only = upload_body
            .as_ref()
            .map(|b| run_leg(*protocol, Direction::UploadOnly, &leg_cfg, Some(&b.path)));

        let (simultaneous_download, simultaneous_upload) = if cfg.run_simultaneous {
            let leg_cfg_dl = leg_cfg.clone();
            let leg_cfg_ul = leg_cfg.clone();
            let up_path = upload_body.as_ref().map(|b| b.path.clone());
            let proto = *protocol;
            let dl_handle = std::thread::spawn(move || run_leg(proto, Direction::Simultaneous, &leg_cfg_dl, None));
            let ul_handle = up_path.map(|p| std::thread::spawn(move || run_leg(proto, Direction::Simultaneous, &leg_cfg_ul, Some(&p))));
            let dl_result = dl_handle.join().ok();
            let ul_result = ul_handle.and_then(|h| h.join().ok());
            (dl_result, ul_result)
        } else {
            (None, None)
        };

        for (dir_label, leg) in [
            ("download_only", Some(&download_only)),
            ("upload_only", upload_only.as_ref()),
            ("simultaneous_download", simultaneous_download.as_ref()),
            ("simultaneous_upload", simultaneous_upload.as_ref()),
        ] {
            if let Some(l) = leg {
                if let Some(ip) = &l.connected_ip {
                    all_ips.push((format!("{}:{}", protocol.as_str(), dir_label), ip.clone()));
                }
                if let Some(url) = &l.final_url {
                    final_urls.push(url.clone());
                }
            }
        }

        let (confidence, confidence_reasons) = confidence_for(&[
            download_only_ref(&download_only),
            upload_only.as_ref(),
            simultaneous_download.as_ref(),
            simultaneous_upload.as_ref(),
        ]);

        results.push(ProtocolComparisonResult {
            protocol: protocol.as_str().to_string(),
            preflight_verdict: preflight_verdict.map(|p| p.verdict.as_str().to_string()),
            download_only: Some(download_only),
            upload_only,
            simultaneous_download,
            simultaneous_upload,
            confidence,
            confidence_reasons,
        });
    }

    let (endpoint_mismatch, endpoint_mismatch_detail) = detect_endpoint_mismatch(&all_ips);
    let (redirected_to_different_host, redirect_detail) = detect_redirect_host_drift(&cfg.host, &final_urls);

    ComparisonReport {
        host: cfg.host.clone(),
        interface: cfg.interface.clone(),
        protocols: results,
        endpoint_mismatch,
        endpoint_mismatch_detail,
        redirected_to_different_host,
        redirect_detail,
    }
}

/// Detects whether any leg's final (post-redirect) URL landed on a
/// different hostname than the one the operator requested. Distinct from
/// `detect_endpoint_mismatch`, which compares resolved IPs across legs of
/// this same run: this compares the requested name against where curl
/// actually ended up, since that final host may itself resolve to a
/// different edge than the requested name would have.
fn detect_redirect_host_drift(requested_host: &str, final_urls: &[String]) -> (bool, Option<String>) {
    let drifted: Vec<&str> = final_urls
        .iter()
        .filter_map(|u| url_host(u))
        .filter(|h| !h.eq_ignore_ascii_case(requested_host))
        .collect();
    if drifted.is_empty() {
        (false, None)
    } else {
        let unique: std::collections::BTreeSet<&str> = drifted.into_iter().collect();
        (
            true,
            Some(format!(
                "requested host '{}' redirected to {}; the measured resource lives at a different hostname, which may itself resolve to a different edge",
                requested_host,
                unique.into_iter().collect::<Vec<_>>().join(", ")
            )),
        )
    }
}

/// Minimal `https://host[:port]/...` host extraction -- no full URL parser
/// dependency needed for this one field.
fn url_host(url: &str) -> Option<&str> {
    let rest = url.strip_prefix("https://").or_else(|| url.strip_prefix("http://"))?;
    let end = rest.find(['/', ':']).unwrap_or(rest.len());
    let host = &rest[..end];
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

fn download_only_ref(l: &LegResult) -> Option<&LegResult> {
    Some(l)
}

/// GAP-017: warn loudly when legs resolved to different IPs. Compares every
/// recorded (label, ip) pair's IP against the first one seen; any
/// disagreement flags the whole comparison, since a mismatch anywhere
/// invalidates comparing throughput across those legs.
pub fn detect_endpoint_mismatch(ips: &[(String, String)]) -> (bool, Option<String>) {
    if ips.len() < 2 {
        return (false, None);
    }
    let baseline_ip = &ips[0].1;
    let mismatched: Vec<String> = ips
        .iter()
        .filter(|(_, ip)| ip != baseline_ip)
        .map(|(label, ip)| format!("{label}={ip}"))
        .collect();
    if mismatched.is_empty() {
        (false, None)
    } else {
        (
            true,
            Some(format!(
                "legs resolved to different endpoint IPs (baseline {}={}): {} -- cross-protocol comparison may be measuring different CDN edges, not the same path",
                ips[0].0, baseline_ip, mismatched.join(", ")
            )),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leg(ip: &str, indicator: LossIndicator) -> LegResult {
        LegResult {
            protocol: "http2".to_string(),
            direction: "download-only".to_string(),
            host: "example.com".to_string(),
            connected_ip: Some(ip.to_string()),
            http_status: Some(200),
            throughput_bps: Some(1_000_000.0),
            bytes_transferred: Some(MIN_VALID_TRANSFER_BYTES),
            time_total_secs: Some(0.5),
            loss_indicator: indicator,
            error: None,
            final_url: None,
            redirect_count: 0,
        }
    }

    #[test]
    fn same_ip_across_legs_is_not_a_mismatch() {
        let ips = vec![
            ("http2:download_only".to_string(), "1.2.3.4".to_string()),
            ("http3:download_only".to_string(), "1.2.3.4".to_string()),
        ];
        let (mismatch, _) = detect_endpoint_mismatch(&ips);
        assert!(!mismatch);
    }

    #[test]
    fn different_ips_across_protocols_flags_mismatch() {
        // The exact field bug: native protocol runs silently picked
        // different CDN edges between protocols (GAP-017).
        let ips = vec![
            ("http2:download_only".to_string(), "1.2.3.4".to_string()),
            ("http3:download_only".to_string(), "5.6.7.8".to_string()),
        ];
        let (mismatch, detail) = detect_endpoint_mismatch(&ips);
        assert!(mismatch);
        assert!(detail.unwrap().contains("5.6.7.8"));
    }

    #[test]
    fn single_leg_cannot_be_a_mismatch() {
        let ips = vec![("http2:download_only".to_string(), "1.2.3.4".to_string())];
        let (mismatch, _) = detect_endpoint_mismatch(&ips);
        assert!(!mismatch);
    }

    #[test]
    fn all_clean_legs_yield_medium_confidence_not_high() {
        // Every leg here is a single sample -- never claim High confidence
        // off one sample per leg.
        let a = leg("1.2.3.4", LossIndicator::Clean);
        let b = leg("1.2.3.4", LossIndicator::Clean);
        let (confidence, reasons) = confidence_for(&[Some(&a), Some(&b)]);
        assert_eq!(confidence, Confidence::Medium);
        assert!(reasons.iter().any(|r| r.contains("single sample")));
    }

    #[test]
    fn any_non_clean_leg_lowers_confidence() {
        let a = leg("1.2.3.4", LossIndicator::Clean);
        let b = leg("1.2.3.4", LossIndicator::TransferFailed);
        let (confidence, reasons) = confidence_for(&[Some(&a), Some(&b)]);
        assert_eq!(confidence, Confidence::Low);
        assert!(reasons.iter().any(|r| r.contains("did not complete cleanly")));
    }

    #[test]
    fn no_legs_at_all_is_low_confidence_with_reason() {
        let (confidence, reasons) = confidence_for(&[None, None]);
        assert_eq!(confidence, Confidence::Low);
        assert!(reasons.iter().any(|r| r.contains("no legs")));
    }

    #[test]
    fn write_out_parser_extracts_all_fields() {
        let text = "200\x1f2\x1f123.4\x1f0\x1f1000\x1f0\x1f0.5\x1f1.2.3.4\x1fhttps://example.com/\x1f1";
        let fields = parse_write_out(text);
        assert_eq!(fields.get("code"), Some(&"200".to_string()));
        assert_eq!(fields.get("remote_ip"), Some(&"1.2.3.4".to_string()));
        assert_eq!(fields.get("url_effective"), Some(&"https://example.com/".to_string()));
        assert_eq!(fields.get("num_redirects"), Some(&"1".to_string()));
    }

    #[test]
    fn url_host_extracts_hostname_from_https_url() {
        assert_eq!(url_host("https://www.cloudflare.com/"), Some("www.cloudflare.com"));
        assert_eq!(url_host("https://example.com:8443/path"), Some("example.com"));
        assert_eq!(url_host("not-a-url"), None);
    }

    #[test]
    fn redirect_drift_detected_when_final_host_differs() {
        let (drifted, detail) = detect_redirect_host_drift(
            "cloudflare.com",
            &["https://www.cloudflare.com/".to_string()],
        );
        assert!(drifted);
        assert!(detail.unwrap().contains("www.cloudflare.com"));
    }

    #[test]
    fn no_redirect_drift_when_final_host_matches_requested() {
        let (drifted, _) = detect_redirect_host_drift(
            "www.cloudflare.com",
            &["https://www.cloudflare.com/".to_string()],
        );
        assert!(!drifted);
    }

    #[test]
    fn body_below_minimum_is_not_clean_even_with_2xx() {
        // The exact bug this module was fixed for: a small (e.g. redirect
        // stub) body must never be reported as a Clean measurement, even
        // when curl reports a 2xx final status after following redirects.
        let small_body_leg = LegResult {
            protocol: "http2".to_string(),
            direction: "download-only".to_string(),
            host: "example.com".to_string(),
            connected_ip: Some("1.2.3.4".to_string()),
            http_status: Some(200),
            throughput_bps: None,
            bytes_transferred: Some(MIN_VALID_TRANSFER_BYTES - 1),
            time_total_secs: Some(0.1),
            loss_indicator: LossIndicator::BodyTooSmall,
            error: None,
            final_url: None,
            redirect_count: 0,
        };
        assert_ne!(small_body_leg.loss_indicator, LossIndicator::Clean);
        assert!(small_body_leg.throughput_bps.is_none());
    }

    #[test]
    fn http_protocol_curl_flags_are_distinct() {
        assert_eq!(HttpProtocol::Http1.curl_flag(), "--http1.1");
        assert_eq!(HttpProtocol::Http2.curl_flag(), "--http2");
        assert_eq!(HttpProtocol::Http3.curl_flag(), "--http3-only");
    }
}
