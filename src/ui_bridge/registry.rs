//! One description of every CLI subcommand, so both UIs render the same
//! capability surface and a newly added command appears automatically.
//!
//! Before this, the TUI and desktop app each hardcoded a list of the 19
//! `NetworkTest` impls. 60 of 79 subcommands were unreachable from either, and
//! nothing detected the drift as new commands landed.
//!
//! The interesting field is [`Platform`]. Roughly a dozen commands read macOS
//! Wi-Fi tooling (`system_profiler`, `wdutil`, `ioreg`, `networkQuality`) or BSD
//! `netstat -I`, but most of those ALSO accept operator-supplied JSON and are
//! perfectly usable anywhere in that mode. Modelling this as a flat "macOS only"
//! boolean would have been wrong in both directions: it would hide commands that
//! work fine from ingest, and it would let a Linux user click one whose live path
//! silently returns nothing. So availability is a property of the mode, not just
//! the OS, and the UI states which it is instead of discovering it by failing.
//!
//! Regenerate after adding a subcommand: the harness gate asserts every command
//! reported by `fraggle-packet --help` appears here.

/// Functional area, used to group commands in both UIs. Chosen so a user with a
/// symptom lands in one bucket rather than scanning 79 flat entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Bucket {
    /// Wi-Fi association, radio state, RF survey, AP compatibility.
    WifiRf,
    /// Throughput, capacity, load, listener admission.
    Throughput,
    /// Path MTU, MSS, routing, per-hop behaviour, captures.
    PathMtu,
    /// Resolution, addressing, IPv6, DHCP, multicast, NAT traversal.
    DnsAddressing,
    /// Operator-supplied switch/AP/fleet telemetry and cross-run controls.
    Infrastructure,
    /// Authentication, policy, VPN, firewall state, fuzzing, replay.
    SecurityPolicy,
    /// Reports, launchers, scenario runner, exporters, helpers.
    Tools,
}

impl Bucket {
    pub const ALL: &'static [Bucket] = &[
        Bucket::WifiRf,
        Bucket::Throughput,
        Bucket::PathMtu,
        Bucket::DnsAddressing,
        Bucket::Infrastructure,
        Bucket::SecurityPolicy,
        Bucket::Tools,
    ];

    pub fn label(&self) -> &'static str {
        match self {
            Bucket::WifiRf => "Wi-Fi & RF",
            Bucket::Throughput => "Throughput & Capacity",
            Bucket::PathMtu => "Path & MTU",
            Bucket::DnsAddressing => "DNS & Addressing",
            Bucket::Infrastructure => "Infrastructure",
            Bucket::SecurityPolicy => "Security & Policy",
            Bucket::Tools => "Tools & Reports",
        }
    }
}

/// Where a command can run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    /// No platform-specific dependency.
    AnyPlatform,
    /// Reads macOS/BSD-only tooling with no ingest alternative, so it cannot
    /// produce a result at all elsewhere.
    MacOsOnly,
    /// Its LIVE sampling path needs macOS/BSD tooling, but it accepts
    /// operator-supplied JSON and is fully usable anywhere in that mode.
    MacOsForLiveSampling,
}

/// Whether this host can run a command, and why not when it cannot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Availability {
    Available,
    /// Usable, but only from supplied data on this host.
    IngestOnly(&'static str),
    Unavailable(&'static str),
}

impl Availability {
    /// True when the UI should let the user launch this without qualification.
    pub fn is_available(&self) -> bool {
        matches!(self, Availability::Available)
    }
    /// True when the UI must not offer a live run at all.
    pub fn is_blocked(&self) -> bool {
        matches!(self, Availability::Unavailable(_))
    }
}

/// One subcommand.
#[derive(Debug, Clone, Copy)]
pub struct Cmd {
    pub name: &'static str,
    pub bucket: Bucket,
    /// Required positional/`--flag` values from the command's own usage line,
    /// so a UI can prompt instead of launching a run that will just error.
    pub required_inputs: &'static [&'static str],
    /// Whether `--json` exists. 21 of 79 have no JSON mode, and asking for one
    /// makes them fail on an unknown flag.
    pub emits_json: bool,
    pub platform: Platform,
    /// Needs root/raw sockets.
    pub needs_privilege: bool,
    /// The gap(s) this command closes, when it closes one.
    pub gaps: Option<&'static str>,
    pub summary: &'static str,
}

impl Cmd {
    /// Availability on the host this binary is running on.
    pub fn availability(&self) -> Availability {
        let darwin = cfg!(target_os = "macos");
        match self.platform {
            Platform::AnyPlatform => Availability::Available,
            Platform::MacOsOnly if darwin => Availability::Available,
            Platform::MacOsOnly => Availability::Unavailable(
                "needs macOS: reads system_profiler/wdutil/networkQuality, which have no equivalent here",
            ),
            Platform::MacOsForLiveSampling if darwin => Availability::Available,
            Platform::MacOsForLiveSampling => Availability::IngestOnly(
                "live sampling needs macOS/BSD tooling; supply operator JSON to run it here",
            ),
        }
    }

    /// The argv to hand [`crate::ui_bridge::run_subcommand`], adding `--json`
    /// only where the command actually supports it.
    pub fn invocation(&self, user_args: &[String]) -> Vec<String> {
        let mut v = user_args.to_vec();
        if self.emits_json && !v.iter().any(|a| a == "--json") {
            v.push("--json".to_string());
        }
        v
    }
}

/// Every subcommand. Generated from `fraggle-packet --help`; gate 079 fails the
/// build if the binary reports one that is missing here.
pub const COMMANDS: &[Cmd] = &[
    Cmd { name: "admission-fanout", bucket: Bucket::Throughput, required_inputs: &["TARGET"], emits_json: true, platform: Platform::AnyPlatform, needs_privilege: false, gaps: Some("GAP-045"), summary: "Barrier-synchronized public-listener admission fanout: never reports a listener that never admitted as zero throughput (GAP-045)" },
    Cmd { name: "ap-compat-matrix", bucket: Bucket::WifiRf, required_inputs: &[], emits_json: true, platform: Platform::MacOsForLiveSampling, needs_privilege: false, gaps: Some("GAP-037"), summary: "AP-generation/radio-mode/client-capability compatibility matrix; refuses a verdict until required comparison cells are present (GAP-037)" },
    Cmd { name: "ap-identity", bucket: Bucket::WifiRf, required_inputs: &[], emits_json: true, platform: Platform::MacOsForLiveSampling, needs_privilege: false, gaps: Some("GAP-024"), summary: "Stable, privacy-safe salted AP/radio identity derived from BSSID without storing or displaying it (GAP-024)" },
    Cmd { name: "auth-portal", bucket: Bucket::SecurityPolicy, required_inputs: &[], emits_json: true, platform: Platform::AnyPlatform, needs_privilege: false, gaps: Some("GAP-049"), summary: "Authentication/captive-portal/policy-assignment workflow: separately timed phases, portal detection without login automation (GAP-049)" },
    Cmd { name: "bufferbloat", bucket: Bucket::Throughput, required_inputs: &[], emits_json: true, platform: Platform::MacOsOnly, needs_privilege: false, gaps: Some("GAP-002"), summary: "Idle/upload-loaded/download-loaded/simultaneous latency via networkQuality (GAP-002)" },
    Cmd { name: "burst-analysis", bucket: Bucket::PathMtu, required_inputs: &["INTERFACE", "TARGET"], emits_json: true, platform: Platform::MacOsForLiveSampling, needs_privilege: false, gaps: Some("GAP-066"), summary: "Bounded burst-loss/reordering/duplication/jitter probe with queue-delay correlation (GAP-066)" },
    Cmd { name: "capacity-knee", bucket: Bucket::Throughput, required_inputs: &["INTERFACE"], emits_json: true, platform: Platform::AnyPlatform, needs_privilege: false, gaps: Some("GAP-070"), summary: "Capacity/latency-knee discovery: distinguishes a capacity plateau from directional unfairness and withholds an established claim without cross-method reproduction (GAP-070)" },
    Cmd { name: "capture", bucket: Bucket::SecurityPolicy, required_inputs: &["INTERFACE"], emits_json: true, platform: Platform::AnyPlatform, needs_privilege: true, gaps: Some("GAP-007"), summary: "Bounded packet capture with duration/size caps and safe privilege handoff (GAP-007)" },
    Cmd { name: "circuit-compare", bucket: Bucket::Infrastructure, required_inputs: &["MANIFEST"], emits_json: true, platform: Platform::AnyPlatform, needs_privilege: false, gaps: Some("GAP-029"), summary: "Compare WAN A-only, B-only, and dual-active phases from an operator manifest; never changes routing (GAP-029)" },
    Cmd { name: "clock-guard", bucket: Bucket::Infrastructure, required_inputs: &[], emits_json: true, platform: Platform::AnyPlatform, needs_privilege: false, gaps: Some("GAP-064"), summary: "Synchronized clock verification: NTP offset with uncertainty, gated against a configured skew threshold, before permitting a one-way delay claim (GAP-064)" },
    Cmd { name: "counter-deltas", bucket: Bucket::Infrastructure, required_inputs: &[], emits_json: true, platform: Platform::MacOsForLiveSampling, needs_privilege: false, gaps: Some("GAP-031"), summary: "Normalized, qualified per-phase interface-counter deltas (GAP-031)" },
    Cmd { name: "counter-liveness", bucket: Bucket::Infrastructure, required_inputs: &[], emits_json: true, platform: Platform::MacOsForLiveSampling, needs_privilege: false, gaps: Some("GAP-043"), summary: "Bracket a known packet stimulus to prove a counter is live, and refuse a zero-drop verdict without corroboration (GAP-043)" },
    Cmd { name: "dependency-health", bucket: Bucket::Infrastructure, required_inputs: &[], emits_json: true, platform: Platform::AnyPlatform, needs_privilege: false, gaps: Some("GAP-059"), summary: "Infrastructure dependency health bundle: DNS/NTP/cert/OCSP/controller checks distinguishing blocked-by-policy from unhealthy (GAP-059)" },
    Cmd { name: "dhcp-lifecycle", bucket: Bucket::DnsAddressing, required_inputs: &["INTERFACE"], emits_json: true, platform: Platform::AnyPlatform, needs_privilege: false, gaps: Some("GAP-048"), summary: "DHCP address-lifecycle and pool-capacity test: safe existing-lease read by default, authorization-gated fresh-lease test (GAP-048)" },
    Cmd { name: "diagnose", bucket: Bucket::Tools, required_inputs: &["TARGET"], emits_json: false, platform: Platform::AnyPlatform, needs_privilege: false, gaps: None, summary: "Full diagnostic against a hostname (DNS, TCP, HTTP, ICMP comparison)" },
    Cmd { name: "dns-secure", bucket: Bucket::DnsAddressing, required_inputs: &["TARGET"], emits_json: false, platform: Platform::AnyPlatform, needs_privilege: false, gaps: None, summary: "DoH/DoT vs plain DNS comparison" },
    Cmd { name: "dns-steering", bucket: Bucket::DnsAddressing, required_inputs: &["RESOLVERS", "NAME"], emits_json: true, platform: Platform::AnyPlatform, needs_privilege: false, gaps: Some("GAP-014"), summary: "Compare A/AAAA/HTTPS/SVCB answers across resolvers to detect steering divergence (GAP-014)" },
    Cmd { name: "dsl-demo", bucket: Bucket::Tools, required_inputs: &[], emits_json: false, platform: Platform::AnyPlatform, needs_privilege: false, gaps: None, summary: "Print a hexdump of a packet described by our DSL (demo helper)" },
    Cmd { name: "ecmp-nat", bucket: Bucket::PathMtu, required_inputs: &[], emits_json: true, platform: Platform::AnyPlatform, needs_privilege: false, gaps: Some("GAP-028"), summary: "Multi-uplink ECMP/LAG hash and NAT-affinity diagnostic via fixed-5-tuple port sweeps (GAP-028)" },
    Cmd { name: "ecn-aqm", bucket: Bucket::PathMtu, required_inputs: &[], emits_json: true, platform: Platform::AnyPlatform, needs_privilege: false, gaps: Some("GAP-023"), summary: "ECN/AQM capability and CE-mark counting with classic-ECN-vs-L4S distinction (GAP-023)" },
    Cmd { name: "endpoints", bucket: Bucket::Throughput, required_inputs: &[], emits_json: true, platform: Platform::AnyPlatform, needs_privilege: false, gaps: None, summary: "Known iperf3 endpoints and the ports recorded as failing, so a known-bad endpoint is never retried or scored as zero throughput" },
    Cmd { name: "first-hop", bucket: Bucket::PathMtu, required_inputs: &[], emits_json: true, platform: Platform::AnyPlatform, needs_privilege: false, gaps: Some("GAP-022"), summary: "First-hop gateway isolation with non-ICMP fallback when echo is suppressed (GAP-022)" },
    Cmd { name: "fleet-orchestrator", bucket: Bucket::Infrastructure, required_inputs: &[], emits_json: true, platform: Platform::AnyPlatform, needs_privilege: false, gaps: Some("GAP-038"), summary: "Distributed wireless-probe fleet orchestrator: management/test-node separation, redacted labels, bounded fanout (GAP-038)" },
    Cmd { name: "flow-dscp-matrix", bucket: Bucket::Throughput, required_inputs: &["INTERFACE", "TARGET"], emits_json: true, platform: Platform::MacOsForLiveSampling, needs_privilege: false, gaps: Some("GAP-034"), summary: "Constant-aggregate flow-count sweep with DSCP marking-survival qualification (GAP-034)" },
    Cmd { name: "fuzz", bucket: Bucket::SecurityPolicy, required_inputs: &["TARGET"], emits_json: false, platform: Platform::AnyPlatform, needs_privilege: false, gaps: None, summary: "Packet fuzzing for security testing" },
    Cmd { name: "gateway-bracket", bucket: Bucket::Throughput, required_inputs: &[], emits_json: true, platform: Platform::AnyPlatform, needs_privilege: false, gaps: Some("GAP-044"), summary: "Pair idle/upload/download/simultaneous load phases with a first-hop gateway RTT/loss bracket (GAP-044)" },
    Cmd { name: "https", bucket: Bucket::Tools, required_inputs: &["TARGET"], emits_json: false, platform: Platform::AnyPlatform, needs_privilege: false, gaps: None, summary: "Test HTTPS connectivity with stage-by-stage analysis (MTU blackhole detection)" },
    Cmd { name: "independent-rates", bucket: Bucket::Throughput, required_inputs: &[], emits_json: true, platform: Platform::AnyPlatform, needs_privilege: false, gaps: Some("GAP-032"), summary: "Independently rate-controlled, time-aligned simultaneous upload/download sweep (GAP-032)" },
    Cmd { name: "iperf-analyze", bucket: Bucket::Throughput, required_inputs: &[], emits_json: true, platform: Platform::AnyPlatform, needs_privilege: false, gaps: Some("GAP-036,GAP-039"), summary: "Version/direction-aware iperf3 JSON parsing and explicit-allowlist endpoint capability discovery (GAP-039/GAP-036)" },
    Cmd { name: "ipv6-validate", bucket: Bucket::DnsAddressing, required_inputs: &["INTERFACE"], emits_json: true, platform: Platform::AnyPlatform, needs_privilege: false, gaps: Some("GAP-015,GAP-056"), summary: "Decomposed IPv6/NAT64/DNS64 validation with separate IPv4 and IPv6 verdicts, plus Happy Eyeballs timing (GAP-056/GAP-015)" },
    Cmd { name: "kitchen-sink", bucket: Bucket::PathMtu, required_inputs: &[], emits_json: true, platform: Platform::AnyPlatform, needs_privilege: false, gaps: None, summary: "Run all tests against common targets and give final verdict" },
    Cmd { name: "listener-lease", bucket: Bucket::Throughput, required_inputs: &["ALLOW", "USE_LISTENER"], emits_json: true, platform: Platform::AnyPlatform, needs_privilege: false, gaps: Some("GAP-040"), summary: "Authorized-only listener leasing with per-transport capacity/duration qualification and endpoint loss-floor declaration (GAP-040)" },
    Cmd { name: "load-guard", bucket: Bucket::Throughput, required_inputs: &[], emits_json: true, platform: Platform::MacOsForLiveSampling, needs_privilege: false, gaps: Some("GAP-027,GAP-047"), summary: "Run a budget-guarded, radio-monitored load phase (GAP-027/GAP-047)" },
    Cmd { name: "media-quality", bucket: Bucket::SecurityPolicy, required_inputs: &["INTERFACE", "TARGET"], emits_json: true, platform: Platform::MacOsForLiveSampling, needs_privilege: false, gaps: Some("GAP-052"), summary: "Synthetic RTP/WebRTC media-quality probe: setup/ICE, burst-derived concealment/freeze risk, MOS-style estimate (GAP-052)" },
    Cmd { name: "mss-evidence", bucket: Bucket::PathMtu, required_inputs: &[], emits_json: true, platform: Platform::AnyPlatform, needs_privilege: false, gaps: Some("GAP-010,GAP-026"), summary: "SYN/SYN-ACK MSS evidence (local/peer/middlebox) and multi-destination MSS clustering vs route MTU (GAP-010/GAP-026)" },
    Cmd { name: "multi", bucket: Bucket::PathMtu, required_inputs: &["TARGETS"], emits_json: false, platform: Platform::AnyPlatform, needs_privilege: false, gaps: None, summary: "Test multiple targets and compare path MTUs" },
    Cmd { name: "multicast-isolation", bucket: Bucket::DnsAddressing, required_inputs: &[], emits_json: true, platform: Platform::AnyPlatform, needs_privilege: false, gaps: Some("GAP-057"), summary: "Discovery/multicast/peer-isolation policy diagnostic: declared expected-reachable/expected-blocked verdicts, name-free responder tallies (GAP-057)" },
    Cmd { name: "multiclient-fairness", bucket: Bucket::WifiRf, required_inputs: &[], emits_json: true, platform: Platform::AnyPlatform, needs_privilege: false, gaps: Some("GAP-051,GAP-072"), summary: "Coordinated multi-client capacity/fairness: refuses a cross-client verdict until both role descriptors exist and their phase windows overlap (GAP-051/GAP-072)" },
    Cmd { name: "nat-capacity", bucket: Bucket::SecurityPolicy, required_inputs: &["TARGET"], emits_json: true, platform: Platform::MacOsForLiveSampling, needs_privilege: false, gaps: Some("GAP-054"), summary: "Firewall/NAT/session-state capacity matrix: authorization-gated disruptive probing, safe-by-default idle-mapping observation (GAP-054)" },
    Cmd { name: "pcap-report", bucket: Bucket::PathMtu, required_inputs: &["FILES"], emits_json: true, platform: Platform::AnyPlatform, needs_privilege: false, gaps: Some("GAP-019"), summary: "Analyze a PCAP/pcapng capture: vantage point, capture health, qualified MTU/loss verdicts (GAP-019)" },
    Cmd { name: "phy-normalized", bucket: Bucket::WifiRf, required_inputs: &["MEASUREMENTS_FILE"], emits_json: true, platform: Platform::MacOsForLiveSampling, needs_privilege: false, gaps: Some("GAP-042"), summary: "PHY-normalized fleet comparison: offered load as a fraction of each client's own PHY capacity (GAP-042)" },
    Cmd { name: "platform-matrix", bucket: Bucket::WifiRf, required_inputs: &[], emits_json: true, platform: Platform::AnyPlatform, needs_privilege: false, gaps: Some("GAP-063"), summary: "Privacy-safe cross-platform/power-save capability matrix with confound-aware attribution (GAP-063)" },
    Cmd { name: "policy-manifest", bucket: Bucket::SecurityPolicy, required_inputs: &["MANIFEST_FILE"], emits_json: true, platform: Platform::AnyPlatform, needs_privilege: false, gaps: Some("GAP-065"), summary: "Expected-policy and service-reachability manifest: probes only allowlisted targets and flags drift from declared allow/deny policy (GAP-065)" },
    Cmd { name: "preflight", bucket: Bucket::SecurityPolicy, required_inputs: &[], emits_json: true, platform: Platform::AnyPlatform, needs_privilege: false, gaps: Some("GAP-025"), summary: "Preflight ALPN/Alt-Svc + real handshake capability across endpoints (GAP-025)" },
    Cmd { name: "printer-raw", bucket: Bucket::Tools, required_inputs: &["TARGET"], emits_json: false, platform: Platform::AnyPlatform, needs_privilege: false, gaps: None, summary: "Raw JetDirect port 9100 PJL + bulk size sweep" },
    Cmd { name: "privilege-status", bucket: Bucket::SecurityPolicy, required_inputs: &[], emits_json: true, platform: Platform::AnyPlatform, needs_privilege: false, gaps: Some("GAP-016"), summary: "Privileged-operation inventory and failure classification: preserve the error, name the exact command, offer an unprivileged path (GAP-016)" },
    Cmd { name: "probe", bucket: Bucket::PathMtu, required_inputs: &["IFACE", "TARGET"], emits_json: false, platform: Platform::AnyPlatform, needs_privilege: true, gaps: None, summary: "Active MTU probe using the native DSL + send-and-capture engine" },
    Cmd { name: "probe-preflight", bucket: Bucket::Infrastructure, required_inputs: &[], emits_json: true, platform: Platform::AnyPlatform, needs_privilege: false, gaps: Some("GAP-041"), summary: "Remote probe health/dependency preflight: quarantines broken binaries, timeouts, and changed SSH host keys with no auto-accept path (GAP-041)" },
    Cmd { name: "probe-rate", bucket: Bucket::PathMtu, required_inputs: &["GATEWAY", "REMOTE"], emits_json: true, platform: Platform::AnyPlatform, needs_privilege: false, gaps: Some("GAP-021"), summary: "Detect ICMP rate-limiting/batching artifacts by comparing normal vs elevated probe cadence (GAP-021)" },
    Cmd { name: "process-model", bucket: Bucket::Infrastructure, required_inputs: &[], emits_json: true, platform: Platform::AnyPlatform, needs_privilege: false, gaps: Some("GAP-069"), summary: "Process-model equivalence and receive-path artifact guard: withholds a directional-collapse verdict unless it reproduces across native-bidir and paired-process methods (GAP-069)" },
    Cmd { name: "protocol-compare", bucket: Bucket::Throughput, required_inputs: &["HOST"], emits_json: true, platform: Platform::AnyPlatform, needs_privilege: false, gaps: Some("GAP-003,GAP-004"), summary: "Controlled H1/H2/H3 comparison with directional vs simultaneous isolation (GAP-003/GAP-004)" },
    Cmd { name: "provider-path", bucket: Bucket::PathMtu, required_inputs: &["TARGET"], emits_json: true, platform: Platform::AnyPlatform, needs_privilege: false, gaps: Some("GAP-061"), summary: "Provider/geography/path-stability comparison with non-response distinguished from loss (GAP-061)" },
    Cmd { name: "quic", bucket: Bucket::PathMtu, required_inputs: &["TARGET"], emits_json: false, platform: Platform::AnyPlatform, needs_privilege: false, gaps: None, summary: "QUIC/UDP PMTUD probe" },
    Cmd { name: "quick", bucket: Bucket::PathMtu, required_inputs: &["TARGET"], emits_json: false, platform: Platform::AnyPlatform, needs_privilege: false, gaps: None, summary: "Quick ICMP-only MTU test" },
    Cmd { name: "radio-diagnostic", bucket: Bucket::WifiRf, required_inputs: &[], emits_json: true, platform: Platform::MacOsForLiveSampling, needs_privilege: false, gaps: Some("GAP-011"), summary: "Wi-Fi radio/retry diagnostic with safe elevation and explicit platform-limitation reporting (GAP-011)" },
    Cmd { name: "reference-endpoint", bucket: Bucket::Throughput, required_inputs: &[], emits_json: true, platform: Platform::AnyPlatform, needs_privilege: false, gaps: Some("GAP-053"), summary: "Reference-endpoint calibration and client-result acceptance: the endpoint can invalidate a client's measurement (GAP-053)" },
    Cmd { name: "replay", bucket: Bucket::SecurityPolicy, required_inputs: &["PCAP"], emits_json: false, platform: Platform::AnyPlatform, needs_privilege: true, gaps: None, summary: "Replay a PCAP file onto the wire (requires root)" },
    Cmd { name: "report", bucket: Bucket::Tools, required_inputs: &["TARGET"], emits_json: false, platform: Platform::AnyPlatform, needs_privilege: false, gaps: None, summary: "Render a unified README_FIRST-style diagnosis of a target" },
    Cmd { name: "resilience", bucket: Bucket::Infrastructure, required_inputs: &["RUN"], emits_json: true, platform: Platform::AnyPlatform, needs_privilege: false, gaps: Some("GAP-062"), summary: "Controlled resilience/failover validation: observes and labels an operator-performed component change, never initiates one (GAP-062)" },
    Cmd { name: "rf-survey", bucket: Bucket::WifiRf, required_inputs: &[], emits_json: true, platform: Platform::MacOsOnly, needs_privilege: false, gaps: Some("GAP-055"), summary: "Bounded time-series RF survey with platform-limited metric qualification and change-point correlation (GAP-055)" },
    Cmd { name: "roaming", bucket: Bucket::WifiRf, required_inputs: &[], emits_json: true, platform: Platform::MacOsForLiveSampling, needs_privilege: false, gaps: Some("GAP-050"), summary: "Controlled roaming/session-continuity test: privacy-safe AP transitions, handoff duration, and VLAN/public-identity continuity (GAP-050)" },
    Cmd { name: "scenario", bucket: Bucket::Tools, required_inputs: &["FILE"], emits_json: false, platform: Platform::AnyPlatform, needs_privilege: false, gaps: None, summary: "Run a declarative scenario from a file or stdin" },
    Cmd { name: "second-network", bucket: Bucket::Infrastructure, required_inputs: &[], emits_json: true, platform: Platform::AnyPlatform, needs_privilege: false, gaps: Some("GAP-013"), summary: "Second-network control workflow: save/compare a connection fingerprint and test bundle across a network switch (GAP-013)" },
    Cmd { name: "serve", bucket: Bucket::Tools, required_inputs: &[], emits_json: false, platform: Platform::AnyPlatform, needs_privilege: false, gaps: None, summary: "Expose a Prometheus metrics scrape endpoint" },
    Cmd { name: "site-ab", bucket: Bucket::Infrastructure, required_inputs: &["AFFECTED_HOST", "CONTROL_HOST"], emits_json: true, platform: Platform::AnyPlatform, needs_privilege: false, gaps: Some("GAP-012"), summary: "Affected-site vs known-good-control A/B workflow: forced protocol, IP pinning, repeated samples, redirect-aware verdict (GAP-012)" },
    Cmd { name: "size-rate-matrix", bucket: Bucket::Throughput, required_inputs: &["INTERFACE", "TARGET"], emits_json: true, platform: Platform::MacOsForLiveSampling, needs_privilege: false, gaps: Some("GAP-033"), summary: "Datagram-size/packet-rate pressure matrix distinguishing packet-rate ceilings from byte-rate policing (GAP-033)" },
    Cmd { name: "ssh-path", bucket: Bucket::Tools, required_inputs: &["TARGET"], emits_json: false, platform: Platform::AnyPlatform, needs_privilege: false, gaps: None, summary: "SSH banner + optional authenticated echo data-path test" },
    Cmd { name: "stun-turn", bucket: Bucket::DnsAddressing, required_inputs: &[], emits_json: true, platform: Platform::AnyPlatform, needs_privilege: false, gaps: Some("GAP-005"), summary: "Repeated STUN binding requests with validation/RTT, mapped-address change detection, and TURN allocation checks (GAP-005)" },
    Cmd { name: "tcp", bucket: Bucket::PathMtu, required_inputs: &["TARGET"], emits_json: false, platform: Platform::AnyPlatform, needs_privilege: false, gaps: None, summary: "TCP-based MTU discovery (no ICMP required)" },
    Cmd { name: "tcp-options", bucket: Bucket::PathMtu, required_inputs: &["TARGET"], emits_json: false, platform: Platform::AnyPlatform, needs_privilege: false, gaps: None, summary: "Query actual negotiated TCP MSS and detect middlebox rewriting" },
    Cmd { name: "tcp-vs-udp", bucket: Bucket::Throughput, required_inputs: &[], emits_json: true, platform: Platform::MacOsForLiveSampling, needs_privilege: false, gaps: Some("GAP-006"), summary: "Controlled TCP-versus-UDP throughput/loss comparison against a user-supplied endpoint (GAP-006)" },
    Cmd { name: "test", bucket: Bucket::Tools, required_inputs: &["TARGET"], emits_json: false, platform: Platform::AnyPlatform, needs_privilege: false, gaps: None, summary: "Run test framework tests (DNS, HTTPS, TCP, RTT, Loss)" },
    Cmd { name: "throughput-tuner", bucket: Bucket::Throughput, required_inputs: &["HOST", "PORT"], emits_json: true, platform: Platform::AnyPlatform, needs_privilege: false, gaps: Some("GAP-046"), summary: "Version-aware maximum-throughput tuner: randomized trials, duration validation, synthetic-max vs representative-application split (GAP-046)" },
    Cmd { name: "tui", bucket: Bucket::Tools, required_inputs: &[], emits_json: false, platform: Platform::AnyPlatform, needs_privilege: false, gaps: None, summary: "Launch interactive TUI" },
    Cmd { name: "upload-sweep", bucket: Bucket::PathMtu, required_inputs: &["TARGET"], emits_json: false, platform: Platform::AnyPlatform, needs_privilege: false, gaps: None, summary: "HTTP(S) upload size sweep (detects data-stall blackholes)" },
    Cmd { name: "vpn", bucket: Bucket::PathMtu, required_inputs: &["VPN_TYPE"], emits_json: false, platform: Platform::AnyPlatform, needs_privilege: false, gaps: None, summary: "Calculate safe MTU for VPN/SASE/Zero-Trust usage" },
    Cmd { name: "vpn-matrix", bucket: Bucket::SecurityPolicy, required_inputs: &["TARGET"], emits_json: true, platform: Platform::AnyPlatform, needs_privilege: false, gaps: Some("GAP-060"), summary: "VPN/encapsulation compatibility matrix: credential-free protocol reachability and real effective MTU/MSS measurement (GAP-060)" },
    Cmd { name: "wired-control", bucket: Bucket::Infrastructure, required_inputs: &[], emits_json: true, platform: Platform::AnyPlatform, needs_privilege: false, gaps: Some("GAP-030"), summary: "Matched wired-versus-Wi-Fi fault-domain control: withholds WLAN attribution when the two paths' public egress identities differ (GAP-030)" },
    Cmd { name: "wired-edge", bucket: Bucket::Infrastructure, required_inputs: &["BRACKET"], emits_json: true, platform: Platform::AnyPlatform, needs_privilege: false, gaps: Some("GAP-058"), summary: "Wired edge/AP-uplink/LLDP/PoE health bundle: read-only ingest, refuses a conclusion without telemetry (GAP-058)" },
];

/// Commands in one bucket, in declaration order.
pub fn in_bucket(bucket: Bucket) -> Vec<&'static Cmd> {
    COMMANDS.iter().filter(|c| c.bucket == bucket).collect()
}

/// Look up one command by its CLI name.
pub fn find(name: &str) -> Option<&'static Cmd> {
    COMMANDS.iter().find(|c| c.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_command_has_a_bucket_and_a_summary() {
        for c in COMMANDS {
            assert!(!c.name.is_empty());
            assert!(!c.summary.is_empty(), "{} has no summary", c.name);
            assert!(Bucket::ALL.contains(&c.bucket), "{} has an unlisted bucket", c.name);
        }
    }

    #[test]
    fn command_names_are_unique() {
        let mut seen = std::collections::BTreeSet::new();
        for c in COMMANDS {
            assert!(seen.insert(c.name), "duplicate registry entry for {}", c.name);
        }
    }

    #[test]
    fn every_bucket_has_at_least_one_command() {
        for b in Bucket::ALL {
            assert!(!in_bucket(*b).is_empty(), "{:?} is empty", b);
        }
    }

    /// `--json` is only appended where the command supports it: 21 commands
    /// would fail on an unknown flag.
    #[test]
    fn json_flag_is_added_only_where_supported() {
        let with = find("endpoints").expect("endpoints is registered");
        assert!(with.emits_json);
        assert!(with.invocation(&[]).contains(&"--json".to_string()));

        let without = find("report").expect("report is registered");
        assert!(!without.emits_json, "report has no --json mode");
        assert!(!without.invocation(&[]).contains(&"--json".to_string()));
    }

    #[test]
    fn an_existing_json_flag_is_not_duplicated() {
        let c = find("endpoints").unwrap();
        let inv = c.invocation(&["--json".to_string()]);
        assert_eq!(inv.iter().filter(|a| *a == "--json").count(), 1);
    }

    /// A command whose live path needs macOS must still be offered elsewhere in
    /// ingest mode, not blocked outright: ap-compat-matrix from --ingest-cells
    /// works fine on Linux.
    #[test]
    fn live_sampling_commands_are_ingest_only_off_macos_not_blocked() {
        let c = find("ap-compat-matrix").unwrap();
        assert_eq!(c.platform, Platform::MacOsForLiveSampling);
        match c.availability() {
            Availability::Available => assert!(cfg!(target_os = "macos")),
            Availability::IngestOnly(reason) => {
                assert!(!cfg!(target_os = "macos"));
                assert!(reason.contains("operator JSON"), "{reason}");
            }
            Availability::Unavailable(_) => panic!("must not be blocked: ingest works anywhere"),
        }
    }

    /// A command with no ingest alternative must be blocked with a reason, never
    /// silently offered to return nothing.
    #[test]
    fn macos_only_commands_are_blocked_elsewhere_with_a_reason() {
        let c = find("rf-survey").unwrap();
        assert_eq!(c.platform, Platform::MacOsOnly);
        match c.availability() {
            Availability::Available => assert!(cfg!(target_os = "macos")),
            Availability::Unavailable(reason) => assert!(reason.contains("macOS"), "{reason}"),
            Availability::IngestOnly(_) => panic!("rf-survey has no ingest mode"),
        }
    }

    #[test]
    fn privileged_commands_are_declared() {
        for name in ["replay", "capture", "probe"] {
            assert!(find(name).unwrap().needs_privilege, "{name} needs root but is not declared");
        }
        assert!(!find("endpoints").unwrap().needs_privilege);
    }

    /// Commands requiring input must say so, so a UI prompts rather than
    /// launching a run that immediately errors.
    #[test]
    fn commands_requiring_input_declare_it() {
        assert!(find("circuit-compare").unwrap().required_inputs.contains(&"MANIFEST"));
        assert!(find("diagnose").unwrap().required_inputs.contains(&"TARGET"));
        assert!(find("endpoints").unwrap().required_inputs.is_empty());
    }
}
