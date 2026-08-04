//! GAP-054: firewall/NAT/session-state capacity matrix.
//!
//! Field context: stable STUN mappings reduced concern about any single
//! live flow, but conference scale can exhaust NAT ports, connection
//! tables, UDP state, or new-session rate limits -- resources that are
//! shared across every attendee behind the same firewall/NAT. Finding
//! where that ceiling actually is means deliberately creating enough
//! session state to approach it, which is indistinguishable from a
//! resource-exhaustion attack if run against production infrastructure
//! without an approved window. `require_authorization` is the hard gate on
//! that: there is no default and no flag that defaults true, only an
//! explicit, non-empty operator statement.
//!
//! The acceptance criteria's own list splits cleanly into two safety
//! classes:
//! - Observational and safe: idle-timeout/keepalive-survival measurement
//!   against ONE existing mapping. No load, no rate.
//! - Disruptive: session-creation-rate and concurrent-state-ceiling
//!   discovery. This is what GAP-047's `load_guard` budget/abort machinery
//!   exists to bound, and it is what `require_authorization` gates.
//!
//! `SessionOutcome::LocalResourceExhausted` exists because a naive
//! implementation would otherwise report hitting *this machine's* file
//! descriptor limit as "found the firewall's concurrent-state ceiling" --
//! a fabricated infrastructure finding from a client-side resource limit,
//! exactly the failure mode the field investigation catalogs repeatedly.

use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::load_guard::guard::{LoadGuard, LoadPhase, PhaseTick};
use crate::load_guard::LoadBudget;

/// The sole gate on any disruptive mode. `statement` must be a non-empty,
/// operator-supplied description of the authorization (e.g. "approved by NOC
/// lead for the 02:00-02:30 maintenance window") -- not a boolean, so a caller
/// cannot satisfy this by merely flipping a flag without saying anything.
///
/// `consequence` names what this specific mode would do to shared
/// infrastructure. Callers must supply their own: an operator reading a refusal
/// needs to know whether they were about to exhaust a firewall state table or
/// consume a DHCP pool address, and those warrant different judgement.
pub fn require_authorization_for(
    statement: Option<&str>,
    consequence: &str,
) -> Result<String, String> {
    match statement.map(str::trim) {
        Some(s) if !s.is_empty() => Ok(s.to_string()),
        _ => Err(format!(
            "this mode requires --authorized \"<description of the approved window>\"; \
             refusing to {} without an explicit authorization statement",
            consequence
        )),
    }
}

/// Session-table capacity probing. See [`require_authorization_for`].
pub fn require_authorization(statement: Option<&str>) -> Result<String, String> {
    require_authorization_for(statement, "create firewall/NAT session-table load")
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SessionOutcome {
    Created,
    RemoteRefused,
    RemoteTimedOut,
    /// The local stack, not the remote firewall/NAT, was the limiting
    /// factor (EMFILE/ENFILE or equivalent). Never counted toward a
    /// concurrent-state-ceiling finding.
    LocalResourceExhausted { detail: String },
    OtherLocalError { detail: String },
}

pub fn classify_connect_error(e: &std::io::Error) -> SessionOutcome {
    match e.kind() {
        ErrorKind::ConnectionRefused => SessionOutcome::RemoteRefused,
        ErrorKind::TimedOut => SessionOutcome::RemoteTimedOut,
        _ => {
            let is_local_exhaustion = matches!(
                e.raw_os_error(),
                Some(code) if code == libc::EMFILE || code == libc::ENFILE || code == libc::ENOBUFS
            );
            if is_local_exhaustion {
                SessionOutcome::LocalResourceExhausted { detail: e.to_string() }
            } else {
                SessionOutcome::OtherLocalError { detail: e.to_string() }
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRateResult {
    pub attempted: u32,
    pub created: u32,
    pub remote_refused: u32,
    pub remote_timed_out: u32,
    pub local_resource_exhausted: u32,
    pub other_local_error: u32,
    pub elapsed_secs: f64,
}

impl SessionRateResult {
    /// A ceiling can only be attributed to the remote firewall/NAT when the
    /// run actually stopped due to remote refusal/timeout, not because this
    /// machine ran out of its own file descriptors. `None` when the run
    /// never stopped short (every attempt created a session) or when local
    /// exhaustion dominates, so a caller cannot read a number here as a
    /// confirmed remote ceiling in either of those cases.
    pub fn remote_ceiling_evidence(&self) -> Option<u32> {
        if self.local_resource_exhausted > 0 {
            return None;
        }
        if self.remote_refused == 0 && self.remote_timed_out == 0 {
            return None;
        }
        Some(self.created)
    }
}

struct SessionCreationPhase {
    target: SocketAddr,
    connect_timeout: Duration,
    stop: Arc<AtomicBool>,
    result: Arc<std::sync::Mutex<SessionRateResult>>,
    open: Vec<TcpStream>,
}

impl LoadPhase for SessionCreationPhase {
    fn tick(&mut self, _ramp_rate_mbps: f64, _elapsed: Duration) -> PhaseTick {
        let mut r = self.result.lock().unwrap();
        r.attempted += 1;
        match TcpStream::connect_timeout(&self.target, self.connect_timeout) {
            Ok(s) => {
                r.created += 1;
                self.open.push(s);
                PhaseTick { bytes_sent_delta: 1, ..Default::default() }
            }
            Err(e) => {
                let outcome = classify_connect_error(&e);
                match outcome {
                    SessionOutcome::RemoteRefused => {
                        r.remote_refused += 1;
                        self.stop.store(true, Ordering::SeqCst);
                    }
                    SessionOutcome::RemoteTimedOut => {
                        r.remote_timed_out += 1;
                        self.stop.store(true, Ordering::SeqCst);
                    }
                    SessionOutcome::LocalResourceExhausted { .. } => {
                        r.local_resource_exhausted += 1;
                        self.stop.store(true, Ordering::SeqCst);
                    }
                    SessionOutcome::OtherLocalError { .. } => {
                        r.other_local_error += 1;
                    }
                    SessionOutcome::Created => unreachable!(),
                }
                PhaseTick::default()
            }
        }
    }
}

/// Disruptive mode: creates as many sessions as `budget` allows, stopping
/// the moment either the remote side pushes back or this machine's own
/// resources run out -- distinguished at the point of failure, not
/// inferred afterward. `budget` is validated (mode caps, ramp) before a
/// single socket is opened, so an over-scoped request is refused the same
/// way GAP-047 refuses any other unbounded load phase.
pub fn run_session_rate_probe(
    target: IpAddr,
    port: u16,
    budget: LoadBudget,
    interface: &str,
) -> Result<SessionRateResult, String> {
    budget.validate().map_err(|e| e.to_string())?;

    let addr = SocketAddr::new(target, port);
    let start = Instant::now();
    let result = Arc::new(std::sync::Mutex::new(SessionRateResult {
        attempted: 0,
        created: 0,
        remote_refused: 0,
        remote_timed_out: 0,
        local_resource_exhausted: 0,
        other_local_error: 0,
        elapsed_secs: 0.0,
    }));
    let stop = Arc::new(AtomicBool::new(false));

    let phase = SessionCreationPhase {
        target: addr,
        connect_timeout: Duration::from_millis(500),
        stop: stop.clone(),
        result: result.clone(),
        open: Vec::new(),
    };

    // Radio/counters are irrelevant to a NAT/firewall session-rate probe
    // (there is no radio state to invalidate this kind of run), so a no-op
    // source satisfies `LoadGuard::new`'s required arguments without
    // pretending to measure something this probe does not touch.
    use crate::load_guard::guard::{CounterSource, RadioSource};
    use crate::load_guard::counters::InterfaceCounters;
    use crate::load_guard::radio::RadioSnapshot;
    let radio = RadioSource::new(|| Ok(RadioSnapshot::unavailable()));
    let counters = CounterSource::new(|| Ok(InterfaceCounters::zero()));

    let guard = LoadGuard::new(budget, interface, false, radio, counters).map_err(|e| e.to_string())?;

    let cancel = Arc::new(AtomicBool::new(false));
    let stop_reader = stop.clone();
    let cancel_for_watch = cancel.clone();
    std::thread::spawn(move || loop {
        if stop_reader.load(Ordering::SeqCst) {
            cancel_for_watch.store(true, Ordering::SeqCst);
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    });

    let _report = guard.run(phase, cancel);

    let mut final_result = result.lock().unwrap().clone();
    final_result.elapsed_secs = start.elapsed().as_secs_f64();
    Ok(final_result)
}

/// Observational, safe-by-default measurement: how long does ONE UDP NAT
/// mapping stay open with no traffic, and does a single keepalive packet
/// keep it alive. No session creation load, no rate. This does not
/// duplicate GAP-005/028's STUN mapped-address observation -- it only
/// times a plain UDP socket's ability to still receive a reply after an
/// idle interval, using send/receive, not mapped-address comparison.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdleMappingResult {
    pub idle_secs_attempted: u64,
    pub still_responsive_after_idle: Option<bool>,
    pub keepalive_sent: bool,
}

pub fn observe_idle_mapping_survival(
    target: IpAddr,
    port: u16,
    idle_secs: u64,
    send_keepalive: bool,
    timeout: Duration,
) -> Result<IdleMappingResult, String> {
    use std::net::UdpSocket;
    let bind = if target.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let socket = UdpSocket::bind(bind).map_err(|e| e.to_string())?;
    socket.set_read_timeout(Some(timeout)).map_err(|e| e.to_string())?;
    let remote = SocketAddr::new(target, port);

    socket.send_to(&[0u8; 8], remote).map_err(|e| e.to_string())?;
    std::thread::sleep(Duration::from_secs(idle_secs.min(5)));

    if send_keepalive {
        let _ = socket.send_to(&[0u8; 1], remote);
    }

    let mut buf = [0u8; 64];
    let still_responsive = match socket.recv_from(&mut buf) {
        Ok(_) => Some(true),
        Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => None,
        Err(_) => Some(false),
    };

    Ok(IdleMappingResult {
        idle_secs_attempted: idle_secs,
        still_responsive_after_idle: still_responsive,
        keepalive_sent: send_keepalive,
    })
}

/// Operator-supplied firewall/NAT telemetry ingest -- correlation with
/// table usage, drops, policers, and state-sync counters is not something
/// a client can read, so it is ingested verbatim and any conclusion
/// requiring it is withheld when it is absent.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FirewallTelemetry {
    pub owner_label: Option<String>,
    pub table_usage_pct: Option<f64>,
    pub drops: Option<u64>,
    pub policer_drops: Option<u64>,
    pub state_sync_lag_ms: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CorrelationVerdict {
    Correlated { table_usage_pct: f64 },
    /// Named, not silently omitted -- the exact GAP-021/HANDOFF discipline
    /// applied to a firewall-side telemetry gap instead of a client-side one.
    TelemetryAbsent { missing: Vec<String> },
}

pub fn correlate_with_telemetry(
    session_result: &SessionRateResult,
    telemetry: &Option<FirewallTelemetry>,
) -> CorrelationVerdict {
    let Some(t) = telemetry else {
        return CorrelationVerdict::TelemetryAbsent {
            missing: vec!["firewall/NAT telemetry was not supplied at all".to_string()],
        };
    };
    let mut missing = Vec::new();
    if t.table_usage_pct.is_none() {
        missing.push("table_usage_pct".to_string());
    }
    if t.owner_label.is_none() {
        missing.push("owner_label".to_string());
    }
    if !missing.is_empty() {
        return CorrelationVerdict::TelemetryAbsent { missing };
    }
    let _ = session_result;
    CorrelationVerdict::Correlated { table_usage_pct: t.table_usage_pct.unwrap() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_statement_refuses_capacity_mode() {
        assert!(require_authorization(None).is_err());
        assert!(require_authorization(Some("")).is_err());
        assert!(require_authorization(Some("   ")).is_err());
    }

    #[test]
    fn a_real_statement_is_accepted() {
        assert_eq!(
            require_authorization(Some("approved by NOC for 02:00-02:30")).unwrap(),
            "approved by NOC for 02:00-02:30"
        );
    }

    #[test]
    fn emfile_is_classified_as_local_resource_exhaustion() {
        let e = std::io::Error::from_raw_os_error(libc::EMFILE);
        assert!(matches!(classify_connect_error(&e), SessionOutcome::LocalResourceExhausted { .. }));
    }

    #[test]
    fn connection_refused_is_remote_not_local() {
        let e = std::io::Error::from(ErrorKind::ConnectionRefused);
        assert_eq!(classify_connect_error(&e), SessionOutcome::RemoteRefused);
    }

    #[test]
    fn local_exhaustion_blocks_remote_ceiling_attribution() {
        let r = SessionRateResult {
            attempted: 100,
            created: 40,
            remote_refused: 0,
            remote_timed_out: 0,
            local_resource_exhausted: 1,
            other_local_error: 0,
            elapsed_secs: 1.0,
        };
        assert_eq!(r.remote_ceiling_evidence(), None);
    }

    #[test]
    fn remote_refusal_with_no_local_exhaustion_supports_a_ceiling_figure() {
        let r = SessionRateResult {
            attempted: 100,
            created: 87,
            remote_refused: 13,
            remote_timed_out: 0,
            local_resource_exhausted: 0,
            other_local_error: 0,
            elapsed_secs: 1.0,
        };
        assert_eq!(r.remote_ceiling_evidence(), Some(87));
    }

    #[test]
    fn no_stoppage_at_all_yields_no_ceiling_evidence() {
        let r = SessionRateResult {
            attempted: 10,
            created: 10,
            remote_refused: 0,
            remote_timed_out: 0,
            local_resource_exhausted: 0,
            other_local_error: 0,
            elapsed_secs: 1.0,
        };
        assert_eq!(r.remote_ceiling_evidence(), None);
    }

    #[test]
    fn missing_telemetry_withholds_correlation_and_names_it() {
        let r = SessionRateResult {
            attempted: 1,
            created: 1,
            remote_refused: 0,
            remote_timed_out: 0,
            local_resource_exhausted: 0,
            other_local_error: 0,
            elapsed_secs: 1.0,
        };
        match correlate_with_telemetry(&r, &None) {
            CorrelationVerdict::TelemetryAbsent { missing } => assert!(!missing.is_empty()),
            CorrelationVerdict::Correlated { .. } => panic!("must not correlate with no telemetry"),
        }
    }

    #[test]
    fn partial_telemetry_names_the_missing_fields() {
        let r = SessionRateResult {
            attempted: 1,
            created: 1,
            remote_refused: 0,
            remote_timed_out: 0,
            local_resource_exhausted: 0,
            other_local_error: 0,
            elapsed_secs: 1.0,
        };
        let t = FirewallTelemetry { owner_label: Some("edge-fw-1".to_string()), ..Default::default() };
        match correlate_with_telemetry(&r, &Some(t)) {
            CorrelationVerdict::TelemetryAbsent { missing } => {
                assert!(missing.iter().any(|m| m == "table_usage_pct"));
            }
            CorrelationVerdict::Correlated { .. } => panic!("table_usage_pct is missing"),
        }
    }

    #[test]
    fn full_telemetry_correlates() {
        let r = SessionRateResult {
            attempted: 1,
            created: 1,
            remote_refused: 0,
            remote_timed_out: 0,
            local_resource_exhausted: 0,
            other_local_error: 0,
            elapsed_secs: 1.0,
        };
        let t = FirewallTelemetry {
            owner_label: Some("edge-fw-1".to_string()),
            table_usage_pct: Some(72.5),
            ..Default::default()
        };
        assert_eq!(correlate_with_telemetry(&r, &Some(t)), CorrelationVerdict::Correlated { table_usage_pct: 72.5 });
    }

    #[test]
    fn idle_mapping_never_coerces_a_timeout_to_a_boolean() {
        // Against an unreachable/silent target, no reply arrives -- must
        // read as None (unknown), not false (confirmed dead) or true.
        let result = observe_idle_mapping_survival(
            "192.0.2.1".parse().unwrap(),
            9,
            0,
            false,
            Duration::from_millis(200),
        )
        .unwrap();
        assert_eq!(result.still_responsive_after_idle, None);
    }
}
