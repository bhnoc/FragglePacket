//! Vendor-neutral registry of iperf3 endpoints and their observed behavior.
//!
//! Operators were hand-typing endpoints, which meant the ports already known to
//! refuse or fail admission got retried every session. Worse, GAP-045's lesson
//! is that a port-open check is not admission validation: eight of twenty-one
//! probes in one fanout never established a connection after their port checks
//! passed, and scoring those as 0 Mbps would have implicated nine working
//! clients.
//!
//! So this registry records what was *actually observed*, including the
//! failures, and refuses to hand out a listener already known to be bad. Nothing
//! here is vendor-specific; a provider is just a name, a documentation URL, and
//! a set of observations.

use serde::{Deserialize, Serialize};

use super::listener_lease::AuthorizedListener;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryListener {
    pub host: String,
    pub port: u16,
    pub region_label: Option<String>,
    #[serde(default)]
    pub transport: Vec<String>,
    /// What was observed when this listener was exercised.
    pub verified: Option<String>,
    pub verified_on: Option<String>,
    /// Which direction this listener served. Two directions on one listener is
    /// not possible: each accepts one test at a time.
    pub purpose: Option<String>,
    pub observed: Option<String>,
}

/// A port that was exercised and did not work. Recorded so it is never retried
/// and, critically, never scored as a zero-throughput measurement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnownBadPort {
    pub host: String,
    /// Either a single port or a range of them; the source registry uses both
    /// shapes depending on what was tested.
    pub port: Option<u16>,
    #[serde(default)]
    pub ports: Vec<u16>,
    pub outcome: String,
    pub verified_on: Option<String>,
    pub must_not_be_recorded_as: Option<String>,
    pub why_it_matters: Option<String>,
}

impl KnownBadPort {
    pub fn covers(&self, host: &str, port: u16) -> bool {
        if self.host != host {
            return false;
        }
        self.port == Some(port) || self.ports.contains(&port)
    }

    pub fn all_ports(&self) -> Vec<u16> {
        let mut v = self.ports.clone();
        if let Some(p) = self.port {
            v.push(p);
        }
        v
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Provider {
    pub provider: String,
    pub documentation: Option<String>,
    /// What authorization this endpoint rests on. A public service is not the
    /// same as a private agreement, and results must be qualified accordingly.
    pub authorization: Option<String>,
    #[serde(default)]
    pub listeners: Vec<RegistryListener>,
    #[serde(default)]
    pub known_bad_ports: Vec<KnownBadPort>,
    #[serde(default)]
    pub caveats: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointRegistry {
    pub schema_version: u32,
    pub note: Option<String>,
    #[serde(default)]
    pub providers: Vec<Provider>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SelectionError {
    UnknownProvider { requested: String, available: Vec<String> },
    /// The requested host:port is recorded as having failed. Handing it out
    /// again would reproduce a known endpoint failure and risk recording it as
    /// a network measurement.
    KnownBad { host: String, port: u16, outcome: String },
    NoListenerForPurpose { provider: String, purpose: String },
}

impl SelectionError {
    pub fn message(&self) -> String {
        match self {
            SelectionError::UnknownProvider { requested, available } => format!(
                "no provider named '{}' in the registry; available: {}",
                requested,
                if available.is_empty() { "none".to_string() } else { available.join(", ") }
            ),
            SelectionError::KnownBad { host, port, outcome } => format!(
                "{}:{} is recorded as a known-bad endpoint ({}); refusing to use it, since a repeat \
                 failure could be recorded as a network measurement rather than an endpoint one",
                host, port, outcome
            ),
            SelectionError::NoListenerForPurpose { provider, purpose } => format!(
                "provider '{}' has no verified listener for '{}'",
                provider, purpose
            ),
        }
    }
}

impl EndpointRegistry {
    pub fn from_json(text: &str) -> Result<Self, String> {
        serde_json::from_str(text).map_err(|e| format!("registry is not valid JSON: {}", e))
    }

    pub fn load(path: &str) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("could not read registry {}: {}", path, e))?;
        Self::from_json(&text)
    }

    pub fn provider(&self, name: &str) -> Option<&Provider> {
        self.providers.iter().find(|p| p.provider == name)
    }

    pub fn provider_names(&self) -> Vec<String> {
        self.providers.iter().map(|p| p.provider.clone()).collect()
    }

    /// True when this host:port was exercised and failed.
    pub fn is_known_bad(&self, host: &str, port: u16) -> Option<&KnownBadPort> {
        self.providers
            .iter()
            .flat_map(|p| p.known_bad_ports.iter())
            .find(|b| b.covers(host, port))
    }

    /// Picks a verified listener for a stated purpose, refusing a known-bad one.
    pub fn select(&self, provider: &str, purpose: &str) -> Result<&RegistryListener, SelectionError> {
        let p = self.provider(provider).ok_or_else(|| SelectionError::UnknownProvider {
            requested: provider.to_string(),
            available: self.provider_names(),
        })?;

        for l in &p.listeners {
            let matches_purpose = l
                .purpose
                .as_deref()
                .map(|s| s.to_lowercase().contains(&purpose.to_lowercase()))
                .unwrap_or(false);
            if !matches_purpose {
                continue;
            }
            if let Some(bad) = self.is_known_bad(&l.host, l.port) {
                return Err(SelectionError::KnownBad {
                    host: l.host.clone(),
                    port: l.port,
                    outcome: bad.outcome.clone(),
                });
            }
            return Ok(l);
        }

        Err(SelectionError::NoListenerForPurpose {
            provider: provider.to_string(),
            purpose: purpose.to_string(),
        })
    }

    /// Builds an allowlist for `listener_lease` from verified listeners only.
    /// Known-bad ports are excluded by construction, so the lease layer cannot
    /// be handed one by accident.
    pub fn allowlist_for(&self, provider: &str) -> Result<Vec<AuthorizedListener>, SelectionError> {
        let p = self.provider(provider).ok_or_else(|| SelectionError::UnknownProvider {
            requested: provider.to_string(),
            available: self.provider_names(),
        })?;
        Ok(p.listeners
            .iter()
            .filter(|l| self.is_known_bad(&l.host, l.port).is_none())
            .map(|l| AuthorizedListener { host: l.host.clone(), port: l.port })
            .collect())
    }

    /// Every caveat that applies to a provider's results. These are not
    /// decoration: they name the endpoint loss floor, the one-test-per-listener
    /// limit, and the drift that make a public measurement qualified rather
    /// than authoritative.
    pub fn caveats_for(&self, provider: &str) -> Vec<String> {
        self.provider(provider).map(|p| p.caveats.clone()).unwrap_or_default()
    }

    /// True when the two listeners chosen for opposite directions sit on
    /// different hosts, which makes a simultaneous result span two provider
    /// paths. GAP-017's endpoint-mismatch concern, applied to the registry.
    pub fn directions_span_different_hosts(a: &RegistryListener, b: &RegistryListener) -> bool {
        a.host != b.host
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REGISTRY: &str = include_str!("../../harness/fixtures/endpoints/public-iperf.json");

    fn reg() -> EndpointRegistry {
        EndpointRegistry::from_json(REGISTRY).expect("bundled registry must parse")
    }

    #[test]
    fn the_bundled_registry_parses() {
        let r = reg();
        assert_eq!(r.schema_version, 1);
        assert!(r.provider("xmission").is_some());
    }

    #[test]
    fn a_verified_listener_is_selected_per_direction() {
        let r = reg();
        let up = r.select("xmission", "upload").expect("upload listener");
        let down = r.select("xmission", "download").expect("download listener");
        assert_eq!(up.port, 5201);
        assert_eq!(down.port, 5201);
        // Different hosts: that is the comparison caveat, not a bug.
        assert!(EndpointRegistry::directions_span_different_hosts(up, down));
    }

    #[test]
    fn the_refused_port_is_known_bad() {
        let r = reg();
        let bad = r
            .is_known_bad("speedtest.xmission.com", 5200)
            .expect("port 5200 refused and must be recorded");
        assert!(bad.outcome.to_lowercase().contains("refused"));
    }

    #[test]
    fn the_admission_failing_range_is_known_bad() {
        let r = reg();
        for port in [5202u16, 5203, 5204, 5205, 5206] {
            assert!(
                r.is_known_bad("speedtest.xmission.com", port).is_some(),
                "port {} failed admission in the field and must be recorded",
                port
            );
        }
    }

    #[test]
    fn a_known_bad_port_is_never_in_the_lease_allowlist() {
        // The central regression: the lease layer must not be handed a port
        // already known to fail, because a repeat failure could be recorded as
        // a network measurement rather than an endpoint one.
        let r = reg();
        let allow = r.allowlist_for("xmission").expect("allowlist");
        for l in &allow {
            assert!(
                r.is_known_bad(&l.host, l.port).is_none(),
                "{}:{} is known bad but reached the allowlist",
                l.host,
                l.port
            );
        }
        assert!(!allow.is_empty(), "verified listeners must survive filtering");
    }

    #[test]
    fn a_known_bad_outcome_is_never_described_as_zero_throughput() {
        let r = reg();
        for p in &r.providers {
            for b in &p.known_bad_ports {
                let note = b.must_not_be_recorded_as.clone().unwrap_or_default();
                assert!(
                    note.contains("zero throughput"),
                    "{:?} must state it is not a zero-throughput result",
                    b.all_ports()
                );
                assert!(
                    !b.outcome.contains("0 Mbps"),
                    "an admission failure must not be phrased as a rate"
                );
            }
        }
    }

    #[test]
    fn caveats_name_the_endpoint_loss_floor_and_single_test_limit() {
        let c = reg().caveats_for("xmission").join(" ").to_lowercase();
        assert!(c.contains("loss floor"), "the 0.6-1.0% endpoint floor must be stated");
        assert!(c.contains("one test at a time"), "the per-listener limit must be stated");
        assert!(c.contains("different"), "the two-path comparison caveat must be stated");
    }

    #[test]
    fn an_unknown_provider_lists_what_is_available() {
        let e = reg().select("nope", "upload").unwrap_err();
        match &e {
            SelectionError::UnknownProvider { available, .. } => {
                assert!(available.contains(&"xmission".to_string()));
            }
            other => panic!("expected UnknownProvider, got {:?}", other),
        }
        assert!(e.message().contains("available"));
    }

    #[test]
    fn an_unmatched_purpose_errors_rather_than_returning_any_listener() {
        // Handing back an arbitrary listener for an unrecognized purpose is how
        // an upload test ends up measuring a download path.
        let e = reg().select("xmission", "multicast").unwrap_err();
        assert!(matches!(e, SelectionError::NoListenerForPurpose { .. }));
    }

    #[test]
    fn client_source_ports_are_not_treated_as_listeners() {
        // 40010-40019 held 5-tuples stable across ECMP hash buckets. Probing
        // them as servers would be both wrong and rude.
        let r = reg();
        let allow = r.allowlist_for("xmission").expect("allowlist");
        for port in 40010u16..=40019 {
            assert!(
                !allow.iter().any(|l| l.port == port),
                "client source port {} must never appear as a listener",
                port
            );
        }
    }
}
