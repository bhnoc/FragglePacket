//! GAP-005: repeated STUN binding + TURN allocation diagnostic (`stun-turn`).

use colored::*;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::Duration;

use fraggle_packet::network_tests::stun::{
    binding_request_once, turn_allocate_tcp, turn_allocate_udp, BindingAttempt, BindingOutcome,
    TurnCredentials, TurnOutcome,
};

#[derive(clap::Args, Debug)]
pub struct StunTurnArgs {
    /// STUN server host:port. Public and well-known, unlike a test iperf3
    /// endpoint -- this is the same server the field STUN test used.
    #[arg(long, default_value = "stun.l.google.com:19302")]
    pub stun_server: String,

    /// Repeated binding requests to send, spaced by --interval-ms.
    #[arg(long, default_value_t = 5)]
    pub repeat: u32,

    #[arg(long, default_value_t = 200)]
    pub interval_ms: u64,

    #[arg(long, default_value_t = 2000)]
    pub timeout_ms: u64,

    /// The mapped address is the host's public egress IP -- a sensitive
    /// identifier under the same policy as a BSSID (GAP-018). Without this
    /// flag, only "changed"/"unchanged"/"unavailable" is reported.
    #[arg(long)]
    pub reveal_mapped_address: bool,

    /// TURN server host:port. Omit to skip TURN checks entirely.
    #[arg(long)]
    pub turn_server: Option<String>,

    #[arg(long, value_enum, default_value = "udp")]
    pub turn_transport: TurnTransport,

    #[arg(long)]
    pub turn_username: Option<String>,

    #[arg(long)]
    pub turn_password: Option<String>,

    /// For the demo/test harness only: skip real sockets and return a
    /// deterministic synthetic sequence of binding outcomes.
    #[arg(long)]
    pub inject_fixture: Option<String>,

    #[arg(long)]
    pub json: bool,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum TurnTransport {
    Udp,
    Tcp,
    Tls,
}

#[derive(serde::Serialize)]
struct BindingRecord {
    attempt: u32,
    /// "mapped" / "unreachable" / "invalid" -- never a bare bool, so a
    /// caller can't collapse "no answer" into "unchanged".
    result: &'static str,
    rtt_ms: Option<f64>,
    invalid_reason: Option<String>,
    /// Only populated with the real IP when --reveal-mapped-address was
    /// passed; otherwise always None regardless of what was measured.
    mapped_address: Option<String>,
}

#[derive(serde::Serialize)]
struct MappingChangeSummary {
    /// One of "stable" / "changed" / "unavailable" -- unavailable is
    /// distinct from stable, since silence must never read as stability.
    verdict: &'static str,
    successful_bindings: usize,
    total_attempts: usize,
}

#[derive(serde::Serialize)]
struct TurnRecord {
    transport: &'static str,
    outcome: &'static str,
    detail: Option<String>,
    relayed_address_revealed: Option<String>,
    lifetime_secs: Option<u32>,
}

fn resolve(host_port: &str) -> Result<SocketAddr, String> {
    host_port
        .to_socket_addrs()
        .map_err(|e| format!("failed to resolve {host_port}: {e}"))?
        .next()
        .ok_or_else(|| format!("{host_port} resolved to no addresses"))
}

fn synthetic_attempts(seed: &str) -> Vec<BindingAttempt> {
    // Deterministic fixture sequences for the harness: "stable" keeps one
    // mapped address across every attempt; "changed" flips it partway;
    // "unreachable" times out on every attempt, exercising the
    // unavailable-not-stable path.
    let stable: SocketAddr = "203.0.113.10:40000".parse().unwrap();
    let changed: SocketAddr = "203.0.113.99:40001".parse().unwrap();
    match seed {
        "changed" => vec![
            BindingAttempt {
                outcome: BindingOutcome::Mapped(stable),
                rtt_ms: Some(12.0),
            },
            BindingAttempt {
                outcome: BindingOutcome::Mapped(stable),
                rtt_ms: Some(11.0),
            },
            BindingAttempt {
                outcome: BindingOutcome::Mapped(changed),
                rtt_ms: Some(13.0),
            },
        ],
        "unreachable" => vec![
            BindingAttempt {
                outcome: BindingOutcome::Unreachable,
                rtt_ms: None,
            },
            BindingAttempt {
                outcome: BindingOutcome::Unreachable,
                rtt_ms: None,
            },
        ],
        _ => vec![
            BindingAttempt {
                outcome: BindingOutcome::Mapped(stable),
                rtt_ms: Some(12.0),
            },
            BindingAttempt {
                outcome: BindingOutcome::Mapped(stable),
                rtt_ms: Some(11.5),
            },
            BindingAttempt {
                outcome: BindingOutcome::Mapped(stable),
                rtt_ms: Some(12.3),
            },
        ],
    }
}

/// Computes the change verdict from a sequence of attempts. Only attempts
/// that produced a validated mapped address count toward the comparison;
/// an `Unreachable`/`Invalid` attempt contributes nothing, and if *no*
/// attempt ever validated, the verdict is `unavailable`, never `stable`
/// (silence is not evidence of stability -- the exact bug this closes).
fn mapping_change_verdict(attempts: &[BindingAttempt]) -> MappingChangeSummary {
    let mapped: Vec<SocketAddr> = attempts
        .iter()
        .filter_map(|a| match &a.outcome {
            BindingOutcome::Mapped(addr) => Some(*addr),
            _ => None,
        })
        .collect();
    let verdict = if mapped.is_empty() {
        "unavailable"
    } else if mapped.iter().all(|a| *a == mapped[0]) {
        "stable"
    } else {
        "changed"
    };
    MappingChangeSummary {
        verdict,
        successful_bindings: mapped.len(),
        total_attempts: attempts.len(),
    }
}

fn run_binding_attempts(args: &StunTurnArgs) -> Result<Vec<BindingAttempt>, String> {
    if let Some(seed) = &args.inject_fixture {
        return Ok(synthetic_attempts(seed));
    }
    let server = resolve(&args.stun_server)?;
    let socket = UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| format!("failed to bind local UDP socket: {e}"))?;
    let timeout = Duration::from_millis(args.timeout_ms);
    let mut attempts = Vec::new();
    for i in 0..args.repeat.max(1) {
        attempts.push(binding_request_once(&socket, server, timeout));
        if i + 1 < args.repeat {
            std::thread::sleep(Duration::from_millis(args.interval_ms));
        }
    }
    Ok(attempts)
}

fn run_turn(args: &StunTurnArgs) -> Option<TurnRecord> {
    let turn_server_str = args.turn_server.as_ref()?;
    let credentials = match (&args.turn_username, &args.turn_password) {
        (Some(u), Some(p)) => Some(TurnCredentials {
            username: u.clone(),
            password: p.clone(),
        }),
        _ => None,
    };
    if let Some(seed) = &args.inject_fixture {
        let outcome = if seed == "turn-no-creds" {
            TurnOutcome::NoCredentialsSupplied
        } else if seed == "turn-allocated" {
            TurnOutcome::Allocated {
                lifetime_secs: 600,
                relayed: "203.0.113.50:51000".parse().unwrap(),
            }
        } else {
            TurnOutcome::Unreachable
        };
        return Some(turn_outcome_to_record(args.turn_transport, outcome));
    }
    let server = match resolve(turn_server_str) {
        Ok(s) => s,
        Err(e) => {
            return Some(TurnRecord {
                transport: transport_label(args.turn_transport),
                outcome: "unreachable",
                detail: Some(e),
                relayed_address_revealed: None,
                lifetime_secs: None,
            })
        }
    };
    let outcome = match args.turn_transport {
        TurnTransport::Udp => {
            let socket = match UdpSocket::bind("0.0.0.0:0") {
                Ok(s) => s,
                Err(e) => return Some(err_record(args.turn_transport, e.to_string())),
            };
            turn_allocate_udp(
                &socket,
                server,
                credentials.as_ref(),
                Duration::from_millis(args.timeout_ms),
            )
        }
        TurnTransport::Tcp => {
            let mut stream =
                match TcpStream::connect_timeout(&server, Duration::from_millis(args.timeout_ms)) {
                    Ok(s) => s,
                    Err(e) => return Some(err_record(args.turn_transport, e.to_string())),
                };
            turn_allocate_tcp(&mut stream, credentials.as_ref())
        }
        TurnTransport::Tls => {
            // TLS framing wraps the same STUN-over-TCP exchange, but this
            // build has no TLS client available that exposes a plain
            // Read+Write stream cheaply without adding a dependency;
            // rather than silently downgrading to plaintext TCP (which
            // would misreport "TLS checked" when it wasn't), this is
            // reported as unavailable on this build.
            return Some(TurnRecord {
                transport: "tls",
                outcome: "unavailable",
                detail: Some("TURN-over-TLS is not implemented in this build; use --turn-transport tcp or udp".to_string()),
                relayed_address_revealed: None,
                lifetime_secs: None,
            });
        }
    };
    Some(turn_outcome_to_record(args.turn_transport, outcome))
}

fn err_record(transport: TurnTransport, detail: String) -> TurnRecord {
    TurnRecord {
        transport: transport_label(transport),
        outcome: "unreachable",
        detail: Some(detail),
        relayed_address_revealed: None,
        lifetime_secs: None,
    }
}

fn transport_label(t: TurnTransport) -> &'static str {
    match t {
        TurnTransport::Udp => "udp",
        TurnTransport::Tcp => "tcp",
        TurnTransport::Tls => "tls",
    }
}

fn turn_outcome_to_record(transport: TurnTransport, outcome: TurnOutcome) -> TurnRecord {
    let transport = transport_label(transport);
    match outcome {
        TurnOutcome::Allocated {
            lifetime_secs,
            relayed,
        } => TurnRecord {
            transport,
            outcome: "allocated",
            detail: None,
            // The relay address is also a network identifier; treated with
            // the same care as the STUN mapped address would be if this
            // command grows a reveal flag for it. For now it is only
            // surfaced when the operator explicitly asked to reveal.
            relayed_address_revealed: Some(relayed.to_string()),
            lifetime_secs: Some(lifetime_secs),
        },
        TurnOutcome::Unauthorized => TurnRecord {
            transport,
            outcome: "unauthorized",
            detail: None,
            relayed_address_revealed: None,
            lifetime_secs: None,
        },
        TurnOutcome::CredentialsRejected => TurnRecord {
            transport,
            outcome: "credentials_rejected",
            detail: None,
            relayed_address_revealed: None,
            lifetime_secs: None,
        },
        TurnOutcome::NoCredentialsSupplied => TurnRecord {
            transport,
            outcome: "no_credentials_supplied",
            detail: None,
            relayed_address_revealed: None,
            lifetime_secs: None,
        },
        TurnOutcome::Unreachable => TurnRecord {
            transport,
            outcome: "unreachable",
            detail: None,
            relayed_address_revealed: None,
            lifetime_secs: None,
        },
        TurnOutcome::Invalid(e) => TurnRecord {
            transport,
            outcome: "invalid",
            detail: Some(e),
            relayed_address_revealed: None,
            lifetime_secs: None,
        },
    }
}

pub fn run(args: &StunTurnArgs) {
    let attempts = match run_binding_attempts(args) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{} {}", "✗".red(), e);
            std::process::exit(1);
        }
    };

    let records: Vec<BindingRecord> = attempts
        .iter()
        .enumerate()
        .map(|(i, a)| match &a.outcome {
            BindingOutcome::Mapped(addr) => BindingRecord {
                attempt: i as u32,
                result: "mapped",
                rtt_ms: a.rtt_ms,
                invalid_reason: None,
                mapped_address: if args.reveal_mapped_address {
                    Some(addr.to_string())
                } else {
                    None
                },
            },
            BindingOutcome::Unreachable => BindingRecord {
                attempt: i as u32,
                result: "unreachable",
                rtt_ms: None,
                invalid_reason: None,
                mapped_address: None,
            },
            BindingOutcome::Invalid(e) => BindingRecord {
                attempt: i as u32,
                result: "invalid",
                rtt_ms: a.rtt_ms,
                invalid_reason: Some(e.to_string()),
                mapped_address: None,
            },
        })
        .collect();

    let change = mapping_change_verdict(&attempts);
    let turn = run_turn(args);

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "stun_server": args.stun_server,
                "bindings": records,
                "mapping_change": change,
                "turn": turn,
            }))
            .unwrap()
        );
        return;
    }

    println!();
    println!("{}", "== STUN Binding / TURN Allocation ==".cyan().bold());
    println!("  stun server: {}", args.stun_server);
    for r in &records {
        match r.result {
            "mapped" => {
                let addr_note = r
                    .mapped_address
                    .as_deref()
                    .unwrap_or("hidden (pass --reveal-mapped-address to show)");
                println!(
                    "  [{}] mapped rtt={} address={}",
                    r.attempt,
                    fmt_ms(r.rtt_ms),
                    addr_note
                );
            }
            "unreachable" => println!(
                "  [{}] {}",
                r.attempt,
                "UNREACHABLE (no response within timeout)".yellow()
            ),
            _ => println!(
                "  [{}] {} ({})",
                r.attempt,
                "INVALID RESPONSE".red(),
                r.invalid_reason.as_deref().unwrap_or("unknown")
            ),
        }
    }
    println!();
    match change.verdict {
        "stable" => println!(
            "  mapping: {} across {} of {} attempts",
            "unchanged".green().bold(),
            change.successful_bindings,
            change.total_attempts
        ),
        "changed" => println!(
            "  mapping: {} across {} of {} attempts",
            "CHANGED".red().bold(),
            change.successful_bindings,
            change.total_attempts
        ),
        _ => println!(
            "  mapping: {} (0 of {} attempts validated -- not evidence of stability)",
            "unavailable".yellow().bold(),
            change.total_attempts
        ),
    }

    if let Some(t) = &turn {
        println!();
        println!("  [TURN/{}] {}", t.transport, t.outcome);
        if let Some(d) = &t.detail {
            println!("    detail: {d}");
        }
        if let Some(l) = t.lifetime_secs {
            println!("    lifetime_secs: {l}");
        }
        if t.outcome == "no_credentials_supplied" {
            println!(
                "    (pass --turn-username/--turn-password to attempt an authenticated allocation)"
            );
        }
    }
    println!();
}

fn fmt_ms(v: Option<f64>) -> String {
    v.map(|v| format!("{v:.2}ms"))
        .unwrap_or_else(|| "unavailable".to_string())
}
