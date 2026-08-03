//! Probes Panel - Native packet engine tools (DSL, Replay, Active Probe, Scenario, Metrics)

use crate::state::{AppState, LogLevel, PanelId, ToastType};
use crate::window_manager::DetachButton;
use dioxus::prelude::*;
use fraggle_packet::fuzzing::dsl::*;

/// Platform-specific suggestion for granting raw-socket access without a full
/// root shell. Shown in toasts when the user clicks a feature that needs it.
fn priv_hint() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        "sudo setcap cap_net_raw,cap_net_admin+eip ./target/release/fraggle-desktop"
    }
    #[cfg(target_os = "macos")]
    {
        "relaunch with: sudo ./target/release/fraggle-desktop"
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        "relaunch the application as administrator"
    }
}

#[component]
pub fn ProbesPanel(state: Signal<AppState>, panel: PanelId) -> Element {
    let tools = state.read().probe_tools.read().clone();

    rsx! {
        div { class: "probes-panel",
            div { class: "panel",
                div { class: "panel-header",
                    span { class: "panel-title", "Native Packet Engine" }
                    DetachButton { panel: panel }
                }
                p { style: "color: var(--term-green-dim); font-size: 12px;",
                    "Scapy-equivalent DSL, Rust PCAP replay, active send-and-capture probes, scenario runner, and Prometheus metrics exporter."
                }
            }

            DslDemoCard { state: state }
            ReplayCard { state: state }
            ActiveProbeCard { state: state }
            ScenarioCard { state: state }
            MetricsCard { state: state }

            div { class: "panel",
                div { class: "panel-header",
                    span { class: "panel-title", "Latest Output" }
                }
                pre {
                    style: "white-space: pre-wrap; font-family: monospace; background: var(--term-bg); color: var(--term-green); padding: 12px; border: 1px solid var(--term-green-dim); max-height: 400px; overflow: auto; min-height: 120px;",
                    if tools.last_output.is_empty() {
                        "No output yet."
                    } else {
                        "{tools.last_output}"
                    }
                }
            }
        }
    }
}

#[component]
fn DslDemoCard(state: Signal<AppState>) -> Element {
    let tools = state.read().probe_tools.read().clone();
    rsx! {
        div { class: "panel",
            div { class: "panel-header",
                span { class: "panel-title", "Packet DSL Demo" }
            }
            div { style: "display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px;",
                LabeledInput {
                    label: "Dst IP",
                    value: tools.dsl_dst.clone(),
                    oninput: move |v: String| state.write().probe_tools.write().dsl_dst = v,
                }
                LabeledInput {
                    label: "Dst Port",
                    value: tools.dsl_port.to_string(),
                    oninput: move |v: String| {
                        if let Ok(p) = v.parse::<u16>() {
                            state.write().probe_tools.write().dsl_port = p;
                        }
                    },
                }
                LabeledInput {
                    label: "Payload size",
                    value: tools.dsl_size.to_string(),
                    oninput: move |v: String| {
                        if let Ok(s) = v.parse::<usize>() {
                            state.write().probe_tools.write().dsl_size = s;
                        }
                    },
                }
            }
            div { style: "margin-top: 8px;",
                button {
                    class: "btn primary",
                    onclick: move |_| {
                        let t = state.read().probe_tools.read().clone();
                        let out = render_dsl_demo(&t.dsl_dst, t.dsl_port, t.dsl_size);
                        state.write().probe_tools.write().last_output = out;
                        state.write().log(LogLevel::Info, "DSL packet crafted");
                    },
                    "Craft + Hexdump"
                }
            }
        }
    }
}

#[component]
fn ReplayCard(state: Signal<AppState>) -> Element {
    let tools = state.read().probe_tools.read().clone();
    rsx! {
        div { class: "panel",
            div { class: "panel-header",
                span { class: "panel-title", "PCAP Replay" }
            }
            p { style: "color: var(--term-green-dim); font-size: 12px;",
                "Replay a PCAP onto the wire. Requires root / admin to open the raw socket."
            }
            div { style: "display: grid; grid-template-columns: 2fr 1fr 1fr 1fr; gap: 8px;",
                LabeledInput {
                    label: "PCAP path",
                    value: tools.replay_pcap.clone(),
                    oninput: move |v: String| state.write().probe_tools.write().replay_pcap = v,
                }
                LabeledInput {
                    label: "Interface",
                    value: tools.replay_iface.clone(),
                    oninput: move |v: String| state.write().probe_tools.write().replay_iface = v,
                }
                LabeledInput {
                    label: "pps (0=full)",
                    value: tools.replay_pps.to_string(),
                    oninput: move |v: String| {
                        if let Ok(p) = v.parse::<u32>() {
                            state.write().probe_tools.write().replay_pps = p;
                        }
                    },
                }
                LabeledInput {
                    label: "loops",
                    value: tools.replay_loops.to_string(),
                    oninput: move |v: String| {
                        if let Ok(n) = v.parse::<u32>() {
                            state.write().probe_tools.write().replay_loops = n;
                        }
                    },
                }
            }
            div { style: "margin-top: 8px;",
                button {
                    class: "btn primary",
                    onclick: move |_| {
                        if !state.read().is_privileged {
                            let msg = format!("PCAP Replay needs root. {}", priv_hint());
                            state.write().log(LogLevel::Warning, msg.clone());
                            state.write().add_toast(msg, ToastType::Warning);
                            return;
                        }
                        let t = state.read().probe_tools.read().clone();
                        state.write().log(LogLevel::Info, format!("Replay {} on {}", t.replay_pcap, t.replay_iface));
                        spawn(async move {
                            let output = tokio::task::spawn_blocking(move || {
                                run_replay_job(&t.replay_pcap, &t.replay_iface, t.replay_pps, t.replay_loops)
                            }).await.unwrap_or_else(|e| format!("join error: {}", e));
                            state.write().probe_tools.write().last_output = output;
                        });
                    },
                    "Run Replay"
                }
            }
        }
    }
}

#[component]
fn ActiveProbeCard(state: Signal<AppState>) -> Element {
    let tools = state.read().probe_tools.read().clone();
    rsx! {
        div { class: "panel",
            div { class: "panel-header",
                span { class: "panel-title", "Active PMTU Probe" }
            }
            p { style: "color: var(--term-green-dim); font-size: 12px;",
                "DSL-crafted DF pings with raw-socket capture. Linux only, requires root."
            }
            div { style: "display: grid; grid-template-columns: 2fr 1fr 1fr 1fr; gap: 8px;",
                LabeledInput {
                    label: "Target IPv4",
                    value: tools.probe_target.clone(),
                    oninput: move |v: String| state.write().probe_tools.write().probe_target = v,
                }
                LabeledInput {
                    label: "Interface",
                    value: tools.probe_iface.clone(),
                    oninput: move |v: String| state.write().probe_tools.write().probe_iface = v,
                }
                LabeledInput {
                    label: "min MTU",
                    value: tools.probe_min.to_string(),
                    oninput: move |v: String| {
                        if let Ok(n) = v.parse::<u16>() {
                            state.write().probe_tools.write().probe_min = n;
                        }
                    },
                }
                LabeledInput {
                    label: "max MTU",
                    value: tools.probe_max.to_string(),
                    oninput: move |v: String| {
                        if let Ok(n) = v.parse::<u16>() {
                            state.write().probe_tools.write().probe_max = n;
                        }
                    },
                }
            }
            div { style: "margin-top: 8px;",
                button {
                    class: "btn primary",
                    onclick: move |_| {
                        if !state.read().is_privileged {
                            let msg = format!("Active PMTU Probe needs root. {}", priv_hint());
                            state.write().log(LogLevel::Warning, msg.clone());
                            state.write().add_toast(msg, ToastType::Warning);
                            return;
                        }
                        let t = state.read().probe_tools.read().clone();
                        spawn(async move {
                            let output = tokio::task::spawn_blocking(move || {
                                run_active_probe(&t.probe_target, &t.probe_iface, t.probe_min, t.probe_max)
                            }).await.unwrap_or_else(|e| format!("join error: {}", e));
                            state.write().probe_tools.write().last_output = output;
                        });
                    },
                    "Run PMTU Probe"
                }
            }
        }
    }
}

#[component]
fn ScenarioCard(state: Signal<AppState>) -> Element {
    let tools = state.read().probe_tools.read().clone();
    rsx! {
        div { class: "panel",
            div { class: "panel-header",
                span { class: "panel-title", "Scenario Runner" }
            }
            p { style: "color: var(--term-green-dim); font-size: 12px;",
                "Describe multi-step probes declaratively. `# step: name` then key: value lines."
            }
            textarea {
                style: "width: 100%; min-height: 160px; font-family: monospace; background: var(--term-bg); color: var(--term-green); border: 1px solid var(--term-green-dim); padding: 8px;",
                oninput: move |e| {
                    state.write().probe_tools.write().scenario_text = e.value();
                },
                "{tools.scenario_text}"
            }
            div { style: "margin-top: 8px;",
                button {
                    class: "btn primary",
                    onclick: move |_| {
                        let t = state.read().probe_tools.read().clone();
                        spawn(async move {
                            let output = tokio::task::spawn_blocking(move || {
                                run_scenario_text(&t.scenario_text)
                            }).await.unwrap_or_else(|e| format!("join error: {}", e));
                            state.write().probe_tools.write().last_output = output;
                        });
                    },
                    "Run Scenario"
                }
            }
        }
    }
}

#[component]
fn MetricsCard(state: Signal<AppState>) -> Element {
    let tools = state.read().probe_tools.read().clone();
    let serving = tools.metrics_serving;
    rsx! {
        div { class: "panel",
            div { class: "panel-header",
                span { class: "panel-title", "Prometheus Metrics" }
            }
            p { style: "color: var(--term-green-dim); font-size: 12px;",
                "Expose a /metrics endpoint for Prometheus scraping. Runs in-process on a background thread."
            }
            div { style: "display: grid; grid-template-columns: 2fr 1fr; gap: 8px;",
                LabeledInput {
                    label: "Bind address",
                    value: tools.metrics_bind.clone(),
                    oninput: move |v: String| state.write().probe_tools.write().metrics_bind = v,
                }
                div { style: "display: flex; align-items: flex-end; gap: 8px;",
                    button {
                        class: if serving { "btn" } else { "btn primary" },
                        disabled: serving,
                        onclick: move |_| {
                            let bind = state.read().probe_tools.read().metrics_bind.clone();
                            start_metrics_server(&bind);
                            state.write().probe_tools.write().metrics_serving = true;
                            state.write().probe_tools.write().last_output = format!(
                                "Serving metrics on http://{}/metrics", bind
                            );
                            state.write().add_toast(
                                format!("Metrics server started on {}", bind),
                                ToastType::Success,
                            );
                        },
                        if serving { "Running" } else { "Start Server" }
                    }
                }
            }
        }
    }
}

#[component]
fn LabeledInput(label: String, value: String, oninput: EventHandler<String>) -> Element {
    rsx! {
        label { style: "display: flex; flex-direction: column; gap: 4px; font-size: 12px; color: var(--term-green-dim);",
            "{label}"
            input {
                r#type: "text",
                value: "{value}",
                oninput: move |e| oninput.call(e.value()),
                style: "background: var(--term-bg); color: var(--term-green); border: 1px solid var(--term-green-dim); padding: 6px; font-family: monospace;",
            }
        }
    }
}

fn render_dsl_demo(dst: &str, port: u16, size: usize) -> String {
    let dst_ip: std::net::Ipv4Addr = match dst.parse() {
        Ok(ip) => ip,
        Err(_) => return format!("invalid dst ip: {}", dst),
    };
    let pkt = Ether::new()
        / Ip::new().dst_addr(dst_ip).df()
        / Tcp::new().dport(port).syn().options(vec![
            TcpOpt::Mss(1460),
            TcpOpt::SAckOK,
            TcpOpt::Nop,
        ])
        / Raw::of_size(size, b'X');
    let mut out = pkt.summary();
    out.push_str("\n\n");
    match pkt.hexdump() {
        Ok(h) => out.push_str(&h),
        Err(e) => out.push_str(&format!("hexdump error: {}", e)),
    }
    out
}

fn run_replay_job(pcap: &str, iface: &str, pps: u32, loops: u32) -> String {
    use fraggle_packet::fuzzing::replay::{replay_pcap, ReplayOptions};
    let mut opts = ReplayOptions::new().loop_count(loops.max(1));
    if !iface.is_empty() {
        opts = opts.iface(iface);
    }
    if pps > 0 {
        opts = opts.pps(pps);
    }
    match replay_pcap(pcap, &opts) {
        Ok(report) => format!(
            "Replay complete\n  packets_sent: {}\n  packets_dropped: {}\n  bytes_sent: {}\n  duration_ms: {}",
            report.packets_sent, report.packets_dropped, report.bytes_sent, report.duration_ms
        ),
        Err(e) => format!("Replay error: {}", e),
    }
}

fn run_active_probe(target: &str, iface: &str, min: u16, max: u16) -> String {
    use fraggle_packet::fuzzing::probe::active_pmtu_probe;
    use std::time::Duration;
    let target_ip: std::net::Ipv4Addr = match target.parse() {
        Ok(ip) => ip,
        Err(_) => return format!("invalid target IPv4: {}", target),
    };
    match active_pmtu_probe(iface, target_ip, min, max, Duration::from_millis(1500)) {
        Ok(r) => format!(
            "Samples: {:?}\nFrag needed: {}\nEstimated MTU: {:?}",
            r.samples_tried, r.frag_needed_reported, r.estimated_mtu
        ),
        Err(e) => format!("Probe error: {}", e),
    }
}

fn run_scenario_text(text: &str) -> String {
    use fraggle_packet::network_tests::scenario::Scenario;
    let scenario = match Scenario::parse(text) {
        Ok(s) => s,
        Err(e) => return format!("parse error: {}", e),
    };
    if scenario.steps.is_empty() {
        return "No steps in scenario".to_string();
    }
    let mut out = String::new();
    for (name, res) in scenario.run() {
        out.push_str(&format!("-- {} --\n", name));
        match res {
            Ok(r) => {
                out.push_str(&format!("status: {:?}\n", r.status));
                for (k, v) in &r.metrics {
                    out.push_str(&format!("  metric {} = {}\n", k, v));
                }
            }
            Err(e) => out.push_str(&format!("error: {}\n", e)),
        }
    }
    out
}

fn start_metrics_server(bind: &str) {
    use fraggle_packet::framework::{serve_metrics, MetricsRegistry};
    let reg = MetricsRegistry::new();
    reg.set_help("fraggle_build_info", "Build metadata");
    reg.set_gauge("fraggle_build_info", 1.0);
    let bind = bind.to_string();
    std::thread::spawn(move || {
        if let Err(e) = serve_metrics(reg, &bind) {
            log::error!("metrics serve failed: {}", e);
        }
    });
}
