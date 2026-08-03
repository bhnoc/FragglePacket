//! MTU Simulator and VPN Calculator

use crate::state::{AppState, PanelId};
use crate::window_manager::DetachButton;
use dioxus::prelude::*;

/// VPN overhead data
const VPN_OVERHEADS: &[(&str, &str, u32)] = &[
    ("none", "No VPN", 0),
    ("wireguard", "WireGuard", 60),
    ("openvpn-udp", "OpenVPN (UDP)", 70),
    ("openvpn-tcp", "OpenVPN (TCP)", 90),
    ("ipsec", "IPsec NAT-T", 72),
    ("ikev2", "IKEv2", 72),
    ("zscaler", "Zscaler", 100),
    ("netskope", "Netskope", 90),
    ("warp", "Cloudflare WARP", 60),
    ("globalprotect", "GlobalProtect", 80),
    ("anyconnect", "Cisco AnyConnect", 80),
    ("fortinet", "Fortinet", 76),
    ("l2tp", "L2TP/IPsec", 76),
    ("pptp", "PPTP", 46),
    ("gre", "GRE", 24),
    ("vxlan", "VXLAN", 50),
];

/// MTU simulator with VPN overhead calculator
#[component]
pub fn Simulator(state: Signal<AppState>, panel: PanelId) -> Element {
    let mut base_mtu = use_signal(|| 1500_u32);
    let mut selected_vpn = use_signal(|| "none".to_string());

    let overhead = VPN_OVERHEADS
        .iter()
        .find(|(id, _, _)| *id == *selected_vpn.read())
        .map(|(_, _, o)| *o)
        .unwrap_or(0);

    let effective_mtu = (*base_mtu.read() as i32 - overhead as i32).max(576) as u32;
    let tcp_mss = effective_mtu.saturating_sub(40); // IP + TCP headers

    rsx! {
        div { class: "simulator-panel",
            // Base MTU slider
            div { class: "panel",
                div { class: "panel-header",
                    span { class: "panel-title", "Interface MTU" }
                    DetachButton { panel: panel }
                }
                div { class: "mtu-slider",
                    input {
                        r#type: "range",
                        min: "576",
                        max: "9000",
                        value: "{base_mtu}",
                        oninput: move |evt| {
                            if let Ok(v) = evt.value().parse::<u32>() {
                                base_mtu.set(v);
                            }
                        }
                    }
                    span { class: "mtu-value", "{base_mtu} bytes" }
                }
                div { class: "mtu-presets",
                    button { class: "btn", onclick: move |_| base_mtu.set(1500), "1500 (Standard)" }
                    button { class: "btn", onclick: move |_| base_mtu.set(1400), "1400 (Safe)" }
                    button { class: "btn", onclick: move |_| base_mtu.set(9000), "9000 (Jumbo)" }
                }
            }

            // VPN selector
            div { class: "panel",
                div { class: "panel-header",
                    span { class: "panel-title", "VPN/SASE Tunnel" }
                }
                div { class: "vpn-grid",
                    for (id, label, ovhd) in VPN_OVERHEADS.iter() {
                        {
                            let id_str = id.to_string();
                            let id_for_click = id_str.clone();
                            rsx! {
                                button {
                                    class: if *selected_vpn.read() == id_str { "category-btn selected" } else { "category-btn" },
                                    onclick: move |_| {
                                        selected_vpn.set(id_for_click.clone());
                                    },
                                    span { class: "label", "{label}" }
                                    span { class: "overhead", "-{ovhd}" }
                                }
                            }
                        }
                    }
                }
            }

            // Results
            div { class: "panel",
                div { class: "panel-header",
                    span { class: "panel-title", "Calculated Values" }
                }
                div { class: "results-grid",
                    div { class: "result",
                        span { class: "result-label", "Base MTU" }
                        span { class: "result-value", "{base_mtu}" }
                    }
                    div { class: "result",
                        span { class: "result-label", "VPN Overhead" }
                        span { class: "result-value status-warning", "-{overhead}" }
                    }
                    div { class: "result",
                        span { class: "result-label", "Effective MTU" }
                        span { class: "result-value status-success", "{effective_mtu}" }
                    }
                    div { class: "result",
                        span { class: "result-label", "TCP MSS" }
                        span { class: "result-value", "{tcp_mss}" }
                    }
                }
            }

            // Recommendations
            div { class: "panel",
                div { class: "panel-header",
                    span { class: "panel-title", "Recommendations" }
                }
                div { class: "recommendations",
                    if overhead > 0 {
                        p { "Configure tunnel interface MTU: {effective_mtu}" }
                        p { "TCP MSS clamp: {tcp_mss}" }
                    } else {
                        p { "No VPN overhead applied. Standard MTU settings recommended." }
                    }
                }
            }
        }
    }
}
