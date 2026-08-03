# FragglePacket Capability Gap List

Living backlog of capabilities discovered while using FragglePacket for real
network investigations. Add new gaps as they are encountered. This document is
for tracking and acceptance criteria only; an entry does not imply that the
feature has been scheduled or implemented.

## Priority definitions

| Priority | Meaning |
| --- | --- |
| P0 | Existing output can produce a materially false diagnosis |
| P1 | Needed to isolate common production network failures |
| P2 | Useful workflow, portability, or reporting improvement |

## Open gaps

| ID | Priority | Gap | Evidence from field use | Acceptance criteria |
| --- | --- | --- | --- | --- |
| GAP-001 | P0 | QUIC PMTU probe is send-only | The probe reported 8,972-byte UDP payloads as successful on an MTU-1500 interface because it only checked that `send` returned successfully. | Require a protocol-valid response or ICMP/error-queue evidence for every tested size. Never label a send-only result as path MTU success. |
| GAP-002 | P1 | No true bufferbloat/latency-under-load command | The RTT test only has a variance heuristic. Investigation required macOS `networkQuality` to measure idle, upload-loaded, download-loaded, and simultaneous latency. | Add `bufferbloat` with idle and loaded latency, directional deltas, throughput, responsiveness grade, configurable duration/interface, and machine-readable output. |
| GAP-003 | P1 | No controlled HTTP protocol comparison | HTTP/1.1, HTTP/2, and HTTP/3 had materially different throughput and loaded latency on the same interface. | Add repeatable H1/H2/H3 tests with fixed endpoint/IP support, sequential and simultaneous modes, per-protocol capacity, latency, loss indicators, and confidence. |
| GAP-004 | P1 | No directional versus full-duplex load isolation | HTTP/3 was healthy directionally but collapsed during one simultaneous run. | Report download-only, upload-only, and simultaneous results separately so bidirectional contention is not misdiagnosed as blanket protocol shaping. |
| GAP-005 | P1 | No real STUN/TURN diagnostics | A hand-built STUN binding test proved UDP/19302 and NAT traversal were healthy, but FragglePacket cannot test it. | Add repeated STUN binding requests with validation and RTT, mapped-address change detection without exposing it by default, plus TURN UDP/TCP/TLS allocation and relay checks. |
| GAP-006 | P1 | No controlled TCP-versus-UDP throughput/loss test | Public/CDN speed tests cannot isolate transport behavior. `iperf3` was not installed and no managed test endpoint was configured. | Support a user-supplied iperf3-compatible endpoint and compare TCP with UDP at selected ports/rates, including loss, jitter, reordering, and bidirectional mode. |
| GAP-007 | P1 | Packet capture workflow is unsafe for high-rate tests | A 75-second full-snaplen capture grew to roughly 2 GB. Capture required a manual sudo handoff. | Add duration, snaplen, byte/file-size cap, rotation, protocol filters, progress, automatic stop, safe privilege handoff, and capture metadata. Default diagnostic captures must be bounded. |
| GAP-008 | P1 | No built-in PCAP comparison report | External `tshark`/`capinfos` are required to compare TCP and QUIC flow counts, sizes, loss signals, ICMP, retransmissions, and timing. | Add a report that consumes one or more PCAPs and summarizes transport/flow statistics without loading the entire file into memory. |
| GAP-009 | P1 | macOS RTT parser reports zero latency | A live RTT run received all packets but displayed zero for min/avg/max/jitter because it expects Linux ping summary syntax. | Parse Darwin and Linux ping output with fixtures; never report zero latency when parsing failed. Mark the metric unavailable instead. |
| GAP-010 | P1 | MSS clamp detection still cannot prove on-wire rewriting | Route-aware TCP_MAXSEG comparison avoids the old false claim, but distinguishing peer MSS from a middlebox still requires SYN/SYN-ACK capture. | Capture or ingest both SYN directions, extract MSS options, distinguish local/peer/middlebox evidence, and label confidence explicitly. |
| GAP-011 | P1 | No Wi-Fi radio/retry diagnostic | Manual inspection found strong 6 GHz RF, but retry counters, WMM, airtime fairness, and channel utilization require elevated platform tools. | Report band/channel/width, RSSI, noise, SNR, MCS, PHY rate, retries, channel utilization, WMM state, and platform limitations with safe elevation. |
| GAP-012 | P1 | No affected-site A/B workflow | Investigations need to compare a named failing site with a known-good control while forcing protocol and resolved IP. | Accept affected/control URLs, force H1/H2/H3 where supported, pin IPs, repeat samples, retain redirect/CDN details, and produce a side-by-side verdict. |
| GAP-013 | P2 | No second-network control workflow | A hotspot rerun is the fastest way to separate client behavior from Wi-Fi infrastructure, but results are currently recorded manually. | Save a connection fingerprint and test bundle, then compare the same suite after the user switches networks without storing SSID/BSSID unless explicitly requested. |
| GAP-014 | P2 | DNS steering comparison is manual | Internal and public resolvers returned different GitHub edge IPs; UDP, DoT, and DoH health alone does not expose CDN steering differences. | Compare A/AAAA/HTTPS/SVCB answers, resolution timing, TTLs, selected endpoint performance, and resolver-specific route changes. |
| GAP-015 | P2 | IPv6 absence is not correlated with application tests | This Wi-Fi had no reachable IPv6, but protocol reports did not explain whether fallback or CDN selection changed. | Record IP-family availability and Happy Eyeballs behavior in protocol comparisons and flag family-specific failures or fallback delays. |
| GAP-016 | P2 | Elevated traceroute/capture failures lack actionable status | TCP traceroute failed with an empty `pcap_activate()` message when BPF access was unavailable. | Detect BPF/raw-socket permission failures, preserve the underlying error, show the exact required privilege, and continue with unprivileged alternatives. |
| GAP-017 | P2 | Results lack run confidence and endpoint-normalization controls | Native protocol runs selected different CDN edge endpoints and sometimes reported low accuracy, complicating comparisons. | Record endpoint IP/name, test accuracy, sample count, variance, warm-up state, and warn when cross-protocol comparisons use different endpoints. |
| GAP-018 | P2 | Sensitive network identifiers need explicit redaction controls | Platform diagnostics may expose SSID, BSSID, MAC addresses, local/public IPs, and resolver details. | Redact identifiers by default in logs/reports and require an explicit flag to retain them. |
| GAP-019 | P0 | PCAP analysis is not capture-offload aware | A host-side capture on an MTU-1500 interface contained more than 500,000 apparent frames over 1,450 bytes and very high TCP analysis counts. TSO/GSO/GRO and capture loss can make these look like on-wire oversize packets, loss, or retransmissions. Re-measured 2026-08-02: the 1,569,970-packet source capture actually holds **zero** frames above 1,514 bytes; the 170,663 flagged frames are 1,510 bytes carrying IP length 1,496, which is legal at MTU 1500. The oversize half of this gap was a measurement error in the original triage. The retransmission inflation is real: a 300,000-packet sample shows 13,269 retransmissions, 1,199 out-of-order, and 7,757 duplicate ACKs. | Detect capture location and offload artifacts; distinguish observed packets from reconstructed host segments; report capture drops; suppress or qualify MTU/loss verdicts when evidence is ambiguous. Frame-size verdicts must compare against link MTU plus L2 encapsulation rather than a bare 1,500-byte constant, so a normal 1,510-byte Ethernet frame is never reported as oversize. |
| GAP-020 | P2 | Privileged platform reports collect unrelated sensitive sections | `wdutil info` provided useful Wi-Fi state but also emitted Bluetooth device names/addresses and other data unrelated to the test. | Extract only an allowlisted set of Wi-Fi/network fields in memory, redact identifiers before writing, and avoid persisting unrelated platform-report sections. |
| GAP-021 | P1 | Latency tests do not detect probe-rate artifacts | First-hop and Internet ICMP latency was stable at one probe/second, but both showed large spikes at five probes/second. A single probe cadence could mislabel control-plane rate limiting or batching as path jitter. | Test at normal and elevated probe rates, correlate gateway and remote samples, identify probable ICMP policing/batching, and avoid treating ICMP-only spikes as application latency without corroboration. |
| GAP-022 | P1 | First-hop isolation depends on ICMP echo | The general event WLAN passed Internet ICMP with zero loss but suppressed every echo request to its default gateway, preventing the same gateway-latency comparison used on the room WLAN. | Fall back to ARP/ND timing, TCP SYN timing, trace TTL responses, or passive gateway observations; report ICMP suppression separately from packet loss. |
| GAP-023 | P1 | No ECN/AQM protocol A/B control | In the same-room control, HTTP/3 reported Accurate ECN while HTTP/2 reported ECN disabled. HTTP/3 retained full upload but lost about 85% of directional download capacity under simultaneous load. | Record ECN negotiation and markings, support safe ECN-on/off comparison where the platform permits it, correlate CE marks with queue delay and direction, and distinguish classic ECN from L4S. |
| GAP-024 | P2 | Cross-SSID tests lack a stable privacy-safe AP identity | Switching from the room SSID to the general SSID changed band, channel, signal, and PHY rate, but platform redaction prevented determining whether both radios belonged to one physical AP. | Generate a locally stable salted AP/radio identifier from BSSID without storing or displaying the BSSID; record band/channel so same-AP, cross-radio, roaming, and cross-AP comparisons are distinguishable. |
| GAP-025 | P0 | Protocol tests do not preflight endpoint capability | HTTP/3-only failed against `speed.cloudflare.com` and `www.apple.com`, while Cloudflare's main site, Google, and Apple's dedicated measurement endpoint supported HTTP/3 from the same WLAN. An endpoint without QUIC could be misdiagnosed as network blocking. | Preflight ALPN/Alt-Svc and a protocol-valid handshake against multiple known-capable endpoints; separate unsupported endpoint, handshake rejection, timeout, and network filtering verdicts; never infer blocking from one host. |
| GAP-026 | P1 | MSS analysis does not correlate multiple destinations with PMTU | On the external MGM control, Apple, Cloudflare, and Google all negotiated MSS 1238 while 1500-byte DF packets succeeded. Individual warnings cannot express the strong evidence for a TCP-specific path policy or distinguish it from a low PMTU. | Probe multiple independent destinations, cluster negotiated/on-wire MSS values, compare them with confirmed route/path MTU, and report whether evidence supports peer-specific MSS, uniform TCP clamping/proxying, or a true PMTU ceiling. |
| GAP-027 | P0 | Load tests do not monitor Wi-Fi association changes or qualify weak RF | A downstairs test began on 5 GHz and roamed to 2.4 GHz after the laptop moved three feet. Later stationary runs remained on weak 2.4 GHz but produced protocol errors and severe H2/H3 impairment. Without before/during/after radio state, mixed-association output could be mistaken for a transport failure. | Sample association identity, band, channel, RSSI, PHY rate, and counters before/during/after every load phase; invalidate results spanning a roam; flag weak/unstable RF; retain failure evidence without calculating protocol collapse ratios from invalid runs. |
| GAP-028 | P1 | No multi-uplink ECMP/LAG hash and NAT-affinity diagnostic | Black Hat uses two 10 Gb provider links. A non-symmetric hash, per-packet spraying, unstable NAT ownership, one bad hash bucket, or unequal member policy could explain why bidirectional QUIC fails while directional QUIC and H2 remain healthy. | Sweep fixed UDP/TCP client ports and destinations, preserve each 5-tuple, record repeated STUN mappings/public egress identity, detect bimodal outcomes and mid-flow rebinding, compare forward/reverse/bidirectional performance, and report evidence for stable per-flow affinity versus path migration. |
| GAP-029 | P1 | No controlled one-circuit-at-a-time comparison workflow | Client-only tests cannot prove which WAN member or shared edge owns a failure. The decisive test requires the same bundle with WAN A only, WAN B only, and both active while collecting member counters. | Export a signed/repeatable test manifest; coordinate pre/post snapshots; label circuit state; ingest per-member utilization, drops, policer, errors, NAT/firewall ownership, and route changes; compare A-only, B-only, and dual-active verdicts without FragglePacket changing production routing itself. |
| GAP-030 | P1 | No matched wired-versus-Wi-Fi fault-domain control | Generic UDP was lossless at 250 Mbps each way and directionally at 350 Mbps, but lost 8-30% downstream at 350 Mbps bidirectional on strong Wi-Fi. Client-only evidence cannot distinguish WLAN airtime/queue policy from the dual WAN paths. | Run the same signed fixed-port matrix on wireless and wired clients in the same routed policy domain; record interface/radio state and edge counters; attribute a failure to WLAN, shared edge, or WAN only when the matched control supports it. |
| GAP-031 | P1 | Load phases do not snapshot and normalize interface-counter deltas | The wired interface began with zero drops and ended the near-gigabit suite with 17,517 cumulative drops, while a separately bracketed 350 Mbps bidirectional UDP phase added zero. Without per-phase snapshots, drops cannot be assigned to a protocol, rate, driver ring, or path. | Capture interface counters immediately before and after every phase; report deltas normalized by packets/bytes; distinguish host/driver drops from remote loss; qualify results when counters wrap, reset, or include unrelated traffic. |
| GAP-032 | P1 | No independently rate-controlled simultaneous upload/download workflow | A single iperf3 `--bidir` session applies the same target in both directions. Independent listeners exposed a sharp Wi-Fi cliff between 250 and 300 Mbps while one direction stayed fixed at 350 Mbps. | Coordinate two time-aligned client sessions against separate server listeners; set independent rates, lengths, ports, durations, and source bindings; merge both JSON results onto one timeline and report the first lossy rate in each direction. |
| GAP-033 | P1 | No datagram-size and packet-rate pressure matrix | At 350 Mbps each way, Wi-Fi downstream loss increased from 16.3% with 1,472-byte payloads to 65.1% with 200-byte payloads, while wired remained near-lossless. Byte rate alone hides packet-processing and airtime pressure. | Sweep safe non-fragmenting payload sizes, calculate offered/received packets per second, verify actual IP family and MTU, compare directional and bidirectional modes, and distinguish packet-rate ceilings from byte-rate policing. |
| GAP-034 | P1 | No constant-aggregate flow-count and QoS classification matrix | Wi-Fi loss varied non-monotonically with 1/2/4/8 flows, and DSCP-marked runs were variable without capture proof that markings survived. Fixed hash buckets and WMM/QoS treatment cannot be inferred from one run. | Hold aggregate rate constant while varying flow count and source ports; interleave repeated controls; sweep DSCP classes; capture DSCP before and after the path; correlate results with WMM access category and infrastructure queue counters. |
| GAP-035 | P1 | No radio-state guard around every load phase | A post-test check showed strong 6 GHz RF, but a roam, channel-width change, PHY-rate change, or power-save transition during an individual phase could invalidate attribution. | Snapshot allowlisted band/channel/width/RSSI/noise/PHY rate/MCS before and after every phase; detect changes; mark affected results invalid; never persist SSID, BSSID, MAC, Bluetooth, or unrelated platform data. |
| GAP-036 | P2 | No test-endpoint capability discovery | The controlled server already exposed independent iperf3 listeners on 443-445, but the client workflow initially assumed only 443. That delayed port-specific and asymmetric tests. | Probe an explicit allowlist of authorized endpoint ports, validate iperf version/features, record listener purpose, and select independent listeners automatically without broad port scanning or server mutation. |
| GAP-037 | P1 | No AP-generation, radio-mode, and client-capability compatibility matrix | Arista API inventory confirmed all 24 probe-associated APs were C-460 on `21.3.0M-13`, while tested clients negotiated VHT or HE rather than EHT. Twenty APs were in reduced-power PoE+ mode, but PC10 reproduced the worst fixed-rate loss on full power and PV10 was clean on full power, so neither AP model, firmware, nor power mode alone explains the cohort split. | Record AP model/firmware/power mode, negotiated HE/EHT mode, MLO state, band/width/NSS and client chipset; repeat the signed threshold test across Wi-Fi 7 AP in BE mode, the same AP/radio in AX mode, a Wi-Fi 6E AP, and native Wi-Fi 7 versus Wi-Fi 6E clients; produce a compatibility verdict matrix. |
| GAP-038 | P1 | No distributed wireless-probe orchestrator | Twenty-four authorized Precog probes span conference-center VLANs and radios, but FragglePacket cannot safely inventory, label, batch, or correlate them through a management-only bastion. | Add a controller that enforces management/test-node separation, stable redacted labels, bounded concurrency, pre/post radio snapshots, per-node timeouts, signed manifests, and merged fleet summaries without persisting management addresses or credentials. |
| GAP-039 | P0 | iperf JSON parsing is not version-, direction-, or duration-aware | Precog clients span iperf3 3.9 and 3.16 while the Mac uses 3.21. In the PC13 receiver-path A/B, 3.9 emitted native bidirectional directions only in per-stream sender flags, so the 3.16 aggregate parser initially displayed the reverse direction as zero. Both 128 KiB native runs also ended with invalid durations and near-zero payload, while a paired listener connection reset produced an empty JSON object that the old parser labeled `ok` at zero Mbps. | Detect client/server versions and feature compatibility; decode direction from validated schema-specific fields; require successful process status, complete JSON, requested-duration tolerance, nonempty byte counts, and both directions before accepting a result; fall back to paired listeners when native mode is incompatible; distinguish offered, sent, received, and estimated rates; never turn missing or invalid fields into zero-throughput network evidence. |
| GAP-040 | P1 | No public-listener allocation and baseline-floor control | XMission exposed multiple listeners, enabling concurrent directional sessions, but each listener accepts one test and old-client reverse UDP showed a roughly 0.6-1.0% floor. Shared public-service/NAT effects can contaminate comparisons. | Discover only authorized listener ranges, lease one listener per active session, cap concurrency, interleave directional controls, estimate endpoint loss floor by client version, detect busy/rate-limit responses, and qualify public-endpoint results. |
| GAP-041 | P1 | No remote probe health and dependency preflight | One trusted node had a broken iperf binary due to missing `libiperf.so.0`, one repeatedly timed out, and three presented changed SSH host keys. Treating those as network failures would corrupt fleet conclusions. | Preflight executable/library health, clock, route, radio association, disk/CPU, and endpoint reachability; quarantine unhealthy nodes; require independently verified host-key rotation; report excluded nodes and reasons. |
| GAP-042 | P1 | No PHY-normalized fleet comparison | Fixed 100+100 Mbps load produced a sharp VHT-versus-HE split, but client PHY rates and generations differ. Fixed rates can conflate normal airtime saturation with compatibility defects. | Calculate offered airtime/PHY fractions per phase, enforce comparable normalized targets, stratify by PHY generation/driver/kernel, and require strong-RF directional controls before attributing a cohort difference to AP backward compatibility. |
| GAP-043 | P1 | No telemetry-counter liveness validation | Privileged wireless station counters were readable on PC6/PV03 but did not advance during known 100+100 Mbps traffic. A zero delta from a frozen driver counter can be falsely reported as proof of zero retries or drops. | Bracket a known packet stimulus, verify expected packet counters advance, detect frozen/reset/wrapped counters, qualify unusable sources, and require an alternate source such as AP/controller telemetry or capture before issuing a zero-drop verdict. |
| GAP-044 | P1 | No local-gateway latency-under-load bracket | Concurrent gateway ping localized PC6 queueing to a path already containing the WLAN downlink: average RTT rose from 1.646 ms idle to 7.146 ms during a 23.550% downstream-loss phase, while PV03 remained near idle. FragglePacket cannot coordinate or interpret this near-side control. | Pair idle, upload, download, and simultaneous load phases with interface-bound first-hop probes; report loss and RTT deltas; correlate their timeline with throughput loss; fall back when ICMP is suppressed; warn that small ICMP packets may receive different queue treatment. |
| GAP-045 | P1 | No synchronized public-listener admission validation | Twenty-one probes started four-stream TCP tests on 21 ports in the same second after port-open checks, but only 12 completed. Eight never established a test connection and one partially admitted streams before timeout. Treating these as zero throughput would falsely implicate clients. | Implement a barrier-synchronized fanout with per-listener protocol admission, server-wide concurrency/capacity metadata, start/end skew validation, partial-stream detection, safety timeouts, minimum valid-cohort rules, and explicit endpoint/admission verdicts that never become zero-throughput measurements. |
| GAP-046 | P2 | No version-aware maximum-throughput tuner | iperf3 3.9 and 3.16 reacted differently to parallel streams and zero-copy. PC3 peaked with four streams/128 KiB while PV03 peaked with eight streams/512 KiB/zero-copy; sixteen streams produced an invalid receiver duration. Public baseline drift was also large. | Add randomized repeated candidate trials, version/capability detection, CPU/socket-limit preflight, duration validation, endpoint-drift brackets, cohort-specific profiles, and separate synthetic-maximum versus representative-application verdicts. Never force socket windows beyond validated client/server maxima. |
| GAP-047 | P0 | No production-safe load budget and automatic abort guard | Conference tests share infrastructure with attendees. A maximum bidirectional run can create severe queueing even on otherwise healthy clients, so an unbounded test can worsen the incident it is measuring. | Require an explicit load budget, progressive ramp, maximum duration/concurrency, maintenance versus live-event mode, and abort thresholds for gateway latency, loss, association change, endpoint error, or operator cancellation. Record why a run stopped and never start maximum stress by default. |
| GAP-048 | P1 | No DHCP, address-lifecycle, and pool-capacity test | Conference networks have rapid client churn, short leases, relays, multiple VLANs, and a high risk of pool exhaustion or slow renewals. A client that already has a lease can look healthy while new arrivals fail. | Measure discover-to-address time, offer/ack source, options, lease duration, renewal/rebind, duplicate-address detection, relay consistency, pool headroom from authorized telemetry, and failure behavior. Support a non-disruptive existing-lease check and a separately authorized fresh-lease test. |
| GAP-049 | P1 | No authentication, captive-portal, and policy-assignment workflow | PSK, open, captive-portal, and 802.1X networks can fail before ordinary IP tests begin. RADIUS delay, portal loops, stale authorization, or wrong role/VLAN assignment can affect only part of the population. | Time association, authentication, portal detection/login handoff, DHCP, DNS, and first usable HTTPS separately. For 802.1X, record EAP method and anonymized RADIUS outcome; verify expected role/VLAN/ACL without storing credentials; detect reauthentication and session-expiry failures. |
| GAP-050 | P1 | No controlled roaming and session-continuity test | A three-foot move changed the test association and invalidated results. Conference users walk between dense rooms while calls, QUIC sessions, and VPNs remain active. | Run a timestamped walk or AP-transition test with continuous gateway, Internet, TCP, QUIC, and optional RTP probes. Record privacy-safe AP/radio transitions, 802.11k/v/r and MLO state, handoff duration, lost packets, session resets, band steering, sticky-client behavior, and whether the assigned VLAN/public identity changes. |
| GAP-051 | P1 | No coordinated multi-client capacity and fairness test | A single client near its PHY ceiling is not representative of a full training room. The incident affected many attendees, while the current fleet tests mostly compare independent public flows and client cohorts. `scripts/bhusa-peer-impact-test.zsh` is a working two-client prototype of the load/observe role split; port its method rather than reinventing it. See also GAP-072, which requires both roles to emit descriptors before a cross-client verdict. | Coordinate bounded representative loads from multiple clients on the same AP/radio; measure aggregate capacity, per-client throughput, airtime, latency, loss, Jain fairness, starvation, client-count scaling, and legacy/new-client interaction. Correlate every phase with AP/controller queue and airtime counters. |
| GAP-052 | P1 | No real-time voice, video, and WebRTC quality test | Speed tests can pass while conferencing fails because calls care about one-way delay, jitter, burst loss, media setup, and TURN behavior. Training rooms depend on Zoom, Teams, Webex, and browser media. | Add synthetic RTP/WebRTC calls with audio- and video-like packet sizes/rates; report setup success, ICE path, one-way delay when clocks permit, RTT, jitter, burst loss, reordering, concealment estimate, freeze risk, and MOS-style qualification. Test direct UDP, TURN/UDP, TURN/TCP, and TURN/TLS without placing a real call. |
| GAP-053 | P1 | No managed internal reference-endpoint kit | Public iperf listeners produced admission failures, rate floors, duration errors, and time drift. Without an internal wired endpoint, WAN, NAT, and public-server variables remain mixed with the WLAN. | Provide a deployable signed server bundle with isolated listeners, health/capacity telemetry, synchronized clocks, bounded resource limits, server-side JSON retention, TLS/QUIC/iperf support, and a calibration mode. Require server CPU, NIC, queue, drop, and interval-validity checks before accepting client results. |
| GAP-054 | P1 | No firewall, NAT, and session-state capacity matrix | Stable STUN mappings reduced concern about one live flow, but conference scale can exhaust NAT ports, connection tables, UDP state, new-session rate limits, or state synchronization between nodes. | With authorization, measure TCP/UDP session creation rate, concurrent-state ceiling, NAT mapping/filtering behavior, idle timeouts, keepalive survival, fragment handling, port allocation, hairpin behavior, and failover continuity. Correlate failures with firewall/NAT owner, table usage, drops, policers, and state-sync counters. |
| GAP-055 | P1 | No time-based RF spectrum, interference, and coverage survey | One radio snapshot cannot reveal intermittent non-Wi-Fi interference, co-channel contention, hidden nodes, DFS events, or load that follows the class schedule. Strong RSSI did not prevent the observed loss. | Collect bounded time-series channel utilization, noise, retries, channel changes, DFS/radar events, neighboring BSS load, non-Wi-Fi utilization, client count, and airtime by location. Produce privacy-safe coverage/capacity maps and correlate change points with test failures and event schedules. |
| GAP-056 | P1 | No complete IPv6, NAT64, and DNS64 validation | Recording that IPv6 is absent does not test broken router advertisements, DHCPv6, neighbor discovery, IPv6 PMTU, NAT64, or dual-stack fallback. These failures can appear site-specific. | Validate RA contents/lifetime, SLAAC and DHCPv6, default route, NDP, DNS AAAA, IPv6 PMTU/PLPMTUD, native reachability, NAT64/DNS64 discovery, IPv4-only and IPv6-only destinations, and Happy Eyeballs timing. Keep IPv4 and IPv6 verdicts separate. |
| GAP-057 | P1 | No multicast, broadcast, discovery, and client-isolation test | Conference WLANs often suppress or proxy ARP, IPv6 ND, mDNS, SSDP, and other multicast traffic. Incorrect suppression or isolation can break discovery, casting, labs, and local services or create broadcast load. | Compare expected policy with observed ARP/ND, DHCP broadcast, mDNS, SSDP, multicast group join/delivery, multicast-to-unicast conversion, and peer isolation. Use authorized paired clients, rate caps, and explicit expected-reachable/expected-blocked verdicts. |
| GAP-058 | P1 | No wired edge, AP uplink, LLDP, and PoE health bundle | Arista CV-CUE reported 20 of 24 tested C-460 APs on `POE_PLUS` with `lowPowerSupply=true`; each requested 40 W but received 25.5 W and linked at 1 Gbps. Only four received 40 W and linked at 5 Gbps. All links were up and APs active/compliant, but the API exposed no CRC, discard, pause, queue, or link-flap counters to bracket a failing phase. | Ingest switch/AP telemetry for LLDP identity, PoE class/budget/draw, reduced-power state, link speed/duplex, LACP member state, VLAN/native-tag consistency, CRC/errors/discards, pause frames, queue drops, and link flaps. Bracket counters around the client test timeline and flag models operating below vendor full-power requirements. |
| GAP-059 | P1 | No infrastructure dependency health bundle | DNS steering is covered, but clients also depend on DHCP, NTP, certificate validation, captive-portal detection, OCSP/CRL reachability, and controller/cloud services. A partial dependency failure can look like a slow website. | Run a dependency manifest that times and validates required DNS UDP/TCP/DoT/DoH behavior, NTP offset/reachability, HTTPS certificate chain and revocation endpoints, portal-detection URLs, and configured controller/cloud dependencies. Distinguish blocked-by-policy from unhealthy. |
| GAP-060 | P1 | No VPN and encapsulation compatibility matrix | Attendees commonly use IPsec/IKEv2, WireGuard, OpenVPN, TLS VPNs, and corporate ZTNA clients. Tunnel overhead, UDP timeouts, fragments, or policy can break one VPN while web tests remain healthy. | Test authorized synthetic tunnels or protocol handshakes across common transports and ports; measure setup, keepalive, effective MTU/MSS, rekey, idle survival, throughput, and simultaneous latency. Never require or capture production VPN credentials. |
| GAP-061 | P1 | No provider, geography, and path-stability comparison | One public endpoint cannot separate a local edge problem from peering, CDN steering, regional congestion, route changes, or asymmetric provider behavior. Traceroute alone is often incomplete. | Use authorized endpoints in multiple providers and regions; record DNS answer, destination ASN/region, TCP/QUIC handshake, throughput, loss, latency, path changes, and repeated trace samples. Correlate results with BGP/provider telemetry when available and avoid treating non-responsive hops as loss. |
| GAP-062 | P1 | No controlled resilience and failover validation | Conference networks depend on redundant controllers, firewalls, WAN links, switches, DHCP/DNS services, and AP uplinks. Healthy steady-state testing does not prove that sessions survive a failure. | During an approved window, run a low-rate continuous session bundle while operators fail one component at a time. Measure outage duration, packet loss, route/NAT identity changes, session survival, state resynchronization, and recovery. FragglePacket must observe and label the change, never initiate production failover itself. |
| GAP-063 | P2 | No cross-platform and power-save client matrix | The observed cohorts also differed by adapter, driver, kernel, and iperf version. Conference populations include macOS, Windows, Linux, iOS, Android, sleep states, TWT, U-APSD, randomized MAC behavior, and different Wi-Fi generations. | Record privacy-safe OS/device/driver/radio capabilities and test the same representative bundle across supported platforms, active versus power-save state, and Wi-Fi generations. Separate platform correlation from infrastructure causation and avoid collecting personal device identifiers. |
| GAP-064 | P1 | No synchronized clock and one-way event-correlation guard | Distributed clients, endpoints, APs, controllers, firewalls, and provider devices need a common timeline. Clock skew can make drops appear in the wrong component and prevents trustworthy one-way-delay measurements. | Preflight NTP/PTP status and clock offset on every authorized node; reject or qualify one-way metrics beyond a configured skew; record monotonic and wall-clock timestamps; merge client, server, and infrastructure events with uncertainty bounds. |
| GAP-065 | P1 | No expected-policy and service-reachability manifest | A conference network intentionally blocks some east-west traffic and may allow different services by SSID/VLAN/role. Generic pass/fail tests can label correct isolation as an outage or miss a wrong authorization policy. | Accept an operator-approved matrix of roles, source zones, destinations, protocols, ports, and expected allow/deny outcomes. Test only listed targets, distinguish timeout/reject/redirect, flag policy drift, and keep security-sensitive topology redacted from attendee-facing reports. |
| GAP-066 | P1 | No burst-loss, reordering, duplication, and microburst analysis | Average loss and throughput hide short bursts that disrupt media and interactive traffic. Parallel streams and queue pressure can also reorder or duplicate packets without changing the long-run average much. | Generate bounded timestamped sequences at representative and ramped rates; report burst length/distribution, gap duration, reordering depth, duplicates, jitter, and queue-delay correlation. Support both client/server logs and packet-capture validation with offload awareness. |
| GAP-069 | P0 | No process-model equivalence and receive-path artifact guard | On PV10 at the same 250 Mbps-per-direction target, native iperf3 `--bidir` stayed approximately balanced at 145–161 Mbps per direction and produced zero `TCPRcvCollapsed`, while the two-process/two-listener method often became severely asymmetric and produced 70–102 receive-collapse events per trial. Combined throughput stayed in a similar 302–326 Mbps band, so the harness can mislabel process or receive-drain unfairness as a network directional collapse. | Compare native bidirectional and paired-process modes at fixed rates and block sizes; capture socket memory, per-core CPU/softirq, `TCPRcvCollapsed`, softnet, and qdisc counters; classify shared-capacity saturation separately from method-specific unfairness; do not attribute a directional collapse to the network unless it reproduces across process models or in an application-representative method. |
| GAP-070 | P0 | No native capacity/latency-knee discovery with application cross-validation | PC13 delivered native bidirectional traffic nearly in full through 60 Mbps per direction, then plateaued near 134–142 Mbps combined from 70–100 while loaded gateway latency rose from 8 to 17–28 ms. Rate-controlled application traffic independently reproduced the knee: 60+60 Mbps remained nearly balanced, but at 70+70 HTTPS upload fell to 44–47 Mbps while download held near 72 Mbps and gateway latency averaged 45–68 ms. Manual listener qualification and public H3 controls were required to avoid endpoint failures and drift. | Add a bounded native-bidirectional rate sweep that leases a distinct qualified listener per phase, interleaves idle latency, randomizes and repeats points around the detected knee, rejects process/schema/duration failures, and distinguishes capacity plateau from directional unfairness. Automatically cross-validate the below-knee and above-knee points with rate-controlled HTTP/2, HTTPS upload, and multiple preflighted HTTP/3 endpoints; bracket public tests with opening/closing controls and report endpoint drift separately. |
| GAP-072 | P1 | Peer-impact tests cannot record the peer's own state, so a 1:many verdict is unfalsifiable | The 2026-08-02 coordinated run measured severe degradation on the loading client (directional download fell from 350.3 Mbps to 201.6 Mbps and lost 42.5% of datagrams; simultaneous phases lost 85-86% downstream with gateway RTT reaching 571.9 ms). The written assessment could not reach a verdict because the peer's mode, listener ports, association, and timestamps were never captured. Worse, the two candidate explanations invert the conclusion: if the peer loaded the same public listeners, listener admission is a confound; if the peer was passive, the same numbers instead record background impairment. | Require both roles to emit a signed run descriptor recording mode, interface, association identity, listener endpoints/ports, clock offset, and phase timestamps; refuse a cross-client verdict until both descriptors are present and their phase windows actually overlap; detect shared-listener contention between roles and label it a confound rather than a result; never report a 1:many impact verdict from one side's evidence alone. |

## Resolved during this investigation

| Item | Resolution |
| --- | --- |
| GAP-067, GAP-068, GAP-071 (vendor controller connector, historical import, config snapshot) | **Dropped as out of scope 2026-08-03.** They required a CV-CUE/Arista connector inside the tool: 1Password credential retrieval, `launchpad.wifi.arista.com` tenant discovery, `/wifi/api/*` routes, and vendor `Version` headers. FragglePacket is vendor-agnostic, and coupling a general-purpose diagnostic to one controller's HTTP API is the wrong architecture. The `arista-ops` skill already owns that access, and `wired_edge.rs` / `ap_compat_matrix.rs` already ingest operator-supplied AP and switch telemetry as vendor-neutral `Option` fields. |
| Stale release binaries silently launched | `start.sh` now rebuilds release binaries when Rust sources or manifests are newer. |
| Hard-coded MSS 1460 was presented as an on-wire advertisement | TCP options analysis now compares TCP_MAXSEG with the active route MTU, accounts for normal TCP-option allowance, and uses cautious verdict wording. |

## Append-only investigation notes

### 2026-08-01 — Wi-Fi protocol investigation

- MTU 1500 was confirmed with DF probes; no large-transfer TCP blackhole was observed.
- TCP_MAXSEG varied by destination, which argues against a blanket MSS clamp.
- Large TCP uploads/downloads completed, while loaded latency increased substantially.
- HTTP/1.1, HTTP/2, and HTTP/3 produced different capacity and responsiveness profiles.
- STUN binding responses succeeded consistently, ruling out blanket UDP/NAT failure.
- Wi-Fi RF snapshot was strong; retry/WMM/channel-utilization data remained privilege-gated.
- A bounded-capture feature is required after an external full-snaplen capture grew to roughly 2 GB.
- Elevated Wi-Fi diagnostics showed 6 GHz/80 MHz 802.11ax, RSSI -53 dBm,
  noise -93 dBm, MCS 11, 1,200 Mbps PHY rate, 0% CCA at the snapshot, and no
  Wi-Fi faults or recoveries in the prior hour. The report still did not expose
  retry or WMM counters.
- TCP/443 traceroute reached the destination operator's network by hop 5. Later
  non-responses are inconclusive because routers and endpoints may decline TTL
  expiry probes.
- SYN capture showed the client advertising MSS 1460 on the MTU-1500 Wi-Fi
  interface. Apple peers advertised 1456 and Cloudflare advertised 1400, which
  supports destination-specific peer/path behavior rather than a blanket local
  outbound MSS clamp.
- Directional HTTP/3 remained fast, while two simultaneous HTTP/3 runs reduced
  download throughput to roughly 28-30 Mbps and raised loaded HTTP latency as
  high as 2.5 seconds. This isolates the strongest symptom to bidirectional QUIC
  load rather than a blanket UDP/443 failure.
- Host-side capture offload made raw frame-size and TCP retransmission counters
  unsuitable for unqualified on-wire conclusions; offload-aware analysis was
  added as a P0 requirement.
- A location baseline found clean one-probe-per-second latency: 4.28 ms average
  to the first-hop gateway with 0.33 ms standard deviation, and 19.36 ms average
  to an Internet control with 1.47 ms standard deviation. At five probes per
  second, both targets showed correlated spikes approaching 100 ms. This is
  consistent with probe-rate-specific ICMP handling and requires application
  traffic corroboration before being called path jitter.

### 2026-08-02 — Same-room general WLAN control

- The control changed from the room SSID's 6 GHz/80 MHz radio at approximately
  -52 dBm and 1,200 Mbps PHY to a 5 GHz/40 MHz radio at -70 dBm and 344 Mbps
  PHY. Route MTU remained 1500 and the resolver set was unchanged.
- Internet-control ICMP was clean at one probe per second: 19.15 ms average,
  0.89 ms standard deviation, and zero loss. The default gateway suppressed
  ICMP echo completely, so gateway loss or latency cannot be inferred from that
  probe.
- HTTP/3 directional capacity was 181.7 Mbps down and 240.3 Mbps up. Under
  simultaneous load, download collapsed to 27.6 Mbps while upload remained
  251.3 Mbps. The same simultaneous-only download collapse therefore followed
  the client across SSIDs and radio profiles in the same room.
- HTTP/2 directional capacity was 218.0 Mbps down and 230.2 Mbps up. Under
  simultaneous load it remained directionally balanced at 94.5 Mbps down and
  108.5 Mbps up, though responsiveness was poor. This differs from HTTP/3's
  strongly asymmetric result.
- HTTP/3 reported Accurate ECN with L4S disabled; HTTP/2 reported ECN disabled.
  This is a correlation and not yet evidence that ECN causes the failure.
- Negotiated MSS remained destination-specific: Apple 1460, Cloudflare 1400,
  and Google 1412 on the same route MTU. No blanket MSS clamp was observed.
- HTTP/3 capability was endpoint-specific: Cloudflare's main site and Google
  completed HTTP/3, while the Cloudflare speed host and Apple's public website
  did not. Apple's dedicated network-quality endpoint did complete HTTP/3.
  Endpoint preflight is therefore required before labeling a QUIC failure as
  network filtering.

### 2026-08-02 — External MGM infrastructure control

- MGM used a distinct subnet, gateway, resolver set, and open 5 GHz/20 MHz WLAN.
  RF was strong at -50 dBm with a 286 Mbps PHY rate. Internet latency averaged
  42.06 ms with 5.89 ms standard deviation and zero loss; its gateway also
  suppressed ICMP echo.
- HTTP/3 directional capacity was 16.40 Mbps down and 44.05 Mbps up. Under
  simultaneous load it remained 16.42 Mbps down and 40.77 Mbps up, with high
  responsiveness. The simultaneous-only HTTP/3 collapse observed on both Black
  Hat SSIDs did not reproduce outside Black Hat infrastructure.
- HTTP/2 was likewise stable downstream: 16.98 Mbps directional and 16.42 Mbps
  simultaneous. MGM appears to enforce an approximately 16-17 Mbps downstream
  policy independent of H2/H3.
- MGM reported ECN unavailable for HTTP/3, while the Black Hat WLANs reported
  Accurate ECN. This strengthens the case for an ECN/AQM control but still does
  not prove causality.
- The Black Hat capture contained 514,587 outbound and 26,017 inbound UDP/443
  packets marked ECT(0), plus six outbound ECT(1) packets, but no CE-marked
  packets. ECN capability was present without observed congestion marking;
  dropping, policing, or directional scheduling remains more likely than CE
  handling alone.
- Apple, Cloudflare, and Google all negotiated MSS 1238 on MGM. In contrast,
  1500-byte IPv4 DF probes succeeded with zero loss. This is strong evidence of
  a uniform TCP-specific clamp or proxy policy rather than a 1280-byte path-MTU
  ceiling, subject to final SYN/SYN-ACK capture confirmation.

### 2026-08-02 — Downstairs BlackHatUSA2026 cross-AP baseline

- The initial association was 5 GHz channel 40 at -77 dBm and 97 Mbps PHY. A
  three-foot laptop move caused a roam to 2.4 GHz channel 5, invalidating two
  setup runs. Stationary official runs stayed on 2.4 GHz at roughly -71 to
  -75 dBm and 68-103 Mbps PHY.
- Stationary unloaded Internet latency was 21.06 ms average with 3.43 ms
  standard deviation and zero loss. The shared gateway again suppressed ICMP.
- HTTP/3 directional completed at 8.92 Mbps down and 66.38 Mbps up, with 2.89
  seconds of download-loaded responsiveness delay. The simultaneous H3 run
  aborted after 10.7 seconds with a protocol error; its partial capacity values
  are not accepted as a collapse baseline.
- HTTP/2 directional completed at 2.46 Mbps down and 34.03 Mbps up. Under
  simultaneous load it delivered 2.08 Mbps down and 18.62 Mbps up, with 5.31
  seconds overall loaded latency and 10.91 seconds for loaded HTTP.
- This location shows severe downstream impairment across both H2 and H3 under
  weak 2.4 GHz RF. It is not a clean reproduction of the upstairs
  simultaneous-only H3 symptom; it is evidence of a separate coverage/capacity
  problem on the general WLAN.
- MSS remained destination-specific and matched the upstairs general WLAN:
  Apple 1460, Cloudflare 1400, and Google 1412. No blanket clamp was observed.

### 2026-08-02 — Downstairs strong-radio Black Hat reproduction

- Switching to a nearby room SSID produced a stable 6 GHz channel 197 / 80 MHz
  association at -55 dBm, with PHY rate increasing from 864 to 1,200 Mbps.
  Unloaded gateway latency averaged 4.58 ms and Internet latency averaged 19.72
  ms, both with zero loss.
- HTTP/3 directional capacity reached 679.28 Mbps down and 331.66 Mbps up.
  Under simultaneous load it fell to 41.44 Mbps down and 165.54 Mbps up, so
  download retained only 6.1% of directional capacity. The run also lost a
  connection after 13.4 seconds.
- On the same radio, HTTP/2 reached 749.62 Mbps down and 617.65 Mbps up
  directionally, then 333.81 Mbps down and 394.86 Mbps up simultaneously with
  no failure. H2 retained 44.5% of directional download and remained balanced.
- This cleanly reproduces the Black Hat simultaneous-H3 failure hundreds of
  feet from the original room on a different channel, subnet, gateway, and
  nearby radio while strong RF and H2 remain healthy. The leading fault domain
  is shared Black Hat controller/upstream QUIC handling or queue policy, not
  MSS, weak RF, one AP, or client-wide QUIC behavior.
- MSS again remained destination-specific: Apple 1460, Cloudflare 1400, and
  Google 1412 on route MTU 1500.

### 2026-08-02 — Fixed-port iperf3 dual-uplink probe

- A controlled iperf3 3.21 server was available at `test.protoevidence.com` on
  TCP/UDP port 443. A two-second directional TCP discovery delivered about 515
  Mbps with zero retransmissions; reverse delivered about 500 Mbps with one.
- Ten three-second bidirectional TCP source-port buckets varied from 33-307
  Mbps upload and 160-576 Mbps download. Client-to-server retransmissions ranged
  from 156 to 21,412 while the reverse sender reported zero in every bucket.
- Ten bidirectional UDP buckets at 50 Mbps each way were lossless. At 250 Mbps
  each way, nine were lossless and one showed 0.164% downstream loss.
- Six bidirectional UDP buckets at 350 Mbps each way showed essentially zero
  upload loss but 8.3-30.1% downstream loss, averaging about 20.4%. The same
  350 Mbps flows were lossless in both directions when run one direction at a
  time on representative ports. This independently proves a bidirectional
  downstream-loss trigger with generic UDP.
- One fixed STUN socket retained the same public mapping throughout a ten-second
  failing 350 Mbps bidirectional run; two STUN responses timed out while UDP
  downstream loss reached 12.2%. Twenty distinct STUN source ports all used one
  public IPv4 address. No client-visible NAT rebinding or egress-IP split was
  observed.
- The port sweep did not form a healthy/bad bimodal split; every 350 Mbps bucket
  showed the same directional failure. One isolated bad ECMP/LAG member is less
  likely than shared queue/policer/WLAN behavior, but only member telemetry,
  wired comparison, and A-only/B-only circuit tests can localize it.

### 2026-08-02 — Matched wired Black Hat control

- The default route moved to a 1 Gbps full-duplex Ethernet interface on a
  separate Black Hat VLAN, MTU 1500. Gateway latency averaged 1.20 ms and
  Internet latency 15.98 ms with zero loss.
- HTTP/3 delivered 749.97 Mbps down and 886.54 Mbps up directionally, then
  674.18 Mbps down and 880.17 Mbps up simultaneously with high responsiveness
  and no error. It retained 89.9% of directional download, eliminating the
  Wi-Fi H3 collapse on the wired path.
- HTTP/2 delivered 889.64 Mbps down and 902.40 Mbps up directionally, then
  850.28 Mbps down and 852.74 Mbps up simultaneously.
- Six wired 350 Mbps-each-way UDP source-port buckets had zero downstream loss;
  five were fully lossless and one had 0.045% upload loss. An additional
  bracketed run was fully lossless and added no interface drops. The matching
  Wi-Fi runs lost 8.3-30.1% downstream on every bucket.
- Six wired bidirectional TCP buckets sustained 940-947 Mbps upload and 809-837
  Mbps download. Local upload retransmissions were 0-22; the remote sender
  reported 6,290-7,563 download retransmissions without throughput collapse,
  so retransmission counts require normalization and sender-context reporting.
- Twenty wired STUN source ports consistently used one public IPv4 address,
  but it differed from the single public address consistently used by twenty
  Wi-Fi ports. The wired result therefore localizes the failure to either the
  WLAN/controller path or VLAN-specific NAT/egress/circuit selection; it does
  not alone prove the dual uplinks are shared identically.

### 2026-08-02 — Wi-Fi duplex-threshold characterization

- With wired and Wi-Fi active simultaneously, identical interface-bound tests
  were lossless on wired through 350 Mbps each way. Wi-Fi showed downstream
  loss at four of five 250-350 Mbps rate points while upstream loss remained
  zero.
- At 350 Mbps each way, Wi-Fi downstream loss increased from 16.3% with
  1,472-byte payloads to 65.1% with 200-byte payloads. Wired handled the same
  packet-rate matrix with at most 0.483% downstream loss and was lossless at
  1,200 bytes.
- Full-size Wi-Fi upload-only and download-only controls each delivered about
  348-350 Mbps with zero loss. Simultaneous traffic delivered 340 Mbps upload
  with zero loss but only 273 Mbps download with 20.8% loss. Host-interface
  error and drop counters did not increase during any of those three phases.
- Independent server listeners permitted asymmetric testing. A fixed 350 Mbps
  download stayed lossless through 200 Mbps simultaneous upload, was nearly
  clean at 250 Mbps, then lost 5.6% at 300 Mbps and 13.6% at 350 Mbps. With
  upload fixed at 350 Mbps, downstream loss similarly jumped from 0.076% at
  250 Mbps to 19.3% at 300 Mbps and 29.7% at 350 Mbps.
- UDP ports 443, 444, and 445 all reproduced downstream-only loss. This argues
  against a UDP/443-only classifier. Flow-count and DSCP results were variable
  and require repeated, infrastructure-correlated testing before attribution.
- Sanitized post-test radio snapshots remained on 6 GHz channel 197 / 80 MHz.
  They ranged from -60 to -63 dBm signal, -89 to -90 dBm noise, and 680-720
  Mbps transmit rate. The privileged follow-up confirmed 11ax, two spatial
  streams, and an 800 ns guard interval. The evidence now favors Wi-Fi
  airtime/controller queue scheduling over MSS, MTU, client CPU, host drops,
  one UDP port policy, or raw dual-uplink capacity.
- The deployed radios were confirmed as Arista C-460 Wi-Fi 7 APs, and the
  investigation originated from multiple training-class attendees reporting
  ordinary application failures. Single-client airtime saturation explains
  the controlled 600-650 Mbps cliff but cannot alone dismiss the multi-user
  incident. Exact firmware/CV-CUE version, C-460 restart and beacon-loss
  history, PoE++ versus reduced-functionality PoE+ state, Ethernet member,
  per-radio utilization, client count, and WMM/OFDMA queue counters are now
  required evidence.
- The deployed C-460 firmware is `21.3.0M-13`. Arista's public C-460 beacon-loss
  restart notice names `21.3.0M-8` and `21.3.0M-9`, so it does not directly
  cover this build or the observed duplex-loss symptom. Obtain the `M-13`
  known/resolved-issue notes and use only a TAC-approved firmware comparison.
- A later recurrence check was run after reports that the issue had stopped.
  On the same strong 6 GHz / 80 MHz association, directional UDP remained
  lossless at about 350 Mbps each way, while simultaneous UDP lost 33.5% of
  downstream traffic. Two surrounding H3 simultaneous runs delivered only
  55.6 and 28.1 Mbps download with low responsiveness; the intervening H2 run
  completed at 317.0 Mbps download. The incident remained active.

### 2026-08-02 — Distributed Precog wireless controls

- Twenty-one of twenty-four authorized probes were reachable through the
  management-only bastion. Three changed SSH host keys and were excluded. One
  reachable probe had a broken iperf shared library and one timed out during
  the 100 Mbps phase; neither was treated as a network result.
- The usable fleet separated into older VHT/5.10/iperf3-3.9 probes and newer
  HE/6.1/iperf3-3.16 probes, all using 5 GHz / 40 MHz wireless links across
  multiple VLANs and locations.
- At 100 Mbps each way against independent XMission listeners, eleven VHT
  probes showed 2.0-47.9% downstream loss, averaging 27.0%, while upstream
  loss averaged only 0.095%. Eight valid HE probes averaged 0.98% downstream
  loss with zero upstream loss.
- Strong-RF matched controls sharpened the cohort result. VHT PC6 was clean
  directionally at 100 Mbps, then rose from 0.669% directional downstream loss
  to 14.673% simultaneous loss with no host-interface errors or drops. HE PV03
  stayed at its approximately 0.7% directional floor during 100+100 Mbps and
  also added no interface errors or drops.
- The cohort split is consistent with a legacy VHT/client-stack interaction on
  the C-460 WLAN, but fixed offered rate and differing PHY capacity remain
  confounders. A PHY-normalized repeat and AP/client mapping are required
  before claiming a C-460 backward-compatibility defect.
- PHY-normalized representative testing narrowed the claim. VHT PC6 showed
  8.3-18.0% directional downstream loss at 150-250 Mbps while upload remained
  effectively lossless past 200 Mbps; HE PV03 stayed near 0.6-0.75% downstream
  loss through 250 Mbps. At scaled simultaneous loads, PC6 60+60 Mbps produced
  1.67% downstream loss and PV03 125+125 Mbps produced 0.578%. Much of the
  fixed-100 cohort gap is capacity/airtime driven; the residual issue is poor
  strong-RF legacy-VHT downstream efficiency.
- Privileged `iw` station counters on PC6/PV03 remained frozen during known
  100+100 Mbps traffic. They cannot localize loss or support a zero-retry/drop
  conclusion. Ordinary interface counters showed no host errors/drops, but AP
  or over-the-air evidence is still required.
- Concurrent local-gateway probes added a near-side discriminator. PC6 gateway
  RTT rose from 1.646 ms idle to 4.116 ms during a 150 Mbps download with
  5.518% downstream loss, then to 7.146 ms average and 22.738 ms maximum during
  a 100+100 phase with 23.550% downstream loss. PV03 stayed near its 2.340 ms
  idle average and near the public-listener loss floor under matching phases.
- Gateway ICMP had zero loss on both nodes and may receive favorable small-
  packet treatment. Its latency co-movement places queueing on a path already
  containing the WLAN downlink and argues against WAN/public service as the
  sole cause, but AP/controller counters or an internal wired endpoint remain
  necessary to identify the dropping queue.
- A matched TCP control reproduced the UDP signature. PC6 delivered 100 Mbps
  upload in two simultaneous runs but only 69.8 and 61.0 Mbps download, with 76
  and 56 downstream-sender retransmissions. PV03 delivered 100-101 Mbps in both
  directions with zero retransmissions in both matched runs.
- Public TCP listener preflight was essential. XMission's Colorado endpoint
  produced a duration-inconsistent 44.6 Mbps receiver summary, a 61.2 Mbps
  reverse ceiling on the healthy control, and a reset. The primary endpoint
  passed 99.9-100 Mbps directional controls before paired results were accepted.
  GAP-040 must cover capacity and duration consistency by transport, not merely
  listener reachability.
- A 21-node/21-listener overlapping TCP fanout started every probe at the exact
  same epoch with four streams for 20 seconds. Twelve completed and delivered
  2.371 Gbps aggregate receiver throughput; nine reached the 50-second safety
  timeout. Eight timed-out clients never established a test connection and one
  admitted only three streams and one interval.
- Completion clustered by public endpoint pool: 5/9 primary, 7/9 Colorado, and
  0/3 Montana. Port-open checks had passed, demonstrating that reachability is
  not synchronized admission/capacity validation. Timeout results were excluded
  rather than recorded as zero throughput. This produced GAP-045.
- The 64 KiB repeat produced the exact same 12 completed devices and nine
  listener timeouts. Valid aggregate receiver throughput changed from 2.371 to
  2.155 Gbps and retransmissions from 101 to 154, but selective public-endpoint
  admission prevents a clean block-size conclusion.
- All 21 probes received zero core-gateway ICMP replies both idle (25 requests
  per node) and under load (100 requests per node) at 0.2-second cadence. This
  is suppression, not measurable latency or proof of loaded loss. GAP-022's
  responsive-target fallback is required before repeating the fanout.
- A 512 KiB repeat removed the nine listener assignments that failed both prior
  barriers. All 12 retained assignments then completed, delivering 2.203 Gbps
  aggregate receiver throughput with 118 retransmissions. This supports fixed
  endpoint/listener admission limitations rather than nine client failures.
- Per-node throughput was not monotonic across 64, 128, and 512 KiB blocks;
  individual PV/PC nodes moved sharply in both directions while others stayed
  stable. Public-endpoint samples cannot select an optimal application block
  size without interleaved repetition and controlled endpoint telemetry.
- Targeted tuning found different provisional maxima by client generation and
  iperf version. PC3/iperf3-3.9 performed best at four streams and 128 KiB;
  additional streams reduced throughput. PV03/iperf3-3.16 reached 454 Mbps at
  eight streams, 512 KiB, and zero-copy. Sixteen streams produced an invalid
  15.84-second receiver duration.
- Opening/final baseline drift was severe on the public endpoints, so the
  profiles are provisional. This produced GAP-046 for version-aware randomized
  tuning with socket/CPU and endpoint-drift controls.
- Six optimized paired bidirectional stress tests used all 12 known-good public
  listeners. Five became strongly upload-dominant, including Wi-Fi 6 clients.
  Local-gateway average latency increased on every node, with loaded maxima of
  63-185 ms, while all gateway pings were returned and radio signal stayed
  within one dB.
- The result is a valid saturation/bufferbloat signature, not proof of the
  earlier fixed-rate legacy-client issue. FragglePacket must label unbounded
  best-case saturation separately from normalized diagnostic load and preserve
  per-direction stream count, block size, endpoint, and duration validity.
