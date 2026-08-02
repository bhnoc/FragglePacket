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
| GAP-019 | P0 | PCAP analysis is not capture-offload aware | A host-side capture on an MTU-1500 interface contained more than 500,000 apparent frames over 1,450 bytes and very high TCP analysis counts. TSO/GSO/GRO and capture loss can make these look like on-wire oversize packets, loss, or retransmissions. | Detect capture location and offload artifacts; distinguish observed packets from reconstructed host segments; report capture drops; suppress or qualify MTU/loss verdicts when evidence is ambiguous. |
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

## Resolved during this investigation

| Item | Resolution |
| --- | --- |
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
