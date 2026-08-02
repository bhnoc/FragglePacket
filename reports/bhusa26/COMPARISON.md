# BHUSA26 Network Test Comparison Matrix

Living comparison of valid Black Hat USA 2026 network tests. Append new rows as
tests are completed; do not replace historical measurements. Weak/roaming 2.4
GHz results are documented separately in
[`location-b-blackhatusa-downstairs-20260802.md`](location-b-blackhatusa-downstairs-20260802.md)
and intentionally excluded from the capacity comparison below.

## Network baselines

| Date/location | Infrastructure | Radio | Signal | PHY rate | Internet latency | Loss | MTU |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: |
| 2026-08-01 original room | Black Hat room WLAN | 6 GHz, 80 MHz, ch. 5 | -53 dBm | 1,200 Mbps | 19.36 ms | 0% | 1500 |
| 2026-08-02 same-room general WLAN | BlackHatUSA2026 | 5 GHz, 40 MHz, ch. 44 | -70 dBm | 344 Mbps | 19.15 ms | 0% | 1500 |
| 2026-08-02 external control | MGM | 5 GHz, 20 MHz, ch. 100 | -50 dBm | 286 Mbps | 42.06 ms | 0% | 1500 |
| 2026-08-02 downstairs strong radio | Black Hat nearby room WLAN | 6 GHz, 80 MHz, ch. 197 | -55 dBm | 864-1,200 Mbps | 19.72 ms | 0% | 1500 |

## Protocol capacity and responsiveness

| Date/location | Protocol | Mode | Download | Upload | Loaded responsiveness | Outcome |
| --- | --- | --- | ---: | ---: | ---: | --- |
| Original room | H1 | Simultaneous | 278 Mbps | 492 Mbps | 104 ms | Completed |
| Original room | H2 | Simultaneous | 266 Mbps | 403 Mbps | 180 ms | Completed |
| Original room | H3 | Directional | 312 Mbps | 609 Mbps | 168-176 ms | Completed |
| Original room | H3 | Simultaneous #1 | 27.9 Mbps | 193 Mbps | 215 ms | Severe download collapse |
| Original room | H3 | Simultaneous #2 | 29.7 Mbps | 305 Mbps | 291 ms overall; 2.54 s loaded HTTP | Severe download collapse |
| Same-room general WLAN | H2 | Directional | 218 Mbps | 230 Mbps | 100-232 ms | Completed |
| Same-room general WLAN | H2 | Simultaneous | 94.5 Mbps | 108 Mbps | 523 ms | Balanced |
| Same-room general WLAN | H3 | Directional | 182 Mbps | 240 Mbps | 305-507 ms | Completed |
| Same-room general WLAN | H3 | Simultaneous | 27.6 Mbps | 251 Mbps | 299 ms | Severe download collapse |
| MGM external control | H2 | Directional | 17.0 Mbps | 26.6 Mbps | 238 ms-1.82 s | Shaped |
| MGM external control | H2 | Simultaneous | 16.4 Mbps | 22.8 Mbps | 217 ms | Stable |
| MGM external control | H3 | Directional | 16.4 Mbps | 44.0 Mbps | 41 ms-1.56 s | Shaped |
| MGM external control | H3 | Simultaneous | 16.4 Mbps | 40.8 Mbps | 41 ms | No collapse |
| Downstairs strong radio | H2 | Directional | 749.6 Mbps | 617.6 Mbps | 73-100 ms | Completed |
| Downstairs strong radio | H2 | Simultaneous | 333.8 Mbps | 394.9 Mbps | 116 ms | Healthy and balanced |
| Downstairs strong radio | H3 | Directional | 679.3 Mbps | 331.7 Mbps | 147-233 ms | Completed |
| Downstairs strong radio | H3 | Simultaneous | 41.4 Mbps | 165.5 Mbps | 394 ms | 93.9% collapse; connection lost |

## H3 directional-to-simultaneous retention

| Location/network | Directional download | Simultaneous download | Retained capacity | Verdict |
| --- | ---: | ---: | ---: | --- |
| Original room | 312 Mbps | 28-30 Mbps | Approximately 9% | Black Hat failure |
| Same-room BlackHatUSA2026 | 182 Mbps | 27.6 Mbps | 15.2% | Black Hat failure |
| Downstairs strong radio | 679.3 Mbps | 41.4 Mbps | 6.1% | Black Hat failure plus connection loss |
| MGM external control | 16.4 Mbps | 16.4 Mbps | 100% | No failure |

## Other diagnostic controls

| Test | Black Hat result | MGM external result | Interpretation |
| --- | --- | --- | --- |
| MSS | Destination-specific: Apple 1460, Cloudflare 1400, Google 1412 | Uniform 1238 across all three | Black Hat does not show a blanket clamp; MGM probably does |
| IPv4 DF/PMTU | 1500-byte total succeeds | 1500-byte total succeeds | No 1280-byte PMTU ceiling |
| STUN | 5/5 successful, approximately 10-12 ms | Not tested | No blanket UDP/NAT failure on Black Hat |
| UDP/443 H3 reachability | Google, Cloudflare, and Apple test endpoint succeed | Apple test endpoint succeeds | QUIC is reachable; failure requires bidirectional load |
| ECN | Accurate ECN negotiated; more than 540,000 ECT packets and zero CE marks in capture | ECN unavailable | CE marking was not observed during the Black Hat capture |
| H2 simultaneous behavior | Capacity falls but remains comparatively balanced | Stable at shaped rate | Failure is disproportionately H3/QUIC |
| Unloaded loss | 0% | 0% | Not an idle packet-loss problem |

## Dual 10 Gb uplink hypotheses

These are investigation candidates, not confirmed findings.

| Potential failure | Fit with evidence | Discriminator |
| --- | --- | --- |
| Forward/reverse QUIC directions use different stateful NAT/firewall owners | Strong | Repeated STUN mapping on one fixed socket during bidirectional load; inside/outside capture correlation |
| One circuit has different UDP/443 policing, QoS, queueing, or flow offload | Strong | Fixed source-port sweep correlated with per-circuit counters |
| ECMP/LAG rebalances an active flow | Strong | Flow-path telemetry and route/member event history at failure time |
| Non-symmetric L3/L4 hashing | Possible | Compare forward/reverse member selection for the same 5-tuple |
| Per-packet spraying rather than per-flow hashing | Possible, but H2 should usually also suffer | Sequence/reordering evidence from simultaneous inside/outside captures |
| One member has errors or drops despite low utilization | Possible | Member-level queue, policer, discard, CRC, and interface counters |
| Aggregate circuit saturation | Unlikely | Tests remain below 1 Gbps against 20 Gbps aggregate capacity |
| MTU mismatch between circuits | Unlikely | 1500-byte DF succeeds and directional H3 exceeds 600 Mbps |

## One-circuit-at-a-time decision matrix

Not yet run. This requires an authorized network-team maintenance window.

| Test outcome | Interpretation |
| --- | --- |
| Circuit A only healthy; circuit B only fails | Circuit B, its edge policy, or provider path is faulty |
| Circuit B only healthy; circuit A only fails | Circuit A, its edge policy, or provider path is faulty |
| Both single-circuit tests healthy; dual-active fails | ECMP/hash symmetry, NAT ownership, or state synchronization problem |
| Both single-circuit tests fail | Shared firewall, controller, QoS, or upstream policy |
| Failure follows one public NAT address | Egress/NAT-specific policy or state owner |
| Failure follows particular fixed source ports | Bad hash bucket or member-path selection |

## Fixed-port iperf3 dual-uplink probe

Test endpoint: `test.protoevidence.com:443`, iperf3 3.21. Tests ran from the
stable downstairs 6 GHz association. Public NAT address and mapped ports are
intentionally omitted.

### TCP controls

| Test | Upload | Download | Upload retransmissions | Download retransmissions |
| --- | ---: | ---: | ---: | ---: |
| Directional discovery | Approximately 515 Mbps | Not run concurrently | 0 | N/A |
| Reverse discovery | N/A | Approximately 500 Mbps | N/A | 1 |
| Bidirectional port 40010 | 237.4 Mbps | 356.0 Mbps | 20,591 | 0 |
| Bidirectional port 40011 | 116.1 Mbps | 568.3 Mbps | 2,934 | 0 |
| Bidirectional port 40012 | 287.5 Mbps | 368.7 Mbps | 3,464 | 0 |
| Bidirectional port 40013 | 130.5 Mbps | 497.1 Mbps | 12,805 | 0 |
| Bidirectional port 40014 | 100.5 Mbps | 576.4 Mbps | 1,572 | 0 |
| Bidirectional port 40015 | 265.2 Mbps | 255.2 Mbps | 17,200 | 0 |
| Bidirectional port 40016 | 198.4 Mbps | 160.0 Mbps | 21,412 | 0 |
| Bidirectional port 40017 | 33.3 Mbps | 470.0 Mbps | 156 | 0 |
| Bidirectional port 40018 | 208.4 Mbps | 294.9 Mbps | 19,202 | 0 |
| Bidirectional port 40019 | 306.8 Mbps | 305.9 Mbps | 9,723 | 0 |

### UDP threshold and direction controls

| Mode | Rate per direction | Ports | Upload loss | Download loss | Verdict |
| --- | ---: | ---: | ---: | ---: | --- |
| Bidirectional | 50 Mbps | 10 | 0% | 0% | Clean |
| Bidirectional | 250 Mbps | 10 | 0% | 0% on 9 ports; 0.164% on 1 | Essentially clean |
| Bidirectional | 350 Mbps | 6 | Approximately 0% | 8.3-30.1%; 20.4% average | Directional failure on every bucket |
| Upload-only | 350 Mbps | 3 representative ports | 0% | N/A | Clean |
| Download-only | 350 Mbps | 3 representative ports | N/A | 0% | Clean |
| Bidirectional plus STUN | 350 Mbps for 10 s | 1 | 0% | 12.2% | NAT mapping stayed stable |

### Client-visible affinity conclusions

| Question | Result | Meaning |
| --- | --- | --- |
| Does one live UDP socket change public mapping under failing load? | No | No evidence of mid-session NAT rebinding |
| Do twenty source ports expose multiple public IPs? | No | Common public NAT/prefix visible; circuit selection remains unknown |
| Do fixed ports split into healthy and bad groups at 350 Mbps? | No | One isolated bad hash bucket/member is less likely |
| Does generic UDP fail below the H3 collapse aggregate rate? | No; 250+250 Mbps was clean | Raw UDP capacity alone does not explain H3 collapse |
| Does 350 Mbps fail one direction at a time? | No | Loss requires simultaneous bidirectional load |
| Can Wi-Fi versus dual WAN now be distinguished? | No | Requires a wired matched run or per-member telemetry |

## Source reports

- [`location-a-baseline-20260801.md`](location-a-baseline-20260801.md)
- [`location-a-blackhatusa-control-20260802.md`](location-a-blackhatusa-control-20260802.md)
- [`location-a-mgm-external-control-20260802.md`](location-a-mgm-external-control-20260802.md)
- [`location-b-blackhatusa-downstairs-20260802.md`](location-b-blackhatusa-downstairs-20260802.md)
- [`location-c-downstairs-strong-radio-retest-20260802.md`](location-c-downstairs-strong-radio-retest-20260802.md)
- [`dual-uplink-client-probe-20260802.md`](dual-uplink-client-probe-20260802.md)
