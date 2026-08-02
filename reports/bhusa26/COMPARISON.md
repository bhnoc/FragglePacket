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

## Matched wired Black Hat control

The wired drop used a separate Black Hat VLAN and a 1 Gbps full-duplex Ethernet
interface. This is a path control, not proof that wired and Wi-Fi traversed the
same firewall, NAT node, or provider circuit.

### Apple network-quality comparison

| Access path | Protocol | Mode | Download | Upload | Overall loaded latency | Outcome |
| --- | --- | --- | ---: | ---: | ---: | --- |
| Strong 6 GHz Wi-Fi | H3 | Directional | 679.28 Mbps | 331.66 Mbps | N/A | Clean directional baseline |
| Strong 6 GHz Wi-Fi | H3 | Simultaneous | 41.44 Mbps | 165.54 Mbps | 394 ms | Connection loss; download retained 6.1% |
| Wired | H3 | Directional | 749.97 Mbps | 886.54 Mbps | N/A | Clean directional baseline |
| Wired | H3 | Simultaneous | 674.18 Mbps | 880.17 Mbps | 56.98 ms | Clean; download retained 89.9% |
| Strong 6 GHz Wi-Fi | H2 | Directional | 749.62 Mbps | 617.65 Mbps | N/A | Clean directional baseline |
| Strong 6 GHz Wi-Fi | H2 | Simultaneous | 333.81 Mbps | 394.86 Mbps | 116 ms | Completed without failure |
| Wired | H2 | Directional | 889.64 Mbps | 902.40 Mbps | N/A | Clean directional baseline |
| Wired | H2 | Simultaneous | 850.28 Mbps | 852.74 Mbps | 12.63 ms | Clean and balanced |

### Fixed-port transport comparison

| Access path | Test | Ports | Upload result | Download result | Verdict |
| --- | --- | ---: | --- | --- | --- |
| Strong 6 GHz Wi-Fi | UDP, 350 Mbps each way | 6 | Approximately 0% loss | 8.3-30.1% loss on every port | Repeatable downstream-loss trigger |
| Wired | UDP, 350 Mbps each way | 6 | 0% on 5 ports; 0.045% on 1 | 0% loss on every port | Trigger absent |
| Strong 6 GHz Wi-Fi | TCP bidirectional | 10 | 33-307 Mbps; 156-21,412 retransmissions | 160-576 Mbps; remote sender reported 0 retransmissions | Severe asymmetric impairment |
| Wired | TCP bidirectional | 6 | 940-947 Mbps; 0-22 retransmissions | 809-837 Mbps; remote sender reported 6,290-7,563 retransmissions | No throughput collapse; normalize counters before comparison |

### Egress identity observation

| Access path | STUN source ports | Client-visible public identity | Meaning |
| --- | ---: | --- | --- |
| Strong 6 GHz Wi-Fi | 20 | Stable identity A | No client-visible port-to-circuit split |
| Wired | 20 | Stable identity B | Stable, but distinct from Wi-Fi |

The clean wired control narrows the fault to the Wi-Fi/controller path or to
VLAN-specific firewall, NAT, egress, or circuit policy. Because the two access
paths exposed different public identities, it does not yet rule out the dual
uplinks.

## Wi-Fi duplex-threshold fingerprint

| Controlled variable | Wi-Fi result | Wired control | Interpretation |
| --- | --- | --- | --- |
| 350 Mbps upload only, 1,472-byte payload | 348.06 Mbps, 0% loss | 348.35 Mbps, 0% loss | Upload direction is healthy |
| 350 Mbps download only, 1,472-byte payload | 349.87 Mbps, 0% loss | 350.05 Mbps, 0% loss | Download direction is healthy |
| 350 Mbps each way, 1,472-byte payload | 340.11 Mbps up/0%; 273.45 Mbps down/20.77% | 348.32 Mbps up/0%; 348.50 Mbps down/0% | Loss requires simultaneous Wi-Fi load |
| 350 Mbps each way, 200-byte payload | 97.09 Mbps up/0%; 113.48 Mbps down/65.12% | 342.00 Mbps up/0%; 345.77 Mbps down/0.48% | Strong packet-rate sensitivity on Wi-Fi |
| UDP server ports 443, 444, and 445 | All reproduced downstream-only loss | Not needed | Not specific to UDP/443 classification |
| Host interface counters around directional/bidirectional phases | No new errors or drops | No new errors or drops | Loss is not reported at the client interface |

### Independently controlled directional rates

| Fixed direction | Variable direction | 25-200 Mbps | 250 Mbps | 300 Mbps | 350 Mbps |
| --- | --- | ---: | ---: | ---: | ---: |
| Download fixed at 350 Mbps | Upload target | 0% downstream loss | 0.054% | 5.586% | 13.568% |
| Upload fixed at 350 Mbps | Download target | 0% downstream loss | 0.076% | 19.300% | 29.734% |

The cliff between 250 and 300 Mbps per direction, persistent preference for
dropping downstream, packet-rate sensitivity, strong 6 GHz RF, and clean wired
control favor Wi-Fi airtime/controller queue scheduling. A VLAN-specific edge
path is still logically possible because wired and Wi-Fi expose different
egress identities, but raw 20 Gbps dual-uplink capacity is not a credible
explanation for this approximately 600-650 Mbps aggregate threshold.

### Same-location recurrence after reports of recovery

| Test | Download | Upload | Downstream loss / responsiveness | Outcome |
| --- | ---: | ---: | --- | --- |
| UDP directional download | 350.01 Mbps | N/A | 0% loss | Clean |
| UDP directional upload | N/A | 348.21 Mbps | 0% loss | Clean |
| UDP simultaneous | 229.90 Mbps | 348.24 Mbps | 33.534% download loss | Failure reproduced |
| H3 simultaneous, run 1 | 55.61 Mbps | 123.69 Mbps | 577 ms; latency-connection error | Failure reproduced |
| H2 simultaneous control | 316.99 Mbps | 243.68 Mbps | 187 ms; completed | Materially healthier |
| H3 simultaneous, run 2 | 28.09 Mbps | 129.54 Mbps | 383 ms; completed | Failure reproduced again |

RF remained strong on the same 6 GHz / 80 MHz channel at -59 dBm with a 720
Mbps transmit rate. Claims that the issue had stopped were not supported by the
controlled recurrence test.

## Distributed Precog wireless cohort

The management-only bastion relayed commands to distributed wireless probes;
it did not generate test traffic. All load originated on downstream probes and
used independent XMission listeners.

| Cohort | Valid nodes | Client stack | Test | Mean upstream loss | Mean downstream loss | Range downstream |
| --- | ---: | --- | --- | ---: | ---: | ---: |
| Older VHT | 11 | 5 GHz/40 MHz, kernel 5.10, iperf3 3.9 | UDP 100+100 Mbps | 0.095% | 27.02% | 2.01-47.94% |
| Newer HE | 8 | 5 GHz/40 MHz, kernel 6.1, iperf3 3.16 | UDP 100+100 Mbps | 0% | 0.98% | 0.62-2.87% |

| Matched strong-RF control | Directional download loss | Simultaneous download loss | Simultaneous upload loss | Host errors/drops |
| --- | ---: | ---: | ---: | ---: |
| VHT PC6 | 0.669% at 100 Mbps | 14.673% at 100+100 Mbps | 0.002% | 0 |
| HE PV03 | 0.729% at 100 Mbps | 0.665% at 100+100 Mbps | 0% | 0 |

This is a strong generation-correlated signal across multiple locations and
VLANs. It is consistent with a C-460 legacy-client/airtime-scheduler interaction
but is not yet proof of an AP firmware defect: the VHT and HE clients also have
different PHY capacity, drivers, kernels, and iperf versions. Repeat at equal
fractions of measured directional capacity and map each probe to its AP/radio.

### Client association correlation

| Factor | Older PC cohort | Newer PV cohort | Correlation assessment |
| --- | --- | --- | --- |
| Active association | Wi-Fi 5 / VHT | Wi-Fi 6 / HE on 5 GHz | Strong cohort split; no client used Wi-Fi 7/EHT |
| Adapter/driver | MediaTek MT7612U / mt76x2u | Intel AX200/AX210 / iwlwifi | Fully confounded with Wi-Fi generation |
| Kernel | 5.10 | 6.1 | Fully confounded with adapter/generation |
| Channel width | 40 MHz on every observed node | 40 MHz on every observed node | Does not explain split |
| Signal | -47 to -65 dBm in valid sample | -56 to -76 dBm in valid sample | Weakest valid node, PV11, was clean |
| Follow-up RX rate | 180-400 Mbps | 206.4-573.5 Mbps | Capacity differs, but rate alone does not fit loss |
| Mean downstream loss at 100+100 | 27.02% | 0.98% | Large fixed-load cohort difference |

Same-channel counterexamples weaken a channel-specific explanation: PC13 versus
PV04 on channel 153 lost 42.965% versus 0.761%; PC10 versus PV06 on channel 157
lost 47.935% versus 1.002%; and PC15/PC16 versus PV11 on channel 116 lost
27.425/33.427% versus 0.619%. These are not confirmed same-AP comparisons.

The association table supports a legacy-client-stack correlation, not a clean
Wi-Fi-version causal claim. Wi-Fi generation, chipset, driver, kernel, and PHY
capacity all change together. The per-device radio table is in
[`precog-distributed-wireless-20260802.md`](precog-distributed-wireless-20260802.md).

### PHY-normalized follow-up

| Control | VHT PC6 | HE PV03 |
| --- | --- | --- |
| Directional downstream at 150 Mbps | 10.439% loss | 0.709% loss |
| Directional downstream at 200 Mbps | 8.333% loss | 0.747% loss |
| Directional downstream at 250 Mbps | 17.972% loss | 0.644% loss |
| Scaled simultaneous target | 60+60 Mbps | 125+125 Mbps |
| Scaled simultaneous downstream loss | 1.670% | 0.578% |

The normalized simultaneous result largely collapses the fixed-100 cohort gap,
so normal capacity/airtime differences explain much of that table. The
remaining anomaly is PC6's poor downstream-only directional efficiency despite
strong RF and clean upload beyond 200 Mbps. Ask Arista to investigate legacy
VHT downstream scheduling/efficiency, but do not present this as a proven
generic C-460 bidirectional defect.

### Gateway-under-load localization

| Control | VHT PC6 | HE PV03 |
| --- | --- | --- |
| Idle gateway RTT avg/max | 1.646 / 3.356 ms | 2.340 / 3.223 ms |
| Download 150: loss; gateway avg/max | 5.518%; 4.116 / 13.816 ms | 0.444%; 2.460 / 3.503 ms |
| Upload 150: loss; gateway avg/max | 0.002%; 2.605 / 10.984 ms | 0%; 2.854 / 5.511 ms |
| Simultaneous 100+100: downstream loss | 23.550% | 0.400% |
| Simultaneous 100+100: gateway avg/max | 7.146 / 22.738 ms | 2.975 / 7.003 ms |

PC6's local-gateway latency increased with the exact downstream-loss condition;
PV03 remained close to idle. No gateway ICMP packets were lost. This places the
queueing signal on a path that already includes the WLAN downlink and makes the
WAN/public endpoint unlikely to be the sole cause, while small-packet ICMP
treatment prevents treating it as proof of the exact drop location.

## Wi-Fi/VLAN versus egress swap matrix

The highest-value infrastructure test is to preserve the client access path
while swapping its forced egress. Use redacted identities A and B to correlate
the test with firewall/NAT and circuit telemetry.

| Controlled test | Result | Interpretation |
| --- | --- | --- |
| Force Wi-Fi VLAN through wired egress B | Becomes healthy | Failure follows egress A: inspect its NAT/firewall owner, queue policy, and circuit |
| Force Wi-Fi VLAN through wired egress B | Still fails | Wi-Fi/controller or Wi-Fi-VLAN-specific processing remains primary |
| Force wired VLAN through Wi-Fi egress A | Begins failing | Failure follows egress A: dual-uplink/NAT/circuit path is primary |
| Force wired VLAN through Wi-Fi egress A | Remains healthy while Wi-Fi through A fails | Access/controller path is primary |
| A-only and B-only are healthy, but dual-active fails | Fails only dual-active | Inspect ECMP symmetry, state ownership/synchronization, and hashing |

## Source reports

- [`location-a-baseline-20260801.md`](location-a-baseline-20260801.md)
- [`location-a-blackhatusa-control-20260802.md`](location-a-blackhatusa-control-20260802.md)
- [`location-a-mgm-external-control-20260802.md`](location-a-mgm-external-control-20260802.md)
- [`location-b-blackhatusa-downstairs-20260802.md`](location-b-blackhatusa-downstairs-20260802.md)
- [`location-c-downstairs-strong-radio-retest-20260802.md`](location-c-downstairs-strong-radio-retest-20260802.md)
- [`dual-uplink-client-probe-20260802.md`](dual-uplink-client-probe-20260802.md)
- [`wired-control-20260802.md`](wired-control-20260802.md)
- [`wifi-duplex-threshold-20260802.md`](wifi-duplex-threshold-20260802.md)
- [`precog-distributed-wireless-20260802.md`](precog-distributed-wireless-20260802.md)
