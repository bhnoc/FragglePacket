# Distributed Precog wireless controls — 2026-08-02

## Purpose

Use authorized Linux wireless probes distributed across conference-center
locations and VLANs to determine whether the simultaneous downstream-loss
signature is local to one Mac/AP or appears across the C-460 WLAN fleet.

Management addresses, probe MACs, BSSIDs, SSIDs, credentials, and public NAT
identities are intentionally omitted. Stable PC/PV device names preserve result
correlation without publishing the management topology.

## Safety and topology

- A dedicated management bastion relayed SSH commands over the laptop's wired
  interface. The bastion generated no test traffic.
- Every ping, radio query, and iperf process ran on a downstream wireless probe.
- Cross-VLAN probe-to-probe traffic was blocked, so the public XMission
  Colorado iperf service was used.
- Independent XMission listeners allowed normal upload and reverse download
  processes to run concurrently without relying on old-client `--bidir`.
- At most four probes ran concurrently, using one session per listener.

## Fleet inventory

| State | Count | Handling |
| --- | ---: | --- |
| Reachable with trusted host key | 21 | Inventory completed |
| Changed SSH host key | 3 | Excluded pending independent verification |
| Broken iperf shared library | 1 of 21 | Excluded from load tests |
| Repeated high-rate timeout | 1 of remaining fleet | Excluded from the 100 Mbps cohort |

The usable fleet contained two distinct client cohorts:

- older VHT clients on 5 GHz/40 MHz, kernel 5.10, primarily iperf3 3.9; and
- newer HE clients on 5 GHz/40 MHz, kernel 6.1, iperf3 3.16.

Observed inventory signal ranged from approximately -47 to -76 dBm. Radio
state was captured around load phases, and strong-RF representatives were used
for the detailed comparison.

## Measurement compatibility

iperf3 3.9 connected with `--bidir` but returned an empty result against the
selected public service. Paired normal and reverse sessions on separate
listeners were therefore used.

Version 3.9 reverse UDP JSON reports offered bitrate and total/lost packets;
the bitrate remains the offered rate even under heavy loss. Tables below use
loss as the reliable metric and do not mislabel offered bitrate as achieved
download throughput.

## Fleet UDP result at 100 Mbps each way

| Node | Cohort | Upstream achieved | Upstream loss | Downstream loss | Qualification |
| --- | --- | ---: | ---: | ---: | --- |
| PC2 | VHT | 24.4 Mbps | 0.504% | 5.910% | Upload rate limited |
| PC3 | VHT | 85.9 Mbps | 0% | 42.868% | Strong RF during inventory |
| PC4 | VHT | 42.8 Mbps | 0.363% | 2.009% | Upload rate limited |
| PC6 | VHT | 100.0 Mbps | 0.004% | 16.545% | Strong RF; detailed repeat below |
| PC8 | VHT | 56.0 Mbps | 0.086% | 17.672% | Upload rate limited |
| PC10 | VHT | 79.0 Mbps | 0.053% | 47.935% | Strong signal during inventory |
| PC13 | VHT | 99.3 Mbps | 0.002% | 42.965% | Stable -59 dBm; prior repeat 36.771% |
| PC14 | VHT | 69.2 Mbps | 0% | 30.535% | Upload rate limited |
| PC15 | VHT | 100.0 Mbps | 0% | 27.425% | Strong RF during inventory |
| PC16 | VHT | 87.2 Mbps | 0.002% | 33.427% | Strong RF during inventory |
| PC17 | VHT | 78.3 Mbps | 0.027% | 29.959% | Upload rate limited |
| PV03 | HE | 98.1 Mbps | 0% | 0.671% | Detailed control below |
| PV04 | HE | 98.1 Mbps | 0% | 0.761% | Clean |
| PV05 | HE | 98.0 Mbps | 0% | 0.646% | Clean |
| PV06 | HE | 98.0 Mbps | 0% | 1.002% | Near endpoint/client floor |
| PV07 | HE | 95.2 Mbps | 0% | 2.866% | HE outlier |
| PV09 | HE | N/A | N/A | N/A | Timed out; excluded |
| PV10 | HE | 98.1 Mbps | 0% | 0.630% | Clean |
| PV11 | HE | 59.5 Mbps | 0% | 0.619% | Upload rate limited; downstream clean |
| PV12 | HE | 98.1 Mbps | 0% | 0.669% | Clean |

### Cohort summary

| Cohort | Valid nodes | Mean upstream loss | Mean downstream loss | Median downstream loss | Downstream range |
| --- | ---: | ---: | ---: | ---: | ---: |
| VHT | 11 | 0.095% | 27.02% | 29.96% | 2.01-47.94% |
| HE | 8 | 0% | 0.98% | 0.67% | 0.62-2.87% |

Every valid VHT probe showed excess downstream loss while upstream loss stayed
near zero. Most HE probes stayed at the old-client/public-endpoint reverse-loss
floor despite identical offered rates.

## Client generation and association correlation

The C-460 access points are Wi-Fi 7 capable, but none of the reachable clients
negotiated an EHT/Wi-Fi 7 association. The table classifies the active client
link: VHT is Wi-Fi 5 and HE on 5 GHz is Wi-Fi 6. AX210 clients are Wi-Fi 6E
capable, but their observed 5 GHz associations are Wi-Fi 6 rather than 6E.

Radio values below are a live follow-up snapshot after the load tests. Rates
adapt dynamically and were not captured at the exact loss interval, so they
are correlation context rather than phase-bracketed causality evidence.

| Device | Client adapter | Active Wi-Fi | Channel | Width | Signal | RX / TX rate | Downstream loss at 100+100 |
| --- | --- | --- | ---: | ---: | ---: | --- | ---: |
| PC1 | MediaTek MT7612U | Wi-Fi 5 | 153 | 40 MHz | -56 dBm | 300 / 360 Mbps | Not tested: broken iperf |
| PC2 | MediaTek MT7612U | Wi-Fi 5 | 48 | 40 MHz | -65 dBm | 180 / 150 Mbps | 5.910% |
| PC3 | MediaTek MT7612U | Wi-Fi 5 | 161 | 40 MHz | -50 dBm | 240 / 324 Mbps | 42.868% |
| PC4 | MediaTek MT7612U | Wi-Fi 5 | 120 | 40 MHz | -55 dBm | 300 / 360 Mbps | 2.009% |
| PC6 | MediaTek MT7612U | Wi-Fi 5 | 104 | 40 MHz | -50 dBm | 400 / 360 Mbps | 16.545% |
| PC8 | MediaTek MT7612U | Wi-Fi 5 | 120 | 40 MHz | -59 dBm | 243 / 243 Mbps | 17.672% |
| PC10 | MediaTek MT7612U | Wi-Fi 5 | 157 | 40 MHz | -52 dBm | 180 / 162 Mbps | 47.935% |
| PC13 | MediaTek MT7612U | Wi-Fi 5 | 153 | 40 MHz | -59 dBm | 300 / 360 Mbps | 42.965% |
| PC14 | MediaTek MT7612U | Wi-Fi 5 | 108 | 40 MHz | -55 dBm | 270 / 400 Mbps | 30.535% |
| PC15 | MediaTek MT7612U | Wi-Fi 5 | 116 | 40 MHz | -60 dBm | 360 / 360 Mbps | 27.425% |
| PC16 | MediaTek MT7612U | Wi-Fi 5 | 116 | 40 MHz | -47 dBm | 300 / 360 Mbps | 33.427% |
| PC17 | MediaTek MT7612U | Wi-Fi 5 | 153 | 40 MHz | -57 dBm | 200 / 360 Mbps | 29.959% |
| PV03 | Intel AX210 | Wi-Fi 6; 6E capable | 144 | 40 MHz | -56 dBm | 573.5 / 573.5 Mbps | 0.671% |
| PV04 | Intel AX210 | Wi-Fi 6; 6E capable | 153 | 40 MHz | -59 dBm | 344.1 / 487.4 Mbps | 0.761% |
| PV05 | Intel AX210 | Wi-Fi 6; 6E capable | 132 | 40 MHz | -65 dBm | 413 / 516 Mbps | 0.646% |
| PV06 | Intel AX200 | Wi-Fi 6 | 157 | 40 MHz | -62 dBm | 309.7 / 458.8 Mbps | 1.002% |
| PV07 | Intel AX200 | Wi-Fi 6 | 140 | 40 MHz | -68 dBm | 344.1 / 458.8 Mbps | 2.866% |
| PV09 | Intel AX200 | Wi-Fi 6 | 108 | 40 MHz | -68 dBm | 344.1 / 413 Mbps | Excluded: load timeout |
| PV10 | Intel AX200 | Wi-Fi 6 | 140 | 40 MHz | -58 dBm | 458.8 / 438.6 Mbps | 0.630% |
| PV11 | Intel AX200 | Wi-Fi 6 | 116 | 40 MHz | -76 dBm | 206.4 / 292.5 Mbps | 0.619% |
| PV12 | Intel AX200 | Wi-Fi 6 | 140 | 40 MHz | -56 dBm | 458.8 / 516 Mbps | 0.669% |
| PV01, PV02, PV13 | Unknown | Unknown | Unknown | Unknown | Unknown | Unknown | Excluded: unverified host keys |

Channel width cannot explain the cohort split because every observed client
used 40 MHz. Channel alone also does not fit: PC13 lost 42.965% while PV04 lost
0.761% on channel 153; PC10 lost 47.935% while PV06 lost 1.002% on channel 157;
and PC15/PC16 lost 27.425/33.427% while PV11 lost 0.619% on channel 116.

Signal and instantaneous rate are not monotonic explanations. Strong PC3 and
PC16 links at -50 and -47 dBm still lost 42.868% and 33.427%, while PV11 stayed
near the endpoint floor at -76 dBm and a 206.4 Mbps RX rate. Within the valid
Wi-Fi 5 sample, the exploratory Pearson correlation between follow-up RX rate
and loss was only -0.17; the small sample and unbracketed rate snapshot make
that descriptive rather than inferential.

The strongest observed grouping is client stack: all tested PC clients use the
same MT7612U/mt76x2u Wi-Fi 5 family and kernel 5.10, while the tested PV clients
use Intel AX200/AX210 with iwlwifi, Wi-Fi 6, and kernel 6.1. Generation, chipset,
driver, kernel, and usable PHY capacity therefore move together and cannot yet
be separated. A matched adapter/driver swap or the same client against an AX-
only C-460 configuration is needed before attributing the result specifically
to Wi-Fi 5 backward compatibility.

## Strong-RF directional versus simultaneous control

| Node | PHY cohort | Directional upload | Directional download loss | Simultaneous upload loss | Simultaneous download loss | Interface error/drop delta |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| PC6 | VHT | 99.99 Mbps / 0% loss | 0.669% | 0.002% | 14.673% | 0 |
| PV03 | HE | 98.12 Mbps / 0% loss | 0.729% | 0% | 0.665% | 0 |

PC6 remained on a strong -50 dBm, 2x2 VHT/40 MHz association around the
detailed phase. Its directional controls were healthy, host-interface counters
were clean, and downstream loss rose by about 22 times only under simultaneous
load. PV03 remained strong on a 2x2 HE/40 MHz association and did not degrade.

## PHY-normalized follow-up

Fixed 100+100 Mbps is not equivalent airtime across VHT and HE clients. The
strong representatives were therefore tested directionally at higher rates and
then simultaneously at rates scaled to their usable directional range.

### Directional UDP sweep

| Node | Cohort | Target | Upload loss | Downstream loss | Estimated downstream received payload |
| --- | --- | ---: | ---: | ---: | ---: |
| PC6 | VHT | 150 Mbps | 0.001% | 10.439% | 134.3 Mbps |
| PC6 | VHT | 200 Mbps | 0.001% | 8.333% | 183.3 Mbps |
| PC6 | VHT | 250 Mbps | 0.004%; sender reached 233.5 Mbps | 17.972% | 205.1 Mbps |
| PV03 | HE | 150 Mbps | 0% | 0.709% | 149.1 Mbps |
| PV03 | HE | 200 Mbps | 0% | 0.747% | 198.6 Mbps |
| PV03 | HE | 250 Mbps | 0% | 0.644% | 248.6 Mbps |

PC6 has a pronounced downstream-only efficiency ceiling even directionally;
its upload remains effectively lossless beyond 200 Mbps. PV03 remains symmetric
and clean through 250 Mbps.

### Scaled simultaneous control

| Node | Target each way | Upload loss | Downstream loss | Estimated downstream received payload |
| --- | ---: | ---: | ---: | ---: |
| PC6 VHT | 60 Mbps | 0.005% | 1.670% | 59.0 Mbps |
| PV03 HE | 125 Mbps | 0% | 0.578% | 124.4 Mbps |

Scaling offered load to the cohorts' different usable capacity largely removes
the dramatic fixed-100 loss split. This weakens a generic "simultaneous traffic
breaks legacy clients" claim. It leaves a narrower and still actionable issue:
strong-RF legacy VHT clients have far poorer C-460 downstream efficiency than
HE clients and are therefore driven into airtime/queue loss much sooner.

## Gateway-under-load localization

Local-gateway ICMP was measured concurrently with directional and simultaneous
public UDP load. The gateway address is omitted from this report. These probes
include the WLAN downlink and provide a useful near-side control while an
authorized internal throughput endpoint is being prepared.

| Node/phase | Public UDP result | Gateway loss | Gateway RTT min/avg/max |
| --- | --- | ---: | --- |
| PC6 VHT idle | No load | 0% | 1.410 / 1.646 / 3.356 ms |
| PC6 upload 150 | 0.002% loss | 0% | 1.424 / 2.605 / 10.984 ms |
| PC6 download 150 | 5.518% loss; est. 141.7 Mbps received | 0% | 1.258 / 4.116 / 13.816 ms |
| PC6 simultaneous 100+100 | Upload 0.001% loss; download 23.550% loss | 0% | 1.454 / 7.146 / 22.738 ms |
| PV03 HE idle | No load | 0% | 1.993 / 2.340 / 3.223 ms |
| PV03 upload 150 | 0% loss; sender reached 148.2 Mbps | 0% | 1.816 / 2.854 / 5.511 ms |
| PV03 download 150 | 0.444% loss; est. 149.4 Mbps received | 0% | 1.703 / 2.460 / 3.503 ms |
| PV03 simultaneous 100+100 | Upload 0% loss; download 0.400% loss | 0% | 1.766 / 2.975 / 7.003 ms |

PC6 gateway latency inflated in the same phases as downstream UDP loss and was
largest during the reproduced simultaneous failure. PV03 stayed close to its
idle gateway baseline under the same phases. Because gateway replies traverse
the client-facing wireless leg, this co-movement is strong evidence that the
PC6 impairment is already present on the WLAN side; it argues against the WAN,
dual uplinks, or public server being the sole cause.

There was no gateway ICMP loss, and small ICMP packets can be queued or treated
differently from bulk UDP. This test therefore localizes queueing latency but
does not by itself identify the dropping component. The decisive follow-up is
the same PC6/PV03 matrix against an authorized internal wired endpoint, paired
with live AP/controller radio and WMM queue counters.

## Matched TCP transport control

TCP used independent upload and reverse-download sessions, each paced at 100
Mbps on a separate listener. XMission's Colorado host failed prerequisite
controls: one receiver summary stretched an eight-second run to 18.05 seconds,
PV03 reverse throughput reached only 61.2 Mbps, and another listener reset.
Those results were excluded.

The primary XMission host then delivered clean directional download baselines
of 99.9 Mbps to PC6 and 100 Mbps to PV03 with zero sender retransmissions. PC6
also delivered a 100 Mbps upload-only baseline with zero retransmissions. Only
after those controls passed was the simultaneous matrix accepted.

| Device/run | Upload delivered | Upload retransmissions | Download delivered | Download sender retransmissions |
| --- | ---: | ---: | ---: | ---: |
| PC6 VHT run 1 | 100 Mbps | 3 | 69.8 Mbps | 76 |
| PV03 HE run 1 | 100 Mbps | 0 | 101 Mbps | 0 |
| PC6 VHT run 2 | 100 Mbps | 0 | 61.0 Mbps | 56 |
| PV03 HE run 2 | 100 Mbps | 0 | 100 Mbps | 0 |

PC6 retained only about 70% and 61% of its clean directional downstream rate
while simultaneous upload remained at the target. PV03 retained full rate in
both directions in both runs. TCP therefore reproduces the downstream-only
contention signature observed with UDP: retransmission and congestion control
present it as a roughly 30-39 Mbps download reduction instead of explicit UDP
loss.

This is a two-device matched control, not a fleet-wide TCP result. Public TCP
listeners must pass directional capacity and duration-consistency preflight;
an available control connection alone does not prove the requested capacity.

## Counter-liveness limitation

Ordinary interface error/drop counters advanced normally as a telemetry source
and showed no added host errors/drops during the PC6/PV03 matched controls.
Privileged wireless station counters were also readable, but their RX packet,
TX packet, retry, failure, beacon-loss, and miscellaneous-drop values did not
advance during a known six-second 100+100 Mbps phase on either node.

Those frozen driver counters are unusable. Their zero delta is not evidence of
zero MAC retries or radio drops. Loss localization still requires live C-460
AP/controller queue and retry counters or an over-the-air capture.

## Interpretation

The incident signature is not confined to one Mac, one AP, one VLAN, 6 GHz, or
one public test server. A large, directionally consistent split correlates with
the older VHT/client cohort across many locations, while the newer HE cohort is
mostly healthy at the same fixed load.

The initial fixed-rate result is substantially explained by differing usable
PHY/airtime capacity. The residual issue is a directionally asymmetric legacy
VHT downstream ceiling that could arise from normal client limitations, driver
behavior, C-460 airtime scheduling, WMM queueing, or compatibility datapath.
It is not proof of an Arista firmware defect.

## Next discriminators

1. Map each redacted probe label to AP serial/model, radio, channel, firmware,
   power mode, client count, and per-WMM queue counters.
2. Repeat at equal fractions of each probe's measured directional capacity,
   not one fixed bitrate.
3. Run the same VHT and HE probes against a C-460 test radio forced to non-BE
   mode and against a Wi-Fi 6E AP with equivalent policy.
4. Obtain an authorized internal endpoint reachable from client VLANs to
   remove public-server and WAN/NAT variables.
5. Capture over-the-air and controller-egress sequence loss for one strong VHT
   failure and one matched HE control.
