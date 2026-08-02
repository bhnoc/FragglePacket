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

## Twenty-one-listener overlapping TCP fanout

All 21 trusted probes were assigned one unique XMission listener and scheduled
for the same start epoch. Each invoked the requested 20-second TCP upload with
four parallel streams and a 128 KiB application block (`-t 20 -P 4 -l 128K`).
PC1's missing `libiperf0` and `libsctp1` packages were installed and verified
before the run; its later timeout was not a loader failure.

| Device | XMission pool | Port | Status | Sender rate | Receiver rate | Retransmissions |
| --- | --- | ---: | --- | ---: | ---: | ---: |
| PC1 | Primary | 5201 | Timed out; no test connection | N/A | N/A | N/A |
| PC2 | Primary | 5202 | Complete | 127.3 Mbps | 121.5 Mbps | 2 |
| PC3 | Primary | 5203 | Complete | 159.9 Mbps | 154.3 Mbps | 5 |
| PC4 | Primary | 5204 | Complete | 137.5 Mbps | 133.5 Mbps | 3 |
| PC6 | Primary | 5205 | Timed out; no test connection | N/A | N/A | N/A |
| PC8 | Primary | 5206 | Complete | 139.0 Mbps | 133.5 Mbps | 3 |
| PC10 | Primary | 5207 | Complete | 128.0 Mbps | 122.1 Mbps | 2 |
| PC13 | Primary | 5208 | Timed out; no test connection | N/A | N/A | N/A |
| PC14 | Primary | 5209 | Timed out; no test connection | N/A | N/A | N/A |
| PC15 | Colorado | 5201 | Complete | 179.1 Mbps | 173.4 Mbps | 7 |
| PC16 | Colorado | 5202 | Complete | 179.0 Mbps | 171.9 Mbps | 9 |
| PC17 | Colorado | 5203 | Complete | 143.2 Mbps | 133.9 Mbps | 10 |
| PV03 | Colorado | 5204 | Complete | 372.0 Mbps | 361.3 Mbps | 23 |
| PV04 | Colorado | 5205 | Timed out after partial admission | N/A | N/A | N/A |
| PV05 | Colorado | 5206 | Complete | 268.9 Mbps | 261.0 Mbps | 9 |
| PV06 | Colorado | 5207 | Complete | 319.3 Mbps | 310.2 Mbps | 13 |
| PV07 | Colorado | 5208 | Timed out; no test connection | N/A | N/A | N/A |
| PV09 | Colorado | 5209 | Complete | 305.0 Mbps | 294.7 Mbps | 15 |
| PV10 | Montana | 5201 | Timed out; no test connection | N/A | N/A | N/A |
| PV11 | Montana | 5205 | Timed out; no test connection | N/A | N/A | N/A |
| PV12 | Montana | 5209 | Timed out; no test connection | N/A | N/A | N/A |

All 21 probes recorded the exact target start epoch. Twelve completed valid
20-second intervals, delivering 2.458 Gbps aggregate sender rate and 2.371 Gbps
aggregate receiver rate with 101 total retransmissions. Nine were terminated
by the 50-second safety timeout. Eight never established an iperf test
connection; PV04 admitted three streams and one interval but did not complete.

Completion by public pool was 5/9 primary, 7/9 Colorado, and 0/3 Montana. The
ports had accepted TCP reachability checks before the run, so simple port-open
preflight did not predict simultaneous listener admission. These timeouts must
not be recorded as zero throughput or attributed to WLAN performance. They
show that the public services cannot currently support a valid 21-listener
synchronized comparison under this command without endpoint coordination.

Among completed results, eight PC-series probes averaged 143.0 Mbps received
and four PV-series probes averaged 306.8 Mbps. That descriptive split is not a
controlled cohort verdict: completion was selective, endpoint pools differed,
and the command measured unbounded TCP upload rather than the prior 100+100
downstream-loss condition.

## 64 KiB repeat and core-gateway latency attempt

The same 21-node barrier test was repeated with a 64 KiB application block.
Each probe sent 25 core-gateway ICMP requests at 0.2-second intervals before
the barrier and 100 requests at the same cadence during the 20-second load.

| Cohort/metric | 128 KiB run | 64 KiB run |
| --- | ---: | ---: |
| Completed nodes | 12 | 12; exact same devices |
| Listener timeouts | 9 | 9; exact same devices |
| Aggregate receiver rate | 2.371 Gbps | 2.155 Gbps |
| Valid-result retransmissions | 101 | 154 |
| PC cohort valid count | 8 | 8 |
| PC cohort average receiver rate | 143.0 Mbps | 142.5 Mbps |
| PV cohort valid count | 4 | 4 |
| PV cohort average receiver rate | 306.8 Mbps | 253.8 Mbps |

The PC cohort was effectively unchanged by block size. The PV valid-result
average and total aggregate were lower with 64 KiB, while retransmissions were
higher. One interleaved public-endpoint sample cannot distinguish a block-size
effect from endpoint/load variability, especially with selective admission.

Core-gateway ICMP did not provide a latency metric. Every node received zero of
25 idle requests and zero of 100 loaded requests. The identical idle and load
suppression indicates an ACL/control-plane policy rather than load-induced loss;
no RTT samples existed from which to calculate a latency delta. A repeat must
use each node's responsive local default gateway or another authorized
near-side target, while retaining the same idle/load bracket.

## 512 KiB pruned-listener repeat

The nine listener assignments that timed out identically in the 128 and 64 KiB
fanouts were removed. The remaining 12 node/listener pairs repeated the shared-
epoch, four-stream, 20-second TCP upload with a 512 KiB application block.

| Device | 128 KiB received | 64 KiB received | 512 KiB received | 512 KiB retransmissions |
| --- | ---: | ---: | ---: | ---: |
| PC2 | 121.5 Mbps | 122.9 Mbps | 118.0 Mbps | 3 |
| PC3 | 154.3 Mbps | 168.2 Mbps | 161.1 Mbps | 3 |
| PC4 | 133.5 Mbps | 139.7 Mbps | 138.0 Mbps | 1 |
| PC8 | 133.5 Mbps | 132.9 Mbps | 127.9 Mbps | 5 |
| PC10 | 122.1 Mbps | 122.4 Mbps | 115.5 Mbps | 7 |
| PC15 | 173.4 Mbps | 145.6 Mbps | 164.4 Mbps | 13 |
| PC16 | 171.9 Mbps | 174.5 Mbps | 107.0 Mbps | 9 |
| PC17 | 133.9 Mbps | 133.8 Mbps | 142.7 Mbps | 7 |
| PV03 | 361.3 Mbps | 264.3 Mbps | 348.4 Mbps | 18 |
| PV05 | 261.0 Mbps | 201.7 Mbps | 341.1 Mbps | 24 |
| PV06 | 310.2 Mbps | 320.2 Mbps | 162.4 Mbps | 10 |
| PV09 | 294.7 Mbps | 229.2 Mbps | 276.8 Mbps | 18 |

| Cohort/metric | 512 KiB result |
| --- | ---: |
| Completion | 12 of 12 |
| Aggregate sender / receiver | 2.292 / 2.203 Gbps |
| Total retransmissions | 118 |
| PC valid count / average receiver | 8 / 134.3 Mbps |
| PV valid count / average receiver | 4 / 282.1 Mbps |

Removing the known-bad public assignments eliminated admission timeouts, which
supports the earlier endpoint/listener interpretation. Throughput did not vary
monotonically with application block size: PC16 and PV06 fell sharply at 512
KiB while PV05 improved sharply, and several PC nodes remained stable. These
single public-endpoint samples show time/path variability and do not establish
a 64, 128, or 512 KiB optimum.

The retained core-gateway control was again fully suppressed: every selected
node received zero of 25 idle replies and zero of 100 loaded replies. It still
provides no latency-under-load measurement.

## Maximum-throughput command tuning

Known-good listeners were used to compare stream count, application block size,
and zero-copy on PC3 (Wi-Fi 5, iperf3 3.9) and PV03 (Wi-Fi 6, iperf3 3.16).
Both clients have eight CPUs, use CUBIC, and expose 212,992-byte default maximum
socket buffers. A forced multi-megabyte `-w` was therefore not tested.

| Candidate | PC3 received | PV03 received | Qualification |
| --- | ---: | ---: | --- |
| `-P 4 -l 128K` | 176 Mbps | 60.2 Mbps | Opening baseline; PV endpoint transient |
| `-P 4 -l 128K -Z` | 172 Mbps | 393 Mbps | Zero-copy did not improve PC3 |
| `-P 8 -l 128K -Z` | 163 Mbps | 324 Mbps | More streams reduced PC3 |
| `-P 8 -l 256K -Z` | 138 Mbps | 395 Mbps | No PC benefit |
| `-P 8 -l 512K -Z` | 148 Mbps | 454 Mbps | Highest PV result |
| `-P 16 -l 128K -Z` | 129 Mbps | Invalid | PV receiver interval stretched to 15.84 seconds |
| Final `-P 4 -l 128K` | 115 Mbps | 304 Mbps | Confirms substantial endpoint/time drift |

iperf3 3.16 can run parallel streams on separate threads, whereas the older
3.9 client does not have that architecture. One universal maximum command is
therefore inferior to version/cohort-aware profiles:

```text
# PC / Wi-Fi 5 / iperf3 3.9
iperf3 -c HOST -p PORT -t 20 -O 3 -P 4 -l 128K -J

# PV / Wi-Fi 6 / iperf3 3.16
iperf3 -c HOST -p PORT -t 20 -O 3 -P 8 -l 512K -Z -J
```

For a single portable fleet command, use `-P 4 -l 128K -Z`; it avoids the old-
client multi-stream penalty while enabling zero-copy where useful. `-O 3`
excludes slow start from the reported interval, and `-J` preserves validation
fields. Do not add a large `-w` until socket maxima are deliberately raised and
validated on both client and server.

These profiles target synthetic best-case upload throughput, not normal
application behavior or the fixed-rate downstream-loss investigation. Public
listener drift makes them provisional; finalize them against the controlled
internal endpoint with randomized repeated trials.

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
