# Distributed Precog wireless controls — 2026-08-02

## Purpose

Use authorized Linux wireless probes distributed across conference-center
locations and VLANs to determine whether the simultaneous downstream-loss
signature is local to one Mac/AP or appears across the C-460 WLAN fleet.

Management addresses, probe MACs, BSSIDs, SSIDs, credentials, and public NAT
identities are intentionally omitted. Stable labels P01-P24 preserve result
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
| P02 | VHT | 24.4 Mbps | 0.504% | 5.910% | Upload rate limited |
| P03 | VHT | 85.9 Mbps | 0% | 42.868% | Strong RF during inventory |
| P04 | VHT | 42.8 Mbps | 0.363% | 2.009% | Upload rate limited |
| P05 | VHT | 100.0 Mbps | 0.004% | 16.545% | Strong RF; detailed repeat below |
| P06 | VHT | 56.0 Mbps | 0.086% | 17.672% | Upload rate limited |
| P07 | VHT | 79.0 Mbps | 0.053% | 47.935% | Strong signal during inventory |
| P08 | VHT | 99.3 Mbps | 0.002% | 42.965% | Stable -59 dBm; prior repeat 36.771% |
| P09 | VHT | 69.2 Mbps | 0% | 30.535% | Upload rate limited |
| P10 | VHT | 100.0 Mbps | 0% | 27.425% | Strong RF during inventory |
| P11 | VHT | 87.2 Mbps | 0.002% | 33.427% | Strong RF during inventory |
| P12 | VHT | 78.3 Mbps | 0.027% | 29.959% | Upload rate limited |
| P15 | HE | 98.1 Mbps | 0% | 0.671% | Detailed control below |
| P16 | HE | 98.1 Mbps | 0% | 0.761% | Clean |
| P17 | HE | 98.0 Mbps | 0% | 0.646% | Clean |
| P18 | HE | 98.0 Mbps | 0% | 1.002% | Near endpoint/client floor |
| P19 | HE | 95.2 Mbps | 0% | 2.866% | HE outlier |
| P20 | HE | N/A | N/A | N/A | Timed out; excluded |
| P21 | HE | 98.1 Mbps | 0% | 0.630% | Clean |
| P22 | HE | 59.5 Mbps | 0% | 0.619% | Upload rate limited; downstream clean |
| P23 | HE | 98.1 Mbps | 0% | 0.669% | Clean |

### Cohort summary

| Cohort | Valid nodes | Mean upstream loss | Mean downstream loss | Median downstream loss | Downstream range |
| --- | ---: | ---: | ---: | ---: | ---: |
| VHT | 11 | 0.095% | 27.02% | 29.96% | 2.01-47.94% |
| HE | 8 | 0% | 0.98% | 0.67% | 0.62-2.87% |

Every valid VHT probe showed excess downstream loss while upstream loss stayed
near zero. Most HE probes stayed at the old-client/public-endpoint reverse-loss
floor despite identical offered rates.

## Strong-RF directional versus simultaneous control

| Node | PHY cohort | Directional upload | Directional download loss | Simultaneous upload loss | Simultaneous download loss | Interface error/drop delta |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| P05 | VHT | 99.99 Mbps / 0% loss | 0.669% | 0.002% | 14.673% | 0 |
| P15 | HE | 98.12 Mbps / 0% loss | 0.729% | 0% | 0.665% | 0 |

P05 remained on a strong -50 dBm, 2x2 VHT/40 MHz association around the
detailed phase. Its directional controls were healthy, host-interface counters
were clean, and downstream loss rose by about 22 times only under simultaneous
load. P15 remained strong on a 2x2 HE/40 MHz association and did not degrade.

## Interpretation

The incident signature is not confined to one Mac, one AP, one VLAN, 6 GHz, or
one public test server. A large, directionally consistent split correlates with
the older VHT/client cohort across many locations, while the newer HE cohort is
mostly healthy at the same fixed load.

This is consistent with a legacy-client interaction in the C-460 radio,
scheduler, WMM queueing, or compatibility datapath. It is not yet proof of an
Arista firmware defect because the cohorts also differ in PHY capacity, Linux
kernel, driver, hardware, and iperf version. Several VHT clients were unable to
achieve the requested upload rate, so normal airtime saturation contributes to
some results.

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
