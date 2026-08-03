# BHUSA26 Internal WLAN Threshold and Arista Correlation Report — 2026-08-02

## Scope and correction

This report records the corrected internal-server testing performed after the public XMission baselines. It replaces the overly narrow interpretation that the failure belongs only to older Wi-Fi 5 clients. Concurrent-load impairment occurs across client generations, but its trigger moves with usable PHY efficiency: many VHT probes show it around 50–100 Mbps, HE probes require roughly 200–250 Mbps to expose material capacity or latency pressure, and the newer 6 GHz laptop reproduced around 350 Mbps. Client generation changes the threshold and expression; it does not define a clean affected/unaffected boundary.

The internal endpoint initially supplied to the investigation was incorrect. After the working destination was demonstrated manually, both probe cohorts reached persistent listeners 5201–5230; 5231–5240 were not reachable during qualification. All tests below used two independently leased internal listeners and originated only from downstream probes. The management node performed SSH orchestration only.

## Test method

- Internal server, removing public-service admission, Internet transit, firewall egress, NAT, and dual-WAN selection from the measured path.
- UDP directional upload and download controls, followed by simultaneous normal/reverse UDP.
- Paced TCP directional upload and download controls, followed by simultaneous normal/reverse TCP.
- 1,400-byte UDP payloads, local-gateway ping during every phase, and sanitized radio/counter snapshots.
- The 100 Mbps fleet run used three-node batches, limiting aggregate simultaneous offered traffic to 600 Mbps.
- The 250 Mbps HE run used one node at a time, limiting simultaneous offered traffic to 500 Mbps.
- iperf3 3.9 and 3.16 aggregate layouts were parsed separately. Timeouts and missing aggregates are reported as invalid, never as zero throughput or zero loss.

## Internal 100+100 Mbps fleet baseline

Run window: 2026-08-03 00:22:54Z–00:32:09Z. Twenty-one trusted probes completed at least seven of eight traffic objects; eleven completed all eight. PV01, PV02, and PV13 were excluded because their changed SSH host keys had not been independently verified.

| Node | PHY | UDP download-control lost | UDP simultaneous upload lost | UDP simultaneous download lost | TCP simultaneous up/down Mbps | UDP-loaded gateway average |
|---|---:|---:|---:|---:|---:|---:|
| PC1 | VHT | 990 | 24 | 22,714 | 38.2 / 99.4 | 48.0 ms |
| PC2 | VHT | 814 | 3,291 | 6,374 | 0.8 / 101.5 | unavailable |
| PC3 | VHT | 5,559 | 52 | 19,688 | 37.3 / 67.1 | 82.7 ms |
| PC4 | VHT | 0 | 381 | 258 | 13.7 / 99.9 | unavailable |
| PC6 | VHT | 1,755 | 0 | 16,131 | 99.5 / 100.6 | 17.8 ms |
| PC8 | VHT | 1,048 | 65 | 6,826 | 26.6 / 88.8 | 65.9 ms |
| PC10 | VHT | 11,504 | 361 | 14,405 | 14.0 / 35.1 | 175.7 ms |
| PC13 | VHT | 1,106 | 78 | 8,328 | 51.3 / 67.7 | 60.9 ms |
| PC14 | VHT | 970 | 0 | 1,936 | 46.2 / 104.5 | 31.6 ms |
| PC15 | VHT | 597 | 34 | 13,378 | 78.7 / 85.2 | 54.7 ms |
| PC16 | VHT | 42,555 | timeout | 44,073 | 2.3 / 1.8 | 36.3 ms |
| PC17 | VHT | 5,897 | 91 | 28,804 | 30.4 / 51.0 | 129.4 ms |
| PV03 | HE | 0 | 0 | 0 | 100.0 / 100.0 | 2.8 ms |
| PV04 | HE | 0 | 0 | 0 | 99.9 / 100.0 | 3.7 ms |
| PV05 | HE | 0 | 0 | 0 | invalid phase | 4.4 ms |
| PV06 | HE | 0 | 0 | 0 | 100.0 / 100.0 | 3.5 ms |
| PV07 | HE | 0 | 0 | 0 | 100.0 / 100.0 | 2.8 ms |
| PV09 | HE | 0 | 0 | 0 | 100.1 / 100.0 | 6.2 ms |
| PV10 | HE | 0 | 0 | 0 | 100.1 / 100.0 | 3.2 ms |
| PV11 | HE | 0 | 0 | 0 | 10.9 / 18.5 | 16.7 ms |
| PV12 | HE | 0 | 0 | 0 | 100.0 / 99.9 | 3.1 ms |

At this fixed rate, VHT simultaneous downstream loss averaged 24.145% with a 21.912% median; all twelve VHT nodes lost downstream datagrams and nine exceeded 10%. All nine HE nodes reported zero UDP loss in both directions. VHT loaded-gateway latency had a 57.817 ms median versus 3.508 ms for HE where summaries were available. This is a strong fixed-rate efficiency split, not proof that HE clients cannot reproduce at a higher rate.

## Internal 250+250 Mbps HE threshold test

The nine HE probes ran sequentially to avoid server saturation. UDP delivered every reverse/downstream stream at approximately 250 Mbps with zero reported datagram loss. Several clients could not sustain the requested simultaneous upload rate, and paced TCP exposed substantial duplex pressure and first-hop latency.

| Node | UDP download-control lost | UDP simultaneous up/down received Mbps | TCP simultaneous up/down Mbps | TCP sender retransmissions up/down | UDP gateway avg/max |
|---|---:|---:|---:|---:|---:|
| PV03 | 0 | 250.0 / 250.0 | 207.2 / 199.0 | 0 / 0 | 3.6 / 15.7 ms |
| PV04 | 0 | 250.0 / 250.0 | 242.0 / 76.4 | 0 / 0 | 4.9 / 13.9 ms |
| PV05 | 0 | 242.8 / 250.0 | 125.1 / 219.0 | 0 / 1 | 8.9 / 45.8 ms |
| PV06 | 0 | 250.4 / 250.0 | 29.0 / 238.8 | 0 / 0 | 7.7 / 30.1 ms |
| PV07 | 0 | 220.3 / 250.0 | 96.6 / 100.7 | 3 / 1 | 9.5 / 55.9 ms |
| PV09 | 0 | 250.0 / 250.0 | 75.5 / 177.3 | 0 / 0 | 6.4 / 20.1 ms |
| PV10 | 0 | 245.2 / 250.0 | 39.4 / 247.8 | 0 / 0 | 9.0 / 105.4 ms |
| PV11 | 0 | 109.4 / 250.0 | 61.0 / 62.7 | 0 / 81 | 22.1 / 79.9 ms |
| PV12 | 0 | 247.5 / 250.0 | 85.1 / 249.8 | 0 / 0 | 8.5 / 49.3 ms |

UDP simultaneous upload had a 247.475 Mbps median, but PV07 and PV11 were rate-limited to 220.327 and 109.364 Mbps. Every UDP downstream stream remained approximately 250 Mbps with zero loss. Paced TCP simultaneous delivery had medians of 85.091 Mbps up and 198.970 Mbps down, while gateway RTT averaged 46.125 ms across the TCP phases. PV04 reproduced a strong downstream TCP collapse—approximately 250 Mbps directionally versus 76.4 Mbps during simultaneous load—while several other HE nodes became upload-limited instead. PV11 was impaired in both directions.

This confirms that HE clients also encounter a higher-rate duplex saturation threshold, but the 250 Mbps expression is not uniformly the same downstream-UDP-loss signature seen in the VHT 100 Mbps fleet. Direction and transport vary by client. The shared signal is loss of usable bidirectional capacity plus first-hop latency under concurrent load.

## Arista correlation

Sanitized controller snapshots bracketed the 100 Mbps fleet window, and periodic client/AP sampling covered the 250 Mbps HE run. No raw client names, SSIDs, MAC addresses, BSSIDs, AP names, or credentials were retained.

For the 100 Mbps fleet window:

- No probe changed hashed AP identity or controller channel.
- No connection-failure count changed and no poor-coverage flag appeared.
- Every associated AP remained active.
- Controller contention did not separate outcomes. Clean HE nodes reached 68–85% contention, including PV12 at 85%, while retaining zero UDP loss.
- Current AP-radio utilization and retry had only weak point-in-time correlations with loss (`r=0.324` and `r=0.274`).
- Clean PV12 had the highest post-run AP-radio utilization, while badly affected VHT nodes existed at both low and high utilization.
- Signal, channel, AP power mode, client count, current controller retry, and AP utilization did not independently explain the fixed-rate cohort split.

The API telemetry is sampled or cached too slowly to clear a seven-second transient. It can demonstrate stable association and absence of durable failures, but not the absence of short queue, WMM, scheduling, or airtime events. Phase-aligned CV-CUE Client Timeline/Related AP Events exports remain necessary for the worst nodes.

During the 250 Mbps HE run, each node produced 38 sanitized controller samples. Every node stayed on one hashed AP and one channel, and every failure count remained zero. Signal ranges were narrow. Controller values moved, but again did not track delivered capacity consistently:

- PV05 contention moved from 6% to 86% yet retained 250 Mbps UDP downstream and 219 Mbps TCP downstream.
- PV12 moved from 15% to 85% contention and retained approximately 250 Mbps downstream in both UDP and TCP.
- PV06 had only 1–2% contention but simultaneous TCP upload fell to 29.0 Mbps.
- PV11 had 18–20% contention, the highest median AP-radio utilization among these samples, and the worst combined TCP delivery at 123.6 Mbps.
- Across the nine nodes, combined TCP delivery versus median controller retry was weakly negative (`r=-0.367`), versus median contention was weakly positive (`r=0.257`), and versus median AP-radio utilization was effectively uncorrelated (`r=0.020`). Gateway latency versus AP-radio utilization was only modest (`r=0.344`).

These are observational correlations from slowly updated controller fields, not phase-level causal measurements. They rule out a simple current-retry, contention, or AP-utilization threshold that explains all HE outcomes.

## Current interpretation

The internal results remove public iperf admission, Internet transit, firewall egress, NAT, and dual-WAN selection from the failing path. The evidence supports a client-facing WLAN duplex-capacity mechanism whose trigger scales with effective PHY/client efficiency. Likely components remain per-client scheduling, aggregation efficiency, WMM/queue behavior, airtime allocation, driver behavior, or an interaction among them. The data does not support a single bad AP, channel, weak-signal threshold, power mode, controller contention threshold, or legacy-only defect.

The best next tests are:

1. Repeat PV04, PV10, PV11, and PV12 at 150/200/225/250/275 Mbps to locate each direction-specific knee rather than relying on one fixed rate.
2. Place a passive observer on the same AP as the aggressor to determine whether impairment is 1:1 or 1:many.
3. Export phase-aligned CV-CUE client and related-AP events for PC16, PC17, PC1, PV04, PV10, and PV11.
4. Compare one client across naturally different APs/channels, then compare matched adapters on the same AP, to separate client/driver behavior from AP-local scheduling.

## Evidence and limitations

- Sanitized probe evidence remains temporarily on the management node under the run IDs `fleet-internal-20260803T0020Z` and `he250-internal-20260803T004103Z`.
- Three HE 250 Mbps directional TCP objects hit bounded timeouts; they are not represented as zero.
- Several iperf3 3.9 TCP controls exceeded the JSON safety bound during the 100 Mbps fleet run; UDP and simultaneous results remain independently valid.
- Controller performance fields are not phase-resolution logs. Causal claims require time-aligned AP/client events or an authorized over-the-air capture.
