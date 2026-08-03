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

## Adaptive HE knee sweep

Run window: 2026-08-03 01:03:36Z–01:13:39Z. PV04, PV10, PV11, and PV12 each completed four directional controls and ten simultaneous UDP/TCP phases, for 56 controlled load phases and 96 iperf traffic objects. The controller supplied 47 synchronized samples per client (188 total) through 01:15:47Z. PV04, PV10, and PV12 were offered 150, 200, 225, 250, and 275 Mbps in each direction. PV11 used 75, 100, 125, 150, and 175 Mbps because its directional ceiling was lower. Under the working definition requested for this analysis, a collapse is a simultaneous TCP directional difference greater than 40 Mbps.

| Node | Directional TCP up/down at maximum rate | First >40 Mbps simultaneous asymmetry | Worst simultaneous TCP up/down | Highest TCP-loaded gateway average | Channel / width | Controller signal range |
|---|---:|---:|---:|---:|---:|---:|
| PV04 | 275.3 / 279.6 Mbps at 275 | 225 Mbps | 195.4 / 74.3 Mbps at 275 | 93.9 ms | 153 / 40 MHz | -56 to -52 dBm |
| PV10 | 276.4 / 276.1 Mbps at 275 | 200 Mbps | 38.3 / 275.9 Mbps at 275 | 39.9 ms | 140 / 40 MHz | -51 to -48 dBm |
| PV11 | 113.8 / 149.6 Mbps at 175 | 125 Mbps | 13.2 / 136.1 Mbps at 150 | 86.0 ms | 116 / 40 MHz | -64 to -61 dBm |
| PV12 | 275.0 / 277.5 Mbps at 275 | 225 Mbps | 246.4 / 70.5 Mbps at 250 | 54.4 ms | 140 / 40 MHz | -49 to -46 dBm |

Thirty-nine of forty simultaneous UDP streams returned valid receiver results, delivered the offered rate within normal generator variance, and reported zero lost datagrams; PV04's 200 Mbps reverse object timed out and is invalid rather than zero. UDP-loaded gateway averages remained 3.4–5.3 ms except PV11, which ranged 3.7–18.0 ms. TCP was different: PV10 became 118.3 Mbps asymmetric at 200 Mbps, PV04 and PV12 crossed the threshold at 225 Mbps, and PV11 crossed it at 125 Mbps. Directional TCP controls were clean at the requested maximum for PV04, PV10, and PV12, while PV11 was already below its 175 Mbps request. The failure direction changed between phases and PV12 recovered to 162.5/170.4 Mbps at 275 Mbps after collapsing to 246.4/70.5 at 250 Mbps. This is not a monotonic hard capacity ceiling; it is a repeatable loss of stable bidirectional TCP capacity under concurrency. The clean simultaneous UDP delivery also argues against the radio simply being unable to carry the aggregate bitrate, although it does not identify which TCP, queue, or scheduler interaction is responsible.

## PV10 TCP flow-count and DSCP matrix

Run window: 2026-08-03 02:25:55Z–02:30:02Z. On the full-power, 5 Gbps-uplink PV10 AP, the test held the target at 250 Mbps in each direction and compared one versus four TCP flows and DSCP 0 versus EF. Each condition had adjacent directional controls and two simultaneous trials in reversed order. The node captured gateway latency, `ss`, `nstat`, qdisc/link counters, and `iw` station deltas; 86 Arista observations covered load and three minutes of recovery.

| Condition | Simultaneous trial 1 up/down | Simultaneous trial 2 up/down | Mean directional difference | Gateway average range | `TCPRcvCollapsed` total |
|---|---:|---:|---:|---:|---:|
| 1 flow, DSCP 0 | 118.2 / 181.1 Mbps | 89.6 / 238.5 Mbps | 105.8 Mbps | 37.8–61.6 ms | 175 |
| 4 flows, DSCP 0 | 77.4 / 243.5 Mbps | 93.7 / 248.5 Mbps | 160.5 Mbps | 42.8–56.6 ms | 223 |
| 1 flow, DSCP EF | 193.8 / 96.9 Mbps | 117.9 / 191.6 Mbps | 85.3 Mbps | 24.8–37.0 ms | 240 |
| 4 flows, DSCP EF | 69.4 / 229.1 Mbps | 80.8 / 242.5 Mbps | 160.7 Mbps | 74.5–90.9 ms | 305 |

Every directional upload control delivered 242.3–249.4 Mbps and every directional download control delivered 250.0–250.3 Mbps, with 4.6–11.3 ms average gateway latency. All eight simultaneous trials exceeded the 40 Mbps collapse threshold and raised gateway average latency to 24.8–90.9 ms. Four flows did not recover capacity; instead, both four-flow conditions consistently became upload-limited. EF did not consistently recover either direction. Therefore, the result does not support a single-flow-only congestion-window problem or a simple DSCP/WMM cure. The four-flow EF latency was worse than four-flow DSCP 0 in both trials, but two trials are insufficient to attribute that interaction to WMM classification.

The client root qdisc recorded no drops, signal stayed -57 to -58 dBm, and negotiated HE rates stayed about 413–459 Mbps at 40 MHz. The client remained on one AP/channel, the AP remained active at full power and 5 Gbps, and exact-window Client Events and Related AP Events both returned zero records. Arista fields were visibly cached: client retry and AP utilization changed in delayed steps rather than tracking the five-second query cadence.

Linux `TcpExtTCPRcvCollapsed` increased in seven of eight simultaneous phases—943 freed socket buffers in total—but remained zero through all eight directional controls. The [Linux kernel SNMP counter documentation](https://www.kernel.org/doc/html/latest/networking/snmp_counter.html) defines this as socket buffers freed while collapsing the receive and out-of-order queues during receive-socket memory pressure. This is the strongest new client-side symptom, but it is not sufficient as a sole cause because one collapsed simultaneous trial recorded zero. It points to receive-path pressure or delayed draining during duplex traffic and justifies testing the iperf process model, block size, socket behavior, per-core softirq load, and driver receive path before assigning the entire failure to the AP.

## PV10 receiver-path and process-model A/B

Run window: 2026-08-03 02:43:56Z–02:48:50Z. The same PV10 client then compared the original two-process/two-listener method with iperf3's native `--bidir` mode at a fixed 250 Mbps request in each direction. Each method was tested twice at 16, 64, and 128 KiB. Eighteen phases captured directional controls, gateway latency, per-core CPU, softirq and softnet counters, iwlwifi interrupts, socket memory, `nstat`, qdisc/link counters, and negotiated station state. Arista supplied 130 observations through 02:54:41Z, including almost six minutes of recovery.

| Method / block | Trial 1 upload / download | Trial 2 upload / download | Mean directional difference | Mean combined throughput | `TCPRcvCollapsed` total |
|---|---:|---:|---:|---:|---:|
| Paired processes, 16 KiB | 75.9 / 250.0 Mbps | 164.9 / 151.5 Mbps | 93.8 Mbps | 321.2 Mbps | 171 |
| Paired processes, 64 KiB | 113.2 / 215.3 Mbps | 115.2 / 208.4 Mbps | 97.7 Mbps | 326.0 Mbps | 158 |
| Paired processes, 128 KiB | 106.1 / 211.5 Mbps | 71.8 / 242.0 Mbps | 137.7 Mbps | 315.7 Mbps | 183 |
| Native `--bidir`, 16 KiB | 171.4 / 135.2 Mbps | 148.1 / 154.9 Mbps | 21.5 Mbps | 304.8 Mbps | 0 |
| Native `--bidir`, 64 KiB | 172.2 / 129.5 Mbps | 150.0 / 157.0 Mbps | 24.9 Mbps | 304.4 Mbps | 0 |
| Native `--bidir`, 128 KiB | 153.7 / 153.5 Mbps | 159.6 / 137.9 Mbps | 11.0 Mbps | 302.4 Mbps | 0 |

The six directional controls delivered 242.7–258.9 Mbps with 6.0–7.9 ms average gateway latency and zero `TCPRcvCollapsed`. All six paired-process trials raised that counter by 70–102, while all six native trials left it at zero. Native bidirectional mode also removed the extreme directional unfairness: only one native trial narrowly crossed the working 40 Mbps threshold at 42.8 Mbps, compared with five of six paired trials at 93.2–174.2 Mbps. Changing the block size did not materially alter either method. Native combined throughput was exceptionally stable at 302.4–304.8 Mbps; paired combined throughput was 315.7–326.0 Mbps but was frequently divided unfairly.

No phase recorded a softnet or client qdisc drop. The busiest observed core did not saturate, negotiated HE rates remained about 413–459 Mbps at 40 MHz, and signal remained -57 to -58 dBm. Native loaded gateway averages still rose to 15.0–25.4 ms, so the WLAN retained a real shared-capacity and queue-delay limit even when it did not collapse directionally. With approximately 303 Mbps of stable native aggregate TCP against a requested 500 Mbps on a half-duplex radio, the simplest current explanation is PHY-scaled airtime saturation plus method-specific process/socket unfairness in the paired harness. That is an inference, not proof that every attendee symptom was a test artifact: multi-process applications can still encounter unfairness, and the observed loaded latency remains operationally relevant.

PV10 remained associated to the same full-power, 5 Gbps-uplink AP on channel 140 at 40 MHz. Controller signal was -52 to -50 dBm, the radio reported one associated client, failure count remained zero, and exact-window Client Events and Related AP Events returned zero records. Retry and contention values changed only in delayed, coarse steps and then remained unchanged through recovery, confirming that these controller snapshots cannot identify which individual test phase caused a change.

## PC13 VHT receiver-path and process-model A/B

Run window: 2026-08-03 03:15:36Z–03:22:44Z. PC13 was selected as the strongest repeatable Wi-Fi 5 case: its earlier fixed-rate tests lost 42.965 Mbps of each 100 Mbps downstream, and a separate repeat lost 36.771 Mbps. The client was still associated as VHT at 40 MHz with -61 to -58 dBm client-reported signal. The PV10 matrix was repeated at the VHT cohort's established 100 Mbps-per-direction trigger. Because PC13 uses iperf3 3.9, native bidirectional results were decoded from per-stream sender/receiver direction flags rather than the newer aggregate keys.

| Method / block | Trial 1 upload / download | Trial 2 upload / download | Mean directional difference | Mean combined throughput | TCP retransmissions |
|---|---:|---:|---:|---:|---:|
| Paired processes, 16 KiB | 56.4 / 71.2 Mbps | 37.5 / 103.5 Mbps | 40.4 Mbps | 134.3 Mbps | 28 |
| Native `--bidir`, 16 KiB | 68.2 / 70.1 Mbps | 35.5 / 38.7 Mbps | 2.5 Mbps | 106.3 Mbps | 0 |
| Paired processes, 64 KiB | 25.8 / 100.9 Mbps | 47.2 / 94.3 Mbps | 61.1 Mbps | 134.1 Mbps | 5 |
| Native `--bidir`, 64 KiB | 69.2 / 70.1 Mbps | 64.4 / 65.8 Mbps | 1.2 Mbps | 134.7 Mbps | 0 |
| Paired processes, 128 KiB | 53.9 / 84.2 Mbps | 28.2 / 46.3 Mbps | 24.2 Mbps | 106.3 Mbps | 55 |
| Native `--bidir`, 128 KiB | invalid duration / near-zero payload | invalid duration / near-zero payload | excluded | excluded | excluded |

Across the four valid, directly comparable 16/64 KiB trials, paired processes averaged 41.7 Mbps upload, 92.5 Mbps download, a 50.7 Mbps directional difference, 134.2 Mbps combined throughput, and 53.2 ms loaded gateway latency. Three of four exceeded the working 40 Mbps asymmetry threshold. Native bidirectional mode averaged 59.3 Mbps upload, 61.2 Mbps download, only a 1.9 Mbps difference, 120.5 Mbps combined, and 22.7 ms gateway latency; none exceeded the threshold. The aggregate reduction includes one balanced but lower-capacity native trial at 35.5/38.7 Mbps. Directional controls delivered 95.5–97.5 Mbps upload and 56.3–100.0 Mbps download, showing some contemporaneous capacity variation.

One original paired 64 KiB trial was excluded after its reverse process returned a connection-reset error; a successful replacement trial is shown. Both native 128 KiB runs transferred near-zero payload over invalid 3.9 durations, so they are a repeatable client/tool compatibility failure rather than measured WLAN throughput. PC13 recorded no `TCPRcvCollapsed`, softnet drops, or qdisc drops. One paired 128 KiB phase saturated one core, but the valid 16/64 KiB paired phases peaked at 48.5–56.9% on their busiest core. The Wi-Fi 5 result therefore reproduces the process-model sensitivity without reproducing PV10's receive-collapse counter: native mode removes the severe directional unfairness at valid block sizes, while iperf3 version and block-size validation remain mandatory.

The controller supplied 130 observations through 03:26:21Z. PC13 remained on one AP, channel 153 at 40 MHz, with -46 to -44 dBm controller-reported signal, 2% client retry, 1% contention/interference, one associated client, and zero connection failures. The AP remained active on firmware 21.3.0M-13 at fixed 18 dBm; its wired link was 1 Gbps and its 40 W request was negotiated down to 25.5 W PoE+. Exact-window Client Events and Related AP Events both returned zero records. Reduced AP power remains a fleet concern, but it cannot explain the method-dependent difference on this unchanged AP, and the observed 134.7 Mbps maximum combined delivery was far below its 1 Gbps wired link.

## PC13 native capacity knee and application reproduction

Run window: 2026-08-03 03:32:31Z–03:50Z. A version-safe native `--bidir` sweep used validated 64 KiB results and a different qualified internal listener for every phase. Two repeated-listener resets and one short-duration result were excluded. The test delivered essentially the full request through 60 Mbps in each direction. At 70 Mbps, combined delivery began to flatten while gateway latency doubled; from 80 through 100 Mbps, combined delivery stayed near 134–142 Mbps while latency continued rising.

| Requested per direction | Valid runs | Mean upload / download | Mean combined delivery | Idle gateway average | Loaded gateway average |
|---:|---:|---:|---:|---:|---:|
| 25 Mbps | 1 | 24.7 / 24.6 Mbps | 49.3 Mbps | 3.05 ms | 3.73 ms |
| 40 Mbps | 1 | 39.7 / 39.5 Mbps | 79.2 Mbps | 2.15 ms | 5.29 ms |
| 50 Mbps | 1 | 49.5 / 49.4 Mbps | 99.0 Mbps | 1.63 ms | 6.26 ms |
| 60 Mbps | 2 | 59.3 / 59.9 Mbps | 119.1 Mbps | 1.79 ms | 8.05 ms |
| 70 Mbps | 3 | 66.6 / 67.2 Mbps | 133.8 Mbps | 1.76 ms | 16.80 ms |
| 80 Mbps | 1 | 70.0 / 71.8 Mbps | 141.8 Mbps | 1.84 ms | 25.38 ms |
| 90 Mbps | 1 | 67.3 / 66.9 Mbps | 134.2 Mbps | 1.96 ms | 27.03 ms |
| 100 Mbps | 1 | 70.9 / 71.4 Mbps | 142.3 Mbps | 1.87 ms | 27.51 ms |

The capacity/latency knee is therefore between 60 and 70 Mbps per direction on this VHT client under current conditions. This is not a directional collapse: native iperf divided the available capacity evenly. It is a real shared-capacity plateau with increasing first-hop queue delay.

The same knee then reproduced with application traffic against Apple's measurement service. Four concurrent HTTP/2 downloads were paired with four rate-limited HTTPS uploads. At 60 Mbps requested in each direction, two trials averaged 61.4 Mbps download and 58.8 Mbps upload; gateway latency rose from 1.80 ms idle to 36.73 ms loaded and peaked at 203.15 ms, with one of 150 loaded pings lost. At 70 Mbps, download held at 71.7 Mbps while upload fell to 45.7 Mbps—24.3 Mbps below its request—and loaded gateway latency averaged 56.46 ms with a 232.59 ms peak. The 70 Mbps behavior repeated in both trials: upload delivered 47.3 and 44.1 Mbps while download delivered 71.5 and 71.8 Mbps.

| Application phase | Runs | Mean download | Mean upload | Loaded gateway average | Highest gateway sample |
|---|---:|---:|---:|---:|---:|
| HTTP/2 download-only control, 70 Mbps | 1 | 71.8 Mbps | — | 19.46 ms | 170.58 ms |
| HTTPS upload-only control, 70 Mbps | 1 | — | 70.2 Mbps | 4.66 ms | 34.51 ms |
| Concurrent HTTP/2 download + HTTPS upload, 60+60 | 2 | 61.4 Mbps | 58.8 Mbps | 36.73 ms | 203.15 ms |
| Concurrent HTTP/2 download + HTTPS upload, 70+70 | 2 | 71.7 Mbps | 45.7 Mbps | 56.46 ms | 232.59 ms |
| HTTP/3 download-only controls | 2 | 18.7–20.1 Mbps | — | 4.02 ms | 57.09 ms |
| HTTP/3 download + HTTPS upload at 60 or 70 | 4 | 14.8 Mbps mean | 60.1–70.3 Mbps | 11.73 ms | 241.59 ms |

The HTTP/3 test used four real H3 streams with negotiated QUIC v1/H3 and HTTP 200 responses. Both bracketing download-only controls delivered 18.7–20.1 Mbps. All four concurrent-upload trials were below that control range at 11.8–18.6 Mbps, averaging 14.8 Mbps, a 23.8% reduction. Because this was a public CDN endpoint with lower and variable capacity, it corroborates an application coexistence penalty but does not define the local WLAN's maximum. The repeated HTTP/2/HTTPS result is the stronger rate-controlled proof that the user-visible problem survives outside the old iperf process model.

Two hundred controller observations covered the native sweep and application phases. PC13 stayed on one AP and channel 153/40 MHz with -45 to -44 dBm controller signal, zero reported retry, one associated client, and zero connection failures. The AP remained active at 18 dBm, 25.5 W PoE+, and 1 Gbps. Controller contention changed from 0 to 77 in one delayed step during the application run and stayed there; this is consistent with cached publication and cannot be assigned to an individual phase. Exact-window Client Events and Related AP Events again returned zero records.

## Effective Arista configuration and event evidence

The read-only integration was extended using Arista's published [CV-CUE OpenAPI index](https://apihelp.wifi.arista.com/data/wm/wm-openapi-root.json), then used only with documented GET routes. Each probe's current client record was joined to its location policy, actual AP template, active AP radio, and matching SSID profile. The four locations use different profile identifiers but returned the same relevant settings. The active association on every AP was radio 2—not one of the AX-only template radios—and radio 2 is configured for Wi-Fi 7 (`BE`) operation while serving these HE/Wi-Fi 6 clients.

| Configuration surface | Effective value on all four tested APs | Investigative relevance |
|---|---|---|
| Platform / software | C-460; 21.3.0M-13 | Common implementation and firmware across the reproduced cases |
| Active radio | 5 GHz radio 2; actual 40 MHz; auto channel; fixed 18 dBm | After Wi-Fi 7 was disabled, `wirelessMode` reads `A_N_AC`; the separate `wirelessProtocol=BE` field describes the radio family and must not be used alone to claim BE is enabled |
| Multi-user features | Downlink OFDMA on in the template; uplink OFDMA off; downlink and uplink MU-MIMO off | With current enabled standards limited to A/N/AC, OFDMA is not exercised; the impairment persisted, eliminating OFDMA/MU-MIMO as necessary causes |
| Wi-Fi 7/airtime features | MRU on, BSS coloring on, spatial reuse on with OBSS-PD -77 dBm, and preamble puncturing off in the template | These AX/BE features are not active in A/N/AC mode; persistence after the mode change eliminates them as necessary triggers |
| Aggregation / thresholds | Frame aggregation and A-MSDU on; RTS 2347; fragmentation 2346; ignore-low-RSSI off | No unusual low RTS/fragmentation cutoff or low-RSSI discard policy was found |
| SSID traffic policy | Shaping values zero; per-user control enabled with upload/download limits zero; WMM on; voice priority with ceiling behavior; WMM admission off | No explicit rate cap was found; QoS/queue treatment remains relevant under duplex load |
| Steering / mobility | Device-level client steering on at -65 dBm; SSID smart steering and load balancing off; 11v transition off; MLO off | PV11 operated near the steering threshold, but all four clients stayed on one AP/channel and logged no transition |
| Wired AP uplink | PV04/PV11/PV12: 25.5 W PoE+, low-power flag, 1 Gbps; PV10: 40 W four-pair PoE, no low-power flag, 5 Gbps; single LAN1, no LAG | Power/uplink differences may aggravate rooms, but PV10's full-power 5 Gbps AP also collapsed, excluding them as the sole fleet-wide cause |

A live post-change configuration refresh successfully read the current client, managed AP, location policy, actual device template, active radio, and matching SSID profile. PC13 and PV10 returned identical relevant radio-template and SSID settings. Their only differences were physical AP delivery: PC13 was low-power at 25.5 W/1 Gbps, while PV10 was full-power at 40 W/5 Gbps. This excludes PoE mode and wired-link speed as the common cause while preserving reduced power as a possible room-specific aggravating factor.

| Remaining configuration surface | Effective value on PC13 and PV10 | Assessment |
|---|---|---|
| Enabled standards | `WIRELESS_MODE_A_N_AC`; radio-family field still reports `BE` | Confirms the non-BE change; enabled-mode and family fields have different meanings |
| Channel / PHY | 20/40 MHz allowed; actual 40 MHz; auto channel; fixed 18 dBm; full guard interval; AP 3x3 | No unusual narrow width or low transmit power; client capability still determines usable PHY |
| WMM / SSID priority | WMM on; SSID priority `VOICE`; ceiling mode; admission control off | Most relevant exposed queue-policy surface, but not proof of forced voice treatment |
| QoS mappings | Downstream DSCP mapping selected; upstream 802.1p enabled; upstream DSCP/TOS disabled; IGMP unicast priority best effort | Directionally different classification paths merit a controlled test-SSID A/B |
| Explicit mapping table | DSCP ranges are unset/default placeholders for priorities 0–7 | No custom DSCP range that directly explains the threshold was found |
| Shaping and per-user policy | SSID shaping 0/0; per-user control enabled but limits 0/0; role-based control and SSID/application firewalls off | No explicit configured bandwidth cap; the enabled zero-limit per-user code path remains safely testable on a cloned profile |
| Rate policy | 12 Mbps minimum unicast rate; maximum 0/unlimited; association limit off | Removes a configured 60–70 Mbps client cap as an explanation |
| Aggregation / contention thresholds | Frame aggregation and A-MSDU on; RTS 2347; fragmentation 2346 | Normal high-throughput settings; disabling aggregation would likely lower capacity and is not the first A/B |
| Steering | Device steering on at -65 dBm; SSID smart steering/load balancing/min-association-RSSI off; 11v off | Clients stayed associated with strong signal, so steering is not aligned with the failing phases |
| Scheduler visibility | No explicit airtime-fairness algorithm, scheduler selection, per-access-category queue depth, or TXOP limit in the accessible schema | Largest configuration blind spot; requires higher-detail AP/TAC telemetry rather than inference from empty fields |

Arista's [radio settings guide](https://www.arista.com/en/ug-cv-cue/cv-cue-radio-settings) documents the OFDMA, MU-MIMO, channel, spatial reuse, and aggregation controls; the [SSID settings guide](https://www.arista.com/en/ug-cv-cue/cv-cue-ssid-settings?print=1&tmpl=component) documents shaping, per-user limits, WMM/QoS, and steering. The [C-460 datasheet](https://www.arista.com/assets/data/pdf/Datasheets/Arista-C-460-Datasheet.pdf) specifies full-function 802.3bt Class 6 power and reduced operation on 802.3at, making the three low-power flags actionable even though they do not explain PV10.

Exact-window `Client Events` and `Related AP Events` queries returned zero records for all four probes. No client changed AP or channel, no connection-failure counter changed, and every AP remained active. Current and historical inference and snapshot routes were also reachable, but did not expose a named cause for these short phases. This is a visibility limitation, not proof that no radio/queue event occurred: Arista's [client monitoring guide](https://www.arista.com/en/ug-cv-cue/cv-cue-monitor-wi-fi) describes the event surfaces, while system audit-log access requires a higher role. The present read key receives `403 ERROR_CODE_OP_NOT_PERMITTED` for audit-log and audit-filter endpoints, so a CV-CUE Superuser must export Device and Location Based Settings changes for the window.

A subsequent live association inventory found 19 active trusted probes on 19 different AP hashes; PV05 and PV06 were absent from the client API at that moment. Consequently, no stationary same-AP Precog pair was available for a valid aggressor/victim experiment. This does not imply the APs have only one client or that peer impact is absent—it only means the controlled probes could not test it without moving a probe or adding another authorized client.

The operator subsequently disabled Wi-Fi 7/802.11be operation on the controlled AP and repeated the full same-client 350 Mbps-per-direction UDP baseline. Directional upload delivered 218.4 Mbps with 1.64% loss, directional download delivered 221.7 Mbps with 36.73% loss, and simultaneous traffic delivered 127.6 Mbps upload with 4.59% loss versus only 35.4 Mbps download with 82.93% loss. Gateway average latency was already 40.7 ms idle and rose to 118.3 ms loaded. The client remained associated as 802.11ax on 6 GHz/80 MHz. That completed A/B rules out Wi-Fi 7/BE mode and Wi-Fi 7 backward compatibility as necessary causes of this incident. It does not rule out behavior shared by both AX and BE modes, such as generic C-460 scheduling, airtime, aggregation, WMM queues, client-driver behavior, or firmware code used by both configurations.

## Current interpretation

The internal results remove public iperf admission, Internet transit, firewall egress, NAT, and dual-WAN selection from the failing path. Receiver-path A/Bs on both HE PV10 and VHT PC13 show that the old paired-process harness exaggerated directional collapse, but the native knee and HTTP/2/HTTPS reproduction prove the user-impacting capacity and latency problem is real. The strongest current explanation is PHY-scaled half-duplex WLAN saturation, amplified into directional unfairness by concurrent application flows and expressed differently by the two client stacks. PV10 raised receive-collapse counters; PC13 did not. Wi-Fi 7/BE mode is ruled out as a necessary cause because disabling it did not change the result. No exposed configuration value is a smoking gun: the most relevant common configurable surface is WMM/QoS classification, while the actual airtime scheduler, per-AC queues, and TXOP limits are not visible to this API role. The remaining fault domain includes generic C-460/AP scheduling, airtime and aggregation efficiency, WMM/queue behavior, shared firmware paths, and client-driver behavior. The data does not support a single bad AP, channel, weak-signal threshold, controller contention threshold, or legacy-only defect.

The best next tests are:

1. On a cloned test SSID/profile, change only the QoS priority/ceiling and downstream/upstream mapping behavior to best effort, then repeat the same 60/70 Mbps native and application phases. Do not disable WMM itself on an 802.11n/ac/ax WLAN.
2. If QoS mapping does not change the result, restore it and disable only the zero-limit per-user traffic-control switch on the cloned profile. This tests the enabled policy code path without changing any configured rate.
3. Repeat the native knee and application test on PV10 and the newer laptop at their normalized trigger rates. This confirms whether the same 60-to-70-style latency knee scales consistently with each client's usable PHY capacity.
4. On one full-power AP and one reduced-power AP, run the same client at a normalized sub-knee and knee load while collecting AP switch-port queue drops/errors, PoE negotiation, radio airtime, and interface counters. This separates a fleet concern from a necessary cause.
5. When two authorized clients naturally share an AP, run alternating victim-only controls and aggressor-loaded trials to distinguish 1:1 from 1:many impact. The current stationary Precog population cannot perform this test because every visible probe is on a different AP.
6. Have a CV-CUE Superuser or Arista TAC expose the scheduler/airtime-fairness selection, per-AC queue occupancy/drops, and TXOP behavior, and export exact-window Device and Location Based Settings audit logs.
7. Use an authorized over-the-air capture plus AP/client packet capture at 60 and 70 Mbps per direction to compare block acknowledgements, retries, TXOP occupancy, contention, aggregation, and TCP ACK timing immediately below and above the proven application knee.

## Evidence and limitations

- Sanitized probe evidence remains temporarily on the management node under the run IDs `fleet-internal-20260803T0020Z` and `he250-internal-20260803T004103Z`.
- Adaptive-knee probe evidence remains temporarily on the management node under `he-knee-internal-20260803T010336Z`; its synchronized local Arista sample contains 188 sanitized observations. Raw credentials, SSIDs, client/AP identifiers, and controller responses were not added to the repository.
- PV10 flow/QoS evidence remains temporarily on the management node under `tcp-flow-qos-20260803T022516Z`; the synchronized Arista sample contains 86 sanitized observations.
- PV10 receiver-path evidence remains temporarily on the management node under `receiver-path-20260803T024209Z`; the synchronized Arista sample contains 130 sanitized observations.
- PC13 receiver-path evidence remains temporarily on the management node under `receiver-path-pc13-20260803T031527Z`; its synchronized Arista sample contains 130 sanitized observations. One failed paired listener result and both invalid native 128 KiB results were excluded rather than converted to zero throughput.
- PC13 native-knee evidence remains temporarily on the management node under `pc13-native-knee-20260803T033217Z` and `pc13-native-knee2-20260803T0337Z`; application evidence remains under `pc13-app-knee-20260803T0343Z` and `pc13-app-h3-closing-20260803T0349Z`. The synchronized Arista sample contains 200 sanitized observations. The HTTP/3 client used user-scoped aioquic 1.3.0 on PC13.
- Three HE 250 Mbps directional TCP objects hit bounded timeouts; they are not represented as zero.
- Several iperf3 3.9 TCP controls exceeded the JSON safety bound during the 100 Mbps fleet run; UDP and simultaneous results remain independently valid.
- Controller performance fields are not phase-resolution logs. Causal claims require time-aligned AP/client events or an authorized over-the-air capture.
