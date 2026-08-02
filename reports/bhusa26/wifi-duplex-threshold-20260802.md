# Wi-Fi duplex-threshold characterization — 2026-08-02

## Executive finding

The failure is a Wi-Fi-specific, downstream-only loss cliff under simultaneous
load. It is not caused by MSS clamping, path MTU, one-way capacity, client CPU,
client interface drops, UDP/443-only classification, or raw 20 Gbps uplink
capacity.

The strongest current hypothesis is airtime/controller queue scheduling for
UDP on the WLAN path. A Wi-Fi-VLAN-specific firewall/NAT/egress policy remains
possible because wired and Wi-Fi expose different public egress identities.

## Test conditions

- Endpoint: `test.protoevidence.com`, independent iperf3 listeners on TCP/UDP
  ports 443, 444, and 445.
- Wi-Fi and wired interfaces were active at the same time and every client
  socket was explicitly bound to the intended interface.
- Two sanitized post-test snapshots remained on 802.11ax, 6 GHz channel 197,
  80 MHz. Signal ranged from -60 to -63 dBm, noise from -89 to -90 dBm, and
  transmit rate from 680 to 720 Mbps. The privileged follow-up also confirmed
  two spatial streams and an 800 ns guard interval. There is no evidence of a
  roam, band change, or RF collapse across the reporting interval.
- Client, gateway, public NAT, MAC, BSSID, and SSID values are omitted.

## Same-moment Wi-Fi versus wired rate sweep

Each direction used 1,200-byte UDP payloads for three seconds.

| Target each way | Wi-Fi upstream loss | Wi-Fi downstream loss | Wired upstream loss | Wired downstream loss |
| ---: | ---: | ---: | ---: | ---: |
| 250 Mbps | 0% | 6.414% | 0% | 0% |
| 275 Mbps | 0% | 1.953% | 0% | 0% |
| 300 Mbps | 0% | 0% | 0% | 0% |
| 325 Mbps | 0% | 2.246% | 0% | 0% |
| 350 Mbps | 0% | 9.060% | 0% | 0% |

The short Wi-Fi samples are non-monotonic, showing scheduling variability.
Wired remained lossless at every rate.

## Datagram-size matrix at 350 Mbps each way

| Payload | Wi-Fi upload | Wi-Fi download | Wi-Fi downstream loss | Wired downstream loss |
| ---: | ---: | ---: | ---: | ---: |
| 200 bytes | 97.09 Mbps | 113.48 Mbps | 65.119% | 0.483% |
| 600 bytes | 253.51 Mbps | 139.22 Mbps | 59.472% | 0.013% |
| 1,200 bytes | 342.94 Mbps | 263.92 Mbps | 21.645% | 0% |
| 1,400 bytes | 343.95 Mbps | 280.18 Mbps | 17.224% | 0.017% |
| 1,472 bytes | 343.43 Mbps | 285.96 Mbps | 16.303% | 0.016% |

Smaller packets substantially amplify the defect, but full-size datagrams
still reproduce it. This indicates packet-rate/queue pressure rather than an
MTU-only failure.

## Directional control with full-size datagrams

| Access | Mode | Upload | Download | Up loss | Down loss | Interface errors/drops added |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Wi-Fi | Upload only | 348.06 Mbps | N/A | 0% | N/A | 0 |
| Wi-Fi | Download only | N/A | 349.87 Mbps | N/A | 0% | 0 |
| Wi-Fi | Simultaneous | 340.11 Mbps | 273.45 Mbps | 0% | 20.771% | 0 |
| Wired | Upload only | 348.35 Mbps | N/A | 0% | N/A | 0 |
| Wired | Download only | N/A | 350.05 Mbps | N/A | 0% | 0 |
| Wired | Simultaneous | 348.32 Mbps | 348.50 Mbps | 0% | 0% | 0 |

Each direction is independently healthy. Combining them causes only Wi-Fi
downstream loss, with no client-interface counter evidence of host drops.

## Independent-rate threshold

Two independent server listeners allowed upload and download rates to be
controlled separately with 1,400-byte payloads and five-second phases.

### Download fixed at 350 Mbps

| Upload target | Upload loss | Download throughput | Download loss |
| ---: | ---: | ---: | ---: |
| 25 Mbps | 0% | 350.07 Mbps | 0% |
| 50 Mbps | 0% | 350.64 Mbps | 0% |
| 100 Mbps | 0% | 350.02 Mbps | 0% |
| 150 Mbps | 0% | 349.66 Mbps | 0% |
| 200 Mbps | 0% | 350.05 Mbps | 0% |
| 250 Mbps | 0% | 349.83 Mbps | 0.054% |
| 300 Mbps | 0% | 330.19 Mbps | 5.586% |
| 350 Mbps | 0% | 289.83 Mbps | 13.568% |

### Upload fixed at 350 Mbps

| Download target | Upload loss | Download throughput | Download loss |
| ---: | ---: | ---: | ---: |
| 25 Mbps | 0% | 24.99 Mbps | 0% |
| 50 Mbps | 0% | 49.99 Mbps | 0% |
| 100 Mbps | 0% | 100.01 Mbps | 0% |
| 150 Mbps | 0% | 149.95 Mbps | 0% |
| 200 Mbps | 0% | 200.01 Mbps | 0% |
| 250 Mbps | 0% | 249.72 Mbps | 0.076% |
| 300 Mbps | 0% | 241.06 Mbps | 19.300% |
| 350 Mbps | 0% | 237.34 Mbps | 29.734% |

Both sweeps locate the transition between 250 and 300 Mbps per direction,
around 600-650 Mbps combined offered load. The network consistently protects
upload while discarding download.

## Port, flow-count, and DSCP controls

- UDP ports 443, 444, and 445 all reproduced downstream-only loss, ranging
  from roughly 11% to 38% across completed repetitions. There is no evidence
  of a UDP/443-only policy.
- Holding aggregate targets near 350 Mbps each way while using 1, 2, 4, and 8
  flows produced Wi-Fi downstream loss of 15.3%, 33.6%, 66.8%, and 6.9%,
  respectively. Wired remained essentially lossless. The non-monotonic result
  does not support a simple fixed bad hash bucket and needs interleaved repeats.
- At 300 Mbps each way, two DSCP repetitions produced downstream loss of
  0.028/0.821% for CS0, 5.033/1.936% for CS1, 13.992/7.007% for AF41, and
  2.788/13.764% for EF. The variation is too large to claim a QoS-class cause
  without packet capture proving DSCP preservation and controller WMM counters.

## Requested infrastructure evidence

During a 10-second 350 Mbps-each-way reproduction, collect synchronized:

1. AP per-client airtime, retry, queue depth/drop, and WMM access-category
   counters;
2. controller client-tunnel ingress/egress drops and UDP queue/policer counters;
3. firewall inside/outside queue, session owner, NAT node, and policy counters;
4. both 10 Gb circuit member utilization, discards, policer, and errors; and
5. an egress-policy swap or A-only/B-only run if operationally possible.

If drops appear before controller egress, the WLAN path is confirmed. If the
controller remains clean and drops follow one NAT/egress identity, the fault is
VLAN/edge/uplink-specific. If both circuits work alone and fail only together,
inspect ECMP symmetry and state ownership.
