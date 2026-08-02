# Conference Center Location A Baseline

Captured 2026-08-01 immediately before moving to another test location. This
summary intentionally omits SSID, BSSID, MAC address, and client address.

## Connection fingerprint

- Interface: Wi-Fi (`en0`)
- Route MTU: 1500
- IP family: IPv4; no active IPv6 route
- Wi-Fi: 802.11ax on 6 GHz channel 5, 80 MHz
- Signal/noise: -52 to -53 dBm / -93 dBm
- PHY: MCS 11, two spatial streams, 1,200 Mbps transmit rate
- Snapshot channel utilization: 0% CCA
- Interface errors/drops: 0 / 0
- Resolver layout: two private conference resolvers with a public fallback

## Unloaded latency

One probe per second, 20 samples:

| Target | Loss | Minimum | Average | Maximum | Stddev |
| --- | ---: | ---: | ---: | ---: | ---: |
| First-hop gateway | 0% | 3.345 ms | 4.276 ms | 4.764 ms | 0.326 ms |
| Internet control | 0% | 18.029 ms | 19.356 ms | 22.984 ms | 1.467 ms |

Five probes per second, 30 samples:

| Target | Loss | Minimum | Average | Maximum | Stddev |
| --- | ---: | ---: | ---: | ---: | ---: |
| First-hop gateway | 0% | 3.386 ms | 28.593 ms | 93.543 ms | 29.425 ms |
| Internet control | 0% | 17.794 ms | 46.373 ms | 112.784 ms | 30.270 ms |

The high-rate spikes appeared at both targets and disappeared at one probe per
second. Treat them as probable ICMP rate-limiting or batching until reproduced
with application traffic.

## Protocol findings already established here

- Client SYN MSS: 1460 on the MTU-1500 interface.
- Peer SYN-ACK MSS varied by destination (Apple 1456; Cloudflare 1400).
- STUN binding: 5/5 successful with roughly 10-12 ms response time.
- HTTP/3 sequential: approximately 312 Mbps down and 609 Mbps up.
- HTTP/3 simultaneous: approximately 28-30 Mbps down on two runs, with loaded
  HTTP latency reaching approximately 2.5 seconds.
- HTTP/1.1 and HTTP/2 fixed-endpoint TCP capacity was broadly similar.

## Repeat at the next location

Use the same one-probe/second gateway and Internet samples, capture the Wi-Fi
channel/signal/PHY fingerprint, then repeat sequential and simultaneous HTTP/3.
Do not run a full packet capture unless a small bounded capture is specifically
needed.
