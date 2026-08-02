# Same-Location MGM External-Infrastructure Control

Captured 2026-08-02 without moving the client. This summary omits MAC/BSSID,
client address, and resolver addresses.

## Connection fingerprint

- Interface: Wi-Fi (`en0`)
- Route MTU: 1500
- Wi-Fi: 802.11ax on 5 GHz channel 100, 20 MHz
- Security: open WLAN
- Signal/noise: -50 dBm / -100 dBm
- PHY: MCS 11, 286 Mbps transmit rate
- Interface errors/drops: 0 / 0
- Subnet, gateway, and DNS policy: distinct from both Black Hat WLANs

## Unloaded latency

| Target | Loss | Minimum | Average | Maximum | Stddev |
| --- | ---: | ---: | ---: | ---: | ---: |
| Internet control | 0% | 30.515 ms | 42.056 ms | 52.175 ms | 5.891 ms |

The MGM gateway suppressed ICMP echo. Internet traffic and Internet ICMP
remained functional, so this is not treated as forwarding loss.

## Directional versus simultaneous load

| Protocol | Mode | Download | Upload | Loaded responsiveness |
| --- | --- | ---: | ---: | ---: |
| HTTP/3 | Directional | 16.401 Mbps | 44.045 Mbps | 1.56 s upload / 41 ms download |
| HTTP/3 | Simultaneous | 16.424 Mbps | 40.769 Mbps | 41 ms overall |
| HTTP/2 | Directional | 16.981 Mbps | 26.559 Mbps | 1.82 s upload / 238 ms download |
| HTTP/2 | Simultaneous | 16.417 Mbps | 22.750 Mbps | 217 ms overall |

MGM appears to enforce approximately 16-17 Mbps downstream regardless of
protocol. Most importantly, simultaneous upload does not reduce H3 download
below its directional baseline. This is the opposite of both Black Hat WLANs,
where H3 download fell to 28-30 Mbps despite directional capacity of 182-312
Mbps and upload remained near full capacity.

HTTP/3 reported ECN unavailable on MGM. It reported Accurate ECN with L4S
disabled on both Black Hat WLAN tests. The Black Hat capture contained over
540,000 ECN-capable UDP/443 packets but no CE marks, so active congestion
marking was not observed. This is correlation requiring an ECN/AQM A/B test,
not proof of causality.

## MSS and PMTU

| Destination | Negotiated MSS |
| --- | ---: |
| Apple | 1238 |
| Cloudflare | 1238 |
| Google | 1238 |

IPv4 DF probes totaling 1500 bytes succeeded with zero loss. The uniform MSS
1238 result is therefore consistent with a TCP-specific path clamp or proxy
policy, not a 1280-byte PMTU ceiling. A SYN/SYN-ACK capture is still required
to locate the rewrite conclusively.

## Verdict

The simultaneous-only H3 download collapse does not follow the Mac onto MGM's
infrastructure. It reproduces on both tested Black Hat WLANs but not on this
separate network, localizing the leading cause to configuration or queueing
shared by Black Hat infrastructure. Shared AQM/ECN handling is now a stronger
hypothesis; room-specific RF, blanket UDP blocking, client-wide behavior, and
MSS clamping are weaker explanations.
