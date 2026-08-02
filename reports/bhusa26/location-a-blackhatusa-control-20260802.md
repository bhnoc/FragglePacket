# Same-Room BlackHatUSA2026 Control

Captured 2026-08-02 without moving the client. This summary omits BSSID, MAC
address, client address, and PSK.

## Connection fingerprint

- Interface: Wi-Fi (`en0`)
- Route MTU: 1500
- IP family: IPv4; no active IPv6 route observed
- Wi-Fi: 802.11ax on 5 GHz channel 44, 40 MHz
- Signal/noise: -70 dBm / -97 dBm
- PHY: MCS 7, 344 Mbps transmit rate
- Interface errors/drops: 0 / 0
- Resolver set: unchanged from the room SSID

This differs materially from the room SSID's 6 GHz/80 MHz, approximately -52
dBm, MCS 11, and 1,200 Mbps PHY connection. Raw throughput should therefore not
be compared without accounting for radio capacity.

## Unloaded latency

One probe per second, 20 Internet-control samples:

| Target | Loss | Minimum | Average | Maximum | Stddev |
| --- | ---: | ---: | ---: | ---: | ---: |
| Internet control | 0% | 17.982 ms | 19.145 ms | 21.130 ms | 0.888 ms |

The default gateway did not answer ICMP echo. This is treated as ICMP
suppression, not 100% forwarding loss, because Internet traffic remained
healthy.

## Directional versus simultaneous load

| Protocol | Mode | Download | Upload | Loaded responsiveness |
| --- | --- | ---: | ---: | ---: |
| HTTP/3 | Directional | 181.729 Mbps | 240.334 Mbps | 305 ms upload / 507 ms download |
| HTTP/3 | Simultaneous | 27.551 Mbps | 251.266 Mbps | 299 ms overall |
| HTTP/2 | Directional | 217.975 Mbps | 230.187 Mbps | 232 ms upload / 100 ms download |
| HTTP/2 | Simultaneous | 94.530 Mbps | 108.484 Mbps | 523 ms overall |

HTTP/3 download retained only about 15% of its directional capacity during
simultaneous upload, while upload retained full capacity. HTTP/2 lost capacity
in both directions but stayed comparatively balanced. The HTTP/3 result closely
matches the 28-30 Mbps simultaneous download previously reproduced on the room
SSID.

HTTP/3 reported Accurate ECN with L4S disabled. HTTP/2 reported ECN disabled.
The Black Hat packet capture contained more than 540,000 ECN-capable UDP/443
packets but no Congestion Experienced (`CE`) marks. ECN capability is therefore
present, but active CE marking was not observed during the captured run. That
difference warrants a controlled test but does not establish causation.

## MSS check

| Destination | Negotiated MSS | Route MTU verdict |
| --- | ---: | --- |
| Apple | 1460 | Consistent with MTU 1500 |
| Cloudflare | 1400 | Destination-specific reduction |
| Google | 1412 | Destination-specific reduction |

The varying values do not support a blanket MSS clamp on this WLAN.

## HTTP/3 endpoint capability control

- Cloudflare main site: HTTP/3 success
- Google: HTTP/3 success
- Cloudflare speed host: HTTP/3 unavailable; HTTP/TCP succeeded
- Apple public website: HTTP/3 unavailable
- Apple network-quality endpoint: HTTP/3 success

The failures are endpoint-specific and do not establish UDP/443 filtering.
FragglePacket must preflight server protocol support and use more than one
known-capable endpoint before producing a network-blocking verdict.

## Current interpretation

The failure follows the client across the room and general SSIDs, different IP
subnets, and different radio profiles. This makes an isolated room-SSID policy
less likely. It remains compatible with shared AP/controller configuration,
shared upstream queue policy, ECN/AQM interaction, client behavior, or a test
endpoint interaction. Testing from a physically different AP and then from a
non-conference network are the strongest next controls.
