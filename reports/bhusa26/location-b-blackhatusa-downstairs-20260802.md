# Downstairs BlackHatUSA2026 Cross-AP Baseline

Captured 2026-08-02 hundreds of feet from the original room. This summary omits
BSSID, MAC address, client address, and credentials.

## Association validity

The initial association was 802.11ax on 5 GHz channel 40 at -77 dBm and 97 Mbps
PHY. Moving the laptop approximately three feet caused it to roam to 2.4 GHz
channel 5, invalidating the first two H3 setup runs.

The official stationary runs remained on 2.4 GHz channel 5 at -71 to -75 dBm,
with PHY rate varying from 68 to 103 Mbps. RF remained weak, so these results
characterize this location but are not a clean capacity comparison with the
upstairs 5/6 GHz baselines.

## Unloaded latency

One probe per second, 10 stationary samples:

| Target | Loss | Minimum | Average | Maximum | Stddev |
| --- | ---: | ---: | ---: | ---: | ---: |
| Internet control | 0% | 18.119 ms | 21.055 ms | 30.444 ms | 3.425 ms |

The shared Black Hat gateway suppressed ICMP echo.

## Stationary load results

| Protocol | Mode | Download | Upload | Loaded responsiveness | Validity |
| --- | --- | ---: | ---: | ---: | --- |
| HTTP/3 | Directional | 8.917 Mbps | 66.379 Mbps | 994 ms upload / 2.894 s download | Completed; low accuracy |
| HTTP/3 | Simultaneous | 4.981 Mbps | 97.977 Mbps | 837 ms overall | Invalid: protocol error after 10.7 s |
| HTTP/2 | Directional | 2.464 Mbps | 34.030 Mbps | 1.721 s upload / 1.821 s download | Completed |
| HTTP/2 | Simultaneous | 2.075 Mbps | 18.618 Mbps | 5.305 s overall | Completed |

The simultaneous H2 run reported loaded HTTP latency of 10.913 seconds. Unlike
the upstairs tests, downstream performance is severely impaired on both H2 and
H3 even before simultaneous load. The partial H3 simultaneous result must not
be used to calculate a collapse ratio.

## MSS check

| Destination | Negotiated MSS |
| --- | ---: |
| Apple | 1460 |
| Cloudflare | 1400 |
| Google | 1412 |

The values are destination-specific and match the upstairs general WLAN. They
do not support a blanket MSS clamp.

## Interpretation

This downstairs association exposes a broad coverage/capacity problem rather
than a clean reproduction of the upstairs simultaneous-only QUIC symptom. Weak
2.4 GHz RF, variable PHY rate, very low downstream throughput, multi-second
loaded latency, and repeated H3 control errors make transport attribution
unsafe. A nearby strong 5/6 GHz association would be required for a matched
cross-AP protocol comparison.
