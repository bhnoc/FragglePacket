# Downstairs Strong-Radio Black Hat Reproduction

Captured 2026-08-02 hundreds of feet from the original room after switching to
a nearby room SSID. This summary omits SSID, BSSID, MAC address, client address,
and credentials.

## Connection fingerprint

- Interface: Wi-Fi (`en0`)
- Route MTU: 1500
- Wi-Fi: 802.11ax on 6 GHz channel 197, 80 MHz
- Signal/noise: -55 dBm / -92 to -93 dBm
- PHY rate: 864 Mbps before testing; 1,200 Mbps after testing
- Subnet and gateway: different from the original upstairs room
- Resolver policy: same Black Hat resolver set
- Association stayed on the same band/channel throughout the official suite

## Unloaded latency

| Target | Loss | Minimum | Average | Maximum | Stddev |
| --- | ---: | ---: | ---: | ---: | ---: |
| First-hop gateway | 0% | 3.324 ms | 4.584 ms | 6.547 ms | 0.742 ms |
| Internet control | 0% | 17.633 ms | 19.718 ms | 23.562 ms | 1.857 ms |

## Directional versus simultaneous load

| Protocol | Mode | Download | Upload | Responsiveness | Outcome |
| --- | --- | ---: | ---: | ---: | --- |
| HTTP/3 | Directional | 679.277 Mbps | 331.659 Mbps | 233 ms upload / 147 ms download | Completed |
| HTTP/3 | Simultaneous | 41.444 Mbps | 165.535 Mbps | 394 ms overall | Connection lost after 13.4 s |
| HTTP/2 | Directional | 749.620 Mbps | 617.647 Mbps | 100 ms upload / 73 ms download | Completed |
| HTTP/2 | Simultaneous | 333.810 Mbps | 394.861 Mbps | 116 ms overall | Completed |

During simultaneous load, H3 retained only 6.1% of its directional download
capacity and lost a connection. H2 retained 44.5%, stayed directionally
balanced, and completed without error. Both protocol pairs ran on the same
stable, strong 6 GHz association.

## MSS check

| Destination | Negotiated MSS |
| --- | ---: |
| Apple | 1460 |
| Cloudflare | 1400 |
| Google | 1412 |

The values remain destination-specific and do not support a blanket MSS clamp.

## Verdict

This is the cleanest reproduction so far. It removes weak RF, one physical
area, one channel, and one IP subnet as explanations. Together with the MGM
external control, it localizes the leading cause to QUIC handling or queue
policy shared across Black Hat infrastructure. Candidate inspection points are
controller WLAN policy, UDP/QUIC classification and policing, per-client queue
scheduling, WMM/TXOP behavior, firewall/flow offload, and upstream AQM/drop
counters.
