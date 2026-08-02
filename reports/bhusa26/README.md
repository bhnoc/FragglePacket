# Black Hat USA 2026 Network Investigation

Sanitized evidence and comparison reports collected while diagnosing
simultaneous HTTP/3 download collapse on the conference WLANs.

## Main finding

HTTP/3 download capacity collapsed during simultaneous upload across multiple
Black Hat WLANs and distant radios. The strongest downstairs control fell from
679 Mbps directional to 41 Mbps simultaneous while H2 remained healthy. The
same test on MGM infrastructure preserved its full directional download rate.
A matched Black Hat wired control retained 674 of 750 Mbps H3 download under
simultaneous load and did not reproduce the generic UDP loss. The wired and
Wi-Fi VLANs exposed distinct public egress identities, so the remaining fault
domain is Wi-Fi/controller processing or VLAN-specific NAT/egress/circuit
selection. MSS behavior on Black Hat was destination-specific and did not
support a blanket clamp.

## Committed reports

- `COMPARISON.md` — living non-2.4 GHz result and hypothesis matrix
- `location-a-baseline-20260801.md` — room WLAN baseline
- `location-a-blackhatusa-control-20260802.md` — same-room general Black Hat WLAN control
- `location-a-mgm-external-control-20260802.md` — external-infrastructure control
- `location-b-blackhatusa-downstairs-20260802.md` — downstairs cross-AP/weak-RF baseline
- `location-c-downstairs-strong-radio-retest-20260802.md` — clean downstairs 6 GHz reproduction
- `dual-uplink-client-probe-20260802.md` — fixed-port TCP/UDP and NAT-affinity probe
- `wired-control-20260802.md` — matched wired H2/H3, UDP/TCP, and egress control
- `wifi-diagnostics-20260801-235547.txt` — sanitized RF/platform snapshot
- `tcp-traceroute-20260801-235547.txt` — TCP/443 path sample

The implementation backlog discovered during this work is maintained in
[`docs/GAP_LIST.md`](../../docs/GAP_LIST.md).

## Local capture not committed

`protocol-comparison-20260801-234815.pcap` remains in this directory locally
but is ignored by Git because it is approximately 2.0 GiB and may contain
broader packet metadata that has not been sanitized.

- Size: 2,147,943,438 bytes
- SHA-256: `f9be3154bb4300095d01bc71a7a469fd239b69ecb8b913273d77355217a8a06c`
- Duration: approximately 59.8 seconds
- Capture filter scope: TCP/443, UDP/443, and ICMP

## Privacy

Committed reports omit SSID credentials, BSSID, client MAC addresses, client
addresses, paired-device names/addresses, and AWDL hardware identifiers. Public
test endpoints and diagnostic private subnets may remain where they are
required to interpret results.
