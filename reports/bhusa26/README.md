# Black Hat USA 2026 Network Investigation

Sanitized evidence and comparison reports collected while diagnosing
simultaneous HTTP/3 download collapse on the conference WLANs.

## Main finding

HTTP/3 download capacity collapsed during simultaneous upload across multiple
Black Hat WLANs and distant radios. The strongest downstairs control fell from
679 Mbps directional to 41 Mbps simultaneous while H2 remained healthy. The
same test on MGM infrastructure preserved its full directional download rate.
A matched Black Hat wired control retained 674 of 750 Mbps H3 download under
simultaneous load and did not reproduce the generic UDP loss. Corrected
internal-server testing then reproduced the distributed impairment without
Internet transit, NAT, firewall egress, or dual-WAN selection. The trigger
scales with client efficiency: many VHT probes fail around 50–100 Mbps, HE
probes show duplex-capacity pressure around 200–250 Mbps, and the newer laptop
reproduces around 350 Mbps. Native bidirectional and application tests showed
that the original paired-process harness exaggerated the directional collapse,
but real capacity plateaus, first-hop latency, and application-flow starvation
remain. Disabling Wi-Fi 7/802.11be on the controlled AP did not change the
result, ruling out Wi-Fi 7 mode as a necessary cause. The remaining fault
domain is the client-facing WLAN datapath, scheduling, airtime, aggregation,
queue behavior, shared AP firmware paths, or client-driver behavior. MSS
behavior did not support a blanket clamp.

## Committed reports

- `internal-wlan-threshold-correlation-20260802.md` — internal fleet baselines, adaptive HE knee sweep, and effective Arista radio/SSID/event correlation
- `network-performance-investigation-report-20260802.md` — executive evidence, exclusions, root-cause assessment, and decisive next test
- `COMPARISON.md` — living non-2.4 GHz result and hypothesis matrix
- `location-a-baseline-20260801.md` — room WLAN baseline
- `location-a-blackhatusa-control-20260802.md` — same-room general Black Hat WLAN control
- `location-a-mgm-external-control-20260802.md` — external-infrastructure control
- `location-b-blackhatusa-downstairs-20260802.md` — downstairs cross-AP/weak-RF baseline
- `location-c-downstairs-strong-radio-retest-20260802.md` — clean downstairs 6 GHz reproduction
- `dual-uplink-client-probe-20260802.md` — fixed-port TCP/UDP and NAT-affinity probe
- `wired-control-20260802.md` — matched wired H2/H3, UDP/TCP, and egress control
- `wifi-duplex-threshold-20260802.md` — packet-size, rate-threshold, port, flow, and DSCP characterization
- `precog-distributed-wireless-20260802.md` — distributed VHT-versus-HE wireless cohort controls
- `peer-impact-20260802.md` — coordinated UDP/TCP same-AP 1:1-versus-1:many experiment (companion TUI: [`docs/CANARY.md`](../../docs/CANARY.md))
- `wired-remote-room-control-20260802.md` — matched UDP/TCP wired control from a separate room and VLAN
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
