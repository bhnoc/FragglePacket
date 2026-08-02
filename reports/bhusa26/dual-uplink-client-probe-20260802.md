# Dual-Uplink Client-Side Probe

Captured 2026-08-02 from the stable downstairs 6 GHz Black Hat association.
The controlled endpoint was `test.protoevidence.com:443`, running iperf3 3.21.
Client, public NAT, and mapped-port identifiers are omitted.

## Objective

Look for client-visible evidence of a bad ECMP/LAG hash bucket, unstable NAT
ownership, generic UDP policing, or a failure that requires simultaneous
bidirectional traffic. These tests cannot identify a physical 10 Gb circuit
without network-side member telemetry.

## TCP results

A two-second directional upload delivered approximately 515 Mbps with zero
retransmissions. Reverse delivered approximately 500 Mbps with one server-side
retransmission.

Ten three-second bidirectional tests using fixed source ports produced 33-307
Mbps upload and 160-576 Mbps download. Client-to-server retransmissions ranged
from 156 to 21,412; reverse-direction retransmissions were zero in every test.
Results varied by port, but did not form two consistent healthy/bad populations.

## UDP results

| Mode | Rate | Result |
| --- | ---: | --- |
| Bidirectional, 10 ports | 50 Mbps each way | Zero loss on all ports |
| Bidirectional, 10 ports | 250 Mbps each way | Nine lossless; one had 0.164% downstream loss |
| Bidirectional, 6 ports | 350 Mbps each way | Approximately zero upload loss; 8.3-30.1% downstream loss |
| Directional, 3 representative ports | 350 Mbps | Zero loss in both upload-only and download-only tests |

The 350 Mbps bidirectional downstream-loss average was approximately 20.4%.
The same rate was lossless in either direction alone. Generic UDP at 250 Mbps
each way was essentially lossless, exceeding the aggregate throughput of the
failed H3 run.

## NAT affinity

One fixed STUN socket was sampled repeatedly before and during a ten-second 350
Mbps bidirectional UDP run. Its public mapping remained unchanged. Two STUN
responses timed out while downstream UDP loss reached 12.2%, but successful
responses before and after the timeouts returned the same mapping.

Twenty additional source ports all exposed one public IPv4 address with unique
mapped ports. This does not reveal which circuit carried a flow when both
circuits share a NAT address or announced prefix, but it provides no evidence
of public-IP flapping or mid-session NAT rebinding.

## Interpretation

- A blanket low-rate UDP block or 250 Mbps policer is not present.
- A single obviously bad source-port/hash population was not observed.
- Simultaneous bidirectional load independently triggers downstream UDP loss.
- Stable STUN mapping weakens the NAT-rebinding hypothesis.
- Because all tests originated on Wi-Fi, the 350+350 Mbps threshold can still
  be influenced by WLAN airtime, WMM/TXOP, or AP queue policy.
- The H3 failure occurs at much lower aggregate throughput than the lossless
  250+250 Mbps generic UDP test, so raw capacity alone is insufficient.

## Required next controls

1. Repeat the exact fixed-port suite from a wired Black Hat client in the same
   routed policy domain.
2. Collect synchronized per-circuit utilization, queue/policer drops, interface
   errors, NAT/firewall ownership, and ECMP/LAG bucket information.
3. In an authorized window, repeat with circuit A only, circuit B only, and both
   active.
4. If possible, capture the selected flows on LAN, WAN A, and WAN B to prove
   forward/reverse member selection and locate packet loss.
