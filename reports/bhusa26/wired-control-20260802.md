# Matched wired Black Hat control — 2026-08-02

## Purpose

Repeat the strongest Wi-Fi failure tests from a Black Hat wired drop to
separate RF/controller behavior from shared upstream and dual-uplink behavior.
The iperf3 endpoint was `test.protoevidence.com:443`. Client, gateway, public
NAT, and hardware addresses are intentionally omitted.

## Path validation

- The default route and test-server route used a 1 Gbps full-duplex Ethernet
  interface with MTU 1500.
- The wired drop used a separate Black Hat VLAN from the Wi-Fi test VLAN.
- Gateway latency averaged 1.20 ms and Internet latency averaged 15.98 ms, both
  with zero packet loss.
- Wi-Fi remained associated, but it was not the selected route for these tests.

## HTTP controls

| Protocol | Mode | Download | Upload | Loaded latency | Result |
| --- | --- | ---: | ---: | ---: | --- |
| H3 | Directional | 749.97 Mbps | 886.54 Mbps | Per-direction only | Completed |
| H3 | Simultaneous | 674.18 Mbps | 880.17 Mbps | 56.98 ms overall | Completed; high responsiveness |
| H2 | Directional | 889.64 Mbps | 902.40 Mbps | Per-direction only | Completed |
| H2 | Simultaneous | 850.28 Mbps | 852.74 Mbps | 12.63 ms overall | Completed; high responsiveness |

Wired H3 retained 89.9% of its directional download capacity during
simultaneous load. The matched strong-radio Wi-Fi test retained only 6.1% and
lost a connection.

## Fixed-port iperf3 controls

Six fixed source-port buckets were tested bidirectionally.

| Transport | Offered load | Upload result | Download result |
| --- | --- | --- | --- |
| UDP | 350 Mbps each way | Five ports had 0% loss; one had 0.045% | All six ports had 0% loss |
| TCP | Unlimited | 940-947 Mbps; 0-22 local-sender retransmissions | 809-837 Mbps; remote sender reported 6,290-7,563 retransmissions |

The Wi-Fi UDP control lost 8.3-30.1% downstream on every one of the same six
port buckets, despite essentially zero upstream loss. The wired test removed
that failure signature.

The high remote TCP retransmission counter did not cause throughput collapse.
Raw retransmission counts are sensitive to duration, sender reporting, and
near-line-rate queue behavior, so FragglePacket should record normalized rates
and interface-counter deltas for each phase before treating them as directly
comparable.

## Interface counter check

The Ethernet interface accumulated receive-drop counters during the complete
near-gigabit suite. A separately bracketed 350 Mbps-each-way UDP run added no
interface drops and reported zero transport loss in both directions. This
means the cumulative counter cannot be assigned to the UDP phase; future runs
must snapshot and delta counters around every load phase.

## Client-visible egress affinity

Twenty wired STUN source ports all used one stable public IPv4 identity. It was
different from the single stable identity observed across twenty Wi-Fi source
ports. No actual public address is retained in this report.

This prevents the clean wired run from fully ruling out the dual uplinks: the
wired and Wi-Fi VLANs may select different NAT nodes, egress policies, or
provider circuits.

## Conclusion

The simultaneous H3 and generic UDP downstream-loss signature is absent on the
wired Black Hat path. The remaining fault domain is:

1. WLAN/controller or Wi-Fi-VLAN-specific processing; or
2. VLAN-specific firewall/NAT ownership, egress selection, or provider circuit.

The most discriminating next test is a controlled egress swap: force the Wi-Fi
VLAN through wired egress identity B and the wired VLAN through Wi-Fi egress
identity A. If failure follows identity A, inspect that NAT/firewall/circuit
path. If it remains attached to Wi-Fi regardless of egress, inspect the WLAN
and controller path. If each circuit is healthy alone but dual-active fails,
inspect ECMP hashing, symmetry, and state synchronization.
