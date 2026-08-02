# Remote-room wired control — 2026-08-02

## Result

A 1 Gbps full-duplex wired runner on a different conference-center VLAN did
not reproduce the wireless bidirectional failure. Wi-Fi interfaces were down,
the public route used the Ethernet interface, the local gateway stayed below
1 ms average during load, and the NIC added zero RX/TX errors or drops. UDP is
the strongest matched control: both directions independently and together
held the 350 Mbps target with at most 0.042% transient loss.

## Test design and endpoint admission

The runner used Ubuntu 24.04, iperf3 3.16, Ethernet MTU 1500, and explicit
source/interface binding. XMission's Salt Lake listener on port 5201 admitted
upload tests. Salt Lake ports 5202-5206 either failed admission or remained at
zero intervals until the safety timeout, and port 5200 refused the connection.
This was an endpoint-admission failure rather than a zero-throughput network
measurement. The valid matrix therefore used two official XMission services:
`speedtest.xmission.com:5201` for upload and
`iperf.soute.xmission.com:5201` for reverse download. The different public
paths are a comparison caveat, but each directional control brackets its own
simultaneous result. XMission documents its public iperf services at
<https://speedtest.xmission.com/>.

UDP used 1,472-byte datagrams at 350 Mbps per direction. TCP used four streams
paced at 87.5 Mbps each, producing a 350 Mbps aggregate target per direction.
Each transport had directional controls and two simultaneous repetitions while
200 ms gateway ping measured the first hop.

## UDP results

| Test | Upload | Download | Wired gateway latency |
| --- | --- | --- | --- |
| Directional controls | 350.0 Mbps; zero loss | 350.0 Mbps; zero loss | 0.5 ms average; 0% loss |
| Simultaneous run 1 | 349.9 Mbps; 151 lost (0.042%) | 350.0 Mbps; zero loss | 0.5 ms average; 0.6 ms maximum; 0% loss |
| Simultaneous run 2 | 350.0 Mbps; zero loss | 350.0 Mbps; 20 lost (0.006%) | 0.4 ms average; 0.6 ms maximum; 0% loss |

## TCP results

| Test | Upload | Download | Wired gateway latency |
| --- | --- | --- | --- |
| Directional controls | 350.0 Mbps; zero retransmissions | 207.2 Mbps; zero sender-reported retransmissions | 0.5 ms average; 0% loss |
| Simultaneous run 1 | 349.8 Mbps; zero retransmissions | 215.0 Mbps; zero sender-reported retransmissions | 0.9 ms average; 2.6 ms maximum; 0% loss |
| Simultaneous run 2 | 349.8 Mbps; zero retransmissions | 297.8 Mbps; 23 sender-reported retransmissions | 0.9 ms average; 2.9 ms maximum; 0% loss |

The Southern Ute TCP path did not reach the requested download target in its
directional control, so it is not a 350 Mbps TCP capacity proof. It nevertheless
did not show the wireless signature: simultaneous upload remained at target,
download did not collapse relative to its directional control, retransmissions
stayed negligible, and first-hop latency remained below 1 ms average.

## Wi-Fi comparison

The immediately preceding Wi-Fi run used the same offered rates. Its
directional UDP controls were approximately 350/348 Mbps, but simultaneous
download fell to 119.1 and 68.0 Mbps with 65.729% and 77.393% loss; gateway
latency rose to 122.1 and 204.8 ms average. The remote-room wired client instead
held 350 Mbps download with effectively zero loss and no first-hop latency
growth. This second wired location materially strengthens the finding that the
failure is not general XMission capacity or conference-wide WAN saturation. It
continues to favor the WLAN/controller path or Wi-Fi-VLAN-specific processing.

Raw JSON, timelines, stderr, and interface counters remain outside Git at
`/tmp/bhusa-wired-twohost.vFBRsY.tgz`. A copy is retained on the runner as
`~/bhusa-wired-twohost.vFBRsY.tgz`.
