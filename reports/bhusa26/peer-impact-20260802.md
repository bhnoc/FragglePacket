# Coordinated same-AP peer-impact test — 2026-08-02

## Purpose and method

This test asks whether the bidirectional degradation is isolated to the client
creating load (1:1) or affects another client on the same AP/radio (1:many).
The primary Mac remained associated as 802.11ax on 6 GHz/80 MHz after Wi-Fi 7
was disabled on the AP. Every iperf3 flow and gateway ping was explicitly bound
to its Wi-Fi interface. The combined suite used independent XMission upload and
reverse-download listeners, UTC phase markers, and 350 Mbps targets in each
direction. UDP used 1,472-byte datagrams. TCP used four streams paced at 87.5
Mbps each, for a 350 Mbps aggregate target per direction. Each transport had
directional controls followed by two simultaneous upload/download repetitions.
The run lasted from 21:11:49 through 21:13:58 UTC.

## UDP results

| Test | Upload | Download | Wi-Fi gateway latency |
| --- | --- | --- | --- |
| Directional controls | 185.4 Mbps; 4,933 lost (4.158%) | 201.6 Mbps; 90,674 lost (42.517%) | 27.5 ms average; 0% ping loss |
| Simultaneous run 1 | 173.0 Mbps; 3,782 lost (2.086%) | 49.5 Mbps; 329,662 lost (85.179%) | 133.7 ms average; 571.9 ms maximum; 15.4% loss |
| Simultaneous run 2 | 184.2 Mbps; 3,687 lost (1.941%) | 46.4 Mbps; 328,243 lost (86.301%) | 144.3 ms average; 394.3 ms maximum; 23.1% loss |

## TCP results

| Test | Upload | Download | Wi-Fi gateway latency |
| --- | --- | --- | --- |
| Directional controls | 150.3 Mbps; 5,250 retransmissions | 275.8 Mbps; 0 reported retransmissions | 8.6 ms average; 0% ping loss |
| Simultaneous run 1 | 59.9 Mbps; 11,428 retransmissions | 150.7 Mbps; 604 retransmissions | 67.3 ms average; 235.2 ms maximum; 0% loss |
| Simultaneous run 2 | 96.3 Mbps; 27,087 retransmissions | 142.0 Mbps; 98 retransmissions | 77.3 ms average; 249.7 ms maximum; 0% loss |

## Assessment

The primary client's UDP directional controls had been 349.9 Mbps upload and
350.3 Mbps download with nearly zero loss immediately before the coordinated
experiment. During the coordinated window they fell to 185.4 and 201.6 Mbps,
and directional download lost 90,674 datagrams. The simultaneous phases then
reproduced severe downstream loss in both UDP and TCP. This is strong
provisional evidence of cross-client impact if the peer was actively loading
the same AP through distinct iperf3 listeners. A final 1:many verdict requires
the peer's mode, listener ports, AP association, timestamps, and output. If the
peer used the same public listeners, listener admission/contention is a
confound; if the peer was passive, the directional degradation instead records
background or transient impairment. Raw primary evidence remains local in
`/tmp/bhusa-peer-impact-load.Y2ok4k` and is not committed.

The reusable harness is
[`scripts/bhusa-peer-impact-test.zsh`](../../scripts/bhusa-peer-impact-test.zsh).
Its recommended design is one client in `MODE=load` and the peer in
`MODE=observe`, followed by a role swap. This isolates harm to the passive peer
without making both clients aggressors.

For a second load client with a live dashboard (simultaneous aggressor), see
[`scripts/canary`](../../scripts/canary) and [`docs/CANARY.md`](../../docs/CANARY.md).
