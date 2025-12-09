# MTU-Related RFCs - Complete Reference

## Core MTU Standards

### RFC 791 - Internet Protocol (1981)
- Defines IP header and fragmentation
- **MTU**: Maximum Transmission Unit - largest datagram a network can transmit
- **DF Flag**: Don't Fragment bit (bit 1 of Flags field)
- **MF Flag**: More Fragments bit (bit 2 of Flags field)
- **Fragment Offset**: 13-bit field for reassembly
- Minimum MTU: 68 bytes (all hosts must accept)
- Recommended minimum: 576 bytes

### RFC 1191 - Path MTU Discovery (1990)
- **PMTUD**: Original Path MTU Discovery mechanism
- Uses ICMP Type 3 Code 4 "Fragmentation Needed and DF Set"
- Process:
  1. Send packet with DF bit set
  2. If too large, router returns ICMP error with next-hop MTU
  3. Sender reduces packet size and retries
- **Problem**: Fails if ICMP is blocked (PMTUD Black Hole)

### RFC 1981 - Path MTU Discovery for IPv6 (1996)
- IPv6 version of PMTUD
- Uses ICMPv6 Type 2 "Packet Too Big"
- IPv6 minimum MTU: 1280 bytes
- Fragmentation only at source (not routers)

### RFC 4821 - Packetization Layer PMTUD (2007)
- **PLPMTUD**: Works without ICMP
- Uses transport layer (TCP/SCTP) acknowledgments
- Sends probe packets of various sizes
- If ACK received = size works, if not = too large
- Solves PMTUD black hole problem

### RFC 8899 - Datagram PLPMTUD (2020)
- **DPLPMTUD**: Extends PLPMTUD to UDP, SCTP, QUIC
- For connectionless protocols
- Probe packet methods:
  - Padding probes (add padding to datagrams)
  - Dedicated probe packets
- State machine: DISABLED -> BASE -> SEARCHING -> SEARCH_COMPLETE -> ERROR
- BASE_PMTU: 1200 bytes (safe starting point)
- MAX_PROBES: 3 (default probe attempts)
- PROBE_TIMER: 15 seconds

## TCP-Specific

### RFC 879 - TCP Maximum Segment Size (1983)
- **MSS**: Maximum Segment Size option
- MSS = MTU - IP header (20) - TCP header (20)
- Default MSS: 536 bytes (assumes 576 MTU)
- Announced in SYN/SYN-ACK packets

### RFC 6691 - TCP MSS and Options (2012)
- Clarifies MSS calculation
- MSS should exclude IP and TCP options
- MSS = MTU - 40 (basic headers)
- With options: MSS = MTU - 60 (typical)

### RFC 2675 - IPv6 Jumbograms (1999)
- Jumbo Payload option for IPv6
- Packets larger than 65,535 bytes
- MTU up to 4,294,967,295 bytes

## ICMP Messages

### ICMP Type 3 (Destination Unreachable)
| Code | Meaning | MTU Related |
|------|---------|-------------|
| 0 | Network Unreachable | No |
| 1 | Host Unreachable | No |
| 2 | Protocol Unreachable | No |
| 3 | Port Unreachable | No |
| 4 | **Fragmentation Needed + DF Set** | YES - Contains Next-Hop MTU |
| 5 | Source Route Failed | No |

### ICMP Type 3 Code 4 Format
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |     Code      |          Checksum             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           unused              |         Next-Hop MTU          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Internet Header + 64 bits of Original Datagram          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

## Tunnel Protocols

### RFC 2784 - GRE (Generic Routing Encapsulation)
- Header: 4 bytes minimum, up to 16 bytes with options
- Overhead: 24 bytes (IP + GRE) minimum

### RFC 4301/4303 - IPsec ESP
- ESP Header: 8+ bytes
- ESP Trailer: 2+ bytes (padding + pad length + next header)
- ESP Auth: 12 bytes (typical ICV)
- Overhead: 50-80 bytes depending on cipher

### RFC 7348 - VXLAN
- UDP encapsulation
- Overhead: 50 bytes (outer IP 20 + UDP 8 + VXLAN 8 + Ethernet 14)

### RFC 8926 - Geneve
- Similar to VXLAN with extensions
- Overhead: 50+ bytes

## Common MTU Values

| Environment | MTU | Notes |
|-------------|-----|-------|
| Ethernet | 1500 | IEEE 802.3 standard |
| Jumbo Frames | 9000 | Data center standard |
| PPPoE | 1492 | 1500 - 8 byte PPPoE header |
| IPv6 minimum | 1280 | Mandated by RFC 8200 |
| IPv4 minimum | 68 | But 576 recommended |
| GRE tunnel | 1476 | 1500 - 24 |
| IPsec (AES-GCM) | 1420-1440 | Varies by mode |
| WireGuard | 1420 | Recommended default |
| VXLAN | 1450 | 1500 - 50 |

## PMTUD Black Hole

**Cause**: ICMP Type 3 Code 4 messages blocked by firewall

**Symptoms**:
- Small packets work (ping OK)
- TCP connection established (SYN/ACK small)
- Large data transfer hangs
- TLS handshake may fail

**Detection**:
- ICMP MTU discovery works
- TCP MSS shows different (lower) value
- Actual data transfer fails

**Solutions**:
1. Allow ICMP Type 3 Code 4 through firewalls
2. Use TCP MSS Clamping
3. Reduce interface MTU
4. Use PLPMTUD (RFC 4821)


