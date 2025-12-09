# MTU Testing Methods - Complete Guide

## Overview of Testing Approaches

| Method | Protocol | Requires Root | Detects Black Hole | Per-Hop Info |
|--------|----------|---------------|-------------------|--------------|
| ICMP Ping + DF | ICMP | Yes | No | No |
| TCP MSS Probe | TCP | No | Yes | No |
| PLPMTUD | TCP/UDP | No | Yes | No |
| Tracepath | UDP | No | Partial | Yes |
| UDP Probe | UDP | Yes | Yes | No |
| QUIC Probe | UDP/QUIC | No | Yes | No |

---

## Method 1: ICMP with DF Bit (Classic PMTUD)

**How it works**: Send ICMP Echo Request with Don't Fragment flag set, binary search for max size.

**Pros**: Simple, fast, universally supported
**Cons**: Requires root, fails if ICMP blocked, only tests ICMP path

**Implementation**:
```
1. Set DF bit on IP header (IP_MTU_DISCOVER = IP_PMTUDISC_DO)
2. Send ICMP Echo Request at size N
3. If reply received: try larger
4. If EMSGSIZE or timeout: try smaller
5. Binary search to find exact MTU
```

**Linux setsockopt**:
```c
int val = IP_PMTUDISC_DO;
setsockopt(sock, IPPROTO_IP, IP_MTU_DISCOVER, &val, sizeof(val));
```

---

## Method 2: TCP Connection Probe

**How it works**: Establish TCP connection, attempt data transfer of various sizes.

**Pros**: No root required, tests real TCP path, detects PMTUD black holes
**Cons**: Requires open port, slower than ICMP

**Implementation**:
```
1. TCP connect to target:port
2. Send HTTP request or data of size N
3. Wait for response with timeout
4. If response: size works
5. If timeout/RST: size too large
6. Binary search
```

**Detecting Black Holes**:
- If connect() works (small SYN/ACK)
- But send() of large data times out
- = PMTUD black hole

---

## Method 3: TCP MSS Analysis

**How it works**: Capture/analyze TCP SYN packets to see announced MSS.

**Pros**: Passive, shows what endpoints actually use
**Cons**: Only shows negotiated MSS, not actual path

**What MSS tells you**:
- MSS 1460 = MTU 1500 (standard)
- MSS 1380-1400 = Tunnel/VPN overhead
- MSS 1220 = Conservative (often PPPoE + tunnel)

**Capture command**:
```bash
tcpdump -i any 'tcp[tcpflags] & (tcp-syn) != 0' -vv
```

---

## Method 4: Tracepath (Per-Hop MTU)

**How it works**: UDP-based traceroute that discovers MTU at each hop.

**Pros**: Shows per-hop MTU, no root needed
**Cons**: Linux only, UDP may be blocked

**Output**:
```
 1:  gateway                               0.5ms pmtu 1500
 2:  isp-router                            5.2ms pmtu 1500
 3:  some-router                          12.3ms pmtu 1400  <- MTU drops here
 4:  destination                          25.1ms reached
```

---

## Method 5: UDP Probing (DPLPMTUD)

**How it works**: Send UDP packets of various sizes, check for delivery via application-layer ACK.

**Pros**: Tests UDP path (important for VoIP, gaming, VPN)
**Cons**: Requires application support, more complex

**RFC 8899 State Machine**:
```
DISABLED -> BASE (1200) -> SEARCHING -> SEARCH_COMPLETE
                ^                            |
                |                            v
                +----------- ERROR <---------+
```

**Probe Packets**:
- Option A: Pad existing datagrams
- Option B: Send dedicated probe packets with sequence numbers

---

## Method 6: QUIC Path MTU Discovery

**How it works**: QUIC has built-in PMTUD using PING frames in padded packets.

**How QUIC does it**:
1. Start at 1200 bytes (minimum)
2. Send PING frame + PADDING to probe size
3. Wait for ACK
4. If ACK: increase probe size
5. If timeout: current size is max

**Advantages**:
- Built into protocol
- Works through NAT
- No ICMP dependency

---

## Method 7: HTTP/HTTPS Large Object Fetch

**How it works**: Download known large object, detect stalls.

**Implementation**:
```
1. HTTP GET large file (>100KB)
2. Set aggressive timeout
3. If completes: path MTU OK
4. If stalls after headers: PMTUD black hole
```

**Good test URLs**:
- speed.cloudflare.com/__down?bytes=100000
- github.com/large-file
- Any CDN test file

---

## Method 8: DNS EDNS0 Probing

**How it works**: Use DNS with EDNS0 buffer size to test UDP MTU.

**EDNS0 Buffer Size**:
- Advertises max UDP response size
- Default: 4096 bytes
- If truncated: indicates MTU issue

**Test**:
```bash
dig +bufsize=1472 @8.8.8.8 google.com
```

---

## Method 9: GRE/Tunnel Encapsulation Test

**How it works**: Create tunnel to known endpoint, test MTU through tunnel.

**Why important**: Reveals inner MTU after encapsulation overhead.

---

## Method 10: Fragmentation Detection

**How it works**: Send large packets WITHOUT DF bit, detect if fragmented.

**Implementation**:
```
1. Send ICMP/UDP at 2000 bytes (no DF)
2. Capture on remote end
3. Count fragments received
4. If fragments > 1: path fragments at some MTU
```

**Detecting fragmentation at firewall**:
- High fragment count = MTU issue
- Fragment reassembly timeouts = fragment drop

---

## Combined Testing Strategy

### Phase 1: Baseline Discovery
1. ICMP probe to find ICMP path MTU
2. tracepath to identify per-hop MTU
3. Note any discrepancies

### Phase 2: Protocol-Specific Testing
4. TCP connect + data transfer
5. UDP probe (if applicable)
6. Compare TCP vs ICMP results

### Phase 3: Application Layer Verification
7. HTTPS fetch test
8. DNS large response test
9. Confirm real-world behavior matches

### Phase 4: Analysis
10. If ICMP > TCP: PMTUD black hole
11. If per-hop shows drop: identify device
12. Calculate VPN overhead impact

---

## Enterprise Testing Checklist

- [ ] Test from multiple source locations
- [ ] Test to multiple destination types (cloud, on-prem, SaaS)
- [ ] Test all protocols in use (ICMP, TCP, UDP)
- [ ] Test with and without VPN
- [ ] Test jumbo frame paths (data center)
- [ ] Document all intermediate device MTU settings
- [ ] Verify ICMP Type 3 Code 4 not blocked
- [ ] Check TCP MSS clamping configuration
- [ ] Test during peak and off-peak hours
- [ ] Validate VoIP/RTP path (UDP-specific)


