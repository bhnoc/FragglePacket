# Tunnel & Encapsulation Overhead Reference

## Quick Reference Table

| Protocol | Overhead (bytes) | Inner MTU @1500 | Notes |
|----------|-----------------|-----------------|-------|
| **VPN Protocols** |
| WireGuard | 60 | 1440 | UDP + WG header |
| OpenVPN (UDP) | 69 | 1431 | UDP + OpenVPN + overhead |
| OpenVPN (TCP) | 89 | 1411 | TCP + OpenVPN (avoid!) |
| IPsec ESP (AES-GCM) | 62 | 1438 | ESP + IV + ICV |
| IPsec ESP (AES-CBC) | 81 | 1419 | ESP + IV + padding + ICV |
| IPsec + NAT-T | 70 | 1430 | Add UDP encap |
| IKEv2/IPsec | 80 | 1420 | Typical deployment |
| L2TP/IPsec | 76 | 1424 | L2TP + ESP |
| PPTP | 48 | 1452 | GRE + PPP (insecure!) |
| SSTP | 70 | 1430 | SSL + PPP |
| **Zero Trust / SASE** |
| Zscaler ZIA/ZPA | 80-100 | 1400-1420 | Varies by config |
| Netskope | 80-90 | 1410-1420 | SASE overhead |
| Cloudflare WARP | 60 | 1440 | WireGuard-based |
| Palo Alto GlobalProtect | 76 | 1424 | IPsec-based |
| Cisco AnyConnect | 80 | 1420 | DTLS/TLS |
| FortiClient | 76 | 1424 | IPsec/SSL |
| Prisma Access | 80 | 1420 | GlobalProtect |
| **Overlay Networks** |
| GRE | 24 | 1476 | Basic GRE |
| GRE + IPsec | 104 | 1396 | Encrypted GRE |
| VXLAN | 50 | 1450 | UDP + VXLAN + inner Eth |
| Geneve | 50 | 1450 | Similar to VXLAN |
| NVGRE | 42 | 1458 | GRE variant |
| STT | 58 | 1442 | TCP-like encap |
| **Other** |
| PPPoE | 8 | 1492 | DSL common |
| PPPoA | 10 | 1490 | ATM variant |
| MPLS (1 label) | 4 | 1496 | Per label |
| MPLS (2 labels) | 8 | 1492 | Common |
| 802.1Q VLAN | 4 | 1496 | VLAN tag |
| QinQ | 8 | 1492 | Double VLAN |

---

## Detailed Breakdown

### WireGuard (60 bytes)
```
Outer IP Header:     20 bytes
UDP Header:           8 bytes
WireGuard Header:    32 bytes
------------------------
Total:               60 bytes
Inner MTU:         1440 bytes (at 1500 outer)
```

### OpenVPN UDP (69 bytes)
```
Outer IP Header:     20 bytes
UDP Header:           8 bytes
OpenVPN Header:       1 byte (opcode)
Packet ID:            4 bytes
HMAC (SHA1):         20 bytes
IV (AES-CBC):        16 bytes
------------------------
Total:               69 bytes
Inner MTU:         1431 bytes
```

### OpenVPN TCP (89 bytes)
```
Outer IP Header:     20 bytes
TCP Header:          20 bytes
OpenVPN Header:       1 byte
Packet ID:            4 bytes
HMAC (SHA1):         20 bytes
IV (AES-CBC):        16 bytes
Length prefix:        2 bytes
TCP options:          6 bytes (typical)
------------------------
Total:               89 bytes
Inner MTU:         1411 bytes

WARNING: TCP-over-TCP causes "TCP meltdown"
         - Double retransmission
         - Poor performance under loss
         - Avoid if possible
```

### IPsec ESP with AES-GCM (62 bytes)
```
Outer IP Header:     20 bytes
ESP Header:           8 bytes (SPI + Seq)
IV (GCM):             8 bytes
ESP Trailer:          2 bytes (pad len + next hdr)
Padding:              0-15 bytes (block align)
ICV (Auth Tag):      16 bytes
NAT-T (if used):      8 bytes (UDP encap)
------------------------
Without NAT-T:       54-69 bytes
With NAT-T:          62-77 bytes
Inner MTU:         1423-1438 bytes
```

### VXLAN (50 bytes)
```
Outer Ethernet:      14 bytes (if L2)
Outer IP Header:     20 bytes
UDP Header:           8 bytes
VXLAN Header:         8 bytes
------------------------
L3 overhead:         36 bytes
Full L2 overhead:    50 bytes
Inner MTU:         1450 bytes (L3)
```

---

## Nested Tunnel Overhead

Common scenarios:

### VPN through Corporate Proxy
```
Base MTU:          1500
Corporate proxy:    -50  (typical)
VPN on top:         -60  (WireGuard)
------------------------
Inner MTU:         1390
```

### Zscaler + Internal VPN
```
Base MTU:          1500
Zscaler ZPA:       -100
Internal IPsec:     -80
------------------------
Inner MTU:         1320
Recommended:       1300
```

### Cloud-to-Cloud (AWS to Azure)
```
Base MTU:          1500
VPN Gateway:        -80
Cross-cloud link:   -20  (overhead varies)
------------------------
Inner MTU:         1400
```

---

## Safe MTU Recommendations

| Scenario | Recommended MTU | TCP MSS |
|----------|-----------------|---------|
| Direct Internet | 1500 | 1460 |
| Single VPN tunnel | 1400 | 1360 |
| SASE/Zero Trust | 1380 | 1340 |
| Nested tunnels | 1300 | 1260 |
| Maximum compatibility | 1280 | 1240 |
| IPv6 minimum | 1280 | 1220 |

---

## Detection Methods

### Identifying Current Overhead
```bash
# On Linux, check interface MTU
ip link show

# Check routing table PMTU
ip route get 8.8.8.8

# Check IPsec SA
ip xfrm state

# Check WireGuard
wg show
```

### Calculating from captures
```
Overhead = Outer_packet_size - Inner_packet_size
```

### When MTU is wrong
Symptoms:
- Ping works, web doesn't
- SSH connects, SCP hangs
- VPN works, apps don't
- Video calls pixelate/freeze
- Initial page loads, then stalls

---

## MSS Clamping Reference

### Formula
```
MSS = MTU - 40 (IPv4)
MSS = MTU - 60 (IPv6)
```

### Common Clamp Values
| Target MTU | IPv4 MSS | IPv6 MSS |
|------------|----------|----------|
| 1500 | 1460 | 1440 |
| 1400 | 1360 | 1340 |
| 1300 | 1260 | 1240 |
| 1280 | 1240 | 1220 |

### Firewall Configuration Examples

**iptables**:
```bash
iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN \
  -j TCPMSS --set-mss 1360
```

**pf (BSD)**:
```
scrub on egress max-mss 1360
```

**Cisco IOS**:
```
interface GigabitEthernet0/0
  ip tcp adjust-mss 1360
```

**Palo Alto**:
```
set network interface ethernet1/1 mtu 1400
set network tcp-mss adjust enable
```


