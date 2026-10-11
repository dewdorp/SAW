"""Link / network / transport decoding. Returns None for anything not decodable (never raises on packet bytes)."""
from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass

ETH_IPV4, ETH_IPV6, ETH_VLAN, ETH_QINQ, ETH_MPLS, ETH_ARP = 0x0800, 0x86DD, 0x8100, 0x88A8, 0x8847, 0x0806
PROTO_ICMP, PROTO_TCP, PROTO_UDP, PROTO_ICMP6 = 1, 6, 17, 58
IPV6_EXT = {0, 43, 44, 60, 51}  # hop-by-hop, routing, fragment, dest-opts, AH


@dataclass(slots=True)
class Pkt:
    ts: float
    src: str
    dst: str
    proto: int
    sport: int
    dport: int
    ip_len: int          # bytes on the wire at IP layer (from header, survives snaplen truncation)
    payload_len: int     # L4 payload bytes per headers
    payload: bytes       # captured L4 payload (may be shorter than payload_len)
    flags: int = 0       # TCP flags
    seq: int = 0
    ack: int = 0
    src_raw: bytes = b""
    dst_raw: bytes = b""


@dataclass(slots=True)
class ArpPkt:
    ts: float
    op: int          # 1 request, 2 reply
    sender_mac: str
    sender_ip: str
    target_mac: str
    target_ip: str
    eth_src: str


def _mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def decode_arp(ts: float, linktype: int, data: bytes) -> ArpPkt | None:
    """Ethernet ARP (IPv4 over Ethernet) only."""
    try:
        if linktype != 1 or len(data) < 42:
            return None
        et, off = struct.unpack("!H", data[12:14])[0], 14
        if et in (ETH_VLAN, ETH_QINQ):
            et, off = struct.unpack("!H", data[16:18])[0], 18
        if et != ETH_ARP:
            return None
        a = data[off:off + 28]
        htype, ptype, hlen, plen, op = struct.unpack("!HHBBH", a[:8])
        if htype != 1 or ptype != 0x0800 or hlen != 6 or plen != 4:
            return None
        return ArpPkt(ts, op, _mac(a[8:14]), str(ipaddress.IPv4Address(a[14:18])), _mac(a[18:24]),
                      str(ipaddress.IPv4Address(a[24:28])), _mac(data[6:12]))
    except (struct.error, ValueError, IndexError):
        return None


def _l3_from_link(linktype: int, d: bytes) -> tuple[int, bytes] | None:
    """→ (ethertype, l3 bytes)."""
    if linktype == 1:  # Ethernet
        if len(d) < 14:
            return None
        et, off = struct.unpack("!H", d[12:14])[0], 14
        for _ in range(3):  # VLAN / QinQ stacking
            if et in (ETH_VLAN, ETH_QINQ) and len(d) >= off + 4:
                et, off = struct.unpack("!H", d[off + 2:off + 4])[0], off + 4
        if et == ETH_MPLS:
            while len(d) >= off + 4:
                bos = d[off + 2] & 0x01
                off += 4
                if bos:
                    break
            et = ETH_IPV4 if len(d) > off and d[off] >> 4 == 4 else ETH_IPV6
        return et, d[off:]
    if linktype in (101, 12, 14):  # raw IP
        if not d:
            return None
        return (ETH_IPV4 if d[0] >> 4 == 4 else ETH_IPV6), d
    if linktype == 228:
        return ETH_IPV4, d
    if linktype == 229:
        return ETH_IPV6, d
    if linktype == 113:  # Linux cooked SLL
        return (struct.unpack("!H", d[14:16])[0], d[16:]) if len(d) >= 16 else None
    if linktype == 276:  # SLL2
        return (struct.unpack("!H", d[0:2])[0], d[20:]) if len(d) >= 20 else None
    if linktype in (0, 108):  # BSD loopback / OpenBSD loop
        if len(d) < 4:
            return None
        fam = struct.unpack("<I" if linktype == 0 else "!I", d[:4])[0]
        if fam == 2:
            return ETH_IPV4, d[4:]
        if fam in (24, 28, 30):
            return ETH_IPV6, d[4:]
        return None
    return None


def decode(ts: float, linktype: int, data: bytes) -> Pkt | None:
    try:
        l3 = _l3_from_link(linktype, data)
        if l3 is None:
            return None
        et, d = l3
        if et == ETH_IPV4:
            if len(d) < 20 or d[0] >> 4 != 4:
                return None
            ihl = (d[0] & 0x0F) * 4
            total = struct.unpack("!H", d[2:4])[0]
            frag = struct.unpack("!H", d[6:8])[0]
            if ihl < 20 or total < ihl:
                return None
            if frag & 0x1FFF:  # non-first fragment: no L4 header
                return None
            proto, sraw, draw = d[9], d[12:16], d[16:20]
            src, dst = str(ipaddress.IPv4Address(sraw)), str(ipaddress.IPv4Address(draw))
            l4, l4_len, ip_len = d[ihl:total], total - ihl, total
        elif et == ETH_IPV6:
            if len(d) < 40 or d[0] >> 4 != 6:
                return None
            plen, nh = struct.unpack("!H", d[4:6])[0], d[6]
            sraw, draw = d[8:24], d[24:40]
            src, dst = str(ipaddress.IPv6Address(sraw)), str(ipaddress.IPv6Address(draw))
            off, ip_len = 40, 40 + plen
            for _ in range(8):
                if nh not in IPV6_EXT or len(d) < off + 8:
                    break
                if nh == 44 and struct.unpack("!H", d[off + 2:off + 4])[0] & 0xFFF8:
                    return None  # non-first fragment
                hlen = (d[off + 1] + 2) * 4 if nh == 51 else 8 if nh == 44 else (d[off + 1] + 1) * 8
                nh, off = d[off], off + hlen
            proto, l4, l4_len = nh, d[off:40 + plen], 40 + plen - off
        else:
            return None
        if proto == PROTO_TCP:
            if len(l4) < 20:
                return None
            sport, dport, seq, ack = struct.unpack("!HHII", l4[:12])
            doff = (l4[12] >> 4) * 4
            if doff < 20:
                return None
            return Pkt(ts, src, dst, proto, sport, dport, ip_len, max(0, l4_len - doff), l4[doff:], l4[13], seq, ack,
                       sraw, draw)
        if proto == PROTO_UDP:
            if len(l4) < 8:
                return None
            sport, dport, ulen = struct.unpack("!HHH", l4[:6])
            return Pkt(ts, src, dst, proto, sport, dport, ip_len, max(0, (ulen or l4_len) - 8), l4[8:], 0, 0, 0, sraw, draw)
        if proto in (PROTO_ICMP, PROTO_ICMP6):
            if len(l4) < 4:
                return None
            return Pkt(ts, src, dst, proto, l4[0], l4[1], ip_len, max(0, l4_len - 8), l4[8:], 0, 0, 0, sraw, draw)
        return Pkt(ts, src, dst, proto, 0, 0, ip_len, l4_len, b"", 0, 0, 0, sraw, draw)
    except (struct.error, ValueError, IndexError):
        return None
