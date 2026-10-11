"""Minimal DNS message parser (RFC 1035 with name compression, loop-safe)."""
from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass, field

QTYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 35: "NAPTR",
          43: "DS", 46: "RRSIG", 48: "DNSKEY", 64: "SVCB", 65: "HTTPS", 99: "SPF", 252: "AXFR", 255: "*"}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


@dataclass
class DnsMsg:
    trans_id: int
    is_response: bool
    rcode: int
    aa: bool
    tc: bool
    rd: bool
    ra: bool
    query: str | None = None
    qtype: int | None = None
    qclass: int | None = None
    answers: list[str] = field(default_factory=list)
    ttls: list[int] = field(default_factory=list)


def _name(b: bytes, i: int) -> tuple[str, int]:
    labels, jumped, end, hops = [], False, i, 0
    while True:
        if i >= len(b) or hops > 64:
            raise ValueError("bad name")
        ln = b[i]
        if ln == 0:
            i += 1
            break
        if ln & 0xC0 == 0xC0:
            if i + 1 >= len(b):
                raise ValueError("bad pointer")
            ptr = ((ln & 0x3F) << 8) | b[i + 1]
            if not jumped:
                end = i + 2
            jumped, i, hops = True, ptr, hops + 1
            continue
        labels.append(b[i + 1:i + 1 + ln].decode("ascii", "replace"))
        i += 1 + ln
        hops += 1
    return ".".join(labels), (end if jumped else i)


def parse(b: bytes) -> DnsMsg | None:
    try:
        if len(b) < 12:
            return None
        tid, fl, qd, an = struct.unpack("!HHHH", b[:8])
        m = DnsMsg(tid, bool(fl & 0x8000), fl & 0x000F, bool(fl & 0x0400), bool(fl & 0x0200), bool(fl & 0x0100),
                   bool(fl & 0x0080))
        i = 12
        if qd:
            m.query, i = _name(b, i)
            m.qtype, m.qclass = struct.unpack("!HH", b[i:i + 4])
            i += 4
            for _ in range(qd - 1):
                _, i = _name(b, i)
                i += 4
        for _ in range(min(an, 50)):
            _, i = _name(b, i)
            rtype, _cls, ttl, rdlen = struct.unpack("!HHIH", b[i:i + 10])
            rd = b[i + 10:i + 10 + rdlen]
            i += 10 + rdlen
            if rtype == 1 and rdlen == 4:
                m.answers.append(str(ipaddress.IPv4Address(rd)))
            elif rtype == 28 and rdlen == 16:
                m.answers.append(str(ipaddress.IPv6Address(rd)))
            elif rtype in (5, 2, 12):
                m.answers.append(_name(b, i - rdlen)[0])
            elif rtype == 16 and rd:
                m.answers.append("TXT " + rd[1:1 + rd[0]].decode("latin-1")[:200])
            else:
                m.answers.append(f"<{QTYPES.get(rtype, rtype)}>")
            m.ttls.append(ttl)
        return m
    except (struct.error, ValueError, IndexError):
        return None
