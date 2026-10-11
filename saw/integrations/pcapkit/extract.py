"""Extract one session (IP/port pair, optional time window) from a PCAP/PCAPNG into a new classic PCAP.

Replaces `tshark -r … -w … <filter>` for hosts without Wireshark. Output keeps the original bytes and the exact
capture times: a nanosecond source gives a nanosecond pcap, anything else the classic microsecond pcap.
"""
from __future__ import annotations

import struct
from typing import BinaryIO

from saw.integrations.pcapkit.decode import decode
from saw.integrations.pcapkit.reader import NS, exact_ns, iter_packets

MAX_PACKETS = 500_000


def extract_session(src: BinaryIO, out: BinaryIO, a: tuple[str, int], b: tuple[str, int],
                    t0: float | None = None, t1: float | None = None, max_packets: int = MAX_PACKETS,
                    proto: int | None = None, info: dict | None = None) -> int:
    """`proto` (6 TCP, 17 UDP, ...) keeps other conversations on the same addresses and ports out; when it is not
    given, the protocol of the first matching packet is the session. A classic pcap has one link type, so packets of
    another link type are left out as well. What was left out is counted in `info`."""
    want = {a, b}
    n = 0
    linktype: int | None = None
    nanos = False
    left_out = info if info is not None else {}
    left_out.update(other_protocol=0, other_linktype=0)
    for ts, lt, data, orig in iter_packets(src):
        if t1 is not None and ts > t1:
            continue  # captures are not guaranteed to be time-ordered
        if t0 is not None and ts < t0:
            continue
        p = decode(float(ts), lt, data)
        if p is None or {(p.src, p.sport), (p.dst, p.dport)} != want:
            continue
        if proto is None:
            proto = p.proto
        if p.proto != proto:
            left_out["other_protocol"] += 1
            continue
        if linktype is None:
            linktype, nanos = lt, getattr(ts, "unit_ns", 1000) < 1000
            out.write(struct.pack("<IHHiIII", 0xA1B23C4D if nanos else 0xA1B2C3D4, 2, 4, 0, 0, 262144, lt))
        elif lt != linktype:
            left_out["other_linktype"] += 1
            continue
        sec, frac = divmod(exact_ns(ts), NS)  # integer arithmetic: the fraction can never round up into the next second
        out.write(struct.pack("<IIII", sec, frac if nanos else frac // 1000, len(data), orig) + data)
        n += 1
        if n >= max_packets:
            break
    if linktype is None:
        out.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
    return n


def session_streams(src: BinaryIO, a: tuple[str, int], b: tuple[str, int], t0: float | None = None,
                    t1: float | None = None, cap: int = 256 * 1024) -> dict:
    """Reassembled payload of one TCP session per direction (client = SYN sender, else first sender)."""
    from saw.integrations.pcapkit.stream import Stream

    want = {a, b}
    sides: dict[tuple[str, int], Stream] = {}
    order: list[tuple[str, int]] = []
    client = None
    packets = 0
    for ts, lt, data, _orig in iter_packets(src):
        if (t0 is not None and ts < t0) or (t1 is not None and ts > t1):
            continue
        ts = float(ts)
        p = decode(ts, lt, data)
        if p is None or {(p.src, p.sport), (p.dst, p.dport)} != want or p.proto != 6:
            continue
        packets += 1
        me = (p.src, p.sport)
        if me not in sides:
            sides[me] = Stream(cap)
            order.append(me)
        if p.flags & 0x02:
            sides[me].syn(p.seq)
            if not p.flags & 0x10:
                client = me
        if p.payload_len:
            sides[me].add(p.seq, p.payload, ts, p.payload_len)
    client = client or (order[0] if order else a)
    server = b if client == a else a
    out = {"client": f"{client[0]}:{client[1]}", "server": f"{server[0]}:{server[1]}", "packets": packets}
    for name, key in (("client_data", client), ("server_data", server)):
        st = sides.get(key)
        if st is not None:
            st.flush_gaps()
        out[name] = bytes(st.data) if st else b""
        out[name.replace("data", "missed")] = st.missed if st else 0
        out[name.replace("data", "truncated")] = st.truncated if st else 0
    return out
