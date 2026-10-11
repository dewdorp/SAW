"""Streaming PCAP / PCAPNG reader (libpcap classic µs/ns, pcapng SHB/IDB/EPB/SPB/OPB). Yields (ts, linktype, data, orig_len).

`ts` is a float for arithmetic, and carries the exact capture time as integer nanoseconds in `ts.ns` (a float cannot
hold nanoseconds of a present-day epoch). Pass a dict as `quality` to learn how the file ended and what was skipped:
a capture that stops in the middle of a record is still read up to that point, but it is reported, not assumed whole.
"""
from __future__ import annotations

import struct
from collections.abc import Iterator
from fractions import Fraction
from typing import BinaryIO

PCAP_MAGICS = {b"\xd4\xc3\xb2\xa1": ("<", 1000), b"\xa1\xb2\xc3\xd4": (">", 1000),
               b"\x4d\x3c\xb2\xa1": ("<", 1), b"\xa1\xb2\x3c\x4d": (">", 1)}  # ns per timestamp unit
PCAPNG_SHB = b"\x0a\x0d\x0d\x0a"
MAX_BLOCK = 256 * 1024 * 1024  # a single block/packet larger than this is treated as corruption
MAX_SNAP = 262_144
NS = 1_000_000_000


class PcapError(ValueError):
    pass


class Ts(float):
    """Capture time in seconds, with the exact value in nanoseconds (`ns`) and the source resolution (`unit_ns`)."""
    __slots__ = ("ns", "unit_ns")

    def __new__(cls, ns: int, unit_ns: int = 1000) -> Ts:
        self = super().__new__(cls, ns / NS)
        self.ns = ns
        self.unit_ns = unit_ns
        return self


def exact_ns(ts: float) -> int:
    """Nanoseconds of a timestamp: exact for reader timestamps, rounded to µs for plain floats."""
    ns = getattr(ts, "ns", None)
    return ns if ns is not None else round(ts * 1_000_000) * 1000


def new_quality() -> dict:
    return {"format": None, "packets": 0, "snapped_packets": 0, "skipped_blocks": 0, "cut_off": False, "damaged": False,
            "note": ""}


def sniff_format(head: bytes) -> str | None:
    if head[:4] in PCAP_MAGICS:
        return "pcap"
    if head[:4] == PCAPNG_SHB:
        return "pcapng"
    return None


class _CutOff(Exception):
    """End of file inside a record (`got` bytes of it were there)."""

    def __init__(self, got: int) -> None:
        self.got = got


def _read(fh: BinaryIO, n: int) -> bytes:
    b = fh.read(n)
    if len(b) < n:
        raise _CutOff(len(b))
    return b


def _iter_pcap(fh: BinaryIO, q: dict) -> Iterator[tuple[float, int, bytes, int]]:
    try:
        hdr = _read(fh, 24)
    except _CutOff:
        raise PcapError("file ends inside the pcap header") from None
    endian, unit = PCAP_MAGICS[hdr[:4]]
    linktype = struct.unpack(endian + "I", hdr[20:24])[0] & 0x0FFFFFFF
    rec = struct.Struct(endian + "IIII")
    while True:
        try:
            head = _read(fh, 16)
        except _CutOff as e:
            if e.got:  # a clean end has no bytes left; anything else is a record that was never finished
                q["cut_off"], q["note"] = True, "file ends inside a packet header"
            return
        sec, frac, incl, orig = rec.unpack(head)
        if incl > MAX_SNAP:
            q["damaged"], q["note"] = True, f"packet record claims {incl} bytes (limit {MAX_SNAP}): reading stopped here"
            raise PcapError(f"record length {incl} exceeds snaplen limit")
        try:
            data = _read(fh, incl)
        except _CutOff:
            q["cut_off"], q["note"] = True, "last packet is incomplete (capture stopped or file was cut while being written)"
            return
        q["packets"] += 1
        if incl < orig:
            q["snapped_packets"] += 1
        yield Ts(sec * NS + frac * unit, unit), linktype, data, orig


def _unit(resol: int) -> tuple[int, int]:
    """Nanoseconds per timestamp unit as (numerator, denominator) for an if_tsresol value (power of 10, or of 2 when
    the top bit is set). Integers, so that the conversion is exact."""
    f = Fraction(NS, 2 ** (resol & 0x7F)) if resol & 0x80 else Fraction(NS, 10 ** resol)
    return f.numerator, f.denominator


def _iter_pcapng(fh: BinaryIO, q: dict) -> Iterator[tuple[float, int, bytes, int]]:
    endian = "<"
    ifaces: list[tuple[int, int, int, int]] = []  # (linktype, ns per unit as num/den, offset in ns)

    def stop(note: str, damaged: bool = False) -> None:
        q["damaged" if damaged else "cut_off"], q["note"] = True, note

    while True:
        try:
            head = _read(fh, 8)
        except _CutOff as e:
            if e.got:
                stop("file ends inside a block header")
            return
        if head[:4] == PCAPNG_SHB:
            try:
                bom = _read(fh, 4)
            except _CutOff:
                return stop("file ends inside a section header")
            endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">" if bom == b"\x1a\x2b\x3c\x4d" else None
            if endian is None:
                q["damaged"], q["note"] = True, "bad byte-order mark in a section header"
                raise PcapError("bad pcapng byte-order magic")
            blen = struct.unpack(endian + "I", head[4:8])[0]
            if not 28 <= blen <= MAX_BLOCK:
                q["damaged"], q["note"] = True, "bad section header length"
                raise PcapError("bad section header length")
            try:
                _read(fh, blen - 12)
            except _CutOff:
                return stop("file ends inside a section header")
            ifaces = []
            continue
        btype, blen = struct.unpack(endian + "II", head)
        if blen < 12 or blen > MAX_BLOCK or blen % 4:
            q["damaged"], q["note"] = True, f"block with impossible length {blen}: reading stopped here"
            raise PcapError(f"bad pcapng block length {blen}")
        try:
            body = _read(fh, blen - 12)
            tail = _read(fh, 4)
        except _CutOff:
            return stop("last block is incomplete (capture stopped or file was cut while being written)")
        if struct.unpack(endian + "I", tail)[0] != blen:  # every block repeats its length at the end
            return stop("block length fields disagree (file is damaged): reading stopped here", damaged=True)
        if btype == 1:  # Interface Description Block
            if len(body) < 8:
                q["skipped_blocks"] += 1
                continue
            linktype = struct.unpack(endian + "H", body[:2])[0]
            (num, den), offset = (1000, 1), 0
            opts = body[8:]
            i = 0
            while i + 4 <= len(opts):
                code, olen = struct.unpack(endian + "HH", opts[i:i + 4])
                if code == 0:
                    break
                val = opts[i + 4:i + 4 + olen]
                if code == 9 and val:  # if_tsresol
                    num, den = _unit(val[0])
                elif code == 14 and len(val) == 8:  # if_tsoffset: seconds to add to every timestamp of the interface
                    offset = struct.unpack(endian + "q", val)[0] * NS
                i += 4 + olen + (-olen % 4)
            ifaces.append((linktype, num, den, offset))
        elif btype in (6, 2):  # Enhanced Packet Block / obsolete Packet Block
            if len(body) < 20:
                q["skipped_blocks"] += 1
                continue
            if btype == 6:
                iid, th, tl, cap, orig = struct.unpack(endian + "IIIII", body[:20])
            else:
                iid, _drops, th, tl, cap, orig = struct.unpack(endian + "HHIIII", body[:20])
            if iid >= len(ifaces) or cap > len(body) - 20:
                q["skipped_blocks"] += 1  # packet of an undeclared interface / longer than its block
                continue
            lt, num, den, offset = ifaces[iid]
            q["packets"] += 1
            if cap < orig:
                q["snapped_packets"] += 1
            yield Ts(((th << 32) | tl) * num // den + offset, max(1, num // den)), lt, body[20:20 + cap], orig
        elif btype == 3:  # Simple Packet Block (no timestamp)
            if len(body) < 4 or not ifaces:
                q["skipped_blocks"] += 1
                continue
            orig = struct.unpack(endian + "I", body[:4])[0]
            q["packets"] += 1
            yield Ts(0), ifaces[0][0], body[4:4 + min(orig, len(body) - 4)], orig


def iter_packets(fh: BinaryIO, quality: dict | None = None) -> Iterator[tuple[float, int, bytes, int]]:
    q = quality if quality is not None else new_quality()
    for k, v in new_quality().items():
        q.setdefault(k, v)
    head = fh.read(4)
    fh.seek(-len(head), 1)
    fmt = sniff_format(head)
    q["format"] = fmt
    if fmt == "pcap":
        yield from _iter_pcap(fh, q)
    elif fmt == "pcapng":
        yield from _iter_pcapng(fh, q)
    else:
        raise PcapError("not a pcap/pcapng file")
