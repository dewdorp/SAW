"""Synthetic PCAP builder for tests and demo samples (Ethernet/IPv4/TCP/UDP, TLS ClientHello, DNS). Data is fake.

`snap` truncates stored bytes while IP/L4 headers keep the real lengths — lets a small file represent large transfers.
"""
from __future__ import annotations

import ipaddress
import struct
from pathlib import Path

SYN, FIN, RST, PSH, ACK = 0x02, 0x01, 0x04, 0x08, 0x10
CHROME_CIPHERS = [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC013, 0xC014, 0x009C,
                  0x009D, 0x002F, 0x0035]
CHROME_EXTS = [0x0000, 0x0017, 0xFF01, 0x000A, 0x000B, 0x0023, 0x0010, 0x0005, 0x000D, 0x0012, 0x0033, 0x002D, 0x002B,
               0x001B, 0x0015, 0x4469]
CHROME_SIGALGS = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]


def _csum(b: bytes) -> int:
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack(f"!{len(b) // 2}H", b))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


class PcapWriter:
    def __init__(self, snap: int = 65535) -> None:
        self.snap = snap
        self.recs: list[bytes] = []
        self.seq: dict[tuple, int] = {}

    def _frame(self, ts: float, src: str, dst: str, proto: int, l4: bytes, l4_wire_len: int) -> None:
        total = 20 + l4_wire_len
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0x4000, 64, proto, 0,
                         ipaddress.IPv4Address(src).packed, ipaddress.IPv4Address(dst).packed)
        ip = ip[:10] + struct.pack("!H", _csum(ip)) + ip[12:]
        eth = b"\x02\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x02\x08\x00"
        frame = eth + ip + l4
        orig_len = 14 + total
        stored = frame[:self.snap]
        sec = int(ts)
        self.recs.append(struct.pack("<IIII", sec, int(round((ts - sec) * 1e6)), len(stored), orig_len) + stored)

    def tcp(self, ts: float, src: str, sp: int, dst: str, dp: int, flags: int, payload: bytes = b"",
            wire_len: int | None = None) -> None:
        k = (src, sp, dst, dp)
        seq = self.seq.get(k, 1000)
        ack = self.seq.get((dst, dp, src, sp), 0)
        n = wire_len if wire_len is not None else len(payload)
        hdr = struct.pack("!HHIIBBHHH", sp, dp, seq, ack if flags & ACK else 0, 5 << 4, flags, 65535, 0, 0)
        self._frame(ts, src, dst, 6, hdr + payload, 20 + n)
        self.seq[k] = seq + n + (1 if flags & (SYN | FIN) else 0)

    def tcp_at(self, ts: float, src: str, sp: int, dst: str, dp: int, flags: int, payload: bytes, seq: int) -> None:
        """TCP segment with an explicit sequence number (out-of-order / retransmission tests)."""
        hdr = struct.pack("!HHIIBBHHH", sp, dp, seq, self.seq.get((dst, dp, src, sp), 0), 5 << 4, flags, 65535, 0, 0)
        self._frame(ts, src, dst, 6, hdr + payload, 20 + len(payload))

    def arp(self, ts: float, op: int, smac: str, sip: str, tmac: str, tip: str) -> None:
        def mac(m: str) -> bytes:
            return bytes(int(x, 16) for x in m.split(":"))

        body = (struct.pack("!HHBBH", 1, 0x0800, 6, 4, op) + mac(smac) + ipaddress.IPv4Address(sip).packed
                + mac(tmac) + ipaddress.IPv4Address(tip).packed)
        frame = (b"\xff" * 6 if op == 1 else mac(tmac)) + mac(smac) + b"\x08\x06" + body + b"\x00" * 18
        sec = int(ts)
        self.recs.append(struct.pack("<IIII", sec, int(round((ts - sec) * 1e6)), len(frame), len(frame)) + frame)

    def duplicate_last(self, n: int = 1) -> None:
        """SPAN-style double capture of the previous frame (same bytes, same time)."""
        self.recs.extend([self.recs[-1]] * n)

    def udp(self, ts: float, src: str, sp: int, dst: str, dp: int, payload: bytes) -> None:
        self._frame(ts, src, dst, 17, struct.pack("!HHHH", sp, dp, 8 + len(payload), 0) + payload, 8 + len(payload))

    # ---- sessions
    def tcp_session(self, ts: float, c: str, cp: int, s: str, sp: int, exchanges: list[tuple[bytes, bytes]],
                    close: str = "fin", rtt: float = 0.01) -> float:
        self.tcp(ts, c, cp, s, sp, SYN)
        self.tcp(ts + rtt, s, sp, c, cp, SYN | ACK)
        self.tcp(ts + 2 * rtt, c, cp, s, sp, ACK)
        t = ts + 3 * rtt
        for req, resp in exchanges:
            if req:
                self.tcp(t, c, cp, s, sp, PSH | ACK, req)
                t += rtt
            if resp:
                self.tcp(t, s, sp, c, cp, PSH | ACK, resp)
                t += rtt
        if close == "fin":
            self.tcp(t, c, cp, s, sp, FIN | ACK)
            self.tcp(t + rtt, s, sp, c, cp, FIN | ACK)
            self.tcp(t + 2 * rtt, c, cp, s, sp, ACK)
            t += 2 * rtt
        elif close == "none":
            pass
        elif close == "rst":
            self.tcp(t, c, cp, s, sp, RST | ACK)
        return t

    def bulk(self, ts: float, src: str, sp: int, dst: str, dp: int, total: int, seg: int = 1448, dur: float = 1.0) -> None:
        """Data volume using truncated frames (headers only stored when snap is small)."""
        n = max(1, total // seg)
        for i in range(n):
            self.tcp(ts + dur * i / n, src, sp, dst, dp, PSH | ACK, b"\0" * min(seg, 64), wire_len=seg)

    def to_bytes(self) -> bytes:
        return struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1) + b"".join(self.recs)

    def save(self, path: Path) -> None:
        path.write_bytes(self.to_bytes())


# ---- payload builders
def client_hello(sni: str | None, alpn: str | None = "h2", ciphers=None, exts=None, sigalgs=None,
                 grease: bool = True) -> bytes:
    ciphers = list(CHROME_CIPHERS if ciphers is None else ciphers)
    exts = list(CHROME_EXTS if exts is None else exts)
    sigalgs = CHROME_SIGALGS if sigalgs is None else sigalgs
    if grease:
        ciphers = [0x0A0A] + ciphers
    ext_bytes = b""
    order = ([0x1A1A] if grease else []) + exts
    for e in order:
        if e == 0x0000:
            if not sni:
                continue
            n = sni.encode()
            d = struct.pack("!HBH", len(n) + 3, 0, len(n)) + n
        elif e == 0x0010:
            if not alpn:
                continue
            a = struct.pack("B", len(alpn)) + alpn.encode()
            d = struct.pack("!H", len(a)) + a
        elif e == 0x000D:
            d = struct.pack("!H", 2 * len(sigalgs)) + b"".join(struct.pack("!H", s) for s in sigalgs)
        elif e == 0x002B:
            d = struct.pack("B", 6) + struct.pack("!HHH", 0x2A2A, 0x0304, 0x0303)
        elif e == 0x000A:
            d = struct.pack("!HHHH", 6, 0x001D, 0x0017, 0x0018)
        elif e == 0x000B:
            d = b"\x01\x00"
        else:
            d = b""
        ext_bytes += struct.pack("!HH", e, len(d)) + d
    body = (struct.pack("!H", 0x0303) + b"\x11" * 32 + b"\x00" + struct.pack("!H", 2 * len(ciphers))
            + b"".join(struct.pack("!H", c) for c in ciphers) + b"\x01\x00" + struct.pack("!H", len(ext_bytes)) + ext_bytes)
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def server_hello(cipher: int = 0x1301, tls13: bool = True) -> bytes:
    ext = struct.pack("!HHH", 0x002B, 2, 0x0304) if tls13 else b""
    body = struct.pack("!H", 0x0303) + b"\x22" * 32 + b"\x00" + struct.pack("!HB", cipher, 0) + struct.pack("!H", len(ext)) + ext
    hs = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + struct.pack("!H", len(hs)) + hs + b"\x17\x03\x03\x00\x10" + b"\x00" * 16


def server_flight_tls12(chain: list[bytes], cipher: int = 0xC02F) -> bytes:
    """TLS 1.2 ServerHello + Certificate + ServerHelloDone (certificates travel in clear before 1.3)."""
    ext = struct.pack("!HHB", 0xFF01, 1, 0)  # renegotiation_info
    sh = struct.pack("!H", 0x0303) + b"\x33" * 32 + b"\x00" + struct.pack("!HB", cipher, 0) + struct.pack("!H", len(ext)) + ext
    certs = b"".join(len(c).to_bytes(3, "big") + c for c in chain)
    cert_body = len(certs).to_bytes(3, "big") + certs
    hs = (b"\x02" + len(sh).to_bytes(3, "big") + sh + b"\x0b" + len(cert_body).to_bytes(3, "big") + cert_body
          + b"\x0e\x00\x00\x00")
    out = b""
    for i in range(0, len(hs), 16384):  # records carry at most 2^14 bytes
        part = hs[i:i + 16384]
        out += b"\x16\x03\x03" + struct.pack("!H", len(part)) + part
    return out


def dns_query(tid: int, name: str, qtype: int = 1) -> bytes:
    q = b"".join(struct.pack("B", len(p)) + p.encode() for p in name.split(".")) + b"\0"
    return struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0) + q + struct.pack("!HH", qtype, 1)


def dns_response(tid: int, name: str, ip: str | None, rcode: int = 0, qtype: int = 1) -> bytes:
    q = b"".join(struct.pack("B", len(p)) + p.encode() for p in name.split(".")) + b"\0"
    an = b""
    if ip and rcode == 0:
        an = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + ipaddress.IPv4Address(ip).packed
    return struct.pack("!HHHHHH", tid, 0x8180 | rcode, 1, 1 if an else 0, 0, 0) + q + struct.pack("!HH", qtype, 1) + an


def http_get(host: str, uri: str, ua: str) -> bytes:
    return f"GET {uri} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {ua}\r\nAccept: */*\r\n\r\n".encode()


def http_resp(status: int = 200, body: bytes = b"{}", ctype: str = "application/json") -> bytes:
    return (f"HTTP/1.1 {status} OK\r\nContent-Type: {ctype}\r\nContent-Length: {len(body)}\r\n\r\n").encode() + body
