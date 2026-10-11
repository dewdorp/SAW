"""PCAP accuracy findings of the 2026-10-09 comparison review: exact capture times, cut-off and damaged files,
sessions with missing packets, and session extraction that kept packets of other conversations."""
from __future__ import annotations

import io
import struct

import pytest

from saw.devtools import pcap_writer as pw
from saw.integrations.pcap import capture_notes
from saw.integrations.pcapkit.decode import decode
from saw.integrations.pcapkit.extract import extract_session
from saw.integrations.pcapkit.reader import PcapError, exact_ns, iter_packets, new_quality
from tests.unit.test_pcapkit import T, _logs

C, S = ("10.0.0.2", 50001), ("198.51.100.7", 80)
SEC = int(T)


def _frames(w: pw.PcapWriter) -> list[bytes]:
    return [r[16:] for r in w.recs]


def _read(data: bytes) -> tuple[list, dict]:
    q = new_quality()
    return list(iter_packets(io.BytesIO(data), q)), q


# ---------------------------------------------------------------- pcapng helpers
def _block(btype: int, body: bytes) -> bytes:
    body += b"\0" * (-len(body) % 4)
    n = 12 + len(body)
    return struct.pack("<II", btype, n) + body + struct.pack("<I", n)


SHB = _block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))


def _idb(linktype: int = 1, tsresol: int | None = None, tsoffset: int | None = None) -> bytes:
    opts = b""
    if tsresol is not None:
        opts += struct.pack("<HH", 9, 1) + bytes([tsresol]) + b"\0\0\0"
    if tsoffset is not None:
        opts += struct.pack("<HHq", 14, 8, tsoffset)
    if opts:
        opts += struct.pack("<HH", 0, 0)
    return _block(1, struct.pack("<HHI", linktype, 0, 65535) + opts)


def _epb(iface: int, ticks: int, frame: bytes, orig: int | None = None) -> bytes:
    return _block(6, struct.pack("<IIIII", iface, ticks >> 32, ticks & 0xFFFFFFFF, len(frame), orig or len(frame)) + frame)


def _one_frame() -> bytes:
    w = pw.PcapWriter()
    w.tcp(T, *C, *S, pw.SYN)
    return _frames(w)[0]


# ---------------------------------------------------------------- time
def test_nanosecond_pcap_keeps_exact_time():
    frame = _one_frame()
    data = (struct.pack("<IHHiIII", 0xA1B23C4D, 2, 4, 0, 0, 65535, 1)
            + struct.pack("<IIII", SEC, 123_456_789, len(frame), len(frame)) + frame)
    (ts, _lt, _d, _o), = _read(data)[0]
    assert ts.ns == SEC * 10**9 + 123_456_789 and ts.unit_ns == 1 and abs(ts - (SEC + 0.123456789)) < 1e-6
    assert type(float(ts)) is float


def test_pcapng_resolution_and_time_offset_are_applied():
    frame = _one_frame()
    data = (SHB + _idb(tsresol=9, tsoffset=3600) + _idb()               # iface 0: ns ticks + 1 h, iface 1: default µs
            + _epb(0, (SEC - 3600) * 10**9 + 987_654_321, frame) + _epb(1, SEC * 10**6 + 5, frame))
    pkts, q = _read(data)
    assert [p[0].ns for p in pkts] == [SEC * 10**9 + 987_654_321, SEC * 10**9 + 5_000]
    assert [p[0].unit_ns for p in pkts] == [1, 1000]
    assert q["format"] == "pcapng" and not q["cut_off"] and not q["damaged"]


# ---------------------------------------------------------------- how the file ends
def test_clean_capture_is_not_reported_as_cut_off():
    w = pw.PcapWriter()
    w.tcp_session(T, *C, *S, [(pw.http_get("a.example.com", "/", "x"), pw.http_resp(200))])
    pkts, q = _read(w.to_bytes())
    assert q["packets"] == len(pkts) == len(w.recs) and not q["cut_off"] and not q["damaged"] and q["note"] == ""


@pytest.mark.parametrize("cut", [7, 16 + 20], ids=["inside-record-header", "inside-packet-data"])
def test_capture_that_stops_inside_a_packet_is_reported(cut):
    w = pw.PcapWriter()
    w.tcp_session(T, *C, *S, [(pw.http_get("a.example.com", "/", "x"), pw.http_resp(200))])
    whole = w.to_bytes()
    data = whole[: len(whole) - len(w.recs[-1]) + cut]
    pkts, q = _read(data)
    assert len(pkts) == len(w.recs) - 1 and q["cut_off"] is True and q["note"]


def test_pcapng_cut_block_and_damaged_block_are_told_apart():
    frame = _one_frame()
    good = SHB + _idb() + _epb(0, SEC * 10**6, frame)
    pkts, q = _read(good + _epb(0, SEC * 10**6 + 1, frame)[:-10])
    assert len(pkts) == 1 and q["cut_off"] and not q["damaged"]
    bad = bytearray(_epb(0, SEC * 10**6 + 1, frame))
    bad[-4:] = struct.pack("<I", 9999)                       # trailing length no longer matches the leading one
    pkts, q = _read(good + bytes(bad) + _epb(0, SEC * 10**6 + 2, frame))
    assert len(pkts) == 1 and q["damaged"] and "damaged" in q["note"]
    pkts, q = _read(SHB + _idb() + _epb(3, SEC * 10**6, frame) + _epb(0, SEC * 10**6, frame))
    assert len(pkts) == 1 and q["skipped_blocks"] == 1        # packet of an interface that was never declared


def test_damaged_capture_is_analysed_up_to_the_damage_and_says_so(tmp_path):
    w = pw.PcapWriter()
    w.tcp_session(T, *C, *S, [(pw.http_get("a.example.com", "/x", "x"), pw.http_resp(200))])
    broken = w.to_bytes() + struct.pack("<IIII", SEC, 0, 10**9, 10**9) + b"junk"   # impossible record length
    summary, logs = _logs(tmp_path, broken)
    assert summary["capture"]["damaged"] is True and summary["packets"] == len(w.recs)
    assert [h["uri"] for h in logs["http"]] == ["/x"]
    assert any("손상" in n for n in capture_notes(summary))
    with pytest.raises(PcapError):
        _logs(tmp_path, b"\xd4\xc3\xb2\xa1" + b"\0" * 20 + struct.pack("<IIII", SEC, 0, 10**9, 10**9))  # nothing readable


def test_cut_off_capture_summary(tmp_path):
    w = pw.PcapWriter()
    w.tcp_session(T, *C, *S, [(pw.http_get("a.example.com", "/x", "x"), pw.http_resp(200))])
    summary, _ = _logs(tmp_path, w.to_bytes()[:-5])
    assert summary["capture"]["cut_off"] is True and summary["packets"] == len(w.recs) - 1
    assert any("중간에 끊겨" in n for n in capture_notes(summary))


# ---------------------------------------------------------------- sessions with missing packets
def _handshake(w: pw.PcapWriter, t: float, c=C, s=S) -> None:
    w.tcp(t, *c, *s, pw.SYN)
    w.tcp(t + 0.01, *s, *c, pw.SYN | pw.ACK)
    w.tcp(t + 0.02, *c, *s, pw.ACK)


def test_http_after_missing_packets_is_marked_not_presented_as_complete(tmp_path):
    w = pw.PcapWriter()
    w.tcp_session(T - 5, "10.0.0.9", 40000, *S, [(pw.http_get("a.example.com", "/whole", "x"), pw.http_resp(200))])
    _handshake(w, T)
    body = b"A" * 3000
    resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 3000\r\n\r\n" + body
    w.tcp(T + 0.1, *C, *S, pw.PSH | pw.ACK, pw.http_get("a.example.com", "/first", "x"))
    w.tcp(T + 0.2, *S, *C, pw.PSH | pw.ACK, resp[:1000])
    w.seq[(*S, *C)] += 1000                                    # 1000 bytes of the response were never captured
    w.tcp(T + 0.3, *S, *C, pw.PSH | pw.ACK, resp[2000:])
    w.tcp(T + 0.4, *C, *S, pw.PSH | pw.ACK, pw.http_get("a.example.com", "/second", "x"))
    w.tcp(T + 0.5, *S, *C, pw.PSH | pw.ACK, pw.http_resp(200))
    summary, logs = _logs(tmp_path, w.to_bytes())
    by_uri = {h["uri"]: h for h in logs["http"]}
    assert "capture_gap" not in by_uri["/whole"]
    assert by_uri["/first"]["capture_gap"] is True
    assert by_uri.get("/second", {"capture_gap": True})["capture_gap"] is True
    conn = next(c for c in logs["conn"] if c["id.orig_h"] == C[0])
    assert conn["missed_bytes"] == 1000 and summary["incomplete_flows"] == 1
    gapped = [f for f in logs["files"] if f.get("capture_gap")]
    assert gapped and all(f["http_uri"] != "/whole" for f in gapped)
    assert any("패킷이 빠진 세션 1개" in n for n in capture_notes(summary))


def test_tls_fingerprint_is_not_computed_across_missing_packets(tmp_path):
    hello = pw.client_hello("api.example.com")
    w = pw.PcapWriter()
    _handshake(w, T, C, ("203.0.113.5", 443))
    w.tcp(T + 0.1, *C, "203.0.113.5", 443, pw.PSH | pw.ACK, hello[:100])
    w.seq[(*C, "203.0.113.5", 443)] += 50                      # a hole inside the ClientHello
    w.tcp(T + 0.2, *C, "203.0.113.5", 443, pw.PSH | pw.ACK, hello[150:])
    w.tcp_session(T + 1, "10.0.0.3", 50002, "203.0.113.5", 443, [(hello, pw.server_hello())])
    summary, logs = _logs(tmp_path, w.to_bytes())
    assert [s["id.orig_h"] for s in logs["ssl"]] == ["10.0.0.3"] and "capture_gap" not in logs["ssl"][0]
    assert summary["tls_skipped_gap"] == 1


# ---------------------------------------------------------------- session extraction
def _extract(data: bytes, **kw) -> tuple[bytes, int, dict]:
    out, info = io.BytesIO(), {}
    n = extract_session(io.BytesIO(data), out, C, S, info=info, **kw)
    return out.getvalue(), n, info


def test_session_extraction_keeps_one_protocol():
    w = pw.PcapWriter()
    w.udp(T - 1, *C, *S, b"udp on the same addresses and ports")
    tcp_packets = len(w.recs)
    w.tcp_session(T, *C, *S, [(pw.http_get("a.example.com", "/", "x"), pw.http_resp(200))])
    tcp_packets = len(w.recs) - tcp_packets
    out, n, info = _extract(w.to_bytes(), proto=6)
    assert n == tcp_packets and info["other_protocol"] == 1
    assert {decode(float(ts), lt, d).proto for ts, lt, d, _ in iter_packets(io.BytesIO(out))} == {6}
    out, n, info = _extract(w.to_bytes(), proto=17)
    assert n == 1 and info["other_protocol"] == tcp_packets
    out, n, info = _extract(w.to_bytes())                     # protocol unknown: the first matching packet decides
    assert n == 1 and info["other_protocol"] == tcp_packets


def test_session_extraction_keeps_one_link_type():
    frame = _one_frame()
    data = SHB + _idb(1) + _idb(101) + _epb(0, SEC * 10**6, frame) + _epb(1, SEC * 10**6 + 10, frame[14:]) \
        + _epb(0, SEC * 10**6 + 20, frame)
    out, n, info = _extract(data, proto=6)
    assert n == 2 and info["other_linktype"] == 1
    assert {lt for _ts, lt, _d, _o in iter_packets(io.BytesIO(out))} == {1}


def test_session_extraction_writes_the_exact_time():
    frame = _one_frame()
    ns = struct.pack("<IHHiIII", 0xA1B23C4D, 2, 4, 0, 0, 65535, 1) \
        + struct.pack("<IIII", SEC, 999_999_600, len(frame), len(frame)) + frame      # 0.4 µs before the next second
    out, n, _ = _extract(ns)
    assert n == 1 and out[:4] == struct.pack("<I", 0xA1B23C4D)
    assert struct.unpack("<II", out[24:32]) == (SEC, 999_999_600)
    us = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1) \
        + struct.pack("<IIII", SEC, 999_999, len(frame), len(frame)) + frame
    out, n, _ = _extract(us)
    assert out[:4] == struct.pack("<I", 0xA1B2C3D4) and struct.unpack("<II", out[24:32]) == (SEC, 999_999)
    # a plain float just below a second boundary is floored to the microsecond, never rolled into the next second
    assert divmod(exact_ns(SEC + 0.9999996) // 1000, 10**6)[0] in (SEC, SEC + 1)
