"""Built-in PCAP analyzer (ADR-0016): fingerprints, flow states, protocols, formats and hostile input."""
from __future__ import annotations

import io
import random
import struct

import orjson
import pytest

from saw.devtools import pcap_writer as pw
from saw.integrations.pcapkit import analyze_pcap, tls
from saw.integrations.pcapkit.extract import extract_session
from saw.integrations.pcapkit.reader import PcapError, iter_packets

T = 1_760_000_000.0


def _logs(tmp_path, data: bytes) -> tuple[dict, dict[str, list[dict]]]:
    src = tmp_path / "c.pcap"
    src.write_bytes(data)
    summary = analyze_pcap(src, tmp_path / "out")
    logs = {f.stem: [orjson.loads(x) for x in f.read_bytes().splitlines()] for f in (tmp_path / "out").glob("*.log")}
    return summary, logs


def test_ja4_matches_foxio_spec_vector():
    """Chrome ClientHello from the JA4 spec → t13d1516h2_8daaf6152771_e5627efa2ab1 (GREASE ignored)."""
    ch = tls.parse_client_hello(pw.client_hello("example.com"))
    assert ch.sni == "example.com" and ch.alpn == ["h2"]
    assert tls.ja4(ch) == "t13d1516h2_8daaf6152771_e5627efa2ab1"
    no_sni = tls.parse_client_hello(pw.client_hello(None, alpn=None))
    assert tls.ja4(no_sni).startswith("t13i151400_")  # SNI/ALPN absent: 'i', 14 extensions, '00'
    assert len(tls.ja3(ch)) == 32


def test_flows_states_and_protocols(tmp_path):
    w = pw.PcapWriter()
    w.tcp_session(T, "10.0.0.1", 50000, "203.0.113.5", 443, [(pw.client_hello("api.example.com"), pw.server_hello())])
    w.tcp_session(T + 1, "10.0.0.2", 50001, "198.51.100.7", 80,
                  [(pw.http_get("svc.example.com", "/a?id=1", "python-httpx/0.27"), pw.http_resp(200)),
                   (pw.http_get("svc.example.com", "/a?id=2", "python-httpx/0.27"), pw.http_resp(404))])
    w.udp(T + 2, "10.0.0.3", 53001, "10.0.0.53", 53, pw.dns_query(7, "x1.example.org", 16))
    w.udp(T + 2.01, "10.0.0.53", 53, "10.0.0.3", 53001, pw.dns_response(7, "x1.example.org", None, 3, 16))
    w.tcp(T + 3, "10.0.0.9", 45000, "10.0.0.10", 22, pw.SYN)
    w.tcp(T + 3.001, "10.0.0.10", 22, "10.0.0.9", 45000, pw.RST | pw.ACK)
    w.tcp(T + 4, "10.0.0.9", 45001, "10.0.0.10", 23, pw.SYN)
    w.bulk(T + 5, "10.0.0.1", 55000, "185.220.100.5", 443, 50 * 1024 * 1024, dur=10)  # mid-stream, truncated frames
    summary, logs = _logs(tmp_path, w.to_bytes())
    assert summary["undecoded"] == 0 and summary["records"] == {"conn": 6, "ssl": 1, "http": 2, "dns": 1, "files": 2}
    conn = {c["id.resp_h"]: c for c in logs["conn"]}
    assert conn["203.0.113.5"]["service"] == "ssl" and conn["198.51.100.7"]["service"] == "http"
    states = sorted(c["conn_state"] for c in logs["conn"])
    assert states == ["OTH", "REJ", "S0", "SF", "SF", "SF"]
    bulk = next(c for c in logs["conn"] if c["id.resp_h"] == "185.220.100.5")
    assert bulk["orig_bytes"] >= 50 * 1024 * 1024 - 1448  # true volume from IP headers despite 64-byte capture
    s = logs["ssl"][0]
    assert s["server_name"] == "api.example.com" and s["version"] == "TLSv13" and s["established"] is True
    assert s["ja4"] == "t13d1516h2_8daaf6152771_e5627efa2ab1" and s["uid"] == conn["203.0.113.5"]["uid"]
    h = logs["http"]
    assert [x["status_code"] for x in h] == [200, 404] and h[1]["trans_depth"] == 2 and h[0]["ts"] < h[1]["ts"]
    d = logs["dns"][0]
    assert d["query"] == "x1.example.org" and d["qtype_name"] == "TXT" and d["rcode_name"] == "NXDOMAIN" and d["rtt"] > 0
    assert all(r["community_id"].startswith("1:") for r in logs["conn"])


def _pcapng(packets: list[tuple[float, bytes]]) -> bytes:
    def block(btype: int, body: bytes) -> bytes:
        body += b"\0" * (-len(body) % 4)
        n = len(body) + 12
        return struct.pack("<II", btype, n) + body + struct.pack("<I", n)
    out = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    opt = struct.pack("<HHB", 9, 1, 9) + b"\0\0\0" + struct.pack("<HH", 0, 0)  # if_tsresol = 10^-9
    out += block(1, struct.pack("<HHI", 1, 0, 65535) + opt)
    for ts, frame in packets:
        t = int(ts * 1e9)
        out += block(6, struct.pack("<IIIII", 0, t >> 32, t & 0xFFFFFFFF, len(frame), len(frame)) + frame)
    return out


def test_pcapng_and_nanosecond_resolution(tmp_path):
    w = pw.PcapWriter()
    w.tcp_session(T + 0.123456789, "10.0.0.1", 50000, "203.0.113.5", 443, [(pw.client_hello("ng.example.com"), pw.server_hello())])
    frames = []
    classic = io.BytesIO(w.to_bytes())
    for ts, _lt, data, _orig in iter_packets(classic):
        frames.append((ts, data))
    _, logs = _logs(tmp_path, _pcapng(frames))
    assert logs["ssl"][0]["server_name"] == "ng.example.com"
    assert abs(logs["conn"][0]["ts"] - (T + 0.123457)) < 1e-5


def test_hostile_and_truncated_input(tmp_path):
    with pytest.raises(PcapError):
        analyze_pcap(_write(tmp_path / "x.pcap", b"MZ\x90\x00" + b"\0" * 100), tmp_path / "o1")
    w = pw.PcapWriter()
    w.tcp_session(T, "10.0.0.1", 50000, "203.0.113.5", 80, [(pw.http_get("a", "/", "ua"), pw.http_resp())])
    data = w.to_bytes()
    s = analyze_pcap(_write(tmp_path / "t.pcap", data[:-7]), tmp_path / "o2")  # cut mid-record
    assert s["packets"] >= 7
    rnd = random.Random(1)
    garbage = data[:24] + b"".join(struct.pack("<IIII", 1, 0, 60, 60) + bytes(rnd.getrandbits(8) for _ in range(60))
                                   for _ in range(300))
    s = analyze_pcap(_write(tmp_path / "g.pcap", garbage), tmp_path / "o3")  # random frames: decode or skip, never crash
    assert s["packets"] == 300
    with pytest.raises(PcapError):
        analyze_pcap(_write(tmp_path / "big.pcap", data[:24] + struct.pack("<IIII", 1, 0, 10**9, 10**9)), tmp_path / "o4")


def _write(p, b: bytes):
    p.write_bytes(b)
    return p


def test_extract_session(tmp_path):
    w = pw.PcapWriter()
    w.tcp_session(T, "10.0.0.1", 50000, "203.0.113.5", 443, [(pw.client_hello("a.example"), pw.server_hello())])
    w.tcp_session(T + 1, "10.0.0.2", 50001, "203.0.113.6", 443, [(pw.client_hello("b.example"), pw.server_hello())])
    out = io.BytesIO()
    n = extract_session(io.BytesIO(w.to_bytes()), out, ("203.0.113.5", 443), ("10.0.0.1", 50000))
    assert n == 8
    out.seek(0)
    pkts = list(iter_packets(out))
    assert len(pkts) == 8 and pkts[0][1] == 1
