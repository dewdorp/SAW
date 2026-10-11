"""Flow table → Zeek-compatible records + forensic artifacts. Streaming with bounded memory.

Records written to <out>/<path>.log (JSON lines, `_path` field):
  conn, dns, http, ssl (Zeek field names)   files (Zeek-like, plus kind/category/entropy/masquerade)
  saw_auth (cleartext authentication: user, outcome, password *properties* only)   saw_arp (IP↔MAC pairs)
Extracted objects go to <out>/files/<sha256> (never executed); a capture summary to <out>/pcap_summary.json.

TCP is reassembled per direction (saw.integrations.pcapkit.stream); byte counts come from IP/L4 headers so
snaplen-truncated captures still report true volumes. Exact duplicate frames (SPAN double-capture) are dropped.
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import re
import struct
from collections import Counter, OrderedDict, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO

import orjson

from saw.integrations.pcapkit import auth, dnsmsg, filetype, httpmsg, tls
from saw.integrations.pcapkit.decode import (
    PROTO_ICMP,
    PROTO_ICMP6,
    PROTO_TCP,
    PROTO_UDP,
    ArpPkt,
    Pkt,
    decode,
    decode_arp,
)
from saw.integrations.pcapkit.reader import PcapError, iter_packets, new_quality
from saw.integrations.pcapkit.stream import Stream

PRODUCER = "saw-pcapkit/2.1.0"
STREAM_CAP = 8 * 1024 * 1024          # stored bytes per TCP direction
STREAM_BUDGET = 384 * 1024 * 1024     # stored bytes across all live flows (low-memory servers)
EXTRACT_BUDGET = 1024 * 1024 * 1024   # extracted object bytes per capture
EXTRACT_MAX_FILE = 64 * 1024 * 1024
TIMEOUT = {PROTO_TCP: 300.0, PROTO_UDP: 60.0}
DEFAULT_TIMEOUT = 60.0
SWEEP_EVERY = 20_000
MAX_FLOWS = 200_000
DUP_WINDOW = 0.05
DNS_PORTS = {53, 5353, 5355}
PROTO_NAME = {PROTO_TCP: "tcp", PROTO_UDP: "udp", PROTO_ICMP: "icmp", PROTO_ICMP6: "icmp"}
SYN, FIN, RST, ACK = 0x02, 0x01, 0x04, 0x10
LINE_SERVICES = {21: "ftp", 110: "pop3", 143: "imap", 25: "smtp", 587: "smtp", 2525: "smtp"}
# response content that suggests an attack request actually worked (success signals for web findings)
RESP_INDICATORS = [
    ("passwd_file", re.compile(rb"root:[^:\n]{0,20}:0:0:")),
    ("win_ini", re.compile(rb"(?i)\[(fonts|extensions|mci extensions)\]\r?\n")),
    ("sql_error", re.compile(rb"(?i)(you have an error in your sql syntax|ORA-\d{5}|SQLSTATE\[|unclosed quotation mark|"
                             rb"pg_query\(\)|SQLite3::|mysql_fetch_|ODBC SQL Server Driver)")),
    ("command_output", re.compile(rb"uid=\d+\([\w.-]+\) gid=\d+|(?i:volume serial number is)|Directory of [A-Z]:\\")),
    ("phpinfo", re.compile(rb"(?i)<title>phpinfo\(\)")),
    ("stack_trace", re.compile(rb"(java\.lang\.[A-Za-z]+Exception|Traceback \(most recent call last\)|Microsoft OLE DB)")),
]
_FTP_PASV = re.compile(r"\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)")
_FTP_EPSV = re.compile(r"\(\|\|\|(\d+)\|\)")
_FTP_PORT = re.compile(r"(?i)^PORT (\d+),(\d+),(\d+),(\d+),(\d+),(\d+)")
_FTP_EPRT = re.compile(r"(?i)^EPRT \|\d\|([^|]+)\|(\d+)\|")


def community_id(p: Pkt) -> str:
    """Community ID v1 (seed 0). ICMP uses type/code as ports (approximation of the one-way mapping)."""
    sa, da, sp, dp = p.src_raw, p.dst_raw, p.sport, p.dport
    if (sa, sp) > (da, dp):
        sa, da, sp, dp = da, sa, dp, sp
    h = hashlib.sha1(struct.pack("!H", 0) + sa + da + struct.pack("!BBHH", p.proto, 0, sp, dp), usedforsecurity=False)
    return "1:" + base64.b64encode(h.digest()).decode()


def _first_record_end(data: bytes) -> int:
    """End offset of the first TLS record (where the hello lives); at least 1 so a hole at offset 0 counts."""
    return max(1, 5 + int.from_bytes(data[3:5], "big")) if len(data) >= 5 else 1


def _is_ip(host: str | None) -> bool:
    if not host:
        return False
    h = host.rsplit(":", 1)[0] if host.count(":") == 1 else host.strip("[]")
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False


@dataclass
class Side:
    stream: Stream
    bytes: int = 0
    pkts: int = 0
    ip_bytes: int = 0
    hist: str = ""
    syn: bool = False
    synack: bool = False
    fin: bool = False
    rst: bool = False
    udp_first: bytes = b""

    def mark(self, letter: str) -> None:
        if letter not in self.hist:
            self.hist += letter


@dataclass
class Flow:
    uid: str
    proto: int
    oh: str
    op: int
    rh: str
    rp: int
    start: float
    last: float
    cid: str
    o: Side
    r: Side
    service: str | None = None
    ftp: dict | None = None  # control-channel state (FTP)

    def closed(self) -> bool:
        return self.o.rst or self.r.rst or (self.o.fin and self.r.fin)


class PcapAnalyzer:
    def __init__(self, out_dir: Path, stream_cap: int = STREAM_CAP) -> None:
        self.out_dir = out_dir
        self.files_dir = out_dir / "files"
        self.stream_cap = stream_cap
        self.flows: dict[tuple, Flow] = {}
        self.fh: dict[str, BinaryIO] = {}
        self.counts: Counter[str] = Counter()
        self.stats: Counter[str] = Counter()
        self.linktypes: Counter[int] = Counter()
        self.services: Counter[str] = Counter()
        self.talkers: Counter[str] = Counter()
        self.first_ts: float | None = None
        self.last_ts: float | None = None
        self._uid = 0
        self.dns_pending: dict[tuple, tuple[float, Flow, dnsmsg.DnsMsg]] = {}
        self.stored = 0
        self.extracted = 0
        self.extracted_hashes: set[str] = set()
        self.recent: OrderedDict[int, float] = OrderedDict()
        self.ftp_expect: dict[tuple[str, int], Flow] = {}
        self.arp: dict[tuple[str, str], dict] = {}

    # ---------------------------------------------------------------- output
    def emit(self, path: str, rec: dict[str, Any]) -> None:
        f = self.fh.get(path)
        if f is None:
            f = self.fh[path] = open(self.out_dir / f"{path}.log", "wb")  # noqa: SIM115 - closed in close()
        rec = {"_path": path, **rec, "_producer": PRODUCER}
        f.write(orjson.dumps({k: v for k, v in rec.items() if v is not None and v != []}) + b"\n")
        self.counts[path] += 1

    def _ids(self, fl: Flow) -> dict[str, Any]:
        return {"uid": fl.uid, "id.orig_h": fl.oh, "id.orig_p": fl.op, "id.resp_h": fl.rh, "id.resp_p": fl.rp,
                "proto": PROTO_NAME.get(fl.proto, str(fl.proto)), "community_id": fl.cid}

    # ---------------------------------------------------------------- packets
    def feed(self, ts: float, linktype: int, data: bytes) -> None:
        self.stats["packets"] += 1
        self.linktypes[linktype] += 1
        h = hash(data)
        prev = self.recent.get(h)
        if prev is not None and abs(ts - prev) <= DUP_WINDOW:
            self.stats["duplicates"] += 1
            return
        self.recent[h] = ts
        if len(self.recent) > 4096:
            self.recent.popitem(last=False)
        if ts:
            self.first_ts = ts if self.first_ts is None else min(self.first_ts, ts)
            self.last_ts = ts if self.last_ts is None else max(self.last_ts, ts)
        p = decode(ts, linktype, data)
        if p is None:
            a = decode_arp(ts, linktype, data)
            if a is not None:
                self.stats["decoded"] += 1
                self._arp(a)
            else:
                self.stats["undecoded"] += 1
            return
        self.stats["decoded"] += 1
        self.stats["ip_bytes"] += p.ip_len
        a, b = (p.src, p.sport), (p.dst, p.dport)
        key = (p.proto, *(a + b if a <= b else b + a))
        fl = self.flows.get(key)
        if fl is not None:
            idle = ts - fl.last
            new_syn = p.proto == PROTO_TCP and p.flags & SYN and not p.flags & ACK and fl.closed()
            if idle > TIMEOUT.get(p.proto, DEFAULT_TIMEOUT) or new_syn:
                self.finish(self.flows.pop(key))
                fl = None
        if fl is None:
            fl = self._new_flow(p)
            self.flows[key] = fl
        self._update(fl, p)
        if self.stats["packets"] % SWEEP_EVERY == 0 or len(self.flows) > MAX_FLOWS:
            self.sweep(ts)

    def _new_flow(self, p: Pkt) -> Flow:
        self._uid += 1
        o, r = (p.src, p.sport), (p.dst, p.dport)
        if p.proto == PROTO_TCP and p.flags & SYN and p.flags & ACK:
            o, r = r, o  # first packet seen is the SYN-ACK: the responder sent it
        elif p.proto == PROTO_UDP and p.sport in DNS_PORTS and p.dport not in DNS_PORTS:
            o, r = r, o
        elif p.proto == PROTO_TCP and not p.flags & SYN and p.sport < 1024 <= p.dport:
            o, r = r, o  # mid-stream: the low port is most likely the server
        uid = "C" + hashlib.sha1(f"{self._uid}:{p.ts}:{o}{r}".encode(), usedforsecurity=False).hexdigest()[:17]
        cap = self.stream_cap if p.proto == PROTO_TCP else 0
        fl = Flow(uid, p.proto, o[0], o[1], r[0], r[1], p.ts, p.ts, community_id(p), Side(Stream(cap)), Side(Stream(cap)))
        exp = self.ftp_expect.get((r[0], r[1])) or self.ftp_expect.get((o[0], o[1]))
        if p.proto == PROTO_TCP and exp is not None:
            fl.service = "ftp-data"
            fl.ftp = {"control": exp}
        return fl

    def _update(self, fl: Flow, p: Pkt) -> None:
        fl.last = max(fl.last, p.ts)
        is_orig = (p.src, p.sport) == (fl.oh, fl.op)
        s = fl.o if is_orig else fl.r
        s.pkts += 1
        s.ip_bytes += p.ip_len
        s.bytes += p.payload_len
        self.talkers[p.src] += p.ip_len
        up = str.upper if is_orig else str.lower
        if p.proto == PROTO_TCP:
            if p.flags & SYN:
                if p.flags & ACK:
                    s.synack = True
                    s.mark(up("h"))
                else:
                    s.syn = True
                    s.mark(up("s"))
                s.stream.syn(p.seq)
            if p.flags & FIN:
                s.fin = True
                s.mark(up("f"))
            if p.flags & RST:
                s.rst = True
                s.mark(up("r"))
            if p.flags & ACK and not p.flags & (SYN | FIN | RST) and not p.payload_len:
                s.mark(up("a"))
            if p.payload_len:
                s.mark(up("d"))
                before = len(s.stream.data)
                if self.stored < STREAM_BUDGET:
                    s.stream.add(p.seq, p.payload, p.ts, p.payload_len)
                else:  # memory budget reached: count only
                    s.stream.cap = len(s.stream.data)
                    s.stream.add(p.seq, p.payload, p.ts, p.payload_len)
                self.stored += len(s.stream.data) - before
        elif p.payload:
            s.mark(up("d"))
            if not s.udp_first:
                s.udp_first = p.payload[:2048]
        if fl.service is None and p.payload:
            fl.service = self._service(fl, p, is_orig)
        if fl.service == "ftp" and p.payload:
            self._ftp_control(fl)
        if p.proto == PROTO_UDP and (p.sport in DNS_PORTS or p.dport in DNS_PORTS):
            self._dns(fl, p)

    @staticmethod
    def _service(fl: Flow, p: Pkt, is_orig: bool) -> str | None:
        d = p.payload
        if p.proto == PROTO_UDP:
            return "dns" if (p.sport in DNS_PORTS or p.dport in DNS_PORTS) else None
        if p.proto != PROTO_TCP:
            return None
        if tls.looks_like_tls(d):
            return "ssl"
        if httpmsg.looks_like_http_request(d) or d.startswith(b"HTTP/1."):
            return "http"
        if d.startswith(b"SSH-"):
            return "ssh"
        if not is_orig:
            if d[:4] in (b"220 ", b"220-"):
                low = d[:200].lower()
                return "ftp" if fl.rp == 21 or b"ftp" in low else "smtp" if fl.rp in (25, 587, 2525) or b"smtp" in low or b"esmtp" in low else None
            if d.startswith(b"+OK") and fl.rp == 110:
                return "pop3"
            if d.startswith(b"* OK") and fl.rp == 143:
                return "imap"
        return LINE_SERVICES.get(fl.rp)

    # ---------------------------------------------------------------- FTP control → data channel mapping
    def _ftp_control(self, fl: Flow) -> None:
        st = fl.ftp = fl.ftp or {"cmd": None, "file": None, "buf_c": "", "buf_s": "", "transfers": []}
        for side, key in ((fl.o, "buf_c"), (fl.r, "buf_s")):
            chunk = side.stream.new_data().decode("latin-1")
            if not chunk:
                continue
            st[key] += chunk
            *lines, st[key] = st[key].split("\n")
            for line in (x.rstrip("\r") for x in lines):
                if key == "buf_c":
                    up = line.upper()
                    if up.startswith(("RETR ", "STOR ", "APPE ", "STOU")):
                        st["cmd"], st["file"] = up[:4], line[5:].strip() or None
                    m = _FTP_PORT.match(line)
                    if m:
                        n = [int(x) for x in m.groups()]
                        self.ftp_expect[(".".join(map(str, n[:4])), n[4] * 256 + n[5])] = fl
                    m = _FTP_EPRT.match(line)
                    if m:
                        self.ftp_expect[(m.group(1), int(m.group(2)))] = fl
                else:
                    m = _FTP_PASV.search(line) if line.startswith("227") else None
                    if m:
                        n = [int(x) for x in m.groups()]
                        self.ftp_expect[(".".join(map(str, n[:4])), n[4] * 256 + n[5])] = fl
                    m = _FTP_EPSV.search(line) if line.startswith("229") else None
                    if m:
                        self.ftp_expect[(fl.rh, int(m.group(1)))] = fl

    # ---------------------------------------------------------------- ARP
    def _arp(self, a: ArpPkt) -> None:
        if a.sender_ip == "0.0.0.0":
            return
        k = (a.sender_ip, a.sender_mac)
        r = self.arp.get(k)
        if r is None:
            r = self.arp[k] = {"ts": a.ts, "last_ts": a.ts, "packets": 0, "replies": 0, "gratuitous": 0}
        r["packets"] += 1
        r["last_ts"] = max(r["last_ts"], a.ts)
        r["replies"] += a.op == 2
        r["gratuitous"] += a.sender_ip == a.target_ip

    # ---------------------------------------------------------------- DNS
    def _dns(self, fl: Flow, p: Pkt) -> None:
        m = dnsmsg.parse(p.payload)
        if m is None or m.query is None:
            return
        k = (fl.uid, m.trans_id, m.query)
        if not m.is_response:
            self.dns_pending[k] = (p.ts, fl, m)
            if len(self.dns_pending) > 50_000:
                for kk in list(self.dns_pending)[:10_000]:
                    self._emit_dns(*self.dns_pending.pop(kk), None)
            return
        q = self.dns_pending.pop(k, None)
        if q is None:
            self._emit_dns(p.ts, fl, m, m)
        else:
            self._emit_dns(q[0], q[1], q[2], m, p.ts)

    def _emit_dns(self, ts: float, fl: Flow, q: dnsmsg.DnsMsg, r: dnsmsg.DnsMsg | None, rts: float | None = None) -> None:
        rec: dict[str, Any] = {"ts": ts, **self._ids(fl), "trans_id": q.trans_id, "query": q.query,
                               "qclass": q.qclass, "qtype": q.qtype,
                               "qtype_name": dnsmsg.QTYPES.get(q.qtype or 0, str(q.qtype)), "RD": q.rd}
        if r is not None:
            rec.update(rcode=r.rcode, rcode_name=dnsmsg.RCODES.get(r.rcode, str(r.rcode)), AA=r.aa, TC=r.tc, RA=r.ra,
                       answers=r.answers or None, TTLs=r.ttls or None, rejected=r.rcode == 5)
            if rts is not None:
                rec["rtt"] = round(max(0.0, rts - ts), 6)
        self.emit("dns", rec)

    # ---------------------------------------------------------------- flow completion
    def _conn_state(self, fl: Flow) -> str:
        o, r = fl.o, fl.r
        if fl.proto != PROTO_TCP:
            return "SF" if o.pkts and r.pkts else "S0" if o.pkts else "OTH"
        est = o.syn and r.synack
        if not o.syn and not r.synack:
            return "OTH"
        if not est:
            if o.syn and r.rst:
                return "REJ"
            if o.syn and o.rst:
                return "RSTOS0"
            if r.synack and r.rst:
                return "RSTRH"
            if o.syn and o.fin:
                return "SH"
            if r.synack and r.fin:
                return "SHR"
            return "S0" if o.syn else "OTH"
        if o.rst:
            return "RSTO"
        if r.rst:
            return "RSTR"
        if o.fin and r.fin:
            return "SF"
        return "S2" if o.fin else "S3" if r.fin else "S1"

    def finish(self, fl: Flow) -> None:
        for s in (fl.o, fl.r):
            s.stream.flush_gaps()
        if fl.proto == PROTO_TCP and fl.o.stream.missed + fl.r.stream.missed:
            self.stats["incomplete_flows"] += 1
        self.services[fl.service or PROTO_NAME.get(fl.proto, "other")] += 1
        self.emit("conn", {"ts": fl.start, **self._ids(fl), "service": fl.service,
                           "duration": round(fl.last - fl.start, 6), "orig_bytes": fl.o.bytes, "resp_bytes": fl.r.bytes,
                           "conn_state": self._conn_state(fl), "missed_bytes": fl.o.stream.missed + fl.r.stream.missed,
                           "history": fl.o.hist + fl.r.hist or None, "orig_pkts": fl.o.pkts,
                           "orig_ip_bytes": fl.o.ip_bytes, "resp_pkts": fl.r.pkts, "resp_ip_bytes": fl.r.ip_bytes})
        if fl.proto == PROTO_TCP:
            o = bytes(fl.o.stream.data[:65536])
            if fl.service == "ssl" or tls.looks_like_tls(o[:6]):
                self._emit_tls(fl)
            if fl.service == "http" or httpmsg.looks_like_http_request(o[:10]):
                self._emit_http(fl)
            if fl.service in ("ftp", "pop3", "imap", "smtp"):
                self._emit_line_auth(fl)
            if fl.service == "ftp-data":
                self._emit_ftp_data(fl)
        self.stored -= len(fl.o.stream.data) + len(fl.r.stream.data)
        fl.o.stream.data, fl.r.stream.data = bytearray(), bytearray()

    def _emit_tls(self, fl: Flow) -> None:
        o, r = bytes(fl.o.stream.data[:65536]), bytes(fl.r.stream.data[:65536])
        # Bytes after a hole are not where the protocol expects them: a fingerprint or certificate computed across
        # missing packets would look valid and be wrong, so nothing is derived from a part that has a hole in it.
        if fl.o.stream.has_gap_in(0, _first_record_end(o)):
            self.stats["tls_skipped_gap"] += 1
            return
        ch = tls.parse_client_hello(o)
        if ch is None:
            return
        server_gap = fl.r.stream.has_gap_in(0, 65536)
        sh = None if fl.r.stream.has_gap_in(0, _first_record_end(r)) else tls.parse_server_hello(r)
        rec: dict[str, Any] = {"ts": fl.o.stream.ts_at(0, fl.start), **self._ids(fl), "server_name": ch.sni,
                               "ja3": tls.ja3(ch), "ja4": tls.ja4(ch, "t"),
                               "client_alpn": ch.alpn or None, "established": sh is not None and fl.r.bytes > 0,
                               "capture_gap": True if server_gap or fl.o.stream.has_gap_in(0, 65536) else None}
        if sh is not None:
            rec["version"] = tls.ZEEK_VERSIONS.get(sh.version, f"0x{sh.version:04x}")
            rec["cipher"] = tls.CIPHERS.get(sh.cipher, f"0x{sh.cipher:04x}")
            rec["ja3s"] = tls.ja3s(sh)
            chain = [] if server_gap else tls.parse_certificates(r)
            if chain:
                leaf = tls.cert_info(chain[0])
                if leaf:
                    rec["cert"] = leaf
                    rec["cert_chain_len"] = len(chain)
                    if ch.sni:
                        rec["cert_name_match"] = tls.name_matches(ch.sni, leaf)
        self.emit("ssl", rec)

    def _file(self, fl: Flow, ts: float, source: str, data: bytes, filename: str | None, ctype: str | None,
              tx: str, rx: str, total: int | None, extra: dict | None = None) -> tuple[str, str] | None:
        """Hash/identify/extract one transferred object; returns (fuid, mime) or None for empty data."""
        if not data:
            return None
        md5 = hashlib.md5(data, usedforsecurity=False).hexdigest()
        sha1 = hashlib.sha1(data, usedforsecurity=False).hexdigest()
        sha256 = hashlib.sha256(data).hexdigest()
        kind, mime, cat = filetype.identify(data)
        declared = filetype.declared_category(filename, ctype)
        extracted = False
        if len(data) <= EXTRACT_MAX_FILE and (sha256 in self.extracted_hashes or self.extracted + len(data) <= EXTRACT_BUDGET):
            if sha256 not in self.extracted_hashes:
                if not self.extracted_hashes:
                    self.files_dir.mkdir(parents=True, exist_ok=True)
                (self.files_dir / sha256).write_bytes(data)
                self.extracted += len(data)
                self.extracted_hashes.add(sha256)
            extracted = True
        fuid = "F" + sha256[:17]
        self.emit("files", {"ts": ts, "fuid": fuid, "uid": fl.uid, "tx_hosts": [tx], "rx_hosts": [rx], "source": source,
                            "mime_type": mime, "kind": kind, "category": cat, "filename": filename,
                            "declared_type": (ctype or "").split(";")[0] or None, "declared_category": declared,
                            "masquerade": filetype.is_masquerade(cat, declared), "seen_bytes": len(data),
                            "total_bytes": total, "missing_bytes": max(0, (total or len(data)) - len(data)),
                            "md5": md5, "sha1": sha1, "sha256": sha256,
                            "entropy": round(filetype.entropy(data[:4 * 1024 * 1024]), 3), "extracted": extracted,
                            **(extra or {})})
        return fuid, mime

    def _emit_http(self, fl: Flow) -> None:
        o, r = bytes(fl.o.stream.data), bytes(fl.r.stream.data)
        reqs = httpmsg.requests(o)
        resps = httpmsg.responses(r, [q.method for q in reqs])
        for n, q in enumerate(reqs):
            rs = resps[n] if n < len(resps) else None
            ts = fl.o.stream.ts_at(q.offset, fl.start)
            url = q.uri[:8192]
            # From the first hole on, message boundaries and the request/response order are a guess: the request, its
            # response and the files taken from them are marked instead of being presented as complete.
            q_end = reqs[n + 1].offset if n + 1 < len(reqs) else len(o)
            rs_end = (resps[n + 1].offset if n + 1 < len(resps) else len(r)) if rs is not None else 0
            req_gap = fl.o.stream.has_gap_in(0, q_end)
            # no response found on a stream with a hole: it may be exactly what is missing
            resp_gap = fl.r.stream.has_gap_in(0, rs_end) if rs is not None else bool(fl.r.stream.gaps)
            gap = {"capture_gap": True} if req_gap or resp_gap else {}
            orig_fuids, orig_names, resp_fuids, resp_names = [], [], [], []
            for up in q.uploads:
                fu = self._file(fl, ts, "HTTP", up.data, up.filename, up.content_type, fl.oh, fl.rh, None,
                                {"http_method": q.method, "http_uri": url, "upload_field": up.field, "direction": "upload",
                                 **({"capture_gap": True} if req_gap else {})})
                if fu:
                    orig_fuids.append(fu[0])
                    orig_names.append(up.filename)
            indicators: list[str] = []
            resp_mime = None
            if rs is not None:
                head = rs.body[:131072]
                if filetype.printable_ratio(head[:4096]) > 0.7:  # success signals are textual
                    indicators = [name for name, rx in RESP_INDICATORS if rx.search(head)]
                if rs.body and q.method != "HEAD":
                    fname = rs.filename or (url.split("?")[0].rsplit("/", 1)[-1] or None)
                    fu = self._file(fl, fl.r.stream.ts_at(rs.offset, ts), "HTTP", rs.body, fname, rs.content_type,
                                    fl.rh, fl.oh, int(rs.headers.get("content-length", "0") or 0) if
                                    rs.headers.get("content-length", "").isdigit() and not rs.headers.get("content-encoding") else None,
                                    {"http_method": q.method, "http_uri": url, "referrer": q.referrer,
                                     "http_host": q.host, "decode_note": rs.decode_note or None, "direction": "download",
                                     **({"capture_gap": True} if resp_gap else {})})
                    if fu:
                        resp_fuids.append(fu[0])
                        resp_mime = fu[1]
                        resp_names.append(fname)
            preview = None
            if q.body and q.method in ("POST", "PUT", "PATCH"):
                from saw.core.security.masking import mask_text

                preview = mask_text(q.body[:1024].decode("utf-8", "replace")).text
            self.emit("http", {"ts": ts, **self._ids(fl), "trans_depth": n + 1, "method": q.method, "host": q.host,
                               "uri": url, "referrer": q.referrer, "version": q.version, "user_agent": q.user_agent,
                               "request_body_len": q.body_len, "response_body_len": len(rs.body) if rs else None,
                               "status_code": rs.status if rs else None, "status_msg": rs.msg if rs else None,
                               "resp_mime_types": [resp_mime] if resp_mime else None,
                               "content_type": rs.content_type if rs else None,
                               "location": rs.headers.get("location") if rs else None,
                               "orig_fuids": orig_fuids, "orig_filenames": [x for x in orig_names if x],
                               "resp_fuids": resp_fuids, "resp_filenames": [x for x in resp_names if x],
                               "host_is_ip": _is_ip(q.host), "request_body_preview": preview,
                               "response_indicators": indicators, "has_authorization": "authorization" in q.headers,
                               **gap})
            a = auth.http_basic(ts, q.headers.get("authorization"), rs.status if rs else None)
            a = a or auth.http_form(ts, q.method, q.headers.get("content-type"), q.body, rs.status if rs else None,
                                    rs.headers.get("location") if rs else None)
            if a is not None:
                self.emit("saw_auth", {**self._ids(fl), **a.record(), "service": "http", "http_uri": url.split("?")[0]})

    def _emit_line_auth(self, fl: Flow) -> None:
        attempts = auth.parse_line_protocol(fl.service or "", fl.o.stream.lines(fl.start), fl.r.stream.lines(fl.start))
        for a in attempts:
            self.emit("saw_auth", {**self._ids(fl), **a.record(), "service": fl.service})

    def _emit_ftp_data(self, fl: Flow) -> None:
        ctl: Flow = fl.ftp["control"] if fl.ftp else None
        st = ctl.ftp if ctl and ctl.ftp else {}
        o, r = bytes(fl.o.stream.data), bytes(fl.r.stream.data)
        data, tx, rx = (o, fl.oh, fl.rh) if len(o) >= len(r) else (r, fl.rh, fl.oh)
        cmd = st.get("cmd")
        self._file(fl, fl.start, "FTP_DATA", data, st.get("file"), None, tx, rx, None,
                   {"ftp_command": cmd, "ftp_control_uid": ctl.uid if ctl else None,
                    "direction": "upload" if cmd in ("STOR", "APPE", "STOU") else "download"})

    def sweep(self, now: float) -> None:
        stale = [k for k, f in self.flows.items()
                 if now - f.last > TIMEOUT.get(f.proto, DEFAULT_TIMEOUT) or (f.closed() and now - f.last > 5)]
        if len(self.flows) - len(stale) > MAX_FLOWS:  # flood (e.g. scan): evict the oldest half
            gone = set(stale)
            rest = sorted((k for k in self.flows if k not in gone), key=lambda k: self.flows[k].last)
            stale += rest[: len(rest) // 2]
            self.stats["evicted"] += len(rest) // 2
        for k in stale:
            fl = self.flows.pop(k, None)
            if fl is not None:
                self.finish(fl)

    def close(self, quality: dict | None = None) -> dict[str, Any]:
        # finish control channels last so FTP data flows can still see their state
        for k in sorted(self.flows, key=lambda k: self.flows[k].service == "ftp"):
            self.finish(self.flows[k])
        self.flows.clear()
        for ts, fl, q in list(self.dns_pending.values()):
            self._emit_dns(ts, fl, q, None)
        self.dns_pending.clear()
        by_ip: dict[str, set[str]] = defaultdict(set)
        for (ip, mac), r in self.arp.items():
            by_ip[ip].add(mac)
        for (ip, mac), r in sorted(self.arp.items()):
            self.emit("saw_arp", {"ts": r["ts"], "ip": ip, "mac": mac, "packets": r["packets"], "replies": r["replies"],
                                  "gratuitous": r["gratuitous"], "last_ts": r["last_ts"], "macs_for_ip": len(by_ip[ip])})
        for f in self.fh.values():
            f.close()
        summary = {"producer": PRODUCER, "packets": self.stats["packets"], "decoded": self.stats["decoded"],
                   "undecoded": self.stats["undecoded"], "duplicates": self.stats["duplicates"],
                   "evicted_flows": self.stats["evicted"], "ip_bytes": self.stats["ip_bytes"],
                   "linktypes": dict(self.linktypes), "records": dict(self.counts), "services": dict(self.services.most_common(20)),
                   "top_talkers": [{"ip": ip, "bytes": n} for ip, n in self.talkers.most_common(10)],
                   "files_extracted": len(self.extracted_hashes), "extracted_bytes": self.extracted,
                   "first_ts": self.first_ts, "last_ts": self.last_ts,
                   "incomplete_flows": self.stats["incomplete_flows"], "tls_skipped_gap": self.stats["tls_skipped_gap"],
                   "capture": {k: (quality or {}).get(k) for k in ("format", "cut_off", "damaged", "note",
                                                                    "snapped_packets", "skipped_blocks")}}
        (self.out_dir / "pcap_summary.json").write_text(json.dumps(summary), encoding="utf-8")
        return summary


def analyze_pcap(src: Path, out_dir: Path, stream_cap: int = STREAM_CAP) -> dict[str, Any]:
    """Analyze one PCAP/PCAPNG file into <out_dir> (see module doc). Returns the capture summary."""
    out_dir.mkdir(parents=True, exist_ok=True)
    a = PcapAnalyzer(out_dir, stream_cap)
    quality = new_quality()
    try:
        with open(src, "rb") as fh:
            for ts, lt, data, _orig in iter_packets(fh, quality):
                a.feed(float(ts), lt, data)
    except PcapError:
        if not quality["packets"]:  # nothing readable at all: not a capture we can say anything about
            a.close(quality)
            raise
        # damaged part-way: what was read before the damage is analysed and the summary says where reading stopped
    except BaseException:
        a.close(quality)
        raise
    return a.close(quality)
