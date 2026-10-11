"""Zeek (JSON / TSV) and Suricata eve.json parsers → CES network data sources (docs/20 §2, docs/06 §3).

Byte direction for flows: bytes_out = sent by the originator (src), bytes_in = received by the originator.
"""
from __future__ import annotations

from typing import Any

import orjson

from saw.parsers.base import BaseParser, Failed, Parsed, ParseResult, Skip

CONN_KEYS = {"conn_state", "orig_bytes", "resp_bytes", "history"}
DNS_KEYS = {"query", "qtype_name", "rcode_name", "trans_id"}
SSL_KEYS = {"server_name", "cipher", "established", "version"}
HTTP_KEYS = {"method", "host", "uri", "status_code", "trans_depth"}
FILES_KEYS = {"fuid", "mime_type", "seen_bytes"}


def _num(v: Any) -> Any:
    if v in (None, "-", "(empty)"):
        return None
    return v


def zeek_record(d: dict[str, Any], path: str | None = None) -> tuple[str, dict, dict] | None:
    keys = set(d)
    kind = path or d.get("_path")
    if not kind:
        if CONN_KEYS & keys and "id.orig_h" in keys:
            kind = "conn"
        elif DNS_KEYS & keys and "query" in keys:
            kind = "dns"
        elif SSL_KEYS & keys and "id.orig_h" in keys:
            kind = "ssl"
        elif HTTP_KEYS & keys and "trans_depth" in keys:
            kind = "http"
        elif FILES_KEYS & keys:
            kind = "files"
        elif "id.orig_h" in keys:
            kind = "other"
        else:
            return None
    f: dict[str, Any] = {"timestamp_raw": str(d.get("ts")) if d.get("ts") is not None else None,
                         "src_ip": _num(d.get("id.orig_h")), "src_port": _num(d.get("id.orig_p")),
                         "dst_ip": _num(d.get("id.resp_h")), "dst_port": _num(d.get("id.resp_p")),
                         "protocol": _num(d.get("proto")), "session_id": _num(d.get("uid"))}
    if d.get("community_id"):
        f["community_id"] = d["community_id"]
    ext = {k: v for k, v in d.items() if not k.startswith("id.") and k not in ("ts", "uid", "proto", "community_id")}
    if kind == "conn":
        f["bytes_out"], f["bytes_in"] = _num(d.get("orig_bytes")), _num(d.get("resp_bytes"))
        if d.get("service"):
            f["protocol"] = d["service"]
        ds, et = "zeek_conn", "conn"
    elif kind == "dns":
        f["domain"] = _num(d.get("query"))
        ds, et = "zeek_dns", "dns_query"
    elif kind == "ssl":
        f["domain"] = _num(d.get("server_name"))
        f["ja3"], f["ja4"] = _num(d.get("ja3")), _num(d.get("ja4"))
        if d.get("ja3s"):
            f["ja3s"] = d["ja3s"]
        cert = d.get("cert") if isinstance(d.get("cert"), dict) else None
        if cert:  # top-level copies for search, IOC matching and grouping; details stay in ext.zeek.cert
            f["cert_sha1"], f["cert_sha256"] = cert.get("sha1"), cert.get("sha256")
            f["cert_subject_cn"], f["cert_issuer_cn"] = cert.get("subject_cn"), cert.get("issuer_cn")
        ds, et = "zeek_ssl", "tls_handshake"
    elif kind == "http":
        f.update(method=_num(d.get("method")), hostname=_num(d.get("host")), uri=_num(d.get("uri")),
                 status_code=_num(d.get("status_code")), user_agent=_num(d.get("user_agent")),
                 bytes_out=_num(d.get("request_body_len")), bytes_in=_num(d.get("response_body_len")))
        if d.get("host_is_ip") and d.get("host"):
            f["hostname"] = d["host"]
        ds, et = "zeek_http", "http_request"
    elif kind == "saw_auth":  # SAW PCAP analyzer: cleartext authentication (password properties only)
        f.update(user=_num(d.get("user")), outcome=_num(d.get("outcome")), protocol=_num(d.get("protocol")))
        ds, et = "pcap_auth", "auth_attempt"
    elif kind == "saw_arp":  # SAW PCAP analyzer: observed IP↔MAC binding
        f["src_ip"] = _num(d.get("ip"))
        ds, et = "pcap_arp", "arp_binding"
    elif kind == "files":
        f["hash"] = _num(d.get("sha256") or d.get("sha1") or d.get("md5"))
        if isinstance(d.get("tx_hosts"), list) and d["tx_hosts"]:
            f["src_ip"] = d["tx_hosts"][0]
        if isinstance(d.get("rx_hosts"), list) and d["rx_hosts"]:
            f["dst_ip"] = d["rx_hosts"][0]
        ds, et = "zeek_files", "file"
    else:
        ds, et = f"zeek_{kind}", kind
    f["data_source"], f["event_type"] = ds, et
    return ds, {k: v for k, v in f.items() if v is not None}, ext


class ZeekJsonParser(BaseParser):
    id, product, data_source, event_type = "zeek_json", "zeek", "zeek_conn", "conn"

    def detect(self, sample: list[str]) -> float:
        lines = [s for s in sample if s.strip()]
        if not lines:
            return 0.0
        hits = sum(1 for s in lines if '"id.orig_h"' in s or ('"_path"' in s and '"ts"' in s))
        return 0.99 * (sum(1 for s in lines if isinstance(self.parse_line(s), Parsed)) / len(lines)) if hits >= len(lines) / 2 else 0.0

    def parse_line(self, line: str) -> ParseResult:
        s = line.strip()
        if not s.startswith("{"):
            return Failed("not JSON")
        try:
            d = orjson.loads(s)
        except orjson.JSONDecodeError:
            return Failed("invalid JSON")
        r = zeek_record(d) if isinstance(d, dict) else None
        if r is None:
            return Failed("not a Zeek record")
        _, f, ext = r
        return Parsed(f, ext)


class ZeekTsvParser(BaseParser):
    id, product, data_source, event_type = "zeek_tsv", "zeek", "zeek_conn", "conn"
    stateful = True

    def __init__(self) -> None:
        self.fields: list[str] = []
        self.path: str | None = None
        self.sep = "\t"

    def reset(self) -> None:
        self.fields, self.path, self.sep = [], None, "\t"

    def detect(self, sample: list[str]) -> float:
        self.reset()
        if not any(s.startswith("#fields") for s in sample):
            return 0.0
        lines = [s for s in sample if s.strip()]
        ok = sum(1 for s in lines if isinstance(self.parse_line(s), (Parsed, Skip)))
        self.reset()
        return 0.99 * ok / max(1, len(lines))

    def parse_line(self, line: str) -> ParseResult:
        s = line.rstrip("\r\n")
        if s.startswith("#"):
            if s.startswith("#separator"):
                v = s.split(" ", 1)[1].strip()
                self.sep = bytes(v, "utf-8").decode("unicode_escape") if v.startswith("\\x") else v
            elif s.startswith("#path"):
                self.path = s.split(self.sep, 1)[1].strip() if self.sep in s else s.split()[1]
            elif s.startswith("#fields"):
                self.fields = s.split(self.sep)[1:]
            return Skip()
        if not self.fields:
            return Failed("no #fields header")
        vals = s.split(self.sep)
        if len(vals) != len(self.fields):
            return Failed("field count mismatch")
        d: dict[str, Any] = {}
        for k, v in zip(self.fields, vals, strict=True):
            if v in ("-", "(empty)"):
                continue
            if k in ("orig_bytes", "resp_bytes", "id.orig_p", "id.resp_p", "status_code", "request_body_len",
                     "response_body_len", "orig_pkts", "resp_pkts", "missed_bytes", "seen_bytes", "trans_depth"):
                try:
                    v = int(v)
                except ValueError:
                    pass
            elif k == "duration":
                try:
                    v = float(v)
                except ValueError:
                    pass
            d[k] = v
        r = zeek_record(d, self.path)
        if r is None:
            return Failed("not a Zeek record")
        _, f, ext = r
        return Parsed(f, ext)


class SuricataEveParser(BaseParser):
    id, product, data_source, event_type = "suricata_eve", "suricata", "suricata", "ids_event"

    def detect(self, sample: list[str]) -> float:
        lines = [s for s in sample if s.strip()]
        if not lines:
            return 0.0
        hits = sum(1 for s in lines if '"event_type"' in s and ('"flow_id"' in s or '"dest_ip"' in s))
        return 0.99 * (sum(1 for s in lines if isinstance(self.parse_line(s), Parsed)) / len(lines)) if hits >= len(lines) / 2 else 0.0

    def parse_line(self, line: str) -> ParseResult:
        s = line.strip()
        try:
            d = orjson.loads(s)
        except orjson.JSONDecodeError:
            return Failed("invalid JSON")
        if not isinstance(d, dict) or "event_type" not in d:
            return Failed("not an eve record")
        et = d["event_type"]
        f: dict[str, Any] = {"timestamp_raw": d.get("timestamp"), "src_ip": d.get("src_ip"), "src_port": d.get("src_port"),
                             "dst_ip": d.get("dest_ip"), "dst_port": d.get("dest_port"),
                             "protocol": (d.get("app_proto") or d.get("proto") or "").lower() or None,
                             "event_type": f"suricata_{et}", "data_source": "suricata"}
        if d.get("community_id"):
            f["community_id"] = d["community_id"]
        if et == "alert":
            a = d.get("alert") or {}
            sev = a.get("severity")
            f["severity"] = {1: "high", 2: "medium", 3: "low"}.get(sev, "info")
        elif et == "tls":
            t = d.get("tls") or {}
            f["domain"] = t.get("sni")
            f["ja3"] = (t.get("ja3") or {}).get("hash") if isinstance(t.get("ja3"), dict) else t.get("ja3")
            f["ja4"] = t.get("ja4")
        elif et == "dns":
            q = d.get("dns") or {}
            f["domain"] = q.get("rrname") or ((q.get("queries") or [{}])[0].get("rrname"))
        elif et == "http":
            h = d.get("http") or {}
            f.update(hostname=h.get("hostname"), uri=h.get("url"), method=h.get("http_method"),
                     status_code=h.get("status"), user_agent=h.get("http_user_agent"))
        elif et == "flow":
            fl = d.get("flow") or {}
            f["bytes_out"], f["bytes_in"] = fl.get("bytes_toserver"), fl.get("bytes_toclient")
        ext = {k: v for k, v in d.items() if k not in ("timestamp", "src_ip", "src_port", "dest_ip", "dest_port")}
        return Parsed({k: v for k, v in f.items() if v is not None}, ext)
