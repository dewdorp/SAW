"""NDR meta-search CSV export (flow + one meta record per row) → CES web / network events.

Header: flow time,source ipaddr,source port,destination ipaddr,destination port,protocol,app category,app1,app2,
source country,destination country,upload packets,upload byte,download packtes,download byte,meta type,meta filter,
meta time,sequence,number of meta,transactionn id,server id,stream id,flow rowid,meta data[,...]

The last column holds `type=<kind>;k=v;k=v` and can spill into the trailing (unnamed) columns when a value contains
commas.  Kinds seen: http_request, http_response, traffic.  Requests and responses of one flow are paired in order
(HTTP/1.x answers in sequence) so a web event carries method + URI + status like an access log.

Privacy: cookie / set-cookie values (session ids, customer numbers) are never stored — only cookie names; the stored
raw_event is redacted the same way.  The untouched original stays in the evidence store (chain of custody).
"""
from __future__ import annotations

import csv
from collections import OrderedDict, deque
from collections.abc import Iterator
from typing import Any

from saw.parsers.base import LINE_MAX, BaseParser, Failed, Parsed, ParseResult, RawLine, Skip

HEADER_PREFIX = "flow time,source ipaddr,source port,destination ipaddr,destination port"
COLS = ["flow time", "source ipaddr", "source port", "destination ipaddr", "destination port", "protocol",
        "app category", "app1", "app2", "source country", "destination country", "upload packets", "upload byte",
        "download packtes", "download byte", "meta type", "meta filter", "meta time", "sequence", "number of meta",
        "transactionn id", "server id", "stream id", "flow rowid", "meta data"]
META_AT = COLS.index("meta data")
PROTO = {"6": "tcp", "17": "udp", "1": "icmp"}

# keys that may start a new `k=v` segment, per meta type (anything else continues the previous value: `q=0.9`,
# `charset=utf-8`, cookie attributes ...).  cookie/set_cookie are always last and swallow the rest.
KEYS = {
    "http_request": {"type", "method", "hostname", "num_of_req", "path", "ua", "refer", "content_type", "multi_attname",
                     "content_language", "accept_language", "xfwd", "cookie"},
    "http_response": {"type", "method", "ret_code", "num_of_res", "content_type", "server", "content_disposition",
                      "set_cookie"},
    "traffic": {"type", "Uploadpackets", "Downloadpackets", "Uploadbytes", "Downloadbytes"},
}
ALL_KEYS = set().union(*KEYS.values())
TAIL_KEYS = {"cookie", "set_cookie"}
PENDING_MAX = 20_000  # unanswered requests kept for pairing (bounded memory)


def parse_meta(s: str) -> dict[str, str]:
    out: dict[str, str] = {}
    kind = s.split(";", 1)[0].partition("=")[2]
    allowed = KEYS.get(kind, ALL_KEYS)
    last = None
    rest = s
    while rest:
        seg, sep, rest = rest.partition(";")
        k, eq, v = seg.partition("=")
        if eq and k in allowed and (k not in out or k == "method"):
            if k in TAIL_KEYS:
                out[k] = (v + sep + rest) if rest else v
                break
            out[k] = v
            last = k
        elif last is not None:
            out[last] += ";" + seg
    return out


def cookie_names(v: str | None) -> list[str]:
    if not v:
        return []
    names = []
    for part in v.split(";"):
        n = part.partition("=")[0].strip()
        if n and n.lower() not in ("path", "domain", "expires", "max-age", "secure", "httponly", "samesite", "charset") \
                and len(n) <= 64 and n not in names:
            names.append(n)
    return names[:40]


def _int(v: str | None) -> int | None:
    try:
        return int(v) if v not in (None, "") else None
    except ValueError:
        return None


class NdrMetaCsvParser(BaseParser):
    id = "ndr_meta_csv"
    version = "1.0.0"
    product = "ndr"
    data_source = "web"
    event_type = "http_access"
    stateful = True

    def detect(self, sample: list[str]) -> float:
        lines = [s.lstrip("﻿") for s in sample if s.strip()]
        if not lines or not lines[0].lower().startswith(HEADER_PREFIX) or "meta data" not in lines[0].lower():
            return 0.0
        body = lines[1:51]
        ok = sum(1 for s in body if isinstance(self._row(s), dict))
        return 0.99 if not body or ok / len(body) >= 0.9 else 0.5

    # ------------------------------------------------------------------ row → record
    def _row(self, line: str) -> dict[str, Any] | Failed | Skip:
        if line.lower().lstrip("﻿").startswith(HEADER_PREFIX):
            return Skip()
        try:
            row = next(csv.reader([line]))
        except (csv.Error, StopIteration):
            return Failed("invalid CSV row")
        if len(row) <= META_AT:
            return Failed("column count mismatch")
        meta = parse_meta(",".join(row[META_AT:]).rstrip(","))
        kind = meta.get("type")
        if not kind:
            return Failed("meta data without type")
        mt = row[COLS.index("meta time")].partition("=")
        flow = row[COLS.index("flow rowid")].partition("=")[2] or row[COLS.index("flow rowid")]
        server = row[COLS.index("server id")].partition("=")[2]
        # A flow number is only unique inside one sensor: records are the same conversation only when the sensor,
        # the stream and both endpoints agree as well (either direction, exports differ in which side comes first).
        pair = (flow, server, row[COLS.index("stream id")].partition("=")[2], row[5],
                frozenset(((row[1], row[2]), (row[3], row[4]))))
        return {"kind": kind, "meta": meta, "row": row, "ts": mt[2] if mt[1] else row[0], "flow": flow,
                "server": server, "pair": pair}

    def _base(self, rec: dict) -> tuple[dict, dict]:
        r = rec["row"]
        f = {"timestamp_raw": rec["ts"], "src_ip": r[1], "src_port": r[2], "dst_ip": r[3], "dst_port": r[4],
             "protocol": PROTO.get(r[5], r[5]),
             "session_id": f"ndr-flow-{rec['server']}-{rec['flow']}" if rec["server"] else f"ndr-flow-{rec['flow']}"}
        ext = {"app_category": r[6], "app": r[7], "app2": r[8], "src_country": r[9], "dst_country": r[10],
               "flow_rowid": rec["flow"], "server_id": rec["server"],
               "stream": r[COLS.index("stream id")].partition("=")[2]}
        return f, {k: v for k, v in ext.items() if v not in ("", None)}

    def _request(self, rec: dict) -> Parsed:
        m = rec["meta"]
        f, ext = self._base(rec)
        f.update(event_type="http_access", method=m.get("method") if m.get("method") != "request" else None,
                 hostname=m.get("hostname") or None, uri=m.get("path") or None, user_agent=m.get("ua"))
        for k, name in (("refer", "referer"), ("content_type", "request_content_type"), ("xfwd", "x_forwarded_for"),
                        ("accept_language", "accept_language"), ("multi_attname", "upload_filename")):
            if m.get(k):
                ext[name] = m[k][:1024]
        if m.get("cookie"):
            ext["cookie_names"] = cookie_names(m["cookie"])
        return Parsed(f, ext, redact=True)

    def _merge_response(self, req: Parsed, rec: dict) -> None:
        m = rec["meta"]
        req.fields["status_code"] = m.get("ret_code") or None
        for k, name in (("content_type", "response_content_type"), ("server", "server"),
                        ("content_disposition", "content_disposition")):
            if m.get(k):
                req.ext[name] = m[k][:1024]
        if m.get("set_cookie"):
            req.ext["set_cookie_names"] = cookie_names(m["set_cookie"])
        req.ext["response_line"] = rec.get("line_no")

    def _response_only(self, rec: dict) -> Parsed:
        f, ext = self._base(rec)
        f.update(data_source="ndr_http", event_type="http_response", status_code=rec["meta"].get("ret_code") or None)
        p = Parsed(f, ext, redact=True)
        self._merge_response(p, rec)
        return p

    def _traffic(self, rec: dict) -> Parsed:
        m, r = rec["meta"], rec["row"]
        f, ext = self._base(rec)
        # flow direction (network.py): bytes_out = sent by the originator (upload), bytes_in = received (download)
        f.update(data_source="zeek_conn", event_type="conn",
                 bytes_out=_int(m.get("Uploadbytes")) if m.get("Uploadbytes") else _int(r[12]),
                 bytes_in=_int(m.get("Downloadbytes")) if m.get("Downloadbytes") else _int(r[14]))
        ext.update(orig_pkts=_int(m.get("Uploadpackets") or r[11]), resp_pkts=_int(m.get("Downloadpackets") or r[13]),
                   service=(r[7] or "").lower() or None)
        return Parsed(f, {k: v for k, v in ext.items() if v is not None}, redact=True)

    # ------------------------------------------------------------------ line API (paste / single line: no pairing)
    def parse_line(self, line: str) -> ParseResult:
        rec = self._row(line)
        if not isinstance(rec, dict):
            return rec
        rec["line"] = line
        if rec["kind"] == "http_request":
            return self._request(rec)
        if rec["kind"] == "http_response":
            return self._response_only(rec)
        if rec["kind"] == "traffic":
            return self._traffic(rec)
        f, ext = self._base(rec)
        f.update(data_source="ndr_meta", event_type=rec["kind"][:64])
        return Parsed(f, {**ext, "meta_keys": sorted(rec["meta"])[:40]}, redact=True)

    # ------------------------------------------------------------------ stream API (ingest: request/response pairing)
    def parse(self, lines: Iterator[RawLine]) -> Iterator[tuple[RawLine, ParseResult]]:
        self.reset()
        pending: OrderedDict[tuple, deque[tuple[RawLine, Parsed]]] = OrderedDict()
        npending = 0
        for rl in lines:
            if len(rl.text) > LINE_MAX:
                yield rl, Failed("line exceeds 1 MB limit")
                continue
            rec = self._row(rl.text)
            if not isinstance(rec, dict):
                yield rl, rec
                continue
            rec["line"], rec["line_no"] = rl.text, rl.line_no
            if rec["kind"] == "http_request":
                pending.setdefault(rec["pair"], deque()).append((rl, self._request(rec)))
                pending.move_to_end(rec["pair"])
                npending += 1
                while npending > PENDING_MAX:  # oldest unanswered request leaves without a status
                    flow, q = next(iter(pending.items()))
                    yield q.popleft()
                    npending -= 1
                    if not q:
                        del pending[flow]
            elif rec["kind"] == "http_response":
                q = pending.get(rec["pair"])
                if q:
                    req_rl, req = q.popleft()
                    npending -= 1
                    if not q:
                        del pending[rec["pair"]]
                    self._merge_response(req, rec)
                    yield req_rl, req
                    yield rl, Skip()  # folded into the request event (ext.response_line)
                else:
                    yield rl, self._response_only(rec)
            else:
                yield rl, self.safe_parse_line(rl.text)
        for q in pending.values():
            yield from q
