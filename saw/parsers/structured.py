"""JSON Lines (generic + Cloudflare), CSV, Key-Value, Generic WAF (KV/JSON/CEF/LEEF) and Syslog parsers."""
from __future__ import annotations

import csv
import io
import re
from collections.abc import Iterator
from typing import Any

import orjson

from saw.parsers.base import LINE_MAX, BaseParser, Failed, Parsed, ParseResult, RawLine, Skip, unique_names

# Candidate source keys for each CES field (first match wins). Keys compared case-insensitively.
FIELD_ALIASES: dict[str, list[str]] = {
    "timestamp_raw": ["timestamp", "@timestamp", "time", "datetime", "date", "eventtime", "event_time",
                      "edgestarttimestamp", "datetimestamp", "ts", "log_time", "rt", "start"],
    "src_ip": ["src_ip", "srcip", "src", "source_ip", "sourceip", "client_ip", "clientip", "c-ip", "remote_addr",
               "remoteaddr", "id.orig_h", "attacker_ip", "ip"],
    "src_port": ["src_port", "srcport", "spt", "sport", "source_port", "clientsrcport", "id.orig_p"],
    "dst_ip": ["dst_ip", "dstip", "dst", "destination_ip", "server_ip", "s-ip", "originip", "id.resp_h"],
    "dst_port": ["dst_port", "dstport", "dpt", "dport", "destination_port", "id.resp_p"],
    "method": ["method", "http_method", "request_method", "clientrequestmethod", "requestmethod"],
    "uri": ["uri", "url", "request_uri", "requesturi", "clientrequesturi", "path", "request", "request_url"],
    "hostname": ["host", "hostname", "clientrequesthost", "server_name", "dhost"],
    "status_code": ["status", "status_code", "statuscode", "edgeresponsestatus", "response_code", "sc-status"],
    "bytes_out": ["bytes_out", "bytes_sent", "body_bytes_sent", "edgeresponsebytes", "out", "response_size"],
    "bytes_in": ["bytes_in", "bytes_received", "clientrequestbytes", "in", "request_size"],
    "user_agent": ["user_agent", "useragent", "http_user_agent", "clientrequestuseragent", "ua", "requestclientapplication"],
    "user": ["user", "username", "user_name", "suser", "account", "login"],
    "severity": ["severity", "level", "risk", "priority"],
    "ja3": ["ja3", "ja3hash", "ja3_hash"],
    "ja4": ["ja4", "ja4hash", "ja4_hash"],
    "domain": ["domain", "query", "sni", "server_name_indication"],
    "session_id": ["session_id", "sessionid", "sid"],
    "request_id": ["request_id", "requestid", "x_request_id"],
    "protocol": ["protocol", "proto", "clientrequestprotocol"],
    "hash": ["sha256", "hash", "file_hash"],
    "process": ["process", "process_name", "image"],
}
_ALIAS_INDEX = {alias: ces for ces, aliases in FIELD_ALIASES.items() for alias in aliases}
# Column headers of CSV/TXT exports (security appliances, SIEM searches, Excel) compared in compact form:
# lower-case without spaces/_/-/./()/[] — "Source IPAddr", "source_ip_addr" and "출발지 IP" all hit.
EXTRA_ALIASES: dict[str, list[str]] = {
    "timestamp_raw": ["flowtime", "detecttime", "detectiontime", "logtime", "receivetime", "receivedtime", "starttime",
                      "createtime", "createdat", "occurtime", "occurredat", "시간", "일시", "발생시간", "발생일시",
                      "탐지시간", "탐지일시", "수집시간", "수집일시", "로그시간", "이벤트시간", "접속시간", "접속일시",
                      "시작시간", "생성시간", "생성일시", "날짜", "탐지일자"],
    "src_ip": ["sourceipaddr", "sourceipaddress", "sourceaddress", "srcaddr", "srcipaddr", "srcaddress",
               "clientaddress", "출발지ip", "출발지주소", "출발지", "소스ip", "송신지ip", "송신ip", "공격자ip", "접속ip",
               "클라이언트ip", "사용자ip", "원본ip", "출발지아이피"],
    "src_port": ["sourceport", "clientport", "출발지포트", "소스포트", "송신포트"],
    "dst_ip": ["destinationipaddr", "destinationipaddress", "destinationaddress", "dstaddr", "dstipaddr",
               "dstaddress", "serveraddress", "targetip", "목적지ip", "목적지주소", "목적지", "도착지ip", "도착지",
               "대상ip", "수신지ip", "서버ip", "피해자ip", "목적지아이피"],
    "dst_port": ["destinationport", "serverport", "targetport", "목적지포트", "도착지포트", "대상포트", "서비스포트"],
    "method": ["메소드", "메서드", "요청방식", "요청메소드"],
    "uri": ["요청url", "요청uri", "url경로", "접속url"],
    "hostname": ["호스트", "호스트명", "서버명"],
    "status_code": ["응답코드", "상태코드", "결과코드", "httpstatus"],
    "user_agent": ["사용자에이전트", "유저에이전트"],
    "user": ["userid", "사용자", "사용자id", "계정", "계정명", "아이디"],
    "severity": ["위험도", "심각도", "등급", "위험등급", "중요도"],
    "bytes_out": ["uploadbyte", "uploadbytes", "sentbytes", "txbytes", "송신바이트", "업로드바이트"],
    "bytes_in": ["downloadbyte", "downloadbytes", "receivedbytes", "rxbytes", "수신바이트", "다운로드바이트"],
    "protocol": ["프로토콜"],
    "domain": ["도메인", "dnsquery", "queryname", "질의도메인"],
}
_COMPACT_DROP = str.maketrans("", "", " _-.()[]/:")


def compact_key(k: str) -> str:
    return k.strip().lower().translate(_COMPACT_DROP)


_COMPACT_INDEX: dict[str, str] = {}
for _ces, _aliases in list(FIELD_ALIASES.items()) + list(EXTRA_ALIASES.items()):
    for _a in _aliases:
        _COMPACT_INDEX.setdefault(compact_key(_a), _ces)
WAF_HINTS = {"action", "rule", "rule_id", "ruleid", "attack", "attack_type", "signature", "sig_id", "policy",
             "violation", "waf", "securityaction", "securityrule", "block", "cs1"}
# JSON records: "action", "policy" and "block" appear in firewall, DDoS and web records too, so they
# alone must not make a record a WAF event.
JSON_WAF_HINTS = WAF_HINTS - {"action", "policy", "block"}
WAF_HINTS_KO = {"공격명", "탐지명", "정책명", "차단여부", "대응", "룰", "룰명", "시그니처", "공격유형", "조치", "탐지룰"}


def alias_for(k: str) -> str | None:
    return _ALIAS_INDEX.get(k.lower()) or _COMPACT_INDEX.get(compact_key(k))


def map_fields(d: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    f: dict[str, Any] = {}
    ext: dict[str, Any] = {}
    for k, v in d.items():
        ces = alias_for(k)
        if ces and ces not in f and (ces == "user_agent" or v not in (None, "", "-")):
            f[ces] = v if not isinstance(v, (dict, list)) else orjson.dumps(v).decode()
        else:
            ext[k] = v
    # "request": "GET /x HTTP/1.1" style
    if isinstance(f.get("uri"), str):
        m = re.match(r"^([A-Z]{3,16})\s+(\S+)(?:\s+HTTP/[\d.]+)?$", f["uri"])
        if m:
            f.setdefault("method", m.group(1))
            f["uri"] = m.group(2)
        elif re.match(r"(?i)^https?://", f["uri"]):
            from urllib.parse import urlsplit

            u = urlsplit(f["uri"])
            f.setdefault("hostname", u.hostname)
            f["uri"] = (u.path or "/") + (f"?{u.query}" if u.query else "")
    if f.get("timestamp_raw") is not None:
        f["timestamp_raw"] = str(f["timestamp_raw"])
    return f, ext


def _flatten(d: dict, prefix: str = "", out: dict | None = None, depth: int = 0) -> dict:
    out = {} if out is None else out
    for k, v in d.items():
        key = f"{prefix}{k}"
        if isinstance(v, dict) and depth < 4:
            _flatten(v, key + ".", out, depth + 1)
        else:
            out[key] = v
    return out


class JsonLinesParser(BaseParser):
    id = "json_lines"
    product = "json"
    data_source = "custom"
    event_type = "log"

    def detect(self, sample: list[str]) -> float:
        return 0.9 * super().detect(sample)  # generic: specific JSON profiles win ties

    def parse_line(self, line: str) -> ParseResult:
        s = line.strip()
        if not s.startswith("{"):
            return Failed("not a JSON object")
        try:
            d = orjson.loads(s)
        except orjson.JSONDecodeError:
            return Failed("invalid JSON")
        if not isinstance(d, dict):
            return Failed("not a JSON object")
        f, ext = map_fields(_flatten(d))
        return Parsed(f, ext)


class CloudflareParser(JsonLinesParser):
    id = "cloudflare_http"
    product = "cloudflare"
    data_source = "web"
    event_type = "http_access"

    def detect(self, sample: list[str]) -> float:
        hits = sum(1 for s in sample if '"ClientIP"' in s or '"ClientRequestHost"' in s or '"EdgeStartTimestamp"' in s)
        return 0.99 / 0.9 * super().detect(sample) if hits >= max(1, len([s for s in sample if s.strip()]) // 2) else 0.0

    def parse_line(self, line: str) -> ParseResult:
        r = super().parse_line(line)
        if isinstance(r, Parsed):
            d = r.ext
            if "ClientIP" in d:
                r.fields["src_ip"] = d.pop("ClientIP")
            for k in ("SecurityAction", "WAFAction", "FirewallMatchesActions"):
                if d.get(k) and d.get(k) not in ("unknown", []):
                    r.fields["event_type"] = "waf_event"
        return r


class GenericJsonWafParser(JsonLinesParser):
    id = "waf_json"
    product = "waf"
    data_source = "waf"
    event_type = "waf_event"

    def detect(self, sample: list[str]) -> float:
        lines = [s for s in sample if s.strip()]
        if not lines:
            return 0.0
        hint = sum(1 for s in lines if any(f'"{h}"' in s.lower() for h in JSON_WAF_HINTS))
        return super().detect(sample) / 0.9 * (0.97 if hint >= len(lines) / 2 else 0.0)


def sniff_delimiter(lines: list[str]) -> str | None:
    """Deterministic delimiter guess (csv.Sniffer is avoided: its regexes backtrack badly on hostile input).

    A delimiter qualifies when it yields the same column count (>=3) on >=90% of lines, parsed with csv.reader.
    """
    best: tuple[int, str] | None = None
    sample = [ln for ln in lines if ln.strip()][:50]
    if len(sample) < 2:
        return None
    for d in (",", "\t", ";", "|"):
        if sample[0].count(d) < 2:
            continue
        try:
            counts = [len(r) for r in csv.reader(sample, delimiter=d)]
        except csv.Error:
            continue
        mode = max(set(counts), key=counts.count)
        if mode >= 3 and counts.count(mode) / len(counts) >= 0.9 and (best is None or mode > best[0]):
            best = (mode, d)
    return best[1] if best else None


def duplicate_columns_note(repeated: list[str]) -> str:
    names = ", ".join(repeated[:5]) + (" 등" if len(repeated) > 5 else "")
    return f"같은 열 이름이 여러 번 나옴({names}): 첫 열만 분석 필드로 쓰고 나머지는 '이름_2'처럼 번호를 붙여 보관함"


CSV_MAX_RECORD_LINES = 64  # one record may span lines inside quotes; bounded like Codex' importer


def _header_delim(line: str) -> str:
    counts = {d: line.count(d) for d in (",", "\t", ";", "|")}
    d = max(counts, key=lambda k: counts[k])
    return d if counts[d] else ","


def _fit_row(row: list[str], width: int) -> list[str] | None:
    """Tolerate exporter quirks: trailing empty cells, missing trailing cells, unquoted commas in the last column."""
    if len(row) == width:
        return row
    if len(row) < width:
        return row + [""] * (width - len(row)) if len(row) >= max(2, width // 2) else None
    extra = row[width:]
    if not any(c.strip() for c in extra):
        return row[:width]
    return row[: width - 1] + [",".join(row[width - 1:]).rstrip(",")]


def infer_source(header: list[str]) -> tuple[str, str]:
    """Data source of a generic table from its columns, so the matching detectors run (web / waf / network flow)."""
    ces = {alias_for(h) for h in header} - {None}
    comp = {compact_key(h) for h in header}
    if "uri" in ces or ("method" in ces and "status_code" in ces):
        waf = comp & ({compact_key(h) for h in WAF_HINTS} | {compact_key(h) for h in WAF_HINTS_KO})
        return ("waf", "waf_event") if waf else ("web", "http_access")
    if {"src_ip", "dst_ip"} <= ces and ({"dst_port", "bytes_out", "bytes_in"} & ces):
        return "connection", "conn"
    return "custom", "log"


class CsvParser(BaseParser):
    version = "2.0.0"
    id = "csv"
    product = "csv"
    data_source = "custom"
    event_type = "log"
    stateful = True

    def __init__(self) -> None:
        self.header: list[str] | None = None
        self.delim = ","
        self.kind = ("custom", "log")
        self.warnings = []
        self._repaired = {"padded": 0, "merged": 0}

    def reset(self) -> None:
        self.header = None
        self.warnings = []
        self._repaired = {"padded": 0, "merged": 0}

    def _repair_notes(self) -> list[str]:
        notes = []
        if self._repaired["padded"]:
            notes.append(f"열이 모자란 행 {self._repaired['padded']}건은 뒤쪽 열을 빈 값으로 두고 읽었습니다(값을 만들지 않음).")
        if self._repaired["merged"]:
            notes.append(f"열이 넘치는 행 {self._repaired['merged']}건은 남는 값을 마지막 열에 합쳐 읽었습니다. "
                         "마지막 열의 값이 올바른지 원문과 비교하세요.")
        return notes

    def detect(self, sample: list[str]) -> float:
        lines = [s.lstrip("\ufeff") for s in sample if s.strip()]
        if len(lines) < 2:
            return 0.0
        d = sniff_delimiter(lines)
        if d is None:
            return 0.0
        head = [h.strip() for h in next(csv.reader([lines[0]], delimiter=d))]
        width = len(head)
        try:  # records, not physical lines: a quoted field may continue on the next lines
            rows = list(csv.reader(lines[1:50], delimiter=d))
        except csv.Error:
            return 0.0
        fit = sum(1 for r in rows if _fit_row(r, width) is not None)
        if width < 3 or not rows or fit < 0.9 * len(rows):
            return 0.0
        known = len({alias_for(h) for h in head} - {None})
        return 0.6 + min(0.35, known * 0.07) if known else 0.4

    def parse_line(self, line: str) -> ParseResult:
        if self.header is None:
            self.delim = _header_delim(line)
            self.header = [h.strip() or f"col{i + 1}" for i, h in enumerate(next(csv.reader([line], delimiter=self.delim)))]
            while len(self.header) > 1 and self.header[-1].startswith("col") and self.header[-1][3:].isdigit():
                self.header.pop()  # unnamed trailing columns (exporters pad rows with commas)
            self.header, repeated = unique_names(self.header)
            if repeated:
                self.warnings = [duplicate_columns_note(repeated)]
            self.kind = infer_source(self.header)
            return Skip()
        raw_row = next(csv.reader(io.StringIO(line), delimiter=self.delim), [])
        row = _fit_row(raw_row, len(self.header))
        if row is None:
            return Failed("column count mismatch")
        if len(raw_row) < len(self.header):
            self._repaired["padded"] += 1
        elif len(raw_row) > len(self.header) and any(c.strip() for c in raw_row[len(self.header):]):
            self._repaired["merged"] += 1
        f, ext = map_fields(dict(zip(self.header, row, strict=True)))
        if self.kind[0] != "custom":
            f.setdefault("data_source", self.kind[0])
            f.setdefault("event_type", self.kind[1])
        return Parsed(f, ext)

    def parse(self, lines: Iterator[RawLine]) -> Iterator[tuple[RawLine, ParseResult]]:
        """Records whose quoted fields contain line breaks (SIEM/Excel exports) are joined before parsing."""
        self.reset()
        pending: list[RawLine] = []
        replay: list[RawLine] = []  # lines to re-read after a stray quote proved not to open a multi-line record
        size = 0
        src = iter(lines)
        while True:
            if replay:
                rl = replay.pop(0)
            else:
                rl = next(src, None)
                if rl is None:
                    break
            if pending:
                pending.append(rl)
                size += len(rl.text)
            elif rl.text.count('"') % 2:
                pending, size = [rl], len(rl.text)
            else:
                yield rl, (self.safe_parse_line(rl.text) if len(rl.text) <= LINE_MAX else Failed("line exceeds 1 MB limit"))
                continue
            text = "\n".join(x.text for x in pending)
            if text.count('"') % 2 == 0:
                yield self._record(pending, text)
                pending = []
            elif len(pending) >= CSV_MAX_RECORD_LINES or size > LINE_MAX:
                yield pending[0], Failed("unterminated quoted field")
                replay = pending[1:] + replay
                pending = []
        if pending:
            yield pending[0], Failed("unterminated quoted field")
            yield from self._plain(pending[1:])
        self.warnings = [*self.warnings, *self._repair_notes()]

    def _plain(self, rest: list[RawLine]) -> Iterator[tuple[RawLine, ParseResult]]:
        for rl in rest:  # end of file inside a stray quote: the remaining lines are ordinary rows
            yield rl, self.safe_parse_line(rl.text)

    def _record(self, parts: list[RawLine], text: str) -> tuple[RawLine, ParseResult]:
        first, last = parts[0], parts[-1]
        end = last.offset + (last.length if last.length >= 0 else len(last.text.encode("utf-8")))
        return RawLine(text, first.offset, first.line_no, end - first.offset), self.safe_parse_line(text)


# A key starts at the line start or after a separator. Without that anchor a long run of word characters
# (e.g. a base64 payload in one CSV field) is re-scanned from every position: detection took seconds per line.
_KV = re.compile(r'(?:^|(?<=[\s,;|&>\[(]))([\w.\-]+)=("(?:[^"\\]|\\.)*"|\'[^\']*\'|[^\s]*)')


def parse_kv(s: str) -> dict[str, str]:
    out = {}
    for k, v in _KV.findall(s):
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
            v = v[1:-1]
        out[k] = v
    return out


class KeyValueParser(BaseParser):
    id = "key_value"
    product = "kv"
    data_source = "custom"
    event_type = "log"

    def detect(self, sample: list[str]) -> float:
        return 0.8 * super().detect(sample)  # generic fallback: specific formats win

    def parse_line(self, line: str) -> ParseResult:
        d = parse_kv(line)
        if len(d) < 3:
            return Failed("fewer than 3 key=value pairs")
        f, ext = map_fields(d)
        # firewall-style kv usually has src/dst + action
        return Parsed(f, ext)


_CEF = re.compile(r"CEF:(\d+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)$")
_LEEF = re.compile(r"LEEF:([\d.]+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)$")


class GenericWafParser(BaseParser):
    """CEF / LEEF / KV formatted WAF events (vendor profiles extend FIELD_ALIASES)."""

    id = "waf_generic"
    product = "waf"
    data_source = "waf"
    event_type = "waf_event"

    def detect(self, sample: list[str]) -> float:
        lines = [s for s in sample if s.strip()]
        if not lines:
            return 0.0
        ok = sum(1 for s in lines if isinstance(self.parse_line(s), Parsed))
        hint = sum(1 for s in lines if "CEF:" in s or "LEEF:" in s or any(f"{h}=" in s.lower() for h in WAF_HINTS))
        return (ok / len(lines)) * (0.96 if hint >= len(lines) / 2 else 0.3)

    def parse_line(self, line: str) -> ParseResult:
        m = _CEF.search(line)
        if m:
            ext = {"cef_vendor": m.group(2), "cef_product": m.group(3), "signature_id": m.group(5),
                   "signature": m.group(6), "cef_severity": m.group(7)}
            kv = parse_kv(m.group(8))
            f, e2 = map_fields(kv)
            ext.update(e2)
            if "request" in kv and "uri" not in f:
                f["uri"] = kv["request"]
            f.setdefault("severity", m.group(7))
            return Parsed(f, ext)
        m = _LEEF.search(line)
        if m:
            sep = "\t"
            body = m.group(6)
            kv = dict(p.split("=", 1) for p in body.split(sep) if "=" in p) or parse_kv(body)
            f, ext = map_fields(kv)
            ext.update({"leef_vendor": m.group(2), "leef_product": m.group(3), "event_id": m.group(5)})
            return Parsed(f, ext)
        d = parse_kv(line)
        if len(d) >= 3 and any(k.lower() in WAF_HINTS for k in d):
            f, ext = map_fields(d)
            return Parsed(f, ext)
        return Failed("not CEF/LEEF/WAF key-value")


_SYSLOG5424 = re.compile(r"^<(\d{1,3})>1\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(-|\[.*?\])\s?(.*)$")
_SYSLOG3164 = re.compile(r"^(?:<(\d{1,3})>)?(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:\[\s]+)(?:\[(\d+)\])?:\s?(.*)$")
_SEV = ["critical", "critical", "critical", "high", "medium", "low", "info", "info"]


class SyslogParser(BaseParser):
    id = "syslog"
    product = "syslog"
    data_source = "linux"
    event_type = "syslog"

    def parse_line(self, line: str) -> ParseResult:
        s = line.rstrip("\r\n")
        m = _SYSLOG5424.match(s)
        if m:
            pri = int(m.group(1))
            f = {"timestamp_raw": m.group(2), "hostname": m.group(3), "process": m.group(4),
                 "severity": _SEV[pri % 8]}
            msg = m.group(8)
            ext = {"app": m.group(4), "procid": m.group(5), "msgid": m.group(6), "message": msg[:4096],
                   "facility": pri // 8}
        else:
            m = _SYSLOG3164.match(s)
            if not m:
                return Failed("not RFC3164/5424 syslog")
            pri = int(m.group(1)) if m.group(1) else None
            f = {"timestamp_raw": m.group(2), "hostname": m.group(3), "process": m.group(4)}
            if pri is not None:
                f["severity"] = _SEV[pri % 8]
            msg = m.group(6)
            ext = {"pid": m.group(5), "message": msg[:4096]}
        # sshd / auth hints
        am = re.search(r"(Failed|Accepted) (password|publickey) for (invalid user )?(\S+) from (\S+) port (\d+)", msg)
        if am:
            f.update(user=am.group(4), src_ip=am.group(5), src_port=am.group(6))
            f["event_type"] = "auth"
            ext["outcome"] = "failure" if am.group(1) == "Failed" else "success"
        else:
            kv = parse_kv(msg)
            if len(kv) >= 3:
                f2, e2 = map_fields(kv)
                for k, v in f2.items():
                    f.setdefault(k, v)
                ext.update({f"kv.{k}": v for k, v in e2.items()})
        return Parsed(f, ext)


# Skip is re-exported for parsers that emit header lines
__all__ = ["CloudflareParser", "CsvParser", "GenericJsonWafParser", "GenericWafParser", "JsonLinesParser",
           "KeyValueParser", "Skip", "SyslogParser", "map_fields"]
