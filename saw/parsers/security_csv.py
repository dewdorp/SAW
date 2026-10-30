"""Strong-header adapters for firewall and NDR CSV exports (Korean and English column names).

Source labels are untrusted observations, never attack truth or device profiles.
Record framing and encoding-aware raw references reuse CsvParser.
"""
from __future__ import annotations

import csv
import io
import ipaddress
import re
from urllib.parse import urlsplit

from saw.parsers.base import LINE_MAX, Failed, Parsed, ParseResult, Skip, unique_names
from saw.parsers.structured import CsvParser, duplicate_columns_note

FW_HEADERS = frozenset(["탐지시간", "그룹명", "장비IP", "대응", "출발지IP", "출발지포트", "목적지IP", "목적지포트", "프로토콜", "TCP플래그", "세션시간", "송신바이트", "수신바이트", "총패킷수", "송신패킷수", "수신패킷수"])
NDR_HEADERS = frozenset(["탐지시간", "로그구분", "그룹명", "장비IP", "대응", "출발지IP", "출발지포트", "출발지국가", "목적지IP", "목적지포트", "프로토콜", "세션ID", "송신바이트", "수신바이트", "요청헤더", "호스트명", "응답값", "User-agent", "공격명"])
_COMMON_FIELDS = {"탐지시간": "timestamp_raw", "출발지IP": "src_ip", "출발지포트": "src_port",
                  "목적지IP": "dst_ip", "목적지포트": "dst_port", "프로토콜": "protocol",
                  "송신바이트": "bytes_out", "수신바이트": "bytes_in"}
_REQUEST_LINE = re.compile(r"([!#$%&'*+.^_`|~0-9A-Za-z-]+) ([\x21-\x7e]+) HTTP/[0-9]\.[0-9]")
_REQUEST_SUMMARY = re.compile(r"(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH|TRACE) (/[\x21-\x7e]*)")
# Reserve one of registry.to_ces's 200 extension slots for adapter metadata.
SECURITY_CSV_MAX_COLUMNS = 199
_AUTHORITY = re.compile(r"(?:[A-Za-z0-9.-]+|\[[0-9A-Fa-f:.]+\]):([0-9]{1,5})")


def _http_request(value: str) -> tuple[str, str] | None:
    # Accept a first-line HTTP request or documented export summary, never headers alone.
    # Exporters may pad the request line with ASCII spaces; keep its internal syntax strict.
    first = value.split("\n", 1)[0].removesuffix("\r").strip(" ")
    # A summary records method/target only; no HTTP version is inferred.
    match = _REQUEST_LINE.fullmatch(first) or _REQUEST_SUMMARY.fullmatch(first)
    if not match:
        return None
    method, target = match.groups()
    if "#" in target:
        return None
    if method == "CONNECT":
        authority = _AUTHORITY.fullmatch(target)
        if authority and 1 <= int(authority.group(1)) <= 65535:
            return method, target
        return None
    if target.startswith("/") or (target == "*" and method == "OPTIONS"):
        return method, target
    if target.startswith(("http://", "https://")):
        try:
            parsed = urlsplit(target)
            if parsed.hostname and not parsed.username and not parsed.password:
                _ = parsed.port  # validate an explicitly supplied port
                return method, target
        except ValueError:
            pass
    return None


DELIMITERS = (",", "\t", ";")
# Enough of the export's own column names to be sure it is this export, even when one or two are missing.
MIN_MATCH = 0.75
CORE_HEADERS = frozenset({"\ud0d0\uc9c0\uc2dc\uac04", "\ucd9c\ubc1c\uc9c0IP", "\ubaa9\uc801\uc9c0IP"})
_PORTS = frozenset({"\ucd9c\ubc1c\uc9c0\ud3ec\ud2b8", "\ubaa9\uc801\uc9c0\ud3ec\ud2b8"})
_BYTES = frozenset({"\uc1a1\uc2e0\ubc14\uc774\ud2b8", "\uc218\uc2e0\ubc14\uc774\ud2b8"})
_IPS = frozenset({"\ucd9c\ubc1c\uc9c0IP", "\ubaa9\uc801\uc9c0IP"})
# An export header may be quoted with a field-list marker ("| # fields a,b,c" or "#fields a,b,c"). Only that exact
# marker is removed; any other text before the first column name is kept and makes the header unrecognised.
_FIELDS_MARKER = re.compile(r"^\s*(?:\|\s*)?#\s*fields\s+", re.I)
_IPV4_LIKE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")
# "200", "200 OK" and "HTTP/1.1 200 OK" all carry the same status; anything else is not a status code.
_STATUS = re.compile(r"(?:HTTP/\d(?:\.\d)?\s+)?([1-5][0-9]{2})(?:\s+\S.*)?", re.S)
VALUE_NOTES = {
    "port": "\ud3ec\ud2b8 \uac12\uc774 0~65535 \ubc94\uc704\uac00 \uc544\ub2c8\uac70\ub098 \uc22b\uc790\uac00 \uc544\ub2cc \uae30\ub85d {n}\uac74\uc740 \ud3ec\ud2b8\ub97c \ubd84\uc11d\uc5d0 \uc4f0\uc9c0 \uc54a\uc558\uc2b5\ub2c8\ub2e4(\uc6d0\ubb38\uc740 \ubcf4\uc874).",
    "number": "\uc1a1\uc218\uc2e0 \ubc14\uc774\ud2b8\uac00 \uc74c\uc218\uc774\uac70\ub098 \uc22b\uc790\uac00 \uc544\ub2cc \uae30\ub85d {n}\uac74\uc740 \ubc14\uc774\ud2b8\ub97c \ud1b5\uacc4\uc5d0 \ub354\ud558\uc9c0 \uc54a\uc558\uc2b5\ub2c8\ub2e4(\uc6d0\ubb38\uc740 \ubcf4\uc874).",
    "ip": "IP \ud615\uc2dd\uc774\uc9c0\ub9cc \uc720\ud6a8\ud558\uc9c0 \uc54a\uc740 \uc8fc\uc18c(\uc608: 999.x.x.x) {n}\uac74\uc740 \uc8fc\uc18c\ub85c \uc4f0\uc9c0 \uc54a\uc558\uc2b5\ub2c8\ub2e4(\uc6d0\ubb38\uc740 \ubcf4\uc874).",
    "status": "\uc751\ub2f5\uac12\uc774 HTTP \uc751\ub2f5 \ucf54\ub4dc\ub85c \ud574\uc11d\ub418\uc9c0 \uc54a\ub294 \uae30\ub85d {n}\uac74\uc740 \uc751\ub2f5 \uc0c1\ud0dc \ubbf8\ud655\uc778\uc73c\ub85c \ub0a8\uacbc\uc2b5\ub2c8\ub2e4.",
    "response_missing": "HTTP \uc694\uccad\uc740 \uc788\uc9c0\ub9cc \uc751\ub2f5\uac12\uc774 \ube44\uc5b4 \uc788\ub294 \uae30\ub85d {n}\uac74\uc740 \uc131\uacf5\u00b7\uc2e4\ud328\ub97c \ucd94\uc815\ud558\uc9c0 \uc54a\uc558\uc2b5\ub2c8\ub2e4.",
    "request_unparsed": "\uc694\uccad\ud5e4\ub354\uc5d0 \uc694\uccad\uc904(\uba54\uc11c\ub4dc\u00b7\uacbd\ub85c)\uc774 \uc5c6\ub294 \uae30\ub85d {n}\uac74\uc740 HTTP \uba54\uc11c\ub4dc\u00b7\uacbd\ub85c\ub97c \ub9cc\ub4e4\uc9c0 \uc54a\uc558\uc2b5\ub2c8\ub2e4.",
}


def _norm(name: str) -> str:
    """Header identity ignoring case and spaces: 'User-Agent' = 'User-agent', '\ucd9c\ubc1c\uc9c0 IP' = '\ucd9c\ubc1c\uc9c0IP'."""
    return "".join(name.lstrip("\ufeff").split()).casefold()


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


class _SecurityCsvParser(CsvParser):
    product = "security_csv"
    version = "1.1.0"
    data_source = "connection"
    event_type = "conn"
    required_headers: frozenset[str] = frozenset()
    csv_format = ""
    # Column roles of this export. The Korean exports keep the module defaults.
    common_fields: dict[str, str] = _COMMON_FIELDS
    core_headers: frozenset[str] = CORE_HEADERS
    port_headers: frozenset[str] = _PORTS
    byte_headers: frozenset[str] = _BYTES
    ip_headers: frozenset[str] = _IPS

    def __init__(self) -> None:
        super().__init__()
        self.reset()

    def reset(self) -> None:
        super().reset()
        self._invalid_header = False
        self._notes: list[str] = []
        self._bad = {key: 0 for key in VALUE_NOTES}

    def _plan(self, line: str) -> dict | None:
        """Map an export header onto the known columns, tolerating case/space, delimiter and missing extras."""
        if len(line) > LINE_MAX:
            return None
        wanted = {_norm(name): name for name in self.required_headers}
        best = None
        marker = _FIELDS_MARKER.match(line.lstrip("\ufeff"))
        text = line.lstrip("\ufeff")[marker.end():] if marker else line
        for delim in DELIMITERS:
            try:
                header = next(csv.reader([text.lstrip("\ufeff")], delimiter=delim, strict=True))
            except (csv.Error, StopIteration):
                continue
            if len(header) > SECURITY_CSV_MAX_COLUMNS:
                continue
            positions: dict[str, list[int]] = {}
            for index, name in enumerate(header):
                canonical = wanted.get(_norm(name))
                if canonical:
                    positions.setdefault(canonical, []).append(index)
            if len(positions) < MIN_MATCH * len(self.required_headers) or not self.core_headers <= set(positions):
                continue
            if best is None or len(positions) > len(best["positions"]):
                best = {"delim": delim, "header": header, "positions": positions}
        if best is None:
            return None
        header, positions = best["header"], best["positions"]
        names, notes, renamed = [None] * len(header), [], []
        ambiguous = sorted(c for c, places in positions.items() if len(places) > 1)
        for canonical, places in positions.items():
            for n, index in enumerate(places, 1):
                # Two columns with one meaning: keep both values, use neither, ask which one is the original.
                names[index] = f"{canonical}_\ud6c4\ubcf4{n}" if len(places) > 1 else canonical
                if len(places) == 1 and header[index] != canonical:
                    renamed.append(f"'{header[index]}'\u2192'{canonical}'")
        extras = []
        for index, name in enumerate(header):
            if names[index] is None:
                clean = name.strip().replace(".", "_") or f"\uc774\ub984\uc5c6\ub294\uc5f4{index + 1}"
                if clean != name:
                    extras.append(f"'{name}'\u2192'{clean}'" if name.strip() else f"{index + 1}\ubc88\uc9f8 \uc5f4(\uc774\ub984 \uc5c6\uc74c)\u2192'{clean}'")
                names[index] = clean
        names, repeated = unique_names(names)
        missing = sorted(self.required_headers - set(positions))
        if marker:
            notes.append("\ud5e4\ub354 \uc55e\uc758 \ud544\ub4dc \ubaa9\ub85d \ud45c\uae30('# fields')\ub97c \uc81c\uac70\ud558\uace0 \uc5f4 \uc774\ub984\uc744 \uc77d\uc5c8\uc2b5\ub2c8\ub2e4.")
        if best["delim"] != ",":
            notes.append(f"\uad6c\ubd84\uc790\ub97c '{'\ud0ed' if best['delim'] == chr(9) else best['delim']}'\ub85c \uc778\uc2dd\ud588\uc2b5\ub2c8\ub2e4.")
        if renamed:
            notes.append("\uc5f4 \uc774\ub984\uc758 \ub300\uc18c\ubb38\uc790\u00b7\uacf5\ubc31 \ucc28\uc774\ub97c \uc815\ub9ac\ud574 \uc778\uc2dd\ud588\uc2b5\ub2c8\ub2e4: " + ", ".join(renamed[:10]))
        if missing:
            notes.append("\uc774 \ud615\uc2dd\uc758 \uc5f4 \uc911 \uc5c6\ub294 \uc5f4: " + ", ".join(missing)
                         + ". \ud574\ub2f9 \uac12\uc774 \ud544\uc694\ud55c \ubd84\uc11d\uc740 '\uc790\ub8cc \uc5c6\uc74c'\uc73c\ub85c \ud45c\uc2dc\ub429\ub2c8\ub2e4.")
        if ambiguous:
            notes.append("\uac19\uc740 \uc758\ubbf8\uc758 \uc5f4\uc774 \uc5ec\ub7ec \uac1c\ub77c \uc5b4\ub290 \uac12\uc774 \uc6d0\ubcf8\uc778\uc9c0 \ud655\uc778\uc774 \ud544\uc694\ud569\ub2c8\ub2e4: " + ", ".join(ambiguous)
                         + ". \uc774 \ud544\ub4dc\ub294 \ubd84\uc11d\uc5d0 \uc4f0\uc9c0 \uc54a\uace0 \ubaa8\ub4e0 \uac12\uc744 \uc6d0\ubb38 \uc5f4\ub85c \ubcf4\uc874\ud588\uc2b5\ub2c8\ub2e4.")
        if extras:
            notes.append("\ucd94\uac00 \uc6d0\ubcf8 \uc5f4 \uc774\ub984\uc744 \uc800\uc7a5 \uac00\ub2a5\ud55c \uc774\ub984\uc73c\ub85c \ubc14\uafd4 \ubcf4\uc874\ud588\uc2b5\ub2c8\ub2e4: " + ", ".join(extras[:10]))
        if repeated:
            notes.append(duplicate_columns_note(repeated))
        exact = not (notes or len(positions) != len(self.required_headers))
        # How well this format explains the export: its own columns present, and the export's columns it knows.
        fit = (len(positions) / len(self.required_headers)) * (sum(len(v) for v in positions.values()) / len(header))
        return {"delim": best["delim"], "names": names, "notes": notes, "missing": missing, "exact": exact,
                "fit": fit}

    def detect(self, sample: list[str]) -> float:
        first = next((line for line in sample if line.strip()), "")
        plan = self._plan(first)
        if plan is None:
            return 0.0
        # A near-match still beats the generic CSV parser (0.95), which would drop session/HTTP/action meaning.
        # Between near-matching formats (an NDR export missing 공격명 but carrying TCP플래그 also near-matches the
        # FW format), the one that explains more of the export wins instead of registration order.
        return 0.99 if plan["exact"] else round(0.951 + 0.038 * plan["fit"], 4)

    def parse(self, lines):
        yield from super().parse(lines)
        self.warnings = [*self._notes, *(VALUE_NOTES[key].format(n=n) for key, n in self._bad.items() if n)]

    def parse_line(self, line: str) -> ParseResult:
        if getattr(self, "_invalid_header", False):
            return Failed("invalid security CSV header")
        if self.header is None:
            plan = self._plan(line)
            if plan is None:
                self._invalid_header = True
                return Failed("invalid security CSV header")
            self.header, self.delim, self._notes = plan["names"], plan["delim"], plan["notes"]
            return Skip()
        if len(line) > LINE_MAX:
            return Failed("line exceeds 1 MB limit")
        try:
            rows = list(csv.reader(io.StringIO(line), delimiter=self.delim, strict=True))
        except csv.Error:
            return Failed("invalid security CSV row (\uc778\uc6a9\ubd80\ud638\u00b7\uad6c\ubd84\uc790 \uc624\ub958)")
        if len(rows) != 1 or len(rows[0]) != len(self.header):
            got = len(rows[0]) if len(rows) == 1 else 0
            detail = (f"\ubd80\uc871\ud55c \uc5f4: {', '.join(self.header[got:][:5])}" if got < len(self.header)
                      else f"\ucd08\uacfc \uac12 {got - len(self.header)}\uac1c")
            # Never pad or merge cells: a shifted value would become a wrong byte/packet count.
            return Failed(f"column count mismatch: \ud5e4\ub354 {len(self.header)}\uc5f4, \uc774 \ud589 {got}\uc5f4 ({detail})")
        source = dict(zip(self.header, rows[0], strict=True))
        fields = {}
        for name, mapped in self.common_fields.items():
            value = source.get(name, "").strip()
            if value in ("", "-"):
                continue
            if name in self.port_headers:
                if not (value.isascii() and value.isdigit()) or int(value) > 65535:  # "²" is a digit, not a port
                    self._bad["port"] += 1
                    continue
            elif name in self.byte_headers:
                value = value.replace(",", "")  # "1,200" from spreadsheet exports
                if not (value.isascii() and value.isdigit()):
                    self._bad["number"] += 1
                    continue
            elif name in self.ip_headers and _IPV4_LIKE.fullmatch(value) and not _valid_ip(value):
                self._bad["ip"] += 1
                continue
            fields[mapped] = value
        fields.update(data_source="connection", event_type="conn")
        self._specific_fields(fields, source)
        # Retain mapped originals too: request/status/action/alert metadata stays inspectable.
        ext = dict(source)
        if "csv_format" in ext or "source_columns" in ext:
            ext["source_columns"] = source
        ext["csv_format"] = self.csv_format
        return Parsed(fields, ext)

    def _specific_fields(self, fields: dict, source: dict) -> None:
        pass


class KoFirewallCsvParser(_SecurityCsvParser):
    id = "ko_fw_csv"
    required_headers = FW_HEADERS
    csv_format = "fw"


class KoNdrCsvParser(_SecurityCsvParser):
    id = "ko_ndr_csv"
    required_headers = NDR_HEADERS
    csv_format = "ndr"

    def _specific_fields(self, fields: dict, source: dict) -> None:
        if source.get("세션ID", "") not in ("", "-"):
            fields["session_id"] = source["세션ID"]
        if source.get("공격명", "").strip() not in ("", "-"):
            # The device's own label, kept verbatim for counting and lookup; it is never treated as attack truth.
            fields["alert_name"] = source["공격명"].strip()[:512]
        request = _http_request(source.get("요청헤더", ""))
        if not request and source.get("요청헤더", "").strip() not in ("", "-"):
            self._bad["request_unparsed"] += 1
        if request:
            fields.update(data_source="web", event_type="http_access", method=request[0], uri=request[1])
            if source.get("호스트명", "") not in ("", "-"):
                fields["hostname"] = source["호스트명"]
            if "User-agent" in source:
                fields["user_agent"] = source["User-agent"]
            status = source.get("응답값", "").strip()
            match = _STATUS.fullmatch(status) if status not in ("", "-") else None
            if match:
                fields["status_code"] = int(match.group(1))
            elif status not in ("", "-"):
                self._bad["status"] += 1  # e.g. 999: unknown, never guessed as success or failure
            else:
                self._bad["response_missing"] += 1


EN_NDR_HEADERS = frozenset(["event_time", "_site", "app", "_schema", "protocol", "src_ip", "src_port", "src_country",
                            "dest_ip", "dest_port", "dest_country", "_device_ip", "_device_name", "method", "host", "path",
                            "query", "user_agent", "referer", "req_cookie", "uuid", "status", "sc_bytes", "cs_bytes"])
EN_FW_HEADERS = frozenset(["_time", "_device_ip", "_device_name", "action", "src_ip", "src_port", "dst_ip", "dst_port",
                           "protocol", "tcp_flag", "duration", "sent_bytes", "rcvd_bytes"])
_EN_NOTES = {
    "ndr_bytes": ("cs_bytes\u00b7sc_bytes\ub294 HTTP \uc694\uccad(\ud074\ub77c\uc774\uc5b8\ud2b8\u2192\uc11c\ubc84)\u00b7\uc751\ub2f5(\uc11c\ubc84\u2192\ud074\ub77c\uc774\uc5b8\ud2b8) "
                  "\ubc14\uc774\ud2b8 \ud6c4\ubcf4\ub85c \uc5f0\uacb0\ud588\uc2b5\ub2c8\ub2e4. \ud589 \ub2e8\uc704\u00b7\ud5e4\ub354 \ud3ec\ud568\u00b7\ub204\uc801 \uc5ec\ubd80\ub294 \uc7a5\ube44 \uba85\uc138\ub85c \ud655\uc778\ud574\uc57c \ud569\ub2c8\ub2e4."),
    "fw_bytes": ("sent_bytes\u00b7rcvd_bytes\ub294 \ucd9c\ubc1c\uc9c0 \uae30\uc900 \uc1a1\u00b7\uc218\uc2e0 \ubc14\uc774\ud2b8 \ud6c4\ubcf4\ub85c \uc5f0\uacb0\ud588\uc2b5\ub2c8\ub2e4. "
                 "\ubc29\ud5a5 \uae30\uc900(\ucd9c\ubc1c\uc9c0\u00b7\uc7a5\ube44)\uacfc \ub204\uc801\u00b7\uc99d\ubd84 \uc5ec\ubd80\ub294 \uc7a5\ube44 \uba85\uc138\ub85c \ud655\uc778\ud574\uc57c \ud569\ub2c8\ub2e4."),
}


def _http_target(path: str, query: str) -> str:
    """Path and query joined as one request target; a path that already has '?' gets the query appended with '&'."""
    path = path or "/"
    if not query:
        return path
    return f"{path}{'&' if '?' in path else '?'}{query.lstrip('?')}"


class EnNdrHttpCsvParser(_SecurityCsvParser):
    """NDR HTTP export with English column names (event_time, dest_ip, path, query, cs_bytes, sc_bytes ...)."""
    id = "en_ndr_http_csv"
    required_headers = EN_NDR_HEADERS
    csv_format = "ndr_http"
    common_fields = {"event_time": "timestamp_raw", "src_ip": "src_ip", "src_port": "src_port", "dest_ip": "dst_ip",
                     "dest_port": "dst_port", "protocol": "protocol", "sc_bytes": "bytes_out", "cs_bytes": "bytes_in"}
    core_headers = frozenset({"event_time", "src_ip", "dest_ip"})
    port_headers = frozenset({"src_port", "dest_port"})
    byte_headers = frozenset({"cs_bytes", "sc_bytes"})
    ip_headers = frozenset({"src_ip", "dest_ip"})

    def parse(self, lines):
        yield from super().parse(lines)
        self.warnings = [*self.warnings, _EN_NOTES["ndr_bytes"]]

    def parse_line(self, line: str) -> ParseResult:
        self._cookie = None
        result = super().parse_line(line)
        if isinstance(result, Parsed) and self._cookie:
            # The stored line carries the cookie names only; the original file keeps the values.
            result.raw = line.replace(self._cookie, "; ".join(f"{n}=[\uac00\ub9bc]" for n in result.ext.get("req_cookie_names", [])))
        return result

    def _specific_fields(self, fields: dict, source: dict) -> None:
        cookie = source.get("req_cookie", "")
        if cookie not in ("", "-"):
            self._cookie = cookie
            # Cookie values never reach the event store (they stay in the original file); the names stay searchable.
            source["req_cookie_names"] = sorted({part.split("=", 1)[0].strip() for part in cookie.split(";")
                                                 if part.split("=", 1)[0].strip()})[:50]
            source["req_cookie"] = "[\uc6d0\ubcf8 \ud30c\uc77c\uc5d0\ub9cc \ubcf4\uc874]"
        method = source.get("method", "").strip().upper()
        path, query = source.get("path", "").strip(), source.get("query", "").strip()
        if path in ("-",):
            path = ""
        if query in ("-",):
            query = ""
        if method or path:
            # The HTTP query belongs to the request target, never to a DNS domain.
            fields.update(data_source="web", event_type="http_access", uri=_http_target(path, query))
            if method:
                fields["method"] = method[:16]
            if source.get("host", "") not in ("", "-"):
                fields["hostname"] = source["host"].strip()
            if source.get("user_agent", "") not in ("", "-"):
                fields["user_agent"] = source["user_agent"]
            status = source.get("status", "").strip()
            match = _STATUS.fullmatch(status) if status not in ("", "-") else None
            if match:
                fields["status_code"] = int(match.group(1))
            elif status not in ("", "-"):
                self._bad["status"] += 1
            else:
                self._bad["response_missing"] += 1


class EnFirewallCsvParser(_SecurityCsvParser):
    """Firewall export with English column names (_time, action, sent_bytes, rcvd_bytes, duration ...)."""
    id = "en_fw_csv"
    required_headers = EN_FW_HEADERS
    csv_format = "fw"
    common_fields = {"_time": "timestamp_raw", "src_ip": "src_ip", "src_port": "src_port", "dst_ip": "dst_ip",
                     "dst_port": "dst_port", "protocol": "protocol", "sent_bytes": "bytes_out", "rcvd_bytes": "bytes_in"}
    core_headers = frozenset({"_time", "src_ip", "dst_ip"})
    port_headers = frozenset({"src_port", "dst_port"})
    byte_headers = frozenset({"sent_bytes", "rcvd_bytes"})
    ip_headers = frozenset({"src_ip", "dst_ip"})

    def parse(self, lines):
        yield from super().parse(lines)
        self.warnings = [*self.warnings, _EN_NOTES["fw_bytes"]]

