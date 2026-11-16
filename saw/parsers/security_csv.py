"""Strong-header adapters for Korean firewall and NDR CSV exports.

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
        for delim in DELIMITERS:
            try:
                header = next(csv.reader([line.lstrip("\ufeff")], delimiter=delim, strict=True))
            except (csv.Error, StopIteration):
                continue
            if len(header) > SECURITY_CSV_MAX_COLUMNS:
                continue
            positions: dict[str, list[int]] = {}
            for index, name in enumerate(header):
                canonical = wanted.get(_norm(name))
                if canonical:
                    positions.setdefault(canonical, []).append(index)
            if len(positions) < MIN_MATCH * len(self.required_headers) or not CORE_HEADERS <= set(positions):
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
        for name, mapped in _COMMON_FIELDS.items():
            value = source.get(name, "").strip()
            if value in ("", "-"):
                continue
            if name in _PORTS:
                if not (value.isascii() and value.isdigit()) or int(value) > 65535:  # "²" is a digit, not a port
                    self._bad["port"] += 1
                    continue
            elif name in _BYTES:
                value = value.replace(",", "")  # "1,200" from spreadsheet exports
                if not (value.isascii() and value.isdigit()):
                    self._bad["number"] += 1
                    continue
            elif name in _IPS and _IPV4_LIKE.fullmatch(value) and not _valid_ip(value):
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
