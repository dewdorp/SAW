"""Strong-header adapters for Korean firewall and NDR CSV exports.

Source labels are untrusted observations, never attack truth or device profiles.
Record framing and encoding-aware raw references reuse CsvParser.
"""
from __future__ import annotations

import csv
import io
import re
from urllib.parse import urlsplit

from saw.parsers.base import LINE_MAX, Failed, Parsed, ParseResult, Skip, unique_names
from saw.parsers.structured import CsvParser

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


class _SecurityCsvParser(CsvParser):
    product = "security_csv"
    version = "1.0.0"
    data_source = "connection"
    event_type = "conn"
    required_headers: frozenset[str] = frozenset()
    csv_format = ""

    def reset(self) -> None:
        super().reset()
        self._invalid_header = False

    def _header(self, line: str) -> list[str] | None:
        if len(line) > LINE_MAX:
            return None
        try:
            header = next(csv.reader([line.lstrip("\ufeff")], strict=True))
        except (csv.Error, StopIteration):
            return None
        if len(header) > SECURITY_CSV_MAX_COLUMNS:
            return None
        # Flat, nonempty names avoid collisions with typed-object field paths.
        if any(not name.strip() or "." in name for name in header):
            return None
        # Exact, unique mandatory names prevent unrelated CSV or ambiguous aliases winning.
        folded = [name.casefold() for name in header]
        if not self.required_headers <= set(header) or any(
                folded.count(name.casefold()) != 1 for name in self.required_headers):
            return None
        return header

    def detect(self, sample: list[str]) -> float:
        first = next((line for line in sample if line.strip()), "")
        return 0.99 if self._header(first) is not None else 0.0

    def parse_line(self, line: str) -> ParseResult:
        if getattr(self, "_invalid_header", False):
            return Failed("invalid security CSV header")
        if self.header is None:
            header = self._header(line)
            if header is None:
                self._invalid_header = True
                return Failed("invalid security CSV header")
            self.header, _ = unique_names(header)
            self.delim = ","
            return Skip()
        if len(line) > LINE_MAX:
            return Failed("line exceeds 1 MB limit")
        try:
            rows = list(csv.reader(io.StringIO(line), strict=True))
        except csv.Error:
            return Failed("invalid security CSV row")
        if len(rows) != 1 or len(rows[0]) != len(self.header):
            return Failed("column count mismatch")
        source = dict(zip(self.header, rows[0], strict=True))
        fields = {mapped: source[name] for name, mapped in _COMMON_FIELDS.items()
                  if source[name] not in ("", "-")}
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
        if source["세션ID"] not in ("", "-"):
            fields["session_id"] = source["세션ID"]
        request = _http_request(source["요청헤더"])
        if request:
            fields.update(data_source="web", event_type="http_access", method=request[0], uri=request[1])
            if source["호스트명"] not in ("", "-"):
                fields["hostname"] = source["호스트명"]
            fields["user_agent"] = source["User-agent"]
            status = source["응답값"].strip()
            if re.fullmatch(r"[1-5][0-9]{2}", status):
                fields["status_code"] = int(status)
