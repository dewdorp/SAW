"""Apache / Nginx (common, combined, + extras) and IIS W3C parsers."""
from __future__ import annotations

import re

from saw.parsers.base import BaseParser, Failed, Parsed, ParseResult, Skip

# host ident user [time] "request" status bytes ["referer" "ua"] [extras...]
_COMBINED = re.compile(
    r'^(?P<src_ip>\S+)\s+(?P<ident>\S+)\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<request>(?:[^"\\]|\\.)*)"\s+(?P<status>\d{3}|-)\s+(?P<bytes>\d+|-)'
    r'(?:\s+"(?P<referer>(?:[^"\\]|\\.)*)"\s+"(?P<ua>(?:[^"\\]|\\.)*)")?(?P<rest>.*)$'
)
_REQ = re.compile(r"^(?P<method>[A-Z]{3,16})\s+(?P<uri>\S+)(?:\s+(?P<proto>HTTP/[\d.]+))?$")


def _request_fields(req: str) -> dict:
    m = _REQ.match(req)
    if not m:
        return {"uri": None, "ext_request": req[:2048]}
    return {"method": m.group("method"), "uri": m.group("uri"), "protocol": (m.group("proto") or "").lower()}


class _ApacheLike(BaseParser):
    data_source = "web"
    event_type = "http_access"

    def parse_line(self, line: str) -> ParseResult:
        m = _COMBINED.match(line.rstrip("\r\n"))
        if not m:
            return Failed("does not match combined/common log format")
        g = m.groupdict()
        f = {"src_ip": g["src_ip"], "user": None if g["user"] == "-" else g["user"], "timestamp_raw": g["time"],
             "status_code": g["status"], "bytes_out": g["bytes"], "user_agent": g.get("ua")}
        rf = _request_fields(g["request"])
        ext: dict = {}
        if "ext_request" in rf:
            ext["request"] = rf.pop("ext_request")
        f.update(rf)
        if g.get("referer") not in (None, "-"):
            ext["referer"] = g["referer"]
        rest = (g.get("rest") or "").strip()
        if rest:
            ext["extra"] = rest[:2048]
            # common nginx extensions: request_time, upstream, host, xff in quotes
            q = re.findall(r'"([^"]*)"', rest)
            if q and re.fullmatch(r"[\d., ]+", q[0] or "") is None and q[0] not in ("-", ""):
                ext["x_forwarded_for"] = q[0]
            rt = re.search(r"(?:rt=|request_time=)?\b(\d+\.\d{3})\b", rest)
            if rt:
                ext["request_time"] = float(rt.group(1))
        return Parsed(f, ext)


class NginxParser(_ApacheLike):
    id = "nginx_combined"
    product = "nginx"

    def detect(self, sample: list[str]) -> float:
        base = super().detect(sample)
        # nginx and apache combined are identical; nginx is the default choice, tie-broken by hints
        return base * (0.99 if any("nginx" in s.lower() for s in sample) else 0.95)


class ApacheParser(_ApacheLike):
    id = "apache_combined"
    product = "apache"

    def detect(self, sample: list[str]) -> float:
        return super().detect(sample) * (0.99 if any("apache" in s.lower() for s in sample) else 0.94)


class IISParser(BaseParser):
    id = "iis_w3c"
    product = "iis"
    data_source = "web"
    event_type = "http_access"
    stateful = True
    MAP = {"c-ip": "src_ip", "s-ip": "dst_ip", "s-port": "dst_port", "cs-method": "method", "cs-uri-stem": "_stem",
           "cs-uri-query": "_query", "sc-status": "status_code", "sc-bytes": "bytes_out", "cs-bytes": "bytes_in",
           "cs(User-Agent)": "user_agent", "cs-username": "user", "cs-host": "hostname"}

    def __init__(self) -> None:
        self.fields: list[str] = []

    def reset(self) -> None:
        self.fields = []

    def detect(self, sample: list[str]) -> float:
        self.reset()
        if not any(s.startswith("#Fields:") for s in sample):
            return 0.0
        lines = [s for s in sample if s.strip()]
        ok = sum(1 for s in lines if isinstance(self.parse_line(s), (Parsed, Skip)))
        self.reset()
        return ok / max(1, len(lines))

    def parse_line(self, line: str) -> ParseResult:
        line = line.rstrip("\r\n")
        if line.startswith("#Fields:"):
            self.fields = line[len("#Fields:"):].split()
            return Skip()
        if line.startswith("#"):
            return Skip()
        if not self.fields:
            return Failed("no #Fields header seen")
        vals = line.split(" ")
        if len(vals) != len(self.fields):
            return Failed("field count mismatch")
        row = dict(zip(self.fields, vals, strict=True))
        f: dict = {}
        ext: dict = {}
        for k, v in row.items():
            if k in self.MAP:
                f[self.MAP[k]] = None if v == "-" else v
            elif k not in ("date", "time"):
                ext[k] = v
        if "date" in row and "time" in row:
            f["timestamp_raw"] = f"{row['date']}T{row['time']}Z"  # IIS logs are UTC by default
        stem, q = f.pop("_stem", None), f.pop("_query", None)
        f["uri"] = (stem or "") + (f"?{q}" if q else "")
        if f.get("user_agent"):
            f["user_agent"] = f["user_agent"].replace("+", " ")
        return Parsed(f, ext)
