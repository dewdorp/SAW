"""Web server logs: Apache / Nginx / Tomcat / WebtoB (common, combined, vhost, + extras), IIS W3C, HAProxy HTTP,
JSON access logs (Nginx json, Caddy), Apache and Nginx error logs."""
from __future__ import annotations

import re

import orjson

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
        return self._fields(m.groupdict())

    def _fields(self, g: dict) -> Parsed:
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


_VHOST = re.compile(r"^(?P<vhost>[A-Za-z0-9][A-Za-z0-9.\-]*\.[A-Za-z0-9.\-]*[A-Za-z0-9](?::(?P<vport>\d{1,5}))?)\s+(?P<line>.+)$")


class VhostCombinedParser(_ApacheLike):
    """Apache vhost_combined (%v:%p before %h) and the same prefix on Nginx ($host:$server_port)."""
    id = "apache_vhost_combined"
    product = "apache"

    def parse_line(self, line: str) -> ParseResult:
        v = _VHOST.match(line.rstrip("\r\n"))
        if not v or re.fullmatch(r"[\d.:]+", v.group("vhost").split(":")[0]):  # an address first is the plain format
            return Failed("no virtual host before the client address")
        m = _COMBINED.match(v.group("line"))
        if not m:
            return Failed("does not match vhost_combined log format")
        r = self._fields(m.groupdict())
        r.fields["hostname"] = v.group("vhost").split(":")[0]
        if v.group("vport"):
            r.fields["dst_port"] = v.group("vport")
        return r


# HAProxy "option httplog": [syslog prefix] haproxy[pid]: client:port [accept_date] frontend backend/server
#   Tq/Tw/Tc/Tr/Tt status bytes req_cookie res_cookie term_state conns queues [{req_hdrs}] [{res_hdrs}] "request"
_HAPROXY = re.compile(
    r"^(?:.*?\s)?haproxy\[\d+\]:\s+(?P<client>\[?[0-9A-Fa-f.:]+?\]?):(?P<cport>\d+)\s+\[(?P<time>[^\]]+)\]\s+"
    r"(?P<frontend>\S+)\s+(?P<backend>[^/\s]+)/(?P<server>\S+)\s+(?P<timers>[-+\d/]+)\s+(?P<status>-?\d{1,3})\s+"
    r"(?P<bytes>\+?\d+)\s+\S+\s+\S+\s+(?P<term>\S{4})\s+(?P<conns>[-+\d/]+)\s+(?P<queues>[\d/]+)\s+"
    r"(?:\{(?P<req_hdrs>[^}]*)\}\s+)?(?:\{(?P<res_hdrs>[^}]*)\}\s+)?\"(?P<request>[^\"]*)\"")


class HAProxyHttpParser(BaseParser):
    id = "haproxy_http"
    product = "haproxy"
    data_source = "web"
    event_type = "http_access"

    def parse_line(self, line: str) -> ParseResult:
        m = _HAPROXY.match(line.rstrip("\r\n"))
        if not m:
            return Failed("does not match HAProxy HTTP log format")
        g = m.groupdict()
        f = {"src_ip": g["client"].strip("[]"), "src_port": g["cport"], "timestamp_raw": g["time"],
             "status_code": None if g["status"].startswith("-") else g["status"], "bytes_out": g["bytes"].lstrip("+")}
        rf = _request_fields(g["request"])
        ext: dict = {"frontend": g["frontend"], "backend": g["backend"], "server": g["server"], "timers": g["timers"],
                     "termination_state": g["term"], "connections": g["conns"], "queues": g["queues"]}
        if "ext_request" in rf:
            ext["request"] = rf.pop("ext_request")
        f.update(rf)
        timers = g["timers"].split("/")
        if len(timers) == 5 and timers[-1].lstrip("+").isdigit():
            ext["request_time"] = int(timers[-1].lstrip("+")) / 1000  # Tt, milliseconds
        # Captured request headers keep the configured order; take only values that look like a host or a client.
        for part in (g.get("req_hdrs") or "").split("|"):
            p = part.strip()
            if not p:
                continue
            if "user_agent" not in f and (" " in p or "/" in p) and re.search(r"[A-Za-z]", p):
                f["user_agent"] = p
            elif "hostname" not in f and re.fullmatch(r"[A-Za-z0-9.\-]+(?::\d+)?", p):
                f["hostname"] = p.split(":")[0]
        if g.get("req_hdrs"):
            ext["captured_request_headers"] = g["req_hdrs"][:1024]
        return Parsed(f, ext)


def _lower_flat(d: dict, prefix: str = "", out: dict | None = None, depth: int = 0) -> dict:
    out = {} if out is None else out
    for k, v in d.items():
        key = f"{prefix}{str(k).lower()}"
        if isinstance(v, dict) and depth < 4:
            _lower_flat(v, key + ".", out, depth + 1)
        else:
            out[key] = v
    return out


def _first(d: dict, *keys):
    for k in keys:
        v = d.get(k)
        if isinstance(v, list):
            v = v[0] if v else None
        if v not in (None, "", "-"):
            return v
    return None


_JSON_SRC = ("remote_addr", "remote_ip", "request.remote_ip", "request.client_ip", "client_ip", "clientip", "c-ip",
             "http.request.remote_ip", "source.ip", "client.ip")
_JSON_STATUS = ("status", "status_code", "response.status", "http.response.status_code", "resp.status")
_JSON_REQ = ("request", "request.uri", "request_uri", "uri", "url.original", "url.path", "path", "request.method",
             "method", "request_method", "http.request.method")


class WebJsonAccessParser(BaseParser):
    """One JSON object per request: Nginx log_format escape=json, Caddy access log, Apache/ECS-style JSON."""
    id = "web_json_access"
    product = "web_json"
    data_source = "web"
    event_type = "http_access"

    def detect(self, sample: list[str]) -> float:
        lines = [s for s in sample if s.strip()]
        if not lines:
            return 0.0
        return 0.98 * sum(1 for s in lines if isinstance(self.parse_line(s), Parsed)) / len(lines)

    def parse_line(self, line: str) -> ParseResult:
        s = line.strip()
        if not s.startswith("{"):
            return Failed("not a JSON object")
        try:
            raw = orjson.loads(s)
        except orjson.JSONDecodeError:
            return Failed("invalid JSON")
        if not isinstance(raw, dict):
            return Failed("not a JSON object")
        d = _lower_flat(raw)
        src, status = _first(d, *_JSON_SRC), _first(d, *_JSON_STATUS)
        if src is None or status is None or _first(d, *_JSON_REQ) is None:
            return Failed("not a web access record (client address, request and status are needed)")
        f: dict = {"src_ip": str(src), "status_code": str(status)}
        req = _first(d, "request") if isinstance(d.get("request"), str) else None
        if req:
            rf = _request_fields(req)
            if "ext_request" in rf:
                rf = {"uri": req}
            f.update(rf)
        f.setdefault("method", _first(d, "request.method", "method", "request_method", "http.request.method"))
        if not f.get("uri"):
            path = _first(d, "request.uri", "request_uri", "uri", "url.original", "url.path", "path")
            query = _first(d, "query_string", "args", "url.query")
            f["uri"] = (str(path) if path else None) and (str(path) + (f"?{query}" if query and "?" not in str(path) else ""))
        ts = _first(d, "time_iso8601", "time_local", "@timestamp", "timestamp", "time", "ts", "msec")
        f["timestamp_raw"] = None if ts is None else str(ts)
        f["bytes_out"] = _first(d, "body_bytes_sent", "bytes_sent", "size", "response.size", "http.response.body.bytes")
        f["bytes_in"] = _first(d, "request_length", "bytes_read", "request.size")
        f["user_agent"] = _first(d, "http_user_agent", "user_agent", "request.headers.user-agent", "user_agent.original")
        f["hostname"] = _first(d, "host", "server_name", "request.host", "http_host", "url.domain")
        f["user"] = _first(d, "remote_user", "user_id", "user.name")
        proto = _first(d, "server_protocol", "request.proto", "protocol")
        if proto and not f.get("protocol"):
            f["protocol"] = str(proto).lower()
        f = {k: v for k, v in f.items() if v is not None}
        # ext.web_json is a typed namespace: every kept value is text under a dot-free key, so records from servers
        # that write a field as a number in one line and "-" in the next never conflict in the index mapping.
        ext = {k.replace(".", "_"): str(v) for k, v in d.items()
               if not isinstance(v, (dict, list)) and v is not None and k not in ("request_time",)}
        rt = _first(d, "request_time", "duration", "upstream_response_time")
        try:
            if rt is not None:
                ext["request_time"] = float(rt)
        except (TypeError, ValueError):
            pass
        return Parsed(f, dict(list(ext.items())[:120]))


_MON = {m: i for i, m in enumerate(("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1)}
# [Tue Nov 03 01:10:00.123456 2026] [module:level] [pid N(:tid N)] [client ip:port] message
_APACHE_ERR = re.compile(
    r"^\[(?:\w{3}\s+)?(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<hms>\d{2}:\d{2}:\d{2})(?P<frac>\.\d+)?\s+(?P<year>\d{4})\]\s+"
    r"\[(?:(?P<module>[\w\-]*):)?(?P<level>[a-z]+\d?)\]\s+(?:\[pid\s+(?P<pid>\d+)(?::tid\s+\d+)?\]\s+)?"
    r"(?:\[client\s+(?P<client>[^\]]+)\]\s+)?(?P<msg>.*)$")
_MODSEC = re.compile(r'\[(id|msg|uri|severity|hostname|unique_id|data|tag)\s+"((?:[^"\\]|\\.)*)"\]')


def _split_client(value: str) -> tuple[str, str | None]:
    v = value.strip()
    if v.startswith("["):  # [ipv6]:port
        host, _, port = v[1:].partition("]:")
        return host, port or None
    if v.count(":") == 1:
        host, port = v.split(":")
        return host, port if port.isdigit() else None
    return v, None


class ApacheErrorParser(BaseParser):
    """Apache 2.4 error_log, including ModSecurity messages written there."""
    id = "apache_error"
    product = "apache"
    data_source = "web"
    event_type = "http_error"

    def parse_line(self, line: str) -> ParseResult:
        m = _APACHE_ERR.match(line.rstrip("\r\n"))
        if not m or m.group("mon") not in _MON:
            return Failed("does not match Apache error log format")
        g = m.groupdict()
        f: dict = {"timestamp_raw": f"{g['year']}-{_MON[g['mon']]:02d}-{int(g['day']):02d}T{g['hms']}{g.get('frac') or ''}",
                   "severity": g["level"]}
        if g.get("client"):
            f["src_ip"], port = _split_client(g["client"])
            if port:
                f["src_port"] = port
        msg = g["msg"]
        ext: dict = {"module": g.get("module") or "", "level": g["level"], "message": msg[:2048]}
        if g.get("pid"):
            ext["pid"] = g["pid"]
        code = re.match(r"(AH\d{5}):", msg)
        if code:
            ext["error_code"] = code.group(1)
        tags = {k: v for k, v in _MODSEC.findall(msg)}
        if "ModSecurity" in msg or "id" in tags and "msg" in tags:
            f["data_source"], f["event_type"] = "waf", "waf_event"
            ext.update({f"modsecurity_{k}": v for k, v in tags.items()})
            if tags.get("uri"):
                f["uri"] = tags["uri"]
            if tags.get("hostname"):
                f["hostname"] = tags["hostname"]
            f["action"] = "blocked" if re.search(r"Access denied with code (\d{3})", msg) else "detected"
            sc = re.search(r"Access denied with code (\d{3})", msg)
            if sc:
                f["status_code"] = sc.group(1)
        else:
            path = re.search(r"(?:: |file )(/[^\s,]+)", msg)
            if path:
                ext["file_path"] = path.group(1)  # a file on the server, not the requested URL
            ref = re.search(r", referer: (\S+)", msg)
            if ref:
                ext["referer"] = ref.group(1)
        return Parsed(f, ext)


# 2026/11/03 01:10:00 [error] 1234#0: *5 message, client: ip, server: name, request: "GET / HTTP/1.1", host: "h"
_NGINX_ERR = re.compile(r"^(?P<time>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[(?P<level>[a-z]+)\] (?P<pid>\d+)#(?P<tid>\d+): "
                        r"(?:\*(?P<cid>\d+) )?(?P<msg>.*)$")
_NGINX_KV = re.compile(r', (client|server|request|upstream|host|referrer): ("(?:[^"\\]|\\.)*"|[^,]*)')


class NginxErrorParser(BaseParser):
    id = "nginx_error"
    product = "nginx"
    data_source = "web"
    event_type = "http_error"

    def parse_line(self, line: str) -> ParseResult:
        m = _NGINX_ERR.match(line.rstrip("\r\n"))
        if not m:
            return Failed("does not match Nginx error log format")
        g = m.groupdict()
        body = g["msg"]
        kv = {k: v.strip('"') for k, v in _NGINX_KV.findall(body)}
        cut = _NGINX_KV.search(body)
        message = body[:cut.start()] if cut else body
        f: dict = {"timestamp_raw": g["time"], "severity": g["level"]}
        if kv.get("client"):
            f["src_ip"] = kv["client"]
        if kv.get("request"):
            rf = _request_fields(kv["request"])
            rf.pop("ext_request", None)
            f.update({k: v for k, v in rf.items() if v})
        if kv.get("host"):
            f["hostname"] = kv["host"].split(":")[0]
        ext: dict = {"level": g["level"], "message": message[:2048], "pid": g["pid"]}
        if g.get("cid"):
            ext["connection"] = g["cid"]
        for k in ("server", "upstream", "referrer"):
            if kv.get(k):
                ext[k] = kv[k]
        kind = next((name for name, rx in _NGINX_KINDS if rx.search(message)), None)
        if kind:
            ext["error_kind"] = kind
        return Parsed(f, ext)


_NGINX_KINDS = [("file_not_found", re.compile(r"No such file or directory|is not found")),
                ("access_forbidden", re.compile(r"access forbidden by rule|directory index of .* is forbidden")),
                ("rate_limited", re.compile(r"limiting requests|limiting connections")),
                ("upstream_failure", re.compile(r"upstream (timed out|prematurely closed)|connect\(\) failed|no live upstreams")),
                ("auth_failure", re.compile(r"user \".*\": password mismatch|was not found in")),
                ("request_too_large", re.compile(r"client intended to send too large body"))]


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
                f[self.MAP[k]] = v if self.MAP[k] == "user_agent" else (None if v == "-" else v)
            elif k not in ("date", "time"):
                ext[k] = v
        if "date" in row and "time" in row:
            f["timestamp_raw"] = f"{row['date']}T{row['time']}Z"  # IIS logs are UTC by default
        stem, q = f.pop("_stem", None), f.pop("_query", None)
        f["uri"] = (stem or "") + (f"?{q}" if q else "")
        if f.get("user_agent"):
            f["user_agent"] = f["user_agent"].replace("+", " ")
        return Parsed(f, ext)
