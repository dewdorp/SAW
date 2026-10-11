"""Lenient HTTP request/response parsing (docs/17 §1-2).

Accepts raw HTTP/1.x (LF or CRLF), HTTP/2 pseudo-headers, `curl` command lines and HAR entries.
Never fetches anything; output values for sensitive headers/cookies are masked.
"""
from __future__ import annotations

import json
import re
import shlex
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

from defusedxml import ElementTree as SafeET

from saw.core.security.masking import SENSITIVE_HEADERS, mask_value

_REQ_LINE = re.compile(r"^([A-Z][A-Z0-9_-]{1,15})\s+(\S+)(?:\s+(HTTP/\d(?:\.\d)?))?\s*$")
_RESP_LINE = re.compile(r"^(HTTP/\d(?:\.\d)?)\s+(\d{3})(?:\s+(.*))?$")
METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT", "PROPFIND", "MKCOL",
           "PROPPATCH", "COPY", "MOVE", "LOCK", "UNLOCK", "SEARCH", "DEBUG"}


@dataclass
class Param:
    name: str
    value: str
    location: str  # query|form|json|xml|multipart|cookie|header|path
    path: str = ""  # e.g. $.user.id

    def key(self) -> str:
        return f"{self.location}:{self.path or self.name}"


@dataclass
class HttpRequest:
    method: str = ""
    target: str = ""
    version: str = ""
    scheme: str = ""
    host: str = ""
    port: int | None = None
    path: str = ""
    query: str = ""
    fragment: str = ""
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: str = ""
    anomalies: list[dict] = field(default_factory=list)

    def header(self, name: str) -> str | None:
        n = name.lower()
        for k, v in self.headers:
            if k.lower() == n:
                return v
        return None

    def header_all(self, name: str) -> list[str]:
        n = name.lower()
        return [v for k, v in self.headers if k.lower() == n]


@dataclass
class HttpResponse:
    version: str = ""
    status: int = 0
    reason: str = ""
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: str = ""

    def header(self, name: str) -> str | None:
        n = name.lower()
        for k, v in self.headers:
            if k.lower() == n:
                return v
        return None


def _split_head_body(text: str) -> tuple[list[str], str]:
    t = text.replace("\r\n", "\n")
    head, sep, body = t.partition("\n\n")
    return head.split("\n"), body


def _parse_headers(lines: list[str], anomalies: list[dict]) -> list[tuple[str, str]]:
    headers: list[tuple[str, str]] = []
    for ln in lines:
        if not ln.strip():
            continue
        if ln[0] in " \t" and headers:  # obs-fold
            k, v = headers[-1]
            headers[-1] = (k, v + " " + ln.strip())
            anomalies.append({"code": "obs_fold", "detail": "obsolete header line folding"})
            continue
        if ":" not in ln[1:]:
            anomalies.append({"code": "malformed_header", "detail": ln[:120]})
            continue
        if ln.startswith(":"):  # HTTP/2 pseudo header
            k, _, v = ln[1:].partition(":")
            headers.append((":" + k.strip(), v.strip()))
            continue
        k, _, v = ln.partition(":")
        if k != k.strip() or not re.fullmatch(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+", k.strip()):
            anomalies.append({"code": "invalid_header_name", "detail": k[:60]})
        headers.append((k.strip(), v.strip()))
    return headers


def _from_curl(text: str) -> str | None:
    s = text.strip()
    if not s.lower().startswith("curl "):
        return None
    s = s.replace("\\\n", " ").replace("^\n", " ")
    try:
        toks = shlex.split(s, posix=True)
    except ValueError:
        return None
    method, url, headers, data = None, None, [], None
    i = 1
    while i < len(toks):
        t = toks[i]
        if t in ("-X", "--request"):
            method = toks[i + 1]
            i += 2
        elif t in ("-H", "--header"):
            headers.append(toks[i + 1])
            i += 2
        elif t in ("-d", "--data", "--data-raw", "--data-binary", "--data-urlencode"):
            data = toks[i + 1]
            i += 2
        elif t in ("-b", "--cookie"):
            headers.append(f"Cookie: {toks[i + 1]}")
            i += 2
        elif t in ("-A", "--user-agent"):
            headers.append(f"User-Agent: {toks[i + 1]}")
            i += 2
        elif t.startswith("-"):
            i += 1
        else:
            url = t
            i += 1
    if not url:
        return None
    u = urllib.parse.urlsplit(url)
    target = (u.path or "/") + (f"?{u.query}" if u.query else "")
    method = method or ("POST" if data is not None else "GET")
    lines = [f"{method} {target} HTTP/1.1", f"Host: {u.netloc}"] + headers
    return "\n".join(lines) + "\n\n" + (data or "")


def _from_har(text: str) -> tuple[str | None, str | None]:
    try:
        d = json.loads(text)
    except ValueError:
        return None, None
    entry = d.get("log", {}).get("entries", [d])[0] if isinstance(d, dict) else None
    if not isinstance(entry, dict) or "request" not in entry:
        return None, None
    rq = entry["request"]
    u = urllib.parse.urlsplit(rq.get("url", ""))
    lines = [f"{rq.get('method', 'GET')} {(u.path or '/')}{'?' + u.query if u.query else ''} HTTP/1.1",
             f"Host: {u.netloc}"]
    lines += [f"{h['name']}: {h['value']}" for h in rq.get("headers", []) if h.get("name", "").lower() != "host"]
    req = "\n".join(lines) + "\n\n" + (rq.get("postData", {}) or {}).get("text", "")
    resp = None
    rs = entry.get("response")
    if rs:
        rl = [f"HTTP/1.1 {rs.get('status', 0)} {rs.get('statusText', '')}"]
        rl += [f"{h['name']}: {h['value']}" for h in rs.get("headers", [])]
        resp = "\n".join(rl) + "\n\n" + (rs.get("content", {}) or {}).get("text", "")
    return req, resp


def split_request_response(text: str) -> tuple[str, str | None]:
    """A pasted blob may contain a request followed by a response."""
    m = re.search(r"(?m)^HTTP/\d(?:\.\d)?\s+\d{3}", text)
    if m and m.start() > 0:
        return text[: m.start()].rstrip("\r\n") + "\n\n", text[m.start():]
    return text, None


def parse_request(text: str) -> HttpRequest | None:
    if text.lstrip().lower().startswith("curl "):
        text = _from_curl(text) or text
    elif text.lstrip().startswith("{"):
        r, _ = _from_har(text)
        if r:
            text = r
    lines, body = _split_head_body(text.lstrip("\r\n"))
    if not lines:
        return None
    req = HttpRequest()
    m = _REQ_LINE.match(lines[0].strip())
    if m and m.group(1) in METHODS:
        req.method, req.target, req.version = m.group(1), m.group(2), m.group(3) or ""
        hdr_lines = lines[1:]
        if not m.group(3):
            req.anomalies.append({"code": "missing_http_version", "detail": "request line without HTTP version"})
    elif lines[0].startswith(":"):
        hdr_lines = lines
        req.version = "HTTP/2"
    else:
        return None
    req.headers = _parse_headers(hdr_lines, req.anomalies)
    if req.version == "HTTP/2" or not req.method:
        req.method = req.header(":method") or req.method
        req.target = req.header(":path") or req.target
        req.scheme = req.header(":scheme") or ""
        if req.header(":authority"):
            req.headers.append(("Host", req.header(":authority") or ""))
    if not req.method:
        return None
    req.body = body
    t = req.target
    if re.match(r"(?i)^https?://", t):
        u = urllib.parse.urlsplit(t)
        req.scheme, host_port, path = u.scheme, u.netloc, u.path or "/"
        req.query, req.fragment = u.query, u.fragment
    else:
        host_port = req.header("host") or ""
        path, _, rest = t.partition("?")
        req.query, _, req.fragment = rest.partition("#")
    if ":" in host_port and not host_port.startswith("["):
        h, _, p = host_port.rpartition(":")
        req.host, req.port = h, int(p) if p.isdigit() else None
    else:
        req.host = host_port
    req.path = path
    if not req.scheme:
        req.scheme = "https" if req.port == 443 else "http" if req.port else ""
    # anomalies
    hosts = req.header_all("host")
    if len(hosts) > 1:
        req.anomalies.append({"code": "duplicate_host", "detail": "Duplicate header: Host"})
    if req.header("content-length") and req.header("transfer-encoding"):
        req.anomalies.append({"code": "cl_te_conflict",
                              "detail": "Content-Length + Transfer-Encoding both present (request smuggling indicator)"})
    if len(req.header_all("content-length")) > 1:
        req.anomalies.append({"code": "duplicate_content_length", "detail": "Duplicate Content-Length"})
    for h in ("x-original-url", "x-rewrite-url", "x-http-method-override", "x-http-method", "x-method-override"):
        if req.header(h):
            req.anomalies.append({"code": "override_header", "detail": f"{h}: {req.header(h)[:80]}"})
    if "\n" in text and "\r\n" not in text:
        req.anomalies.append({"code": "lf_only", "detail": "LF line endings (copied or non-standard)"})
    return req


def parse_response(text: str) -> HttpResponse | None:
    lines, body = _split_head_body(text.lstrip("\r\n"))
    if not lines:
        return None
    m = _RESP_LINE.match(lines[0].strip())
    if not m:
        return None
    r = HttpResponse(version=m.group(1), status=int(m.group(2)), reason=(m.group(3) or "").strip())
    r.headers = _parse_headers(lines[1:], [])
    r.body = body
    return r


# ---------------------------------------------------------------- parameters
def _flatten_json(obj: Any, path: str, out: list[Param], depth: int = 0) -> None:
    if depth > 32:
        return
    if isinstance(obj, dict):
        for k, v in list(obj.items())[:500]:
            _flatten_json(v, f"{path}.{k}", out, depth + 1)
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:200]):
            _flatten_json(v, f"{path}[{i}]", out, depth + 1)
    else:
        name = re.sub(r"\[\d+\]$", "", path.rsplit(".", 1)[-1])
        out.append(Param(name, "" if obj is None else str(obj), "json", path))


def extract_params(req: HttpRequest) -> list[Param]:
    ps: list[Param] = []
    for k, v in urllib.parse.parse_qsl(req.query, keep_blank_values=True):
        ps.append(Param(k, v, "query"))
    if req.query and not ps:
        ps.append(Param("", req.query, "query"))
    for i, seg in enumerate([s for s in req.path.split("/") if s]):
        if re.fullmatch(r"\d+|[0-9a-fA-F-]{32,36}", seg):
            ps.append(Param(f"path[{i}]", seg, "path"))
    ct = (req.header("content-type") or "").lower()
    body = req.body.strip()
    if body:
        if "json" in ct or body[:1] in "{[":
            try:
                _flatten_json(json.loads(body), "$", ps)
            except ValueError:
                ps.append(Param("body", body[:4096], "form" if "=" in body else "json"))
        elif "xml" in ct or body.startswith("<"):
            try:
                root = SafeET.fromstring(body.encode())
                for el in root.iter():
                    if el.text and el.text.strip():
                        ps.append(Param(el.tag, el.text.strip(), "xml", el.tag))
                    for ak, av in el.attrib.items():
                        ps.append(Param(f"{el.tag}@{ak}", av, "xml"))
            except Exception:  # noqa: BLE001 - malformed/hostile XML is just text
                ps.append(Param("body", body[:4096], "xml"))
        elif "multipart/form-data" in ct:
            m = re.search(r"boundary=\"?([^\";]+)", ct, re.I)
            if m:
                for part in body.split("--" + m.group(1)):
                    nm = re.search(r'name="([^"]+)"', part)
                    if nm:
                        _, _, val = part.replace("\r\n", "\n").partition("\n\n")
                        ps.append(Param(nm.group(1), val.strip()[:4096], "multipart"))
        else:
            for k, v in urllib.parse.parse_qsl(body, keep_blank_values=True):
                ps.append(Param(k, v, "form"))
    for c in req.header_all("cookie"):
        for kv in c.split(";"):
            if "=" in kv:
                k, _, v = kv.strip().partition("=")
                ps.append(Param(k, v, "cookie"))
    for h in ("referer", "x-forwarded-for", "x-real-ip", "user-agent", "origin", "x-forwarded-host"):
        v = req.header(h)
        if v:
            ps.append(Param(h, v, "header"))
    return ps


def display_headers(headers: list[tuple[str, str]]) -> list[dict]:
    out = []
    for k, v in headers:
        masked = k.lower() in SENSITIVE_HEADERS
        out.append({"name": k, "value": mask_value(v) if masked else v, "masked": masked})
    return out
