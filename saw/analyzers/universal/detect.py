"""Universal input detection (docs/16). Pure, deterministic, plug-in style detectors."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from saw.analyzers.http.parser import _REQ_LINE, _RESP_LINE, METHODS
from saw.analyzers.http.useragent import classify_ua
from saw.analyzers.ioc.observables import extract, refang, refang_with_map
from saw.analyzers.payload.transforms import printable_ratio

VERSION = "universal/1.0.0"


@dataclass
class Detection:
    type: str
    span: tuple[int, int]
    confidence: float
    evidence: list[str] = field(default_factory=list)
    value: str | None = None
    context: str | None = None
    scope: str | None = None

    def to_dict(self) -> dict:
        d = {"type": self.type, "span": list(self.span), "confidence": round(self.confidence, 2),
             "evidence": self.evidence}
        for k in ("value", "context", "scope"):
            if getattr(self, k) is not None:
                d[k] = getattr(self, k)
        return d


def d_http(text: str) -> list[Detection]:
    out = []
    lines = text.lstrip().splitlines()
    if not lines:
        return out
    first = lines[0].strip()
    m = _REQ_LINE.match(first)
    off = text.find(first)
    if m and m.group(1) in METHODS:
        ev = ["request-line"]
        conf = 0.85
        if re.search(r"(?im)^host:\s*\S+", text):
            ev.append("Host header")
            conf = 0.99
        out.append(Detection("http_request", (off, len(text)), conf, ev))
    elif first.lower().startswith("curl ") and re.search(r"https?://", first):
        out.append(Detection("http_request", (off, len(text)), 0.9, ["curl command"]))
    elif re.search(r"(?m)^:method:", text):
        out.append(Detection("http_request", (0, len(text)), 0.95, ["HTTP/2 pseudo-headers"]))
    mr = re.search(r"(?m)^HTTP/\d(?:\.\d)?\s+\d{3}.*$", text)
    if mr and _RESP_LINE.match(mr.group(0).strip()):
        out.append(Detection("http_response", (mr.start(), len(text)), 0.95, ["status-line"]))
    for hm in re.finditer(r"(?im)^(user-agent|x-forwarded-for|host|authorization|cookie):[ \t]*(.+)$", text):
        name = hm.group(1).lower()
        if name == "user-agent":
            c = classify_ua(hm.group(2))
            out.append(Detection("user_agent", (hm.start(2), hm.end(2)), 0.95, [f"class={c['class']}"],
                                 value=hm.group(2).strip(), context=c["class"]))
        elif name == "host":
            out.append(Detection("host", (hm.start(2), hm.end(2)), 0.99, ["Host header"], value=hm.group(2).strip()))
    if out and out[0].type == "http_request":
        qm = re.search(r"\?([^\s#]+)", first)
        if qm:
            for pm in re.finditer(r"([^&=]+)=([^&]*)", qm.group(1)):
                out.append(Detection("query_param", (off + qm.start(1) + pm.start(), off + qm.start(1) + pm.end()),
                                     0.99, ["query string"], value=pm.group(1)))
    return out


def d_iocs(text: str) -> list[Detection]:
    out = []
    refanged, imap = refang_with_map(text)
    for o in extract(refanged):
        o.span = (imap[o.span[0]], imap[o.span[1] - 1] + 1)
        ctx = None
        line_start = text.rfind("\n", 0, o.span[0]) + 1
        hdr = re.match(r"([\w-]+):", text[line_start:o.span[0]])
        if hdr:
            ctx = hdr.group(1)
        conf = 0.98 if o.type in ("ipv4", "ipv6", "url") else 0.9 if o.type == "domain" else 0.8
        ev = [f"valid {o.type}"]
        if o.type in ("md5", "sha1", "sha256", "sha512") and re.search(r"(?i)(md5|sha1|sha-?256|sha-?512|hash)",
                                                                        text[max(0, o.span[0] - 30):o.span[0]]):
            conf, ev = 0.97, ev + ["hash keyword nearby"]
        out.append(Detection(o.type, o.span, conf, ev, value=o.value, context=ctx, scope=o.scope or None))
    if refang(text) != text:
        out.append(Detection("defanged_ioc", (0, len(text)), 0.9, ["defang notation (hxxp / [.])"]))
    return out


def d_json_xml(text: str) -> list[Detection]:
    s = text.strip()
    out = []
    if s[:1] in "{[":
        try:
            json.loads(s)
            out.append(Detection("json", (text.find(s[0]), len(text)), 0.99, ["valid JSON"]))
        except ValueError:
            pass
    elif s.startswith("<") and re.search(r"</\w+>\s*$|/>\s*$", s):
        out.append(Detection("xml", (text.find("<"), len(text)), 0.85, ["markup document"]))
    return out


_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")
_B64 = re.compile(r"(?<![A-Za-z0-9+/=_-])([A-Za-z0-9+/]{16,}={0,2})(?![A-Za-z0-9+/=])")
_HEXS = re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}|(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}){12,}(?![0-9a-fA-F])")
_URLENC = re.compile(r"(?:%[0-9a-fA-F]{2}[^\s%]{0,8}){3,}")
_UNI = re.compile(r"(?:\\u[0-9a-fA-F]{4}|%u[0-9a-fA-F]{4}){2,}")
_HTMLENT = re.compile(r"(?:&(?:#\d{2,5}|#x[0-9a-fA-F]{2,4}|[a-z]{2,6});){2,}")
_PS = re.compile(r"(?i)powershell(?:\.exe)?\b.*?\s-e(?:nc(?:odedcommand)?|c)?\s+([A-Za-z0-9+/=]{16,})")


def d_encoded(text: str) -> list[Detection]:
    import base64

    out = []
    for m in _JWT.finditer(text):
        out.append(Detection("jwt", m.span(), 0.98, ["header.payload.signature (eyJ…)"]))
    jwt_spans = [m.span() for m in _JWT.finditer(text)]
    for m in _PS.finditer(text):
        out.append(Detection("powershell_encoded", m.span(1), 0.95, ["-EncodedCommand switch"]))
    for m in _B64.finditer(text):
        if any(a <= m.start() < b for a, b in jwt_spans) or re.fullmatch(r"[0-9a-fA-F]+", m.group(1)):
            continue
        t = m.group(1)
        try:
            dec = base64.b64decode(t + "=" * (-len(t) % 4))
        except Exception:  # noqa: BLE001
            continue
        try:
            dtxt = dec.decode("utf-8")
        except UnicodeDecodeError:
            try:
                dtxt = dec.decode("utf-16-le")
            except UnicodeDecodeError:
                continue
        pr = printable_ratio(dtxt)
        if pr > 0.9 or dec[:2] == b"\x1f\x8b":
            out.append(Detection("base64", m.span(1), 0.6 + 0.35 * pr, [f"decodes to printable text ({pr:.0%})"]))
    for rx, typ, why in ((_HEXS, "hex", "hex byte run"), (_URLENC, "url_encoded", "percent-encoding density"),
                         (_UNI, "unicode_escape", "\\u / %u escapes"), (_HTMLENT, "html_entity", "HTML entities")):
        for m in rx.finditer(text):
            out.append(Detection(typ, m.span(), 0.85, [why]))
    return out


def d_log(text: str) -> list[Detection]:
    from saw.parsers.registry import detect

    lines = [ln for ln in text.splitlines() if ln.strip()][:200]
    if not lines or (len(lines) == 1 and _REQ_LINE.match(lines[0].strip())):
        return []
    det = detect(lines)
    if det.confidence >= 0.6 and det.parser_id not in ("key_value",) or det.confidence >= 0.9:
        return [Detection("log_lines", (0, len(text)), det.confidence,
                          [f"parser {det.parser_id}", f"{len(lines)} line(s)"], value=det.parser_id)]
    return []


DETECTORS = [d_http, d_iocs, d_json_xml, d_encoded, d_log]

RECOMMEND = {
    "http_request": [("http", True), ("ioc", True), ("payload", False), ("related_logs", False),
                     ("similar_case", False), ("timeline", False)],
    "ipv4": [("ioc", True)], "ipv6": [("ioc", True)], "domain": [("ioc", True)], "url": [("ioc", True)],
    "md5": [("ioc", True)], "sha1": [("ioc", True)], "sha256": [("ioc", True)], "sha512": [("ioc", True)],
    "base64": [("payload", True)], "hex": [("payload", True)], "url_encoded": [("payload", True)],
    "unicode_escape": [("payload", True)], "html_entity": [("payload", True)], "jwt": [("payload", True)],
    "powershell_encoded": [("payload", True)],
    "log_lines": [("log", True), ("ioc", True)],
}


def detect_all(text: str) -> dict:
    dets: list[Detection] = []
    for fn in DETECTORS:
        try:
            dets += fn(text)
        except Exception as e:  # noqa: BLE001 - one detector failing must not break the others
            dets.append(Detection("detector_error", (0, 0), 0.0, [f"{fn.__name__}: {type(e).__name__}"]))
    types = {d.type for d in dets}
    # resolver: an HTTP request containing only url-encoded query is still primarily HTTP
    rec: dict[str, bool] = {}
    for t in types:
        for a, auto in RECOMMEND.get(t, []):
            rec[a] = rec.get(a, False) or auto
    if sum(1 for d in dets if d.type == "http_request") > 1 or len(re.findall(r"(?m)^[A-Z]{3,7} /\S* HTTP/", text)) > 1:
        rec["diff"] = False
    if "payload" in rec and "http_request" in types:
        rec["payload"] = any(t in types for t in ("base64", "url_encoded", "unicode_escape", "html_entity"))
    return {
        "detections": [d.to_dict() for d in sorted(dets, key=lambda d: (d.span[0], -d.span[1]))],
        "recommended": [{"analysis": a, "auto": auto} for a, auto in rec.items()],
        "meta": {"analyzer_version": VERSION},
    }
