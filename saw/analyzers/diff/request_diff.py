"""Request Diff & Evolution (docs/18)."""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

from saw.analyzers.http.analyze import analyze_response
from saw.analyzers.http.parser import extract_params, parse_request, split_request_response

VERSION = "diff/1.0.0"
BYPASS_HEADERS = {"x-forwarded-for", "x-original-url", "x-rewrite-url", "x-http-method-override", "origin",
                  "referer", "x-real-ip", "x-forwarded-host", "x-custom-ip-authorization", "client-ip"}
AUTH_HEADERS = {"authorization", "cookie"}


@dataclass
class Canon:
    idx: int
    method: str
    path: str
    segments: list[str]
    params: list[dict]
    headers: dict[str, str]
    body_kind: str
    body_size: int
    body_hash: str
    status: int | None = None
    resp_size: int | None = None
    error_sig: str | None = None
    raw: str = ""
    partial: bool = False

    def to_dict(self) -> dict:
        return {"idx": self.idx, "method": self.method, "path": self.path, "params": self.params,
                "headers": {k: ("●●●●" if k in AUTH_HEADERS else v) for k, v in self.headers.items()},
                "body": {"kind": self.body_kind, "size": self.body_size}, "status": self.status,
                "response_size": self.resp_size, "error_signature": self.error_sig, "partial": self.partial}


@dataclass
class Change:
    type: str
    field: str
    before: str | None = None
    after: str | None = None
    detail: str = ""


@dataclass
class Transition:
    from_idx: int
    to_idx: int
    changes: list[Change] = field(default_factory=list)
    bypass: bool = False
    bypass_reason: str = ""


def split_requests(blob: str) -> list[str]:
    """Split pasted text into request(+response) chunks: '###' separators, or request-line starts."""
    if "\n###" in blob or blob.startswith("###"):
        parts = re.split(r"(?m)^###.*$", blob)
    else:
        starts = [m.start() for m in re.finditer(r"(?m)^(?:[A-Z]{3,10} \S+ HTTP/\d|curl )", blob)]
        if not starts:
            return [blob]
        starts.append(len(blob))
        parts = [blob[a:b] for a, b in zip(starts, starts[1:], strict=False)]
    return [p.strip("\n") for p in parts if p.strip()]


def canonicalize(raw: str, idx: int) -> Canon:
    req_txt, resp_txt = split_request_response(raw)
    req = parse_request(req_txt)
    if req is None:
        raise ValueError(f"request #{idx + 1} is not a recognizable HTTP request")
    params = [{"name": p.name, "location": p.location, "value": p.value, "path": p.path}
              for p in extract_params(req) if p.location != "header"]
    headers = {}
    for k, v in req.headers:
        lk = k.lower()
        headers[lk] = hashlib.sha256(v.encode()).hexdigest()[:12] if lk in AUTH_HEADERS else v
    ct = (req.header("content-type") or "").split(";")[0].strip().lower()
    body_kind = "none" if not req.body.strip() else ("json" if "json" in ct or req.body.strip()[:1] in "{[" else
                                                    "xml" if "xml" in ct else "form" if "form" in ct else "raw")
    c = Canon(idx, req.method, req.path, [s for s in req.path.split("/") if s], params, headers, body_kind,
              len(req.body), hashlib.sha256(req.body.encode()).hexdigest()[:12], raw=raw)
    if resp_txt:
        r = analyze_response(resp_txt)
        if r:
            c.status, c.resp_size = r["status"], r["size"]
            c.error_sig = r["error_signatures"][0]["kind"] if r["error_signatures"] else None
    return c


def from_event(ev: dict, idx: int) -> Canon:
    """Partial canonical request built from a log event (no headers/body)."""
    from saw.analyzers.log.normalize import uri_template

    path, _, params, _ = uri_template(ev.get("uri") or "")
    return Canon(idx, ev.get("method") or "", path or "", [s for s in (path or "").split("/") if s],
                 [{"name": k, "location": "query", "value": v, "path": ""} for k, v in params.items()],
                 {"user-agent": ev.get("user_agent") or ""}, "none", 0, "", ev.get("status_code"),
                 ev.get("bytes_out"), None, raw=ev.get("raw_event", ""), partial=True)


def _numdelta(a: str, b: str) -> str:
    if re.fullmatch(r"-?\d+", a or "") and re.fullmatch(r"-?\d+", b or ""):
        d = int(b) - int(a)
        return f"{d:+d}"
    return ""


def diff(a: Canon, b: Canon) -> list[Change]:
    ch: list[Change] = []
    if a.method != b.method:
        ch.append(Change("METHOD_SWITCH", "method", a.method, b.method))
    if a.path != b.path:
        if a.path.lower() == b.path.lower():
            ch.append(Change("CASE_VARIATION", "path", a.path, b.path))
        else:
            ch.append(Change("PATH_CHANGE", "path", a.path, b.path))
    pa = {(p["location"], p["name"]): p["value"] for p in a.params}
    pb = {(p["location"], p["name"]): p["value"] for p in b.params}
    used_b: set = set()
    for (la, na), va in pa.items():
        if (la, na) in pb:
            used_b.add((la, na))
            vb = pb[(la, na)]
            if va != vb:
                import urllib.parse as up

                if up.unquote(up.unquote(va)) == up.unquote(up.unquote(vb)):
                    ch.append(Change("ENCODING_CHANGE", f"{la}.{na}", va, vb))
                else:
                    ch.append(Change("PARAM_VALUE_CHANGE", f"{la}.{na}", va, vb, _numdelta(va, vb)))
            continue
        moved = [(lb, nb) for (lb, nb), vb in pb.items() if nb == na and lb != la and (lb, nb) not in used_b]
        if moved:
            used_b.add(moved[0])
            ch.append(Change("PARAM_LOCATION_MOVE", na, la, moved[0][0]))
            continue
        renamed = [(lb, nb) for (lb, nb), vb in pb.items() if vb == va and lb == la and (lb, nb) not in used_b
                   and (lb, nb) not in pa]
        if renamed:
            used_b.add(renamed[0])
            ch.append(Change("PARAM_RENAME", f"{la}", na, renamed[0][1]))
            continue
        ch.append(Change("PARAM_REMOVED", f"{la}.{na}", va, None))
    for (lb, nb), vb in pb.items():
        if (lb, nb) not in used_b and (lb, nb) not in pa:
            ch.append(Change("PARAM_ADDED", f"{lb}.{nb}", None, vb))
    for h in sorted(set(a.headers) | set(b.headers)):
        if h in ("content-length", "host") and h in a.headers and h in b.headers:
            continue
        ha, hb = a.headers.get(h), b.headers.get(h)
        if ha == hb:
            continue
        if h in AUTH_HEADERS:
            ch.append(Change("AUTH_CHANGE", h, "●●●●" if ha else None, "●●●●" if hb else None, "value hash changed"))
        elif ha is None:
            ch.append(Change("HEADER_ADDED", h, None, hb, "bypass-relevant header" if h in BYPASS_HEADERS else ""))
        elif hb is None:
            ch.append(Change("HEADER_REMOVED", h, ha, None))
        else:
            ch.append(Change("HEADER_CHANGED", h, ha, hb, "bypass-relevant header" if h in BYPASS_HEADERS else ""))
    if (a.body_kind, a.body_hash) != (b.body_kind, b.body_hash) and not (a.partial or b.partial):
        ch.append(Change("BODY_CHANGE", "body", f"{a.body_kind}/{a.body_size}B", f"{b.body_kind}/{b.body_size}B"))
    if a.status != b.status or (a.resp_size and b.resp_size and a.resp_size != b.resp_size):
        ratio = ""
        if a.resp_size and b.resp_size:
            ratio = f"size ×{b.resp_size / a.resp_size:.1f}"
        ch.append(Change("RESPONSE_CHANGE", "response", f"{a.status} / {a.resp_size}", f"{b.status} / {b.resp_size}",
                         ratio))
    return ch


def _is_fail(s: int | None) -> bool:
    return s is not None and 400 <= s < 500


def _is_ok(s: int | None) -> bool:
    return s is not None and 200 <= s < 300


STRATEGY_LABELS = {
    "PARAM_RENAME": "parameter renaming", "METHOD_SWITCH": "method switching",
    "PARAM_LOCATION_MOVE": "parameter location move", "ENCODING_CHANGE": "encoding change",
    "HEADER_ADDED": "header injection", "HEADER_CHANGED": "header manipulation", "CASE_VARIATION": "case variation",
    "PATH_CHANGE": "path variation", "AUTH_CHANGE": "credential/session change",
    "PARAM_VALUE_CHANGE": "value iteration",
}


def evolution(canons: list[Canon]) -> dict:
    trans: list[Transition] = []
    counts: dict[str, int] = {}
    for a, b in zip(canons, canons[1:], strict=False):
        t = Transition(a.idx, b.idx, diff(a, b))
        if _is_fail(a.status) and _is_ok(b.status):
            t.bypass, t.bypass_reason = True, f"{a.status} → {b.status}"
        elif a.resp_size and b.resp_size and b.resp_size >= 3 * a.resp_size and _is_ok(b.status):
            t.bypass, t.bypass_reason = True, f"response size ×{b.resp_size / a.resp_size:.1f}"
        for c in t.changes:
            counts[c.type] = counts.get(c.type, 0) + 1
        trans.append(t)
    strat = [STRATEGY_LABELS[k] for k, _ in sorted(counts.items(), key=lambda x: -x[1]) if k in STRATEGY_LABELS]
    cumulative = [{"idx": c.idx, "changes": [vars(x) for x in diff(canons[0], c)]} for c in canons[1:]]
    return {
        "requests": [c.to_dict() for c in canons],
        "transitions": [{"from": t.from_idx, "to": t.to_idx, "changes": [vars(c) for c in t.changes],
                         "bypass": t.bypass, "bypass_reason": t.bypass_reason} for t in trans],
        "cumulative_vs_first": cumulative,
        "bypass_points": [{"from": t.from_idx, "to": t.to_idx, "reason": t.bypass_reason} for t in trans if t.bypass],
        "strategy": (" + ".join(strat[:3]) + " based variation") if strat else None,
        "change_counts": counts,
        "meta": {"analyzer_version": VERSION},
    }


def analyze_diff(raw_requests: list[str]) -> dict:
    if len(raw_requests) == 1:
        raw_requests = split_requests(raw_requests[0])
    if not 2 <= len(raw_requests) <= 200:
        raise ValueError("Request Diff requires 2–200 requests")
    return evolution([canonicalize(r, i) for i, r in enumerate(raw_requests)])
