"""HTTP Analyzer entry point (pure function)."""
from __future__ import annotations

import json
import re

from saw.analyzers.http.parser import (
    HttpRequest, display_headers, extract_params, parse_request, parse_response, split_request_response,
)
from saw.analyzers.http.useragent import classify_ua
from saw.analyzers.patterns import scan_value
from saw.analyzers.payload.transforms import TransformError, auto_decode, t_jwt
from saw.core.security.masking import mask_text, mask_value

VERSION = "http/1.0.0"

_ENCODED_HINT = re.compile(r"%[0-9a-fA-F]{2}|&#?\w+;|\\u[0-9a-fA-F]{4}|^[A-Za-z0-9+/_-]{16,}={0,2}$")
_ERROR_SIGS = [
    (re.compile(r"(?i)(SQL syntax|mysql_fetch|ORA-\d{5}|PostgreSQL.*ERROR|SQLSTATE\[|Unclosed quotation mark|"
                r"sqlite3?\.|ODBC|JDBC|SQLException)"), "sql_error"),
    (re.compile(r"(?i)(Traceback \(most recent call last\)|at [\w.$]+\([\w]+\.java:\d+\)|"
                r"Exception in thread|System\.\w+Exception|Fatal error:.*on line \d+)"), "stack_trace"),
    (re.compile(r"(?i)(root:x:0:0:|\[boot loader\]|\[extensions\])"), "file_content_leak"),
]


def _type_guess(v: str) -> str:
    if re.fullmatch(r"-?\d+", v):
        return "numeric"
    if re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", v):
        return "uuid"
    if re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}(,\s*(\d{1,3}\.){3}\d{1,3})*", v):
        return "ip"
    if v.startswith("eyJ") and v.count(".") == 2:
        return "jwt"
    if re.fullmatch(r"[^@\s]+@[^@\s]+\.[a-zA-Z]{2,}", v):
        return "email"
    if re.fullmatch(r"[0-9a-fA-F]{16,}", v):
        return "hex"
    if re.fullmatch(r"(?i)(true|false)", v):
        return "bool"
    if len(v) >= 20 and re.fullmatch(r"[A-Za-z0-9+/_=-]+", v):
        return "token"
    return "string"


def jwt_info(token: str) -> dict | None:
    try:
        d = json.loads(t_jwt(token))
    except (TransformError, ValueError):
        return None
    warnings = []
    alg = str(d["header"].get("alg", "")).lower()
    if alg in ("none", ""):
        warnings.append("alg=none (서명 없음)")
    elif alg.startswith("hs"):
        warnings.append(f"symmetric alg {alg.upper()} (키 추측 공격 대상 여부 확인)")
    if "kid" in d["header"] and re.search(r"[./\\'\"]", str(d["header"]["kid"])):
        warnings.append("suspicious kid value")
    exp = d["payload"].get("exp")
    if isinstance(exp, (int, float)):
        import time

        if exp < time.time():
            warnings.append("token expired")
    return {"header": d["header"], "payload": d["payload"], "warnings": warnings,
            "note": "서명은 검증하지 않음 (decode only)"}


def analyze_request(req: HttpRequest) -> dict:
    params = extract_params(req)
    ua = classify_ua(req.header("user-agent"))
    p_out, patterns = [], []
    jwts = []
    for p in params:
        raw = p.value
        chain = auto_decode(raw) if _ENCODED_HINT.search(raw) and p.location != "cookie" else None
        decoded = chain.output if chain and chain.steps else None
        hits = scan_value(decoded or raw, p.name, f"{p.location}.{p.path or p.name}")
        if decoded:
            # evidence that the payload was encoded is itself a signal
            for h in hits:
                h.evidence.append(type(h.evidence[0])("encoding", " → ".join(s.label for s in chain.steps)))
        if p.location in ("query", "form", "json", "path") and p.location != "header" and hits == []:
            pass
        patterns += hits
        masked = p.location == "cookie" or re.search(r"(?i)(pass|token|secret|session|auth|key)", p.name)
        t = _type_guess(raw)
        if t == "jwt":
            ji = jwt_info(raw)
            if ji:
                jwts.append({"location": p.key(), **ji})
        # a decoded secret is still a secret: every stage of the chain is protected like the value itself
        show = (lambda v: mask_value(v)) if masked else (lambda v: mask_text(v).text)
        p_out.append({
            "name": p.name, "location": p.location, "path": p.path,
            "value": show(raw),
            "decoded": show(decoded) if decoded else None,
            "decode_chain": [{"op": s.op, "label": s.label, "output": show(s.output[:500]), "note": s.note}
                             for s in chain.steps]
            if chain and chain.steps else [],
            "type": t, "masked": bool(masked), "flags": [h.pattern for h in hits],
        })
    auth = req.header("authorization") or ""
    m = re.match(r"(?i)bearer\s+(eyJ\S+)", auth)
    if m:
        ji = jwt_info(m.group(1))
        if ji:
            jwts.append({"location": "header.authorization", **ji})
    hints = []
    if ua["class"] in ("script", "scanner", "empty"):
        hints.append({"code": f"ua_{ua['class']}", "label": f"User-Agent class: {ua['class']}"})
    if any(p["type"] == "numeric" and p["location"] in ("query", "path", "json") for p in p_out):
        hints.append({"code": "numeric_object_id", "label": "Numeric object identifier",
                      "context_required": "Potential API Enumeration은 로그 문맥(순차성·볼륨)이 필요합니다"})
    xff = req.header("x-forwarded-for")
    if xff:
        hints.append({"code": "xff_present", "label": f"X-Forwarded-For: {xff[:80]}"})
    if any(h.pattern for h in patterns) and not req.body and req.method == "GET":
        pass
    return {
        "method": req.method, "scheme": req.scheme, "host": req.host, "port": req.port,
        "uri": mask_text(req.target).text, "path": req.path, "query": mask_text(req.query).text if req.query else req.query,
        "version": req.version,
        "headers": display_headers(req.headers),
        "user_agent": {"raw": req.header("user-agent"), **ua},
        "content_type": req.header("content-type"),
        "body": {"length": len(req.body), "preview": mask_text(req.body[:2000]).text},
        "parameters": p_out,
        "patterns": [h.to_dict() for h in patterns],
        "anomalies": req.anomalies,
        "jwt": jwts,
        "hints": hints,
    }


def analyze_response(text: str) -> dict | None:
    r = parse_response(text)
    if not r:
        return None
    sigs = [{"kind": kind, "match": m.group(0)[:120]} for rx, kind in _ERROR_SIGS if (m := rx.search(r.body))]
    mt = mask_text(r.body[:200_000])
    return {
        "status": r.status, "reason": r.reason, "version": r.version,
        "headers": display_headers(r.headers), "content_type": r.header("content-type"),
        "size": len(r.body.encode("utf-8", errors="ignore")),
        "body_preview": mt.text[:4000],  # rendered as text only; HTML is never rendered
        "error_signatures": sigs,
        "sensitive_data_kinds": sorted(set(mt.kinds)),
    }


def analyze_http(request_text: str, response_text: str | None = None) -> dict:
    if response_text is None:
        request_text, response_text = split_request_response(request_text)
    req = parse_request(request_text)
    if req is None:
        raise ValueError("input is not a recognizable HTTP request")
    out = analyze_request(req)
    resp = analyze_response(response_text) if response_text else None
    out["response"] = resp
    if resp:
        for p in out["patterns"]:
            if resp["status"] in (401, 403, 406, 429) or resp["status"] >= 500 and not resp["error_signatures"]:
                p["not_evidence"].append(f"Response {resp['status']} (blocked/failed?)")
            if resp["error_signatures"]:
                p["evidence"].append({"kind": "response_error_signature",
                                      "value": resp["error_signatures"][0]["match"], "span": None})
    out["meta"] = {"analyzer_version": VERSION}
    return out
