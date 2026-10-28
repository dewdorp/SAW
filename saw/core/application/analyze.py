"""Synchronous paste analysis orchestration (docs/16 flow F1)."""
from __future__ import annotations

import hashlib

from sqlalchemy.orm import Session

from saw.analyzers.diff.request_diff import analyze_diff
from saw.analyzers.http.analyze import analyze_http
from saw.analyzers.ioc.analyze import analyze_observable
from saw.analyzers.payload.transforms import TransformError, apply_chain, auto_decode
from saw.analyzers.universal.detect import detect_all
from saw.core.application import audit
from saw.core.application.context import internal_context
from saw.core.security.authz import Principal
from saw.core.security.masking import mask_text
from saw.parsers.registry import parse_text

IOC_TYPES = {"ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256", "sha512"}


def _audit(s: Session, p: Principal, kind: str, text: str) -> None:
    audit.record(s, f"analyze.{kind}", actor_id=p.user_id, actor_name=p.username,
                 detail={"sha256": hashlib.sha256(text.encode()).hexdigest(), "size": len(text)})


def ioc(s: Session, p: Principal, values: list[str], with_context: bool = True,
        org_unit_id: str | None = None) -> list[dict]:
    out = []
    for v in values[:200]:
        r = analyze_observable(v)
        if r.get("type") and with_context:
            r["internal_context"] = internal_context(s, p, r["type"], r["value"], org_unit_id=org_unit_id)
        out.append(r)
    return out


def payload(text: str, chain: list[str] | None = None) -> dict:
    from saw.analyzers.ioc.observables import extract
    from saw.analyzers.patterns import scan_value

    try:
        ch = apply_chain(text, chain) if chain else auto_decode(text)
    except TransformError as e:
        raise ValueError(f"transform failed: {e}") from None
    steps = [{"op": st.op, "label": st.label, "input_preview": mask_text(st.input_preview).text,
              "output": mask_text(st.output[:20000]).text, "note": st.note} for st in ch.steps]
    return {
        "input_preview": mask_text(text[:2000]).text,
        "steps": steps,
        "output": mask_text(ch.output[:50000]).text,
        "output_truncated": len(ch.output) > 50000,
        "confidence": ch.confidence,
        "incomplete": ch.incomplete,
        "cyberchef_recipe": ch.recipe() if ch.steps else None,
        "patterns": [h.to_dict() for h in scan_value(ch.output)],
        "iocs": [o.to_dict() for o in extract(ch.output)][:100],
        "meta": {"analyzer_version": "payload/1.0.0"},
    }


def universal(s: Session, p: Principal, text: str) -> dict:
    _audit(s, p, "universal", text)
    res = detect_all(text)
    types = {d["type"] for d in res["detections"]}
    results: dict = {}
    auto = {r["analysis"] for r in res["recommended"] if r["auto"]}
    if "http" in auto and "http_request" in types:
        try:
            results["http"] = analyze_http(text)
        except ValueError as e:
            results["http"] = {"error": str(e)}
    if "ioc" in auto:
        vals = []
        for d in res["detections"]:
            if d["type"] in IOC_TYPES and d.get("value") and d["value"] not in vals:
                vals.append(d["value"])
        results["ioc"] = ioc(s, p, vals[:20])
    if "payload" in auto:
        enc = [d for d in res["detections"] if d["type"] in
               ("base64", "hex", "url_encoded", "unicode_escape", "html_entity", "jwt", "powershell_encoded")]
        if enc:
            d = max(enc, key=lambda x: x["span"][1] - x["span"][0])
            try:
                results["payload"] = payload(text[d["span"][0]:d["span"][1]])
            except ValueError as e:
                results["payload"] = {"error": str(e)}
    if "log" in auto:
        lg = parse_text(text, investigation_id="adhoc")
        results["log"] = summarize_log(lg)
    res["results"] = results
    res["input_masked"] = mask_text(text).kinds
    return res


def summarize_log(lg: dict) -> dict:
    evs = lg["events"]
    from collections import Counter

    def top(field: str, n: int = 5):
        return [{"value": k, "count": v} for k, v in Counter(e.get(field) for e in evs if e.get(field)).most_common(n)]

    tss = sorted(e["timestamp"] for e in evs if e.get("timestamp"))
    patterns = Counter((e.get("method"), e.get("uri_template"), e.get("status_code")) for e in evs if e.get("uri_template"))
    tagged = [e for e in evs if any(str(t).startswith("pattern:") for t in e.get("tags", []))]
    return {
        "parser": lg["parser"], "confidence": lg["confidence"], "candidates": lg["candidates"],
        "events": len(evs), "failed": lg["failed"], "failure_samples": lg["failure_samples"],
        "time_range": [tss[0], tss[-1]] if tss else None,
        "top_src_ip": top("src_ip"), "top_uri_template": top("uri_template"), "top_status": top("status_code"),
        "top_user_agent": top("user_agent"),
        "patterns": [{"method": k[0], "uri_template": k[1], "status": k[2], "count": v}
                     for k, v in patterns.most_common(10)],
        "suspicious": [{"line_no": e["raw_ref"]["line_no"], "tags": e.get("tags"), "uri": mask_text(e.get("uri") or "").text}
                       for e in tagged[:50]],
        "sample_events": [{k: v for k, v in e.items() if k != "raw_event"} for e in evs[:20]],
    }


def http(s: Session, p: Principal, request: str, response: str | None) -> dict:
    _audit(s, p, "http", request)
    return analyze_http(request, response)


def diff(s: Session, p: Principal, requests: list[str]) -> dict:
    _audit(s, p, "diff", "\n".join(requests))
    return analyze_diff(requests)


def log(s: Session, p: Principal, text: str, parser_id: str | None) -> dict:
    _audit(s, p, "log", text)
    return summarize_log(parse_text(text, parser_id=parser_id))
