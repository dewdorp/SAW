"""Deterministic Behavior FeatureSet extraction (docs/25 §3) — basis for Similar Case & Same/Different."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

FEATURE_VERSION = "features/1.0.0"
KST = timezone(timedelta(hours=9))
WEIGHTS = {"uri_template": 3.0, "param_sequential": 2.5, "ja4": 2.5, "attack_category": 2.0, "ua_class": 1.5,
           "ua_family": 1.5, "src_infra": 1.5, "success_ratio_bucket": 1.0, "rate_vs_baseline_bucket": 1.0,
           "request_interval_bucket": 1.0, "time_of_day": 0.7, "target_asset_criticality": 0.8, "payload_family": 1.5,
           "attack_techniques": 2.0, "stage_set": 1.0, "src_ip_count_bucket": 0.7}


def _bucket(v: float, edges: list[tuple[float, str]], default: str) -> str:
    for e, label in edges:
        if v <= e:
            return label
    return default


def _metric(f: dict, name: str):
    for m in f.get("metrics", []):
        if m.get("name") == name:
            return m
    return None


def from_findings(findings: list[dict]) -> dict:
    fs: dict = {}
    cats, stages, techs, payload = set(), set(), set(), set()
    for f in findings:
        cats.add(f.get("category"))
        stages.add(f.get("stage"))
        for a in f.get("attack") or []:
            if a.get("confidence") != "candidate":
                techs.add(a["technique_id"])
        for e in f.get("entities", []):
            if e.startswith("uri_template:"):
                fs.setdefault("uri_template", e.split(":", 1)[1])
            if e.startswith("ja4:"):
                fs.setdefault("ja4", e.split(":", 1)[1])
            if e.startswith("user_agent:"):
                fs.setdefault("ua_family", e.split(":", 1)[1].split("/")[0].lower())
        seq = _metric(f, "sequential_ratio")
        if seq and seq.get("observed") is not None:
            fs["param_sequential"] = seq["observed"] >= 0.8
        sr = _metric(f, "http_2xx_ratio")
        if sr and sr.get("observed") is not None:
            fs["success_ratio_bucket"] = _bucket(sr["observed"], [(0.1, "<0.1"), (0.5, "0.1-0.5"), (0.9, "0.5-0.9")], ">0.9")
        rate = _metric(f, "request_rate_per_min")
        if rate and rate.get("ratio"):
            fs["rate_vs_baseline_bucket"] = _bucket(rate["ratio"], [(2, "<2x"), (10, "2-10x")], ">10x")
        srcs = _metric(f, "source_ips")
        if srcs and srcs.get("observed") is not None:
            fs["src_ip_count_bucket"] = _bucket(srcs["observed"], [(1, "1"), (10, "2-10"), (100, "10-100")], ">100")
        for c in f.get("checks", []):
            if c.get("label") == "Multiple Cloud IP" and c.get("passed"):
                fs["src_infra"] = "cloud_multi"
            if c.get("label") == "Automated interval" and c.get("passed"):
                fs["request_interval_bucket"] = "automated"
            if c.get("label") == "Non-browser User-Agent" and c.get("passed"):
                fs.setdefault("ua_class", "script")
        if f.get("category", "").startswith("web.injection_like"):
            payload.add(f["title"].replace("Potential ", "").replace(" Attempts", "").lower())
        if f.get("category") == "web.api_enumeration":
            fs.setdefault("ua_class", "script")
        ts = f.get("time_start")
        if ts and "time_of_day" not in fs:
            dt = ts if isinstance(ts, datetime) else datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            h = dt.astimezone(KST).hour
            fs["time_of_day"] = "business" if 9 <= h < 18 else "off_hours"
    if cats:
        fs["attack_category"] = sorted(c for c in cats if c)
    if stages:
        fs["stage_set"] = sorted(s for s in stages if s)
    if techs:
        fs["attack_techniques"] = sorted(techs)
    if payload:
        fs["payload_family"] = sorted(payload)
    fs["_version"] = FEATURE_VERSION
    return fs


def compare(a: dict, b: dict) -> tuple[float, list[str], list[str]]:
    """Weighted similarity in [0,1] + Same / Different feature keys."""
    same, diff = [], []
    num = den = 0.0
    for k, w in WEIGHTS.items():
        va, vb = a.get(k), b.get(k)
        if va is None and vb is None:
            continue
        den += w
        if va is None or vb is None:
            diff.append(k)
            continue
        if isinstance(va, list) or isinstance(vb, list):
            sa, sb = set(va if isinstance(va, list) else [va]), set(vb if isinstance(vb, list) else [vb])
            j = len(sa & sb) / max(1, len(sa | sb))
            num += w * j
            (same if j >= 0.5 else diff).append(k)
        elif va == vb:
            num += w
            same.append(k)
        else:
            diff.append(k)
    return (num / den if den else 0.0), same, diff
