"""IOC analyzer pure part: classification + offline enrichment (internal context is added by the service)."""
from __future__ import annotations

from saw.analyzers.ioc.enrichment import OfflineEnricher, default_enricher
from saw.analyzers.ioc.observables import classify, defang, ip_scope, refang, registered_domain

VERSION = "ioc/1.0.0"


def analyze_observable(value: str, enricher: OfflineEnricher | None = None) -> dict:
    v = refang(value.strip())
    t = classify(v)
    if t is None:
        return {"input": value, "type": None, "error": "unrecognized observable"}
    en = enricher or default_enricher()
    out: dict = {"input": value, "value": v.lower() if t in ("domain", "md5", "sha1", "sha256", "sha512") else v,
                 "type": t, "defanged": defang(v)}
    if t in ("ipv4", "ipv6"):
        out["scope"] = ip_scope(v)
        out["offline"] = en.lookup_ip(v) if out["scope"] == "external" else {"note": "internal/reserved address"}
    elif t == "domain":
        out["registered_domain"] = registered_domain(v)
        out["punycode"] = v.encode("idna").decode() if any(ord(c) > 127 for c in v) else None
    elif t == "url":
        from urllib.parse import urlsplit

        u = urlsplit(v)
        out["host"] = u.hostname
        out["registered_domain"] = registered_domain(u.hostname or "")
        out["note"] = "SAW는 분석 대상 URL에 접속하지 않습니다 (passive only)"
    out["external_lookups"] = {"rdap": "manual", "ti": "manual",
                               "note": "외부 조회는 분석가 명시 실행 + 정책 허용 시에만 (OPSEC, ENV-10)"}
    return out
