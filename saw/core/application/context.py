"""Internal SOC Context for an observable across the investigations the principal may read (docs/17 §7.2)."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from saw import container
from saw.core.application.investigations import list_for
from saw.core.schemas.query import AggRequest, Filter
from saw.core.security.authz import Principal
from saw.storage.models import Case, Entity, Investigation

FIELDS_BY_TYPE = {
    "ipv4": ["src_ip", "dst_ip"], "ipv6": ["src_ip", "dst_ip"], "domain": ["domain", "hostname"],
    "url": ["uri"], "md5": ["hash"], "sha1": ["hash"], "sha256": ["hash"], "sha512": ["hash"],
    "ja4": ["ja4"], "ja3": ["ja3"], "user": ["user"], "uri_template": ["uri_template"],
}
MAX_INVESTIGATIONS = 50


def internal_context(s: Session, p: Principal, obs_type: str, value: str) -> dict:
    es = container.get().events
    fields = FIELDS_BY_TYPE.get(obs_type, [])
    by_source: dict[str, int] = {}
    first, last = None, None
    related: dict[str, dict[str, int]] = {"uri_template": {}, "ja4": {}, "user": {}, "dst_asset_id": {},
                                          "dst_ip": {}, "src_ip": {}}
    seen_in: list[dict] = []
    for inv in list_for(s, p, limit=MAX_INVESTIGATIONS):
        total = 0
        for f in fields:
            flt = [Filter(field=f, op="is", value=value)]
            n = es.count(inv.id, flt)
            if not n:
                continue
            total += n
            for b in es.aggregate(inv.id, flt, AggRequest(type="terms", field="data_source", size=20))["buckets"]:
                by_source[b["key"]] = by_source.get(b["key"], 0) + b["count"]
            lo, hi = es.time_bounds(inv.id, flt)
            first = min(filter(None, [first, lo]), default=None)
            last = max(filter(None, [last, hi]), default=None)
            for rf in related:
                if rf == f:
                    continue
                for b in es.aggregate(inv.id, flt, AggRequest(type="terms", field=rf, size=5))["buckets"]:
                    related[rf][str(b["key"])] = related[rf].get(str(b["key"]), 0) + b["count"]
        if total:
            seen_in.append({"investigation_id": inv.id, "display_id": inv.display_id, "title": inv.title,
                            "events": total, "status": inv.status, "verdict": inv.verdict,
                            "verdict_reason": inv.verdict_reason, "closed_at": inv.closed_at})
    # entities recorded on investigations (e.g. pasted IOCs) also count
    ent_inv_ids = {e.investigation_id for e in s.execute(select(Entity).where(Entity.value == value)).scalars()}
    readable = {i["investigation_id"] for i in seen_in} | {inv.id for inv in list_for(s, p, MAX_INVESTIGATIONS)}
    for iid in ent_inv_ids & readable - {i["investigation_id"] for i in seen_in}:
        inv = s.get(Investigation, iid)
        if inv:
            seen_in.append({"investigation_id": inv.id, "display_id": inv.display_id, "title": inv.title,
                            "events": 0, "status": inv.status, "verdict": inv.verdict,
                            "verdict_reason": inv.verdict_reason, "closed_at": inv.closed_at})
    inv_ids = [i["investigation_id"] for i in seen_in]
    cases = []
    for c in s.execute(select(Case)).scalars():
        if set(c.investigation_ids or []) & set(inv_ids):
            cases.append({"case_id": c.id, "display_id": c.display_id, "title": c.title, "verdict": c.verdict,
                          "status": c.status})
    connector_ctx = []
    from saw.connectors import registry as creg

    for cfg in creg.enabled(s):
        try:
            connector_ctx.append(creg.get(s, cfg.id).get_context(obs_type, value))
        except Exception as e:  # noqa: BLE001 - a broken connector must not break analysis
            connector_ctx.append({"connector": cfg.name, "error": str(e)[:200]})
    for cc in connector_ctx:
        for k, v in (cc.get("events_by_source") or {}).items():
            by_source[f"{k} (SIEM)"] = by_source.get(f"{k} (SIEM)", 0) + v
        first = min(filter(None, [first, cc.get("first_seen")]), default=None)
        last = max(filter(None, [last, cc.get("last_seen")]), default=None)
    top = {k: sorted(({"value": vk, "count": vc} for vk, vc in v.items()), key=lambda x: -x["count"])[:5]
           for k, v in related.items() if v}
    return {
        "first_seen": first, "last_seen": last,
        "events_by_source": by_source,
        "total_events": sum(by_source.values()),
        "related": top,
        "investigations": seen_in,
        "related_cases": cases,
        "previous_verdicts": [i for i in seen_in if i["verdict"]],
        "connectors": connector_ctx,
        "scope_note": f"최근 {MAX_INVESTIGATIONS}개 접근 가능 Investigation + 활성 Connector {len(connector_ctx)}개",
    }
