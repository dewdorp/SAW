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


def affiliate_scoped(obs_type: str, value: str) -> bool:
    """Internal (re-used) addresses name different hosts in different affiliates."""
    from saw.analyzers.ioc.observables import affiliate_local

    return obs_type in ("ipv4", "ipv6") and affiliate_local(value)


def _seen(inv: Investigation, events: int) -> dict:
    return {"investigation_id": inv.id, "display_id": inv.display_id, "title": inv.title,
            "org_unit_id": inv.org_unit_id, "org_unit": inv.org_unit or "",
            "events": events, "status": inv.status, "verdict": inv.verdict,
            "verdict_reason": inv.verdict_reason, "closed_at": inv.closed_at}


def internal_context(s: Session, p: Principal, obs_type: str, value: str, org_unit_id: str | None = None) -> dict:
    es = container.get().events
    fields = FIELDS_BY_TYPE.get(obs_type, [])
    scoped = affiliate_scoped(obs_type, value)
    # A private address is only meaningful inside one affiliate: never add another affiliate's counts or verdicts.
    readable = list_for(s, p, limit=MAX_INVESTIGATIONS, org_unit_id=org_unit_id if scoped and org_unit_id else None)
    groups: dict[str, dict] = {}

    def group_of(inv: Investigation) -> dict:
        key = (inv.org_unit_id or f"unassigned:{inv.id}") if scoped else "all"
        if key not in groups:
            groups[key] = {"org_unit_id": inv.org_unit_id if scoped else None,
                           "org_unit": (inv.org_unit or "미지정") if scoped else "",
                           "by_source": {}, "first": None, "last": None, "seen_in": [],
                           "related": {"uri_template": {}, "ja4": {}, "user": {}, "dst_asset_id": {},
                                       "dst_ip": {}, "src_ip": {}}}
        return groups[key]

    for inv in readable:
        total = 0
        g = None
        for f in fields:
            flt = [Filter(field=f, op="is", value=value)]
            n = es.count(inv.id, flt)
            if not n:
                continue
            g = g or group_of(inv)
            total += n
            for b in es.aggregate(inv.id, flt, AggRequest(type="terms", field="data_source", size=20))["buckets"]:
                g["by_source"][b["key"]] = g["by_source"].get(b["key"], 0) + b["count"]
            lo, hi = es.time_bounds(inv.id, flt)
            g["first"] = min(filter(None, [g["first"], lo]), default=None)
            g["last"] = max(filter(None, [g["last"], hi]), default=None)
            for rf, counts in g["related"].items():
                if rf == f:
                    continue
                for b in es.aggregate(inv.id, flt, AggRequest(type="terms", field=rf, size=5))["buckets"]:
                    counts[str(b["key"])] = counts.get(str(b["key"]), 0) + b["count"]
        if total:
            g["seen_in"].append(_seen(inv, total))
    # entities recorded on investigations (e.g. pasted IOCs) also count
    ent_inv_ids = {e.investigation_id for e in s.execute(select(Entity).where(Entity.value == value)).scalars()}
    listed = {i["investigation_id"] for g in groups.values() for i in g["seen_in"]}
    for inv in readable:
        if inv.id in ent_inv_ids and inv.id not in listed:
            group_of(inv)["seen_in"].append(_seen(inv, 0))
    by_affiliate = [{"org_unit_id": g["org_unit_id"], "org_unit": g["org_unit"], "first_seen": g["first"],
                     "last_seen": g["last"], "events_by_source": g["by_source"],
                     "total_events": sum(g["by_source"].values()), "investigations": g["seen_in"],
                     "previous_verdicts": [i for i in g["seen_in"] if i["verdict"]]} for g in groups.values()]
    merged = not scoped or len(groups) <= 1
    by_source: dict[str, int] = {}
    related: dict[str, dict[str, int]] = {}
    first, last = None, None
    seen_in: list[dict] = [i for g in groups.values() for i in g["seen_in"]]
    if merged:
        for g in groups.values():
            for k, v in g["by_source"].items():
                by_source[k] = by_source.get(k, 0) + v
            for rf, counts in g["related"].items():
                for k, v in counts.items():
                    related.setdefault(rf, {})[k] = related.setdefault(rf, {}).get(k, 0) + v
            first = min(filter(None, [first, g["first"]]), default=None)
            last = max(filter(None, [last, g["last"]]), default=None)
    inv_ids = [i["investigation_id"] for i in seen_in]
    cases = []
    for c in s.execute(select(Case).where(Case.status.notin_(["deleted", "deleting"]))).scalars():
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
    for cc in connector_ctx if merged else []:
        for k, v in (cc.get("events_by_source") or {}).items():
            by_source[f"{k} (SIEM)"] = by_source.get(f"{k} (SIEM)", 0) + v
        first = min(filter(None, [first, cc.get("first_seen")]), default=None)
        last = max(filter(None, [last, cc.get("last_seen")]), default=None)
    top = {k: sorted(({"value": vk, "count": vc} for vk, vc in v.items()), key=lambda x: -x["count"])[:5]
           for k, v in related.items() if v}
    note = f"최근 {MAX_INVESTIGATIONS}개 접근 가능 조사 + 활성 Connector {len(connector_ctx)}개"
    if scoped:
        note += (" · 내부(사설) 주소는 관계사별로 다른 장비일 수 있어 관계사마다 따로 보여 주며 합산하지 않습니다"
                 if not merged else " · 내부(사설) 주소: 한 관계사(또는 미지정 조사 1건) 범위의 결과입니다")
    return {
        "first_seen": first, "last_seen": last,
        "events_by_source": by_source,
        "total_events": sum(by_source.values()),
        "related": top,
        "investigations": seen_in,
        "related_cases": cases,
        "previous_verdicts": [i for i in seen_in if i["verdict"]] if merged else [],
        "connectors": connector_ctx,
        "affiliate_scoped": scoped,
        "affiliate_separated": not merged,
        "by_affiliate": by_affiliate if scoped else [],
        "scope_note": note,
    }
