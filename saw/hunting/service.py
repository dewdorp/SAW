"""Threat Hunting (docs/30): Hypothesis → Query → Result → Pivot → Next query, READ ONLY, budgeted, audited.

Queries are the structured SAW Query Model (never raw DSL). Every step records who (analyst/ai) and why.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone

from pydantic import BaseModel, Field
from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Text, select
from sqlalchemy.orm import Mapped, Session, mapped_column

from saw import container
from saw.core.application import audit
from saw.core.application.investigations import Forbidden, NotFound, list_for, require
from saw.core.schemas.query import AggRequest, Filter, TimeRange
from saw.core.security.authz import Principal, can
from saw.core.security.masking import mask_event
from saw.storage.db import Base, new_id, utcnow

MAX_STEPS = 20
MAX_DAYS = 90
PIVOT_FIELDS = ["src_ip", "ja4", "src_as_org", "uri_template", "user_agent", "dst_ip", "domain", "user"]


class HuntSession(Base):
    __tablename__ = "hunt_session"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    display_id: Mapped[str] = mapped_column(String(32))
    investigation_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    scope: Mapped[str] = mapped_column(String(16), default="investigation")  # investigation | global | connector
    connector_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    hypothesis: Mapped[str] = mapped_column(Text)
    seed: Mapped[dict] = mapped_column(JSON, default=dict)  # e.g. {"technique_id": "T1505.003"} from TIE
    status: Mapped[str] = mapped_column(String(16), default="active")
    outcome: Mapped[str | None] = mapped_column(String(16), nullable=True)
    outcome_md: Mapped[str] = mapped_column(Text, default="")
    owner_id: Mapped[str] = mapped_column(String(36))
    owner_name: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class HuntStep(Base):
    __tablename__ = "hunt_step"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    session_id: Mapped[str] = mapped_column(ForeignKey("hunt_session.id"), index=True)
    seq: Mapped[int] = mapped_column(Integer)
    parent_seq: Mapped[int | None] = mapped_column(Integer, nullable=True)
    actor: Mapped[str] = mapped_column(String(16))  # analyst | ai (accepted by analyst)
    accepted_by: Mapped[str] = mapped_column(String(64), default="")
    rationale: Mapped[str] = mapped_column(Text)
    query: Mapped[dict] = mapped_column(JSON, default=dict)
    result_summary: Mapped[dict] = mapped_column(JSON, default=dict)
    pivots: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class HuntQuery(BaseModel):
    sources: list[str] = Field(default_factory=list)
    time: TimeRange | None = None
    filters: list[Filter] = Field(default_factory=list)
    aggs: list[AggRequest] = Field(default_factory=list, max_length=5)


def _scopes(s: Session, p: Principal, h: HuntSession) -> list[str]:
    if h.scope == "investigation":
        return [h.investigation_id] if h.investigation_id else []
    return [i.id for i in list_for(s, p, 200)]


def _check_budget(q: HuntQuery, h_steps: int) -> None:
    if h_steps >= MAX_STEPS:
        raise ValueError(f"hunt step budget exhausted ({MAX_STEPS})")
    if q.time and q.time.start and q.time.end:
        a = datetime.fromisoformat(q.time.start.replace("Z", "+00:00"))
        b = datetime.fromisoformat(q.time.end.replace("Z", "+00:00"))
        if (b - a) > timedelta(days=MAX_DAYS):
            raise ValueError(f"time range exceeds {MAX_DAYS} days")
    for a in q.aggs:
        if a.size > 100:
            raise ValueError("aggregation size ≤ 100")


def execute(s: Session, p: Principal, h: HuntSession, q: HuntQuery) -> dict:
    flt = list(q.filters)
    if q.sources:
        flt.append(Filter(field="data_source", op="in", value=q.sources))
    total, samples, aggs = 0, [], [dict() for _ in q.aggs]
    if h.scope == "connector":
        from saw.connectors import registry as creg

        conn = creg.get(s, h.connector_id or "")
        page = conn.search(flt, q.time, 20)
        samples = page["events"]
        total = len(samples)
        for i, a in enumerate(q.aggs):
            aggs[i] = conn.aggregate(flt, a, q.time)
    else:
        es = container.get().events
        merged: list[Counter] = [Counter() for _ in q.aggs]
        for inv_id in _scopes(s, p, h):
            n = es.count(inv_id, flt, q.time)
            if not n:
                continue
            total += n
            if len(samples) < 20:
                samples += es.search(inv_id, flt, q.time, limit=20 - len(samples))["events"]
            for i, a in enumerate(q.aggs):
                r = es.aggregate(inv_id, flt, a, q.time)
                if a.type == "terms":
                    for b in r["buckets"]:
                        merged[i][b["key"]] += b["count"]
                else:
                    aggs[i] = r
        for i, a in enumerate(q.aggs):
            if a.type == "terms":
                aggs[i] = {"buckets": [{"key": k, "count": v} for k, v in merged[i].most_common(a.size)]}
    masked = [mask_event(e)[0] for e in samples]
    return {"total": total, "aggs": [{"type": a.type, "field": a.field, **aggs[i]} for i, a in enumerate(q.aggs)],
            "samples": [{k: e.get(k) for k in ("event_id", "investigation_id", "timestamp", "data_source", "src_ip", "dst_ip",
                                                "method", "uri", "status_code", "user_agent", "ja4", "domain", "src_as_org")}
                        for e in masked]}


def pivots(q: HuntQuery, result: dict) -> list[dict]:
    """Deterministic pivot candidates with a stated reason (concentration of a value among results)."""
    used = {f.field for f in q.filters}
    out = []
    total = max(1, len(result["samples"]))
    for a in result["aggs"]:
        if a.get("type") == "terms" and a.get("buckets"):
            tot = sum(b["count"] for b in a["buckets"]) or 1
            b = a["buckets"][0]
            if a["field"] not in used and b["count"] / tot >= 0.3:
                out.append({"field": a["field"], "value": b["key"], "reason": f"결과의 {b['count'] / tot:.0%}가 {a['field']}={b['key']}"})
    for f in PIVOT_FIELDS:
        if f in used:
            continue
        vals = Counter(str(e.get(f)) for e in result["samples"] if e.get(f))
        if vals:
            v, c = vals.most_common(1)[0]
            if c / total >= 0.5 and len(vals) <= max(3, total // 4) and not any(x["field"] == f for x in out):
                out.append({"field": f, "value": v, "reason": f"샘플 {c}/{total}건이 동일 {f}"})
    return out[:6]


def create(s: Session, p: Principal, hypothesis: str, investigation_id: str | None, scope: str, connector_id: str | None,
           seed: dict | None) -> HuntSession:
    if not hypothesis.strip():
        raise ValueError("hypothesis is required")
    if scope == "investigation":
        if not investigation_id:
            raise ValueError("investigation_id required for investigation scope")
        require(s, p, "investigation.read", investigation_id)
    elif scope in ("global", "connector"):
        if not can(p, "hunt.global"):
            raise Forbidden("hunt.global")
    else:
        raise ValueError("scope must be investigation|global|connector")
    n = len(s.execute(select(HuntSession)).scalars().all()) + 1
    h = HuntSession(display_id=f"H-{utcnow():%Y}-{n:03d}", investigation_id=investigation_id, scope=scope, connector_id=connector_id,
                    hypothesis=hypothesis, seed=seed or {}, owner_id=p.user_id, owner_name=p.username)
    s.add(h)
    s.flush()
    audit.record(s, "hunt.create", actor_id=p.user_id, actor_name=p.username, target_type="hunt", target_id=h.id,
                 investigation_id=investigation_id, detail={"scope": scope})
    return h


def get(s: Session, p: Principal, hid: str) -> HuntSession:
    h = s.get(HuntSession, hid)
    if h is None:
        raise NotFound("hunt not found")
    if h.investigation_id:
        require(s, p, "investigation.read", h.investigation_id)
    elif h.owner_id != p.user_id and not can(p, "hunt.global"):
        raise Forbidden("hunt.global")
    return h


def add_step(s: Session, p: Principal, hid: str, q: HuntQuery, rationale: str, actor: str = "analyst",
             parent_seq: int | None = None) -> HuntStep:
    h = get(s, p, hid)
    if h.status != "active":
        raise ValueError("hunt is concluded")
    if not rationale.strip():
        raise ValueError("rationale (why this query) is required")
    steps = s.execute(select(HuntStep).where(HuntStep.session_id == hid)).scalars().all()
    _check_budget(q, len(steps))
    res = execute(s, p, h, q)
    st = HuntStep(session_id=hid, seq=len(steps) + 1, parent_seq=parent_seq, actor=actor if actor in ("analyst", "ai") else "analyst",
                  accepted_by=p.username, rationale=rationale, query=q.model_dump(), result_summary=res, pivots=pivots(q, res))
    s.add(st)
    audit.record(s, "hunt.query", actor_id=p.user_id, actor_name=p.username, target_type="hunt", target_id=hid,
                 investigation_id=h.investigation_id,
                 detail={"seq": st.seq, "actor": st.actor, "fields": sorted({f.field for f in q.filters}), "total": res["total"]})
    s.flush()
    return st


def conclude(s: Session, p: Principal, hid: str, outcome: str, summary: str) -> HuntSession:
    h = get(s, p, hid)
    if outcome not in ("confirmed", "refuted", "inconclusive"):
        raise ValueError("outcome must be confirmed|refuted|inconclusive")
    h.status, h.outcome, h.outcome_md = "concluded", outcome, summary
    audit.record(s, "hunt.conclude", actor_id=p.user_id, actor_name=p.username, target_type="hunt", target_id=hid,
                 investigation_id=h.investigation_id, detail={"outcome": outcome})
    return h


def to_dict(s: Session, h: HuntSession) -> dict:
    steps = s.execute(select(HuntStep).where(HuntStep.session_id == h.id).order_by(HuntStep.seq)).scalars().all()
    return {"id": h.id, "display_id": h.display_id, "investigation_id": h.investigation_id, "scope": h.scope,
            "connector_id": h.connector_id, "hypothesis": h.hypothesis, "seed": h.seed, "status": h.status,
            "outcome": h.outcome, "outcome_md": h.outcome_md, "owner": h.owner_name, "created_at": h.created_at,
            "budget": {"steps_used": len(steps), "max_steps": MAX_STEPS, "max_days": MAX_DAYS},
            "steps": [{"seq": x.seq, "parent_seq": x.parent_seq, "actor": x.actor, "accepted_by": x.accepted_by, "rationale": x.rationale,
                       "query": x.query, "result": x.result_summary, "pivots": x.pivots, "created_at": x.created_at} for x in steps]}


def hunt_finding(s: Session, p: Principal, hid: str, seq: int, title: str) -> str:
    """Analyst-authored Finding from a hunt step (evidence = that step's query)."""
    from saw.storage.models import Finding

    h = get(s, p, hid)
    if not h.investigation_id:
        raise ValueError("findings can only be created for investigation-scoped hunts")
    require(s, p, "investigation.write", h.investigation_id)
    st = s.execute(select(HuntStep).where(HuntStep.session_id == hid, HuntStep.seq == seq)).scalar_one_or_none()
    if st is None:
        raise NotFound("step not found")
    from saw.core.application.analysis import next_finding_id

    f = Finding(display_id=next_finding_id(s), investigation_id=h.investigation_id, detector_id="hunt.manual",
                detector_version="1.0.0", title=title if title.startswith(("Possible", "Potential")) else f"Potential {title}",
                category="hunt.result", stage="UNCLASSIFIED", risk_level="medium", risk_score=50.0,
                risk_factors=[{"name": "analyst_assessed", "value": True}], confidence="medium",
                metrics=[{"name": "matching_events", "label": "Matching events", "observed": st.result_summary.get("total")}],
                checks=[{"label": f"Hunt {h.display_id} step {seq}", "passed": True, "value": st.rationale[:120]}],
                entities=[f"{q['field'] if q['field'] != 'src_ip' else 'ip'}:{q['value']}" for q in st.query.get("filters", [])
                          if q.get("op") == "is"][:5],
                evidence_refs={"query": {"filters": st.query.get("filters", [])}, "sample_event_ids":
                               [e["event_id"] for e in st.result_summary.get("samples", [])][:20], "total": st.result_summary.get("total")},
                attack=[{"technique_id": h.seed["technique_id"], "name": h.seed.get("name", ""), "tactic": None, "source": "analyst",
                         "confidence": "medium", "condition": "hunt confirmed hypothesis", "condition_met": True,
                         "rationale": h.hypothesis[:200], "attack_version": "analyst"}] if h.seed.get("technique_id") else [],
                explanation_md=f"Hunting {h.display_id}: {h.hypothesis}", dedup_key=f"hunt:{hid}:{seq}",
                time_start=datetime.now(timezone.utc))
    s.add(f)
    audit.record(s, "hunt.finding", actor_id=p.user_id, actor_name=p.username, target_type="finding", target_id=f.id,
                 investigation_id=h.investigation_id)
    s.flush()
    return f.id
