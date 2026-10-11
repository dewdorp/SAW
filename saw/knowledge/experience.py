"""SOC Experience use cases (docs/25): draft → review → approved (reviewer ≠ analyst) → deprecated, with revisions.

Only `approved_data` is production knowledge. Editing an approved experience creates a new draft revision while the
approved copy keeps serving search until the new revision is approved (no silent changes to knowledge).
"""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from saw.core.application import audit
from saw.core.application.ids import next_display_id
from saw.core.application.investigations import Forbidden, NotFound, require
from saw.core.security.authz import Principal, can
from saw.core.security.masking import mask_text
from saw.knowledge.features import from_findings
from saw.knowledge.models import Experience, KnowledgeRevision
from saw.storage.db import utcnow
from saw.storage.models import Finding, Investigation

FIELDS = ["title", "category", "event_type", "product", "asset", "attack_type", "observables", "behavior_features",
          "initial_assessment", "analysis_steps", "recommended_checks", "final_verdict", "reason", "response",
          "false_positive_conditions", "detection_conditions", "related_case_ids", "confidence"]
CATEGORIES = {"attack", "benign_pattern", "false_positive", "operational", "tuning"}
EXPIRY_DAYS = {"attack": 365, "false_positive": 180, "benign_pattern": 180, "operational": 365, "tuning": 180}


def _snapshot(s: Session, e: Experience, actor: str, note: str = "") -> None:
    s.add(KnowledgeRevision(kind="experience", ref_id=e.id, rev=e.rev, status=e.status, data=e.data, actor=actor, note=note))


def _clean(data: dict) -> dict:
    out = {k: data.get(k) for k in FIELDS if k in data}
    if out.get("category") and out["category"] not in CATEGORIES:
        raise ValueError(f"category must be one of {sorted(CATEGORIES)}")
    # observables are stored masked-safe (no PII in knowledge by default)
    if isinstance(out.get("observables"), list):
        out["observables"] = [{**o, "value": mask_text(str(o.get("value", ""))).text} for o in out["observables"]]
    return out


def to_dict(e: Experience, include_working: bool = True) -> dict:
    d = {"id": e.id, "display_id": e.display_id, "status": e.status, "rev": e.rev, "approved_rev": e.approved_rev,
         "analyst": e.analyst_name, "analyst_id": e.analyst_id, "reviewer": e.reviewer_name, "review_comment": e.review_comment,
         "expires_at": e.expires_at, "last_reviewed_at": e.last_reviewed_at, "deprecated": e.deprecated,
         "source_investigation_id": e.source_investigation_id, "created_at": e.created_at, "updated_at": e.updated_at,
         "needs_review": bool(e.expires_at and e.expires_at.replace(tzinfo=e.expires_at.tzinfo or utcnow().tzinfo) < utcnow()),
         "approved": e.approved_data}
    if include_working:
        d["data"] = e.data
    return d


def create(s: Session, p: Principal, data: dict, source_inv: str | None = None) -> Experience:
    if not can(p, "knowledge.write"):
        raise Forbidden("knowledge.write")
    d = _clean(data)
    if not d.get("title"):
        raise ValueError("title is required")
    e = Experience(display_id=next_display_id(s, "EXP", daily=False, width=4), data=d, analyst_id=p.user_id,
                   analyst_name=p.username, source_investigation_id=source_inv)
    s.add(e)
    s.flush()
    _snapshot(s, e, p.username, "created")
    audit.record(s, "experience.create", actor_id=p.user_id, actor_name=p.username, target_type="experience", target_id=e.id)
    return e


def draft_from_investigation(s: Session, p: Principal, inv: Investigation) -> Experience:
    """Close flow → automatic draft (docs/25 §2 mapping). Reviewer approval still required."""
    from saw.core.application.analysis import finding_dict

    fs = [finding_dict(f) for f in s.execute(select(Finding).where(
        Finding.investigation_id == inv.id, Finding.status.notin_(["false_positive", "duplicate"]))
        .order_by(Finding.risk_score.desc())).scalars()]
    top = fs[0] if fs else None
    detail = inv.close_detail or {}
    verdict = inv.verdict or "unknown"
    category = {"attack": "attack", "false_positive": "false_positive", "normal": "benign_pattern"}.get(verdict, "operational")
    observables = []
    for f in fs[:5]:
        for ent in f["entities"][:4]:
            t, _, v = ent.partition(":")
            if t in ("ip", "domain", "ja4", "uri_template") and {"type": t, "value": v} not in observables:
                observables.append({"type": t, "value": v, "role": "observed"})
    data = {
        "title": f"{inv.title} — {top['title'].replace('Possible ', '').replace('Potential ', '')}" if top else inv.title,
        "category": category,
        "attack_type": top["category"] if top else None,
        "event_type": sorted({f["category"].split(".")[0] for f in fs}),
        "observables": observables[:15],
        "behavior_features": from_findings(fs[:10]),
        "initial_assessment": "; ".join(f"{f['display_id']} {f['title']}" for f in fs[:5]),
        "analysis_steps": [{"step": f"Finding {f['display_id']} 검토", "finding": f["title"]} for f in fs[:5]],
        "recommended_checks": [{"check": c, "why": "Close 시 수행", "how": ""} for c in detail.get("checks", [])],
        "final_verdict": verdict, "reason": inv.verdict_reason or "", "response": detail.get("response", ""),
        "false_positive_conditions": [], "detection_conditions":
            ([{"logic": detail["detection_idea"], "data_source": "web"}] if detail.get("detection_idea") else []),
        "related_case_ids": [], "confidence": "medium",
    }
    e = create(s, p, data, source_inv=inv.id)
    _snapshot(s, e, p.username, f"auto-draft from {inv.display_id}")
    return e


def _get(s: Session, eid: str) -> Experience:
    e = s.get(Experience, eid)
    if e is None:
        raise NotFound("experience not found")
    return e


def visible(e: Experience, p: Principal) -> bool:
    """Drafts are private to their author until approved (docs/25 §2 safety)."""
    return e.approved_data is not None or e.analyst_id == p.user_id or can(p, "knowledge.approve")


def update(s: Session, p: Principal, eid: str, data: dict) -> Experience:
    e = _get(s, eid)
    if not can(p, "knowledge.write"):
        raise Forbidden("knowledge.write")
    if e.analyst_id != p.user_id and not can(p, "knowledge.approve"):
        raise Forbidden("only the author or a reviewer can edit")
    e.data = {**e.data, **_clean(data)}
    e.rev += 1
    e.status = "draft"  # approved copy (approved_data) stays live until re-approval
    e.updated_at = utcnow()
    _snapshot(s, e, p.username, "edited")
    audit.record(s, "experience.update", actor_id=p.user_id, actor_name=p.username, target_type="experience", target_id=eid,
                 detail={"rev": e.rev})
    return e


def submit(s: Session, p: Principal, eid: str) -> Experience:
    e = _get(s, eid)
    if e.analyst_id != p.user_id and not can(p, "knowledge.approve"):
        raise Forbidden("only the author can submit")
    if e.status != "draft":
        raise ValueError(f"cannot submit from {e.status}")
    e.status = "review"
    _snapshot(s, e, p.username, "submitted")
    audit.record(s, "experience.submit", actor_id=p.user_id, actor_name=p.username, target_type="experience", target_id=eid)
    return e


def _contributors(s: Session, e: Experience) -> set[str]:
    """Everyone who changed the content since the last approval: a reviewer who edits the text is an author of it."""
    rows = s.execute(select(KnowledgeRevision.actor, KnowledgeRevision.note).where(
        KnowledgeRevision.kind == "experience", KnowledgeRevision.ref_id == e.id,
        KnowledgeRevision.rev > (e.approved_rev or 0)))
    return {actor for actor, note in rows if (note or "").startswith(("created", "edited", "auto-draft"))}


def approve(s: Session, p: Principal, eid: str, comment: str = "", fp_conflict_ack: bool = False) -> Experience:
    e = _get(s, eid)
    if not can(p, "knowledge.approve"):
        raise Forbidden("knowledge.approve")
    if e.analyst_id == p.user_id or p.username in _contributors(s, e):
        raise Forbidden("reviewer must differ from everyone who wrote this revision (4-eyes)")
    if e.status != "review":
        raise ValueError(f"cannot approve from {e.status}")
    conflicts = fp_conflicts(s, p, e.data.get("false_positive_conditions") or [])
    if conflicts["matches"] and not fp_conflict_ack:
        raise ValueError(f"FP conditions match {conflicts['matches']} events of confirmed attacks; acknowledge to approve")
    now = utcnow()
    e.status, e.approved_data, e.approved_rev = "approved", dict(e.data), e.rev
    e.reviewer_id, e.reviewer_name, e.review_comment = p.user_id, p.username, comment
    e.last_reviewed_at = now
    e.expires_at = now + timedelta(days=EXPIRY_DAYS.get(e.data.get("category") or "attack", 365))
    _snapshot(s, e, p.username, f"approved: {comment}")
    audit.record(s, "experience.approve", actor_id=p.user_id, actor_name=p.username, target_type="experience", target_id=eid,
                 detail={"rev": e.rev, "fp_conflicts": conflicts["matches"]})
    _index_knowledge(e, s)
    return e


def reject(s: Session, p: Principal, eid: str, comment: str) -> Experience:
    e = _get(s, eid)
    if not can(p, "knowledge.approve"):
        raise Forbidden("knowledge.approve")
    if not comment.strip():
        raise ValueError("rejection reason is required")
    e.status, e.review_comment = "draft", comment
    _snapshot(s, e, p.username, f"rejected: {comment}")
    audit.record(s, "experience.reject", actor_id=p.user_id, actor_name=p.username, target_type="experience", target_id=eid)
    return e


def deprecate(s: Session, p: Principal, eid: str, reason: str) -> Experience:
    e = _get(s, eid)
    if not can(p, "knowledge.approve"):
        raise Forbidden("knowledge.approve")
    e.status, e.deprecated = "deprecated", True
    _snapshot(s, e, p.username, f"deprecated: {reason}")
    audit.record(s, "experience.deprecate", actor_id=p.user_id, actor_name=p.username, target_type="experience", target_id=eid)
    return e


def revisions(s: Session, eid: str) -> list[dict]:
    return [{"rev": r.rev, "status": r.status, "actor": r.actor, "note": r.note, "at": r.at, "data": r.data}
            for r in s.execute(select(KnowledgeRevision).where(KnowledgeRevision.kind == "experience",
                                                               KnowledgeRevision.ref_id == eid).order_by(KnowledgeRevision.at)).scalars()]


def fp_conflicts(s: Session, p: Principal, conditions: list[dict]) -> dict:
    """FP conditions must not match events of investigations closed as Attack (docs/13 T-23)."""
    from saw import container
    from saw.core.schemas.query import Filter

    if not conditions:
        return {"matches": 0, "investigations": []}
    flt = []
    for c in conditions:
        if isinstance(c, dict) and c.get("field"):
            flt.append(Filter(field=c["field"], op=c.get("op", "is"), value=c.get("value")))
    if not flt:
        return {"matches": 0, "investigations": []}
    es = container.get().events
    total, invs = 0, []
    for inv in s.execute(select(Investigation).where(Investigation.verdict == "attack")).scalars():
        n = es.count(inv.id, flt)
        if n:
            total += n
            invs.append({"id": inv.id, "display_id": inv.display_id, "events": n})
    return {"matches": total, "investigations": invs}


def _index_knowledge(e: Experience, s: Session) -> None:
    """Keep the similarity index fresh (Phase 9)."""
    from saw.knowledge.similar import index_experience

    index_experience(e, s)


def list_for(s: Session, p: Principal, status: str | None = None, q: str | None = None) -> list[Experience]:
    rows = s.execute(select(Experience).order_by(Experience.updated_at.desc())).scalars().all()
    out = [e for e in rows if visible(e, p)]
    if status == "review_queue":
        out = [e for e in out if e.status == "review" and e.analyst_id != p.user_id]
    elif status:
        out = [e for e in out if e.status == status]
    if q:
        ql = q.lower()
        out = [e for e in out if ql in str(e.data).lower() or ql in e.display_id.lower()]
    return out


_ = require
