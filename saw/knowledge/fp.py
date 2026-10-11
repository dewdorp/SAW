"""False Positive rules & Playbooks (docs/25, docs/13 T-23). FP rules flag, they never suppress."""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from saw import container
from saw.core.application import audit
from saw.core.application.ids import next_display_id
from saw.core.application.investigations import Forbidden, NotFound
from saw.core.schemas.query import Filter
from saw.core.security.authz import Principal, can
from saw.knowledge.models import FalsePositiveRule, KnowledgeRevision, Playbook
from saw.storage.db import utcnow
from saw.storage.models import Finding


def fp_dict(r: FalsePositiveRule) -> dict:
    return {"id": r.id, "display_id": r.display_id, "title": r.title, "detector_id": r.detector_id, "conditions": r.conditions,
            "reason": r.reason, "status": r.status, "conflicts": r.conflicts, "expires_at": r.expires_at, "rev": r.rev,
            "created_by": r.created_by, "approved_by": r.approved_by}


def create_fp(s: Session, p: Principal, title: str, detector_id: str | None, conditions: list[dict], reason: str,
              days: int = 180) -> FalsePositiveRule:
    from saw.knowledge.experience import fp_conflicts

    if not can(p, "knowledge.write"):
        raise Forbidden("knowledge.write")
    if not conditions:
        raise ValueError("at least one condition is required")
    for c in conditions:
        Filter(**c)  # validate field names / ops
    if not 1 <= days <= 365:
        raise ValueError("expiry must be 1..365 days")
    r = FalsePositiveRule(display_id=next_display_id(s, "FP", daily=False, width=4), title=title, detector_id=detector_id,
                          conditions=conditions, reason=reason, created_by=p.user_id, expires_at=utcnow() + timedelta(days=days),
                          conflicts=fp_conflicts(s, p, conditions))
    s.add(r)
    s.flush()
    s.add(KnowledgeRevision(kind="fp_rule", ref_id=r.id, rev=1, status="draft", data=fp_dict(r) | {"expires_at": None},
                            actor=p.username))
    audit.record(s, "fp_rule.create", actor_id=p.user_id, actor_name=p.username, target_type="fp_rule", target_id=r.id,
                 detail={"conflicts": r.conflicts.get("matches", 0)})
    return r


def approve_fp(s: Session, p: Principal, rid: str, ack_conflicts: bool = False) -> FalsePositiveRule:
    r = s.get(FalsePositiveRule, rid)
    if r is None:
        raise NotFound("fp rule not found")
    if not can(p, "knowledge.approve"):
        raise Forbidden("knowledge.approve")
    if r.created_by == p.user_id:
        raise Forbidden("reviewer must differ from the author (4-eyes)")
    if r.conflicts.get("matches") and not ack_conflicts:
        raise ValueError("rule matches events of confirmed attacks; acknowledge to approve")
    r.status, r.approved_by = "approved", p.user_id
    r.rev += 1
    s.add(KnowledgeRevision(kind="fp_rule", ref_id=r.id, rev=r.rev, status="approved", data=fp_dict(r) | {"expires_at": None},
                            actor=p.username))
    audit.record(s, "fp_rule.approve", actor_id=p.user_id, actor_name=p.username, target_type="fp_rule", target_id=rid)
    return r


def match_fp_rules(s: Session, f: Finding) -> list[dict]:
    """Approved, unexpired rules whose conditions match the finding's evidence → shown as a flag (no suppression)."""
    es = container.get().events
    out = []
    now = utcnow()
    for r in s.execute(select(FalsePositiveRule).where(FalsePositiveRule.status == "approved")).scalars():
        if r.expires_at and r.expires_at.replace(tzinfo=r.expires_at.tzinfo or now.tzinfo) < now:
            continue
        if r.detector_id and r.detector_id != f.detector_id:
            continue
        q = (f.evidence_refs or {}).get("query", {})
        flt = [Filter(**x) for x in q.get("filters", [])] + [Filter(**c) for c in r.conditions]
        n = es.count(f.investigation_id, flt)
        if n:
            total = (f.evidence_refs or {}).get("total") or 1
            out.append({"id": r.id, "display_id": r.display_id, "title": r.title, "matched_events": n,
                        "share": round(n / total, 3), "reason": r.reason})
    return out


def pb_dict(b: Playbook) -> dict:
    return {"id": b.id, "title": b.title, "applies_to": b.applies_to, "steps": b.steps, "status": b.status, "rev": b.rev}


def upsert_playbook(s: Session, p: Principal, title: str, applies_to: list[str], steps: list[dict], pid: str | None = None) -> Playbook:
    if not can(p, "knowledge.approve"):
        raise Forbidden("knowledge.approve")
    b = s.get(Playbook, pid) if pid else None
    if b is None:
        b = Playbook(title=title, applies_to=applies_to, steps=steps)
        s.add(b)
    else:
        b.title, b.applies_to, b.steps, b.rev = title, applies_to, steps, b.rev + 1
        b.updated_at = utcnow()
    s.flush()
    s.add(KnowledgeRevision(kind="playbook", ref_id=b.id, rev=b.rev, status="approved", data=pb_dict(b), actor=p.username))
    audit.record(s, "playbook.upsert", actor_id=p.user_id, actor_name=p.username, target_type="playbook", target_id=b.id)
    return b


def playbooks_for(s: Session, category: str | None) -> list[dict]:
    rows = s.execute(select(Playbook).where(Playbook.status == "approved")).scalars().all()
    return [pb_dict(b) for b in rows if not category or category in (b.applies_to or []) or "*" in (b.applies_to or [])]
