"""Investigation use cases + access resolution (docs/32)."""
from __future__ import annotations

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from saw.core.application import audit
from saw.core.application.ids import next_display_id
from saw.core.domain.enums import InvestigationStatus, Verdict
from saw.core.security.authz import InvestigationAccess, Principal, can
from saw.storage.db import utcnow
from saw.storage.models import Investigation, InvestigationMember


class Forbidden(Exception):
    pass


class NotFound(Exception):
    pass


def access_of(s: Session, p: Principal, inv_id: str) -> InvestigationAccess:
    m = s.get(InvestigationMember, (inv_id, p.user_id))
    return InvestigationAccess(m.access if m else None)


def require(s: Session, p: Principal, permission: str, inv_id: str) -> Investigation:
    from saw.core.application.data_deletion import lock_investigation

    inv = s.get(Investigation, inv_id)
    if inv is None:
        raise NotFound("investigation not found")
    if not can(p, permission, access_of(s, p, inv_id)):
        audit.record(s, "authz.denied", actor_id=p.user_id, actor_name=p.username, target_type="investigation",
                     target_id=inv_id, investigation_id=inv_id, outcome="denied", detail={"perm": permission})
        raise Forbidden(permission)
    return lock_investigation(s, inv_id)


def create(s: Session, p: Principal, title: str, org_unit: str = "") -> Investigation:
    if not can(p, "investigation.create"):
        raise Forbidden("investigation.create")
    inv = Investigation(display_id=next_display_id(s, "INV"), title=title.strip()[:256] or "Untitled",
                        owner_id=p.user_id, org_unit=org_unit)
    s.add(inv)
    s.flush()
    s.add(InvestigationMember(investigation_id=inv.id, user_id=p.user_id, access="owner"))
    audit.record(s, "investigation.create", actor_id=p.user_id, actor_name=p.username,
                 target_type="investigation", target_id=inv.id, investigation_id=inv.id,
                 detail={"title": inv.title})
    return inv


def list_for(s: Session, p: Principal, limit: int = 50) -> list[Investigation]:
    q = select(Investigation).order_by(Investigation.created_at.desc()).limit(limit)
    if not can(p, "investigation.read"):
        return []
    from saw.core.domain.enums import Role

    if Role.SOC_MANAGER not in p.roles:
        member_ids = select(InvestigationMember.investigation_id).where(InvestigationMember.user_id == p.user_id)
        q = q.where(or_(Investigation.id.in_(member_ids)))
    return [i for i in s.execute(q).scalars() if not (i.settings or {}).get("data_deletion")]


def add_member(s: Session, p: Principal, inv_id: str, user_id: str, access: str) -> None:
    inv = require(s, p, "investigation.write", inv_id)
    if access not in {"owner", "editor", "viewer"}:
        raise ValueError("bad access")
    s.merge(InvestigationMember(investigation_id=inv.id, user_id=user_id, access=access))
    audit.record(s, "investigation.member", actor_id=p.user_id, actor_name=p.username, target_type="user",
                 target_id=user_id, investigation_id=inv.id, detail={"access": access})


def close(s: Session, p: Principal, inv_id: str, verdict: str, reason: str, detail: dict) -> Investigation:
    inv = require(s, p, "investigation.close", inv_id)
    if not reason.strip():
        raise ValueError("analyst comment is required")
    inv.verdict = str(Verdict(verdict))
    inv.verdict_reason = reason
    from saw.behavior.service import closure_references
    inv.close_detail = {**detail, "behavior_results": closure_references(s, inv_id)}
    inv.status = InvestigationStatus.CLOSED
    inv.closed_at = utcnow()
    audit.record(s, "investigation.close", actor_id=p.user_id, actor_name=p.username,
                 target_type="investigation", target_id=inv.id, investigation_id=inv.id,
                 detail={"verdict": inv.verdict})
    return inv
