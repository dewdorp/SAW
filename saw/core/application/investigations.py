"""Investigation use cases + access resolution (docs/32)."""
from __future__ import annotations

from datetime import datetime, timedelta

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


MAX_PERIOD_DAYS = 400


def checked_period(start, end):
    """Validate a declared investigation period; naive values are read in the configured timezone."""
    if start is None and end is None:
        return None, None
    if start is None or end is None:
        raise ValueError("investigation period needs both start and end")
    from zoneinfo import ZoneInfo

    from saw.config import get_settings

    zone = ZoneInfo(get_settings().default_timezone)
    start = start if start.tzinfo else start.replace(tzinfo=zone)
    end = end if end.tzinfo else end.replace(tzinfo=zone)
    if end < start:
        raise ValueError("investigation period end is before its start")
    if (end - start).days > MAX_PERIOD_DAYS:
        raise ValueError(f"investigation period is limited to {MAX_PERIOD_DAYS} days")
    return start, end


def period_settings(settings: dict | None, start, end) -> dict:
    """The declared scope lives in settings (time_start/time_end are derived from the data, not chosen)."""
    out = {k: v for k, v in (settings or {}).items() if k != "period"}
    if start is not None:
        out["period"] = {"start": start.isoformat(), "end": end.isoformat()}
    return out


def declared_period(inv: Investigation) -> tuple[str | None, str | None]:
    period = (inv.settings or {}).get("period") or {}
    return period.get("start"), period.get("end")


def period_window(inv: Investigation):
    """The declared period as one time window for every count, chart and check.

    A period that ends at 23:59:59 of a day means "through that whole day": it is applied as the half-open
    window [start, next day 00:00), so records at 23:59:59.500 are inside it. Any other end stays inclusive.
    """
    from saw.core.schemas.query import TimeRange

    start, end = declared_period(inv)
    if not start or not end:
        return None
    begin, finish = datetime.fromisoformat(start), datetime.fromisoformat(end)
    if (finish.hour, finish.minute, finish.second, finish.microsecond) == (23, 59, 59, 0):
        following = (finish + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
        return TimeRange(start=begin.isoformat(), end=following.isoformat(), end_exclusive=True)
    return TimeRange(start=begin.isoformat(), end=finish.isoformat())


def create(s: Session, p: Principal, title: str, org_unit: str = "", org_unit_id: str | None = None,
           period_start=None, period_end=None) -> Investigation:
    if not can(p, "investigation.create"):
        raise Forbidden("investigation.create")
    from saw.source_context.service import record_org_assignment, resolve_org

    label, org_id = resolve_org(s, org_unit, org_unit_id)
    period_start, period_end = checked_period(period_start, period_end)
    inv = Investigation(display_id=next_display_id(s, "INV"), title=title.strip()[:256] or "Untitled",
                        owner_id=p.user_id, org_unit=label, org_unit_id=org_id,
                        settings=period_settings({}, period_start, period_end))
    s.add(inv)
    s.flush()
    s.add(InvestigationMember(investigation_id=inv.id, user_id=p.user_id, access="owner"))
    record_org_assignment(s, p, inv, org_unit)
    audit.record(s, "investigation.create", actor_id=p.user_id, actor_name=p.username,
                 target_type="investigation", target_id=inv.id, investigation_id=inv.id,
                 detail={"title": inv.title})
    return inv


def list_for(s: Session, p: Principal, limit: int = 50, *, org_unit_id: str | None = None,
             before: str | None = None) -> list[Investigation]:
    q = select(Investigation).order_by(Investigation.created_at.desc(), Investigation.id.desc()).limit(max(limit, 1))
    if org_unit_id is not None:
        q = q.where(Investigation.org_unit_id == org_unit_id)
    if before is not None:
        cursor = require(s, p, "investigation.read", before)
        q = q.where(or_(Investigation.created_at < cursor.created_at,
                       (Investigation.created_at == cursor.created_at) & (Investigation.id < cursor.id)))
    if not can(p, "investigation.read"):
        return []
    from saw.core.domain.enums import Role

    if not (p.roles & {Role.SOC_MANAGER, Role.ADMIN}):
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
