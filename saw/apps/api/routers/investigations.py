from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from saw.apps.api.deps import AuthContext, auth, db
from saw.core.application import investigations as inv_svc
from saw.core.domain.enums import Verdict
from saw.storage.models import Evidence, Finding, Investigation

router = APIRouter(prefix="/investigations", tags=["investigations"])


class InvIn(BaseModel):
    title: str = Field(min_length=1, max_length=256)
    org_unit: str = Field("", max_length=64)
    org_unit_id: str | None = Field(None, max_length=36)


class MemberIn(BaseModel):
    user_id: str
    access: str = "editor"


class CloseIn(BaseModel):
    verdict: Verdict
    reason: str
    checks: list[str] = []
    response: str = ""
    detection_idea: str = ""
    limits: str = ""  # what could not be established ("closed with limits" is said, not hidden)
    save_experience: bool = False
    behavior_assessment: str = Field("", max_length=5000)
    impact_assessment: str = Field("", max_length=5000)
    follow_up: list[dict] = Field(default_factory=list, max_length=30)


def inv_out(s: Session, i: Investigation) -> dict:
    ev = s.execute(select(Evidence).where(Evidence.investigation_id == i.id)).scalars().all()
    fc = dict(s.execute(select(Finding.risk_level, func.count()).where(Finding.investigation_id == i.id)
                        .group_by(Finding.risk_level)).all())
    return {
        "id": i.id, "display_id": i.display_id, "title": i.title, "status": i.status,
        "org_unit": i.org_unit, "org_unit_id": i.org_unit_id,
        "risk_level": i.risk_override or i.risk_level, "risk_score": i.risk_score,
        "time_start": i.time_start, "time_end": i.time_end, "verdict": i.verdict,
        "created_at": i.created_at, "closed_at": i.closed_at, "settings": i.settings,
        "evidence": [{"id": e.id, "kind": e.kind, "title": e.title, "status": e.status, "size": e.total_size,
                      "file_count": e.file_count, "context_snapshot_id": e.context_snapshot_id} for e in ev],
        "finding_counts": fc,
    }


@router.post("", status_code=201)
def create(body: InvIn, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    i = inv_svc.create(s, ctx.principal, body.title, body.org_unit, body.org_unit_id)
    return inv_out(s, i)


@router.get("")
def list_(org_unit_id: str | None = None, before: str | None = None, limit: int = Query(50, ge=1, le=200),
          ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    return [inv_out(s, i) for i in inv_svc.list_for(s, ctx.principal, limit, org_unit_id=org_unit_id, before=before)]


@router.get("/{inv_id}")
def get(inv_id: str, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    return inv_out(s, inv_svc.require(s, ctx.principal, "investigation.read", inv_id))


class SettingsIn(BaseModel):
    title: str | None = None
    org_unit: str | None = Field(None, max_length=64)
    org_unit_id: str | None = Field(None, max_length=36)
    clock_skew: dict[str, float] | None = None  # seconds per data_source (display/correlation only; raw unchanged)


@router.patch("/{inv_id}")
def patch(inv_id: str, body: SettingsIn, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    from saw.core.application import audit

    i = inv_svc.require(s, ctx.principal, "investigation.write", inv_id)
    if {"org_unit", "org_unit_id"} & body.model_fields_set:
        from saw.source_context.service import set_investigation_org

        i = set_investigation_org(s, ctx.principal, inv_id, body.org_unit, body.org_unit_id)
    if body.title:
        i.title = body.title[:256]
    if body.clock_skew is not None:
        if any(abs(v) > 86400 for v in body.clock_skew.values()):
            raise ValueError("clock skew must be within ±1 day")
        i.settings = {**(i.settings or {}), "clock_skew": body.clock_skew}
    audit.record(s, "investigation.update", actor_id=ctx.principal.user_id, actor_name=ctx.principal.username,
                 target_type="investigation", target_id=inv_id, investigation_id=inv_id,
                 detail={"fields": sorted(body.model_dump(exclude_none=True))})
    return inv_out(s, i)


@router.post("/{inv_id}/members")
def add_member(inv_id: str, body: MemberIn, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    inv_svc.add_member(s, ctx.principal, inv_id, body.user_id, body.access)
    return {"ok": True}


@router.post("/{inv_id}/close")
def close(inv_id: str, body: CloseIn, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    from saw.core.application.guidance import FollowUp, build_closure_draft
    draft = build_closure_draft(s, ctx.principal, inv_id)
    extra = [FollowUp.model_validate({k: v for k, v in x.items() if k != "check_id"}).model_dump() for x in body.follow_up]
    draft["behavior_assessment"] = body.behavior_assessment.strip() or draft["behavior_assessment"]
    draft["impact_assessment"] = body.impact_assessment.strip() or draft["impact_assessment"]
    known = [{k: v for k, v in x.items() if k != "check_id"} for x in draft["follow_up"]]
    for item in extra:
        if item not in known:
            draft["follow_up"].append(item)
            known.append(item)
    i = inv_svc.close(s, ctx.principal, inv_id, body.verdict, body.reason,
                      {"checks": body.checks, "response": body.response, "detection_idea": body.detection_idea,
                       "limits": body.limits.strip()[:1000], "guidance": draft})
    from saw.core.application import reviews

    need = reviews.on_close(s, ctx.principal, i)  # an attack verdict goes into reports: someone else looks at it
    out = inv_out(s, i)
    out["review_needed"] = need.id if need else None
    from saw.knowledge.similar import index_investigation

    index_investigation(s, i)
    if body.save_experience:
        from saw.knowledge.experience import draft_from_investigation

        out["experience_id"] = draft_from_investigation(s, ctx.principal, i).id
    return out
