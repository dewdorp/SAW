from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from saw.apps.api.deps import AuthContext, auth, db
from saw.core.application.investigations import list_for
from saw.hunting import service as svc

router = APIRouter(prefix="/hunts", tags=["hunting"])


class HuntIn(BaseModel):
    hypothesis: str = Field(min_length=3, max_length=2000)
    investigation_id: str | None = None
    scope: str = "investigation"
    connector_id: str | None = None
    seed: dict | None = None


class StepIn(BaseModel):
    query: svc.HuntQuery
    rationale: str = Field(min_length=1, max_length=2000)
    actor: str = "analyst"
    parent_seq: int | None = None


class ConcludeIn(BaseModel):
    outcome: str
    summary: str = ""


class FindingIn(BaseModel):
    seq: int
    title: str = Field(min_length=3, max_length=200)


@router.post("", status_code=201)
def create(body: HuntIn, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    h = svc.create(s, ctx.principal, body.hypothesis, body.investigation_id, body.scope, body.connector_id, body.seed)
    return svc.to_dict(s, h)


@router.get("")
def list_(ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    readable = {i.id for i in list_for(s, ctx.principal, 500)}
    rows = s.execute(select(svc.HuntSession).order_by(svc.HuntSession.created_at.desc())).scalars().all()
    return [svc.to_dict(s, h) for h in rows if (h.investigation_id in readable) or h.owner_id == ctx.principal.user_id]


@router.get("/{hid}")
def get(hid: str, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    return svc.to_dict(s, svc.get(s, ctx.principal, hid))


@router.post("/{hid}/steps")
def step(hid: str, body: StepIn, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    svc.add_step(s, ctx.principal, hid, body.query, body.rationale, body.actor, body.parent_seq)
    return svc.to_dict(s, svc.get(s, ctx.principal, hid))


@router.post("/{hid}/conclude")
def conclude(hid: str, body: ConcludeIn, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    return svc.to_dict(s, svc.conclude(s, ctx.principal, hid, body.outcome, body.summary))


@router.post("/{hid}/finding")
def finding(hid: str, body: FindingIn, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    return {"finding_id": svc.hunt_finding(s, ctx.principal, hid, body.seq, body.title)}
