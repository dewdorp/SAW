"""Confirmation records of an investigation and shared results of the team (see core/application/checks.py)."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from saw.apps.api.deps import AuthContext, auth, client_ip, db
from saw.core.application import checks
from saw.core.application.investigations import require

router = APIRouter(tags=["checks"])


class CheckIn(BaseModel):
    target_type: str | None = None
    target_key: str | None = None
    target_label: str | None = None
    scope: dict[str, Any] | None = None
    questions: list[str] | None = None
    judgement: str | None = None
    note: str | None = None
    evidence: list[str] | None = None
    time_start: str | None = None
    time_end: str | None = None
    shared: bool | None = None
    share: dict[str, Any] | None = None
    guidance: dict[str, Any] | None = None
    behavior: dict[str, Any] | None = None


class LookupIn(BaseModel):
    event_ids: list[str] = Field(default_factory=list, max_length=1000)
    entity_keys: list[str] = Field(default_factory=list, max_length=2000)


class KeysIn(BaseModel):
    keys: list[str] = Field(default_factory=list, max_length=50)


class NoteIn(BaseModel):
    note: str = ""


class CiteIn(BaseModel):
    source_id: str
    note: str = ""


def _conflict(e: checks.Conflict):
    return HTTPException(409, str(e))


@router.get("/investigations/{inv_id}/checks")
def list_(inv_id: str, target_key: str | None = None, history: bool = False, ctx: AuthContext = Depends(auth),
          s: Session = Depends(db, scope="function")):
    require(s, ctx.principal, "investigation.read", inv_id)
    return {"checks": [checks.to_dict(c) for c in checks.list_checks(s, inv_id, target_key, history, principal=ctx.principal)],
            "summary": checks.summary(s, inv_id, principal=ctx.principal), "me": ctx.principal.user_id}


@router.post("/investigations/{inv_id}/checks", status_code=201)
def create(inv_id: str, body: CheckIn, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    return checks.to_dict(checks.create(s, ctx.principal, inv_id, body.model_dump(exclude_none=True)))


@router.put("/investigations/{inv_id}/checks/{check_id}")
def change(inv_id: str, check_id: str, body: CheckIn, ctx: AuthContext = Depends(auth),
           s: Session = Depends(db, scope="function")):
    try:
        return checks.to_dict(checks.change(s, ctx.principal, inv_id, check_id, body.model_dump(exclude_none=True)))
    except checks.Conflict as e:
        raise _conflict(e) from None


@router.post("/investigations/{inv_id}/checks/{check_id}/cancel")
def cancel(inv_id: str, check_id: str, body: NoteIn, ctx: AuthContext = Depends(auth),
           s: Session = Depends(db, scope="function")):
    try:
        return checks.to_dict(checks.cancel(s, ctx.principal, inv_id, check_id, body.note))
    except checks.Conflict as e:
        raise _conflict(e) from None


@router.get("/investigations/{inv_id}/checks/marks")
def marks(inv_id: str, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    require(s, ctx.principal, "investigation.read", inv_id)
    return checks.marks(s, inv_id, principal=ctx.principal)


@router.post("/investigations/{inv_id}/checks/lookup")
def lookup(inv_id: str, body: LookupIn, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    require(s, ctx.principal, "investigation.read", inv_id)
    return checks.lookup(s, inv_id, body.event_ids, body.entity_keys, principal=ctx.principal)


@router.post("/investigations/{inv_id}/checks/team")
def team(inv_id: str, body: KeysIn, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    return {"items": checks.team_for(s, ctx.principal, inv_id, body.keys)}


@router.post("/investigations/{inv_id}/checks/cite", status_code=201)
def cite(inv_id: str, body: CiteIn, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    return checks.to_dict(checks.cite(s, ctx.principal, inv_id, body.source_id, body.note))


@router.get("/team-checks/inbox")
def inbox(ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    return checks.inbox(s, ctx.principal)


@router.get("/team-checks/{check_id}/evidence")
def evidence(check_id: str, request: Request, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    return checks.evidence_view(s, ctx.principal, check_id, client_ip(request))


@router.post("/team-checks/{check_id}/recheck")
def recheck(check_id: str, body: NoteIn, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    return checks.to_dict(checks.request_recheck(s, ctx.principal, check_id, body.note), full=False)
