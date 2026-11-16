"""Peer review requests for important conclusions (see core/application/reviews.py)."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from saw.apps.api.deps import AuthContext, auth, db
from saw.core.application import reviews, teamwork
from saw.core.application.investigations import require

router = APIRouter(tags=["reviews"])


class RequestIn(BaseModel):
    subject_type: str = "other"
    subject_id: str = ""
    subject_label: str = ""
    conclusion: str
    scope_note: str = ""
    evidence: list[str] = Field(default_factory=list, max_length=20)
    reviewer_id: str


class DecideIn(BaseModel):
    outcome: str
    note: str


@router.get("/investigations/{inv_id}/reviews")
def list_(inv_id: str, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    require(s, ctx.principal, "investigation.read", inv_id)
    return {"reviews": reviews.list_for_investigation(s, inv_id), "me": ctx.principal.user_id,
            "outcomes": reviews.OUTCOMES}


@router.post("/investigations/{inv_id}/reviews", status_code=201)
def request(inv_id: str, body: RequestIn, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    return reviews.to_dict(s, reviews.request(s, ctx.principal, inv_id, body.model_dump()))


@router.post("/investigations/{inv_id}/reviews/{review_id}/withdraw")
def withdraw(inv_id: str, review_id: str, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    return reviews.to_dict(s, reviews.withdraw(s, ctx.principal, inv_id, review_id))


class SupportIn(BaseModel):
    question: str
    scope_note: str = ""
    helper_id: str


class SupportUpdateIn(BaseModel):
    status: str
    result_note: str = ""
    remaining: str = ""


@router.get("/investigations/{inv_id}/support")
def support_list(inv_id: str, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    inv = require(s, ctx.principal, "investigation.read", inv_id)
    from saw.core.domain.enums import Role

    return {"items": teamwork.list_for_investigation(s, inv_id), "me": ctx.principal.user_id,
            "can_request": inv.owner_id == ctx.principal.user_id or bool(ctx.principal.roles & {Role.SOC_MANAGER, Role.ADMIN})}


@router.post("/investigations/{inv_id}/support", status_code=201)
def support_request(inv_id: str, body: SupportIn, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    return teamwork.to_dict(teamwork.request(s, ctx.principal, inv_id, body.question, body.scope_note, body.helper_id))


@router.post("/investigations/{inv_id}/support/{support_id}/cancel")
def support_cancel(inv_id: str, support_id: str, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    return teamwork.to_dict(teamwork.cancel(s, ctx.principal, inv_id, support_id))


@router.post("/support/{support_id}")
def support_update(support_id: str, body: SupportUpdateIn, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    return teamwork.to_dict(teamwork.update(s, ctx.principal, support_id, body.status, body.result_note, body.remaining))


@router.get("/support/inbox")
def support_inbox(ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    return {"items": teamwork.inbox(s, ctx.principal)}


@router.get("/investigations/{inv_id}/closing-check")
def closing_check(inv_id: str, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    inv = require(s, ctx.principal, "investigation.read", inv_id)
    return {"items": teamwork.closing_check(s, inv)}


@router.get("/reviews/inbox")
def inbox(ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    return reviews.inbox(s, ctx.principal)


@router.get("/reviews/reviewers")
def reviewers(ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    return reviews.reviewers(s, ctx.principal)


@router.post("/reviews/{review_id}/decide")
def decide(review_id: str, body: DecideIn, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    return reviews.to_dict(s, reviews.decide(s, ctx.principal, review_id, body.outcome, body.note))
