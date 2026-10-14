from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from saw.apps.api.deps import AuthContext, auth, db, require_perm
from saw.core.application.investigations import NotFound
from saw.llm import service

router = APIRouter(prefix="/ai", tags=["ai"])


class ActionIn(BaseModel):
    investigation_id: str
    action: str
    finding_id: str | None = None
    question: str = Field("", max_length=2000)


class FeedbackIn(BaseModel):
    feedback: str = Field(pattern="^(helpful|wrong|unsafe)$")


@router.get("/status")
def status(ctx: AuthContext = Depends(auth)):
    return service.provider_status()


@router.post("/actions")
def action(body: ActionIn, ctx: AuthContext = Depends(require_perm("ai.use")), s: Session = Depends(db, scope="function")):
    return service.run(s, ctx.principal, body.investigation_id, body.action, body.question, body.finding_id,
                       session_id=ctx.session.id)


@router.get("/context")
def context(investigation_id: str, finding_id: str, ctx: AuthContext = Depends(require_perm("ai.use")),
            s: Session = Depends(db, scope="function")):
    return service.preview_context(s, ctx.principal, investigation_id, finding_id)


@router.post("/{rid}/feedback")
def feedback(rid: str, body: FeedbackIn, ctx: AuthContext = Depends(require_perm("ai.use")), s: Session = Depends(db, scope="function")):
    r = s.get(service.LlmInteraction, rid)
    if r is None or r.user_id != ctx.principal.user_id:
        raise NotFound("interaction not found")
    if r.investigation_id:
        from saw.core.application.investigations import require
        require(s, ctx.principal, "investigation.read", r.investigation_id)
    r.feedback = body.feedback
    return {"ok": True}
