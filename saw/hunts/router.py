"""Hunts: the list an analyst starts from, the activities of one hunt, and the review of each activity."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from saw.apps.api.deps import AuthContext, auth, db
from saw.hunts import service

router = APIRouter(tags=["hunts"])


@router.get("/hunts")
def hunts(ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    return service.listing(s, ctx.principal)


@router.get("/investigations/{inv_id}/hunt")
def latest(inv_id: str, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    return service.latest(s, ctx.principal, inv_id)


@router.post("/investigations/{inv_id}/hunt/run")
def run(inv_id: str, body: service.RunIn | None = None, ctx: AuthContext = Depends(auth),
        s: Session = Depends(db, scope="function")):
    return service.run(s, ctx.principal, inv_id, body)


@router.get("/investigations/{inv_id}/ai-investigations")
def ai_list(inv_id: str, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    from saw.llm import investigator

    return investigator.listing(s, ctx.principal, inv_id)


@router.post("/investigations/{inv_id}/ai-investigations", status_code=201)
def ai_start(inv_id: str, body: dict | None = None, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    from saw.core.application.investigations import Forbidden
    from saw.core.security.authz import can
    from saw.llm import investigator

    if not can(ctx.principal, "ai.use"):
        raise Forbidden("ai.use")
    return investigator.start(s, ctx.principal, inv_id, body)


@router.post("/investigations/{inv_id}/ai-investigations/{run_id}/cancel")
def ai_cancel(inv_id: str, run_id: str, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    from saw.llm import investigator

    return investigator.cancel(s, ctx.principal, inv_id, run_id)


@router.post("/ai/investigator/probe")
def ai_probe(ctx: AuthContext = Depends(auth)):
    """Ask the model for one real answer: a server that lists models is not yet a model that can investigate."""
    from saw.core.application.investigations import Forbidden
    from saw.core.security.authz import can
    from saw.llm import investigator

    if not can(ctx.principal, "ai.use"):
        raise Forbidden("ai.use")
    return investigator.status(probe=True)


@router.post("/investigations/{inv_id}/hunt/reviews", status_code=201)
def review(inv_id: str, body: service.ReviewIn, ctx: AuthContext = Depends(auth),
           s: Session = Depends(db, scope="function")):
    return service.review(s, ctx.principal, inv_id, body)


@router.get("/investigations/{inv_id}/hunt/activities/{activity_id}/evidence")
def activity_evidence(inv_id: str, activity_id: str, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    return service.activity_evidence(s, ctx.principal, inv_id, activity_id)
