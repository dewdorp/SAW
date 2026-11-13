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


@router.post("/investigations/{inv_id}/hunt/reviews", status_code=201)
def review(inv_id: str, body: service.ReviewIn, ctx: AuthContext = Depends(auth),
           s: Session = Depends(db, scope="function")):
    return service.review(s, ctx.principal, inv_id, body)
