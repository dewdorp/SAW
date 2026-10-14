"""Scoped guidance reads. Merely opening guidance never creates a Check."""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from saw.apps.api.deps import AuthContext, auth, db
from saw.core.application import guidance

router = APIRouter(tags=["guidance"])


@router.post("/investigations/{inv_id}/guidance/preview")
def preview(inv_id: str, body: guidance.ScopeIn, ctx: AuthContext = Depends(auth),
            s: Session = Depends(db, scope="function")):
    return guidance.preview(s, ctx.principal, inv_id, body)


@router.get("/investigations/{inv_id}/guidance/closure-draft")
def closure_draft(inv_id: str, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    return guidance.build_closure_draft(s, ctx.principal, inv_id)
