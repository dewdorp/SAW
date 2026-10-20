"""Selected truth and exact policy/spec APIs."""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from saw.apps.api.deps import AuthContext, db, require_perm
from saw.detection import testing

router = APIRouter(tags=["detection"])


@router.get("/detection-cases")
def list_cases(investigation_id: str | None = None, limit: int = Query(50, ge=1, le=100), before: str | None = None,
               ctx: AuthContext = Depends(require_perm("knowledge.read")), s: Session = Depends(db, scope="function")):
    return testing.list_cases(s, ctx.principal, investigation_id, limit, before)


@router.post("/detection-cases", status_code=201)
def create_case(body: testing.CaseInput, ctx: AuthContext = Depends(require_perm("detection.write")),
                s: Session = Depends(db, scope="function")):
    return testing.case_dict(testing.create_case(s, ctx.principal, body.model_dump(), session_id=ctx.session.id))


@router.post("/detection-cases/{case_id}/versions", status_code=201)
def revise_case(case_id: str, body: testing.CaseInput, ctx: AuthContext = Depends(require_perm("detection.write")),
                s: Session = Depends(db, scope="function")):
    return testing.case_dict(testing.create_case(s, ctx.principal, body.model_dump(), case_id, session_id=ctx.session.id))


@router.get("/detection-cases/versions/{version_id}")
def get_case(version_id: str, ctx: AuthContext = Depends(require_perm("knowledge.read")),
             s: Session = Depends(db, scope="function")):
    return testing.case_dict(testing.get_case(s, ctx.principal, version_id))
