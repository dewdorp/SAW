"""Scenarios: catalogue, preview on current data. Saving and versions use the knowledge endpoints (kind "scenario")."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from saw.apps.api.deps import AuthContext, auth, db
from saw.scenarios import service

router = APIRouter(tags=["scenarios"])


class PreviewIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    content: dict


@router.get("/scenarios")
def catalog(org_unit_id: str | None = None, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    return service.catalog(s, ctx.principal, org_unit_id)


@router.post("/scenarios/describe")
def describe(body: PreviewIn, ctx: AuthContext = Depends(auth)):
    from saw.flows.knowledge import ScenarioContent

    # The sentence is shown while the analyst is still typing: a name not written yet is not an error here.
    raw = {**body.content, "name": str(body.content.get("name") or "").strip() or "이름 없음"}
    content = ScenarioContent.model_validate(raw).model_dump()
    return {"description": service.describe(content), "unit": service._unit(content), "content": content}


@router.post("/investigations/{inv_id}/scenarios/preview")
def preview(inv_id: str, body: PreviewIn, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    return service.preview(s, ctx.principal, inv_id, body.content)
