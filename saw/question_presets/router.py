"""Question previews on the current logs and saved question conditions."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from saw.apps.api.deps import AuthContext, auth, db
from saw.question_presets import service

router = APIRouter(tags=["question-presets"])


class PreviewIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    parameters: dict[str, Any] = Field(default_factory=dict)
    sensitivity: str = "normal"
    preset_id: str | None = None
    preset_version: int | None = None


@router.post("/investigations/{inv_id}/question-bundles/{bundle}/preview")
def preview(inv_id: str, bundle: str, body: PreviewIn, ctx: AuthContext = Depends(auth),
            s: Session = Depends(db, scope="function")):
    """Run one question's condition on this investigation's current logs, saved or not. Nothing is stored."""
    from saw.core.application import question_bundles as qb
    from saw.core.application.investigations import period_window, require
    from saw.detection.derived_access import require_investigation_results

    inv = require(s, ctx.principal, "investigation.read", inv_id)
    require_investigation_results(s, ctx.principal, inv_id)
    if body.sensitivity not in qb.SENSITIVITY:
        raise HTTPException(status_code=422, detail="sensitivity must be low, normal or high")
    parameters, preset = body.parameters, None
    if body.preset_id:
        stored_bundle, parameters, preset = service.parameters_of(s, ctx.principal, inv_id, body.preset_id, body.preset_version)
        if stored_bundle != bundle:
            raise HTTPException(status_code=422, detail="저장된 조건이 다른 질문의 조건입니다")
    time = period_window(inv)
    result = qb.run_one(inv, bundle, parameters, sensitivity=body.sensitivity, time=time)
    return {**result, "scope": qb.scope_of(inv, time), "preset": preset, "preview": preset is None}


@router.get("/investigations/{inv_id}/question-examples")
def examples(inv_id: str, q: str = Query("", max_length=200), kind: str = Query("", pattern="^(|detection|hunt|scenario)$"),
             ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    """The 120 example specifications with their execution, data and calculation states for this investigation."""
    from saw.core.application.investigations import require
    from saw.core.application.question_examples import search

    require(s, ctx.principal, "investigation.read", inv_id)
    return search(inv_id, q, kind)


@router.get("/investigations/{inv_id}/question-presets")
def presets(inv_id: str, bundle: str | None = None, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    return {"items": service.list_for(s, ctx.principal, inv_id, bundle), "scopes": service.SCOPES}


@router.post("/investigations/{inv_id}/question-presets", status_code=201)
def create(inv_id: str, body: service.PresetIn, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    return service.save(s, ctx.principal, inv_id, body)


@router.get("/investigations/{inv_id}/question-presets/{preset_id}")
def read(inv_id: str, preset_id: str, version: int | None = Query(None, ge=1), ctx: AuthContext = Depends(auth),
         s: Session = Depends(db, scope="function")):
    out = service.get(s, ctx.principal, inv_id, preset_id, version)
    versions = out["versions"]
    if len(versions) > 1:
        out["last_change"] = service.diff(versions[-2]["parameters"], versions[-1]["parameters"])
    return out


@router.put("/investigations/{inv_id}/question-presets/{preset_id}")
def update(inv_id: str, preset_id: str, body: service.PresetIn, ctx: AuthContext = Depends(auth),
           s: Session = Depends(db, scope="function")):
    try:
        return service.save(s, ctx.principal, inv_id, body, preset_id)
    except service.Conflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from None
