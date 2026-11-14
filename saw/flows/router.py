"""Business-meaning knowledge, flow analysis runs and per-incident judgements."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from saw.apps.api.deps import AuthContext, auth, db
from saw.flows import knowledge, service

router = APIRouter(tags=["flows"])


def _conflict(exc: knowledge.Conflict) -> JSONResponse:
    from fastapi.encoders import jsonable_encoder

    return JSONResponse(jsonable_encoder({"type": "https://saw.local/problems/409", "title": "Conflict", "status": 409,
                                          "detail": str(exc), "conflicts": exc.items}), status_code=409,
                        media_type="application/problem+json")


class ExtractIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    text: str = Field(min_length=1, max_length=4000)
    host: str = Field("", max_length=255)


class PreviewIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: str = Field(pattern="^(activity|link|flow|scenario|criteria)$")
    content: dict


class RememberIn(BaseModel):
    """Save what the analyst learned in one step: reusable knowledge, this incident's judgement, then re-analyse."""
    model_config = ConfigDict(extra="forbid")
    items: list[knowledge.KnowledgeIn] = Field(default_factory=list, max_length=20)
    judgement: service.JudgementIn | None = None
    rerun: bool = True


@router.get("/knowledge/flow-items")
def items(kind: str | None = Query(None, pattern="^(activity|link|flow|scenario|criteria)$"), org_unit_id: str | None = None,
          host: str | None = None, q: str = Query("", max_length=200), ctx: AuthContext = Depends(auth),
          s: Session = Depends(db, scope="function")):
    return {"items": knowledge.list_all(s, ctx.principal, kind=kind, org_unit_id=org_unit_id, host=host, q=q)}


@router.post("/knowledge/flow-items", status_code=201)
def create(body: knowledge.KnowledgeIn, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    try:
        return knowledge.create(s, ctx.principal, body)
    except knowledge.Conflict as exc:
        return _conflict(exc)


@router.post("/knowledge/flow-items/extract")
def extract(body: ExtractIn, ctx: AuthContext = Depends(auth)):
    return knowledge.extract(body.text, {"host": body.host})


@router.get("/knowledge/flow-items/{kid}")
def one(kid: str, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    return knowledge.get(s, ctx.principal, kid)


@router.put("/knowledge/flow-items/{kid}")
def update(kid: str, body: knowledge.UpdateIn, ctx: AuthContext = Depends(auth),
           s: Session = Depends(db, scope="function")):
    try:
        return knowledge.update(s, ctx.principal, kid, body)
    except knowledge.Conflict as exc:
        return _conflict(exc)


@router.post("/knowledge/flow-items/{kid}/stop")
def stop(kid: str, body: knowledge.StateIn, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    try:
        return knowledge.set_status(s, ctx.principal, kid, body, "stopped")
    except knowledge.Conflict as exc:
        return _conflict(exc)


@router.post("/knowledge/flow-items/{kid}/restore")
def restore(kid: str, body: knowledge.StateIn, ctx: AuthContext = Depends(auth),
            s: Session = Depends(db, scope="function")):
    try:
        return knowledge.set_status(s, ctx.principal, kid, body, "active")
    except knowledge.Conflict as exc:
        return _conflict(exc)


@router.post("/knowledge/flow-items/{kid}/versions/{version}/restore")
def restore_version(kid: str, version: int, body: knowledge.StateIn, ctx: AuthContext = Depends(auth),
                    s: Session = Depends(db, scope="function")):
    try:
        return knowledge.restore_version(s, ctx.principal, kid, version, body)
    except knowledge.Conflict as exc:
        return _conflict(exc)


@router.get("/knowledge/flow-items/{kid}/history")
def history(kid: str, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    return {"versions": knowledge.history(s, ctx.principal, kid)}


@router.get("/knowledge/flow-items/{kid}/affected")
def affected(kid: str, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    return {"investigations": service.affected(s, ctx.principal, kid)}


@router.post("/investigations/{inv_id}/flow-knowledge/preview")
def preview(inv_id: str, body: PreviewIn, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    return knowledge.preview(s, ctx.principal, inv_id, body.kind, body.content)


@router.get("/investigations/{inv_id}/flows")
def latest(inv_id: str, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    return service.latest(s, ctx.principal, inv_id)


@router.post("/investigations/{inv_id}/flows/run")
def run(inv_id: str, body: service.RunIn | None = None, ctx: AuthContext = Depends(auth),
        s: Session = Depends(db, scope="function")):
    return service.run(s, ctx.principal, inv_id, body)


@router.get("/investigations/{inv_id}/flows/runs")
def runs(inv_id: str, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    return {"runs": service.list_runs(s, ctx.principal, inv_id)}


@router.get("/investigations/{inv_id}/flows/runs/{run_id}")
def run_get(inv_id: str, run_id: str, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    return service.get_run(s, ctx.principal, inv_id, run_id)


@router.get("/investigations/{inv_id}/flows/runs/{run_id}/flow")
def flow(inv_id: str, run_id: str, key: str = Query(..., max_length=200), ctx: AuthContext = Depends(auth),
         s: Session = Depends(db, scope="function")):
    return service.flow_detail(s, ctx.principal, inv_id, run_id, key)


@router.post("/investigations/{inv_id}/flows/judgements", status_code=201)
def judge(inv_id: str, body: service.JudgementIn, ctx: AuthContext = Depends(auth),
          s: Session = Depends(db, scope="function")):
    return service.judge(s, ctx.principal, inv_id, body)


@router.post("/investigations/{inv_id}/flows/remember", status_code=201)
def remember(inv_id: str, body: RememberIn, ctx: AuthContext = Depends(auth),
             s: Session = Depends(db, scope="function")):
    """One step for the analyst: reusable knowledge is saved as knowledge, the judgement stays with this incident."""
    saved = []
    try:
        for item in body.items:
            if not item.evidence.investigation_id:
                item.evidence.investigation_id = inv_id
            saved.append(knowledge.create(s, ctx.principal, item))
    except knowledge.Conflict as exc:
        s.rollback()
        return _conflict(exc)
    judgement = service.judge(s, ctx.principal, inv_id, body.judgement) if body.judgement else None
    result = service.run(s, ctx.principal, inv_id, {"reason": "knowledge_changed"}) if body.rerun and saved else None
    return {"saved": saved, "judgement": judgement,
            "run": {k: result[k] for k in ("id", "version", "status", "summary", "changes")} if result else None}
