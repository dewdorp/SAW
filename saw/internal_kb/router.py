"""Internal golden records and device alert-name meanings."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from saw.apps.api.deps import AuthContext, auth, db
from saw.internal_kb import candidates, golden, signatures

router = APIRouter(tags=["internal-knowledge"])


@router.get("/investigations/{inv_id}/internal-golden")
def golden_for_investigation(inv_id: str, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    return {"record": golden.for_investigation(s, ctx.principal, inv_id)}


@router.get("/investigations/{inv_id}/internal-golden/draft")
def golden_draft(inv_id: str, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    return {"content": golden.draft(s, ctx.principal, inv_id)}


@router.post("/investigations/{inv_id}/internal-golden", status_code=201)
def golden_save(inv_id: str, body: golden.SaveIn, ctx: AuthContext = Depends(auth),
                s: Session = Depends(db, scope="function")):
    return golden.save(s, ctx.principal, inv_id, body)


@router.get("/knowledge/internal-golden")
def golden_list(org_unit_id: str | None = None, limit: int = Query(100, ge=1, le=500),
                ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    return {"items": golden.list_records(s, ctx.principal, org_unit_id=org_unit_id, limit=limit)}


@router.get("/knowledge/internal-golden-export")
def golden_export(audience: str = Query(..., pattern="^(agent|evaluator)$"), split: str | None = None,
                  org_unit_id: str | None = None, ctx: AuthContext = Depends(auth),
                  s: Session = Depends(db, scope="function")):
    from fastapi.responses import Response

    data = golden.export(s, ctx.principal, audience=audience, split=split, org_unit_id=org_unit_id)
    name = "agent-input.jsonl" if audience == "agent" else "evaluator-answer.jsonl"
    return Response(data, media_type="application/x-ndjson",
                    headers={"Content-Disposition": f'attachment; filename="{name}"'})


@router.get("/knowledge/internal-golden/{record_id}")
def golden_get(record_id: str, version: int | None = Query(None, ge=1), ctx: AuthContext = Depends(auth),
               s: Session = Depends(db, scope="function")):
    return golden.get(s, ctx.principal, record_id, version)


@router.get("/knowledge/device-signatures")
def signature_list(q: str = Query("", max_length=200), ctx: AuthContext = Depends(auth),
                   s: Session = Depends(db, scope="function")):
    return {"items": signatures.list_all(s, ctx.principal, q=q)}


@router.post("/knowledge/device-signatures", status_code=201)
def signature_create(body: signatures.SignatureIn, ctx: AuthContext = Depends(auth),
                     s: Session = Depends(db, scope="function")):
    return signatures.create(s, ctx.principal, body)


@router.put("/knowledge/device-signatures/{sid}")
def signature_update(sid: str, body: signatures.UpdateIn, ctx: AuthContext = Depends(auth),
                     s: Session = Depends(db, scope="function")):
    return signatures.update(s, ctx.principal, sid, body)


@router.get("/knowledge/device-signatures/{sid}/history")
def signature_history(sid: str, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    return {"items": signatures.history(s, ctx.principal, sid)}


@router.get("/investigations/{inv_id}/alert-names")
def investigation_alert_names(inv_id: str, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    return signatures.investigation_alerts(s, ctx.principal, inv_id)


@router.get("/knowledge/golden-candidates")
def candidate_list(q: str = Query("", max_length=200), source_kind: str | None = Query(None, pattern="^(casebook|investigation)$"),
                   status: str | None = Query(None, pattern="^(candidate|saved)$"), source_id: str | None = Query(None, max_length=64),
                   ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    return {"items": candidates.list_items(s, ctx.principal, q=q, source_kind=source_kind, status=status,
                                           source_id=source_id)}


@router.post("/knowledge/golden-candidates", status_code=201)
def candidate_add(body: candidates.AddIn, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    return candidates.add(s, ctx.principal, body)


@router.patch("/knowledge/golden-candidates/{candidate_id}")
def candidate_update(candidate_id: str, body: candidates.UpdateIn, ctx: AuthContext = Depends(auth),
                     s: Session = Depends(db, scope="function")):
    return candidates.update(s, ctx.principal, candidate_id, body)


@router.delete("/knowledge/golden-candidates/{candidate_id}", status_code=204)
def candidate_remove(candidate_id: str, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    candidates.remove(s, ctx.principal, candidate_id)


@router.post("/knowledge/golden-candidates/save")
def candidate_save(body: candidates.IdsIn, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    return {"items": candidates.save(s, ctx.principal, body)}


@router.post("/knowledge/golden-candidates/export")
def candidate_export(body: candidates.IdsIn, audience: str = Query(..., pattern="^(agent|evaluator)$"),
                     ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    from fastapi.responses import Response

    data = candidates.export(s, ctx.principal, body, audience)
    name = "agent-input.jsonl" if audience == "agent" else "evaluator-answer.jsonl"
    return Response(data, media_type="application/x-ndjson",
                    headers={"Content-Disposition": f'attachment; filename="{name}"'})
