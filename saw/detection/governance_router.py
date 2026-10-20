"""Version-pinned local detection policy operations; never external deployment."""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from saw.apps.api.deps import AuthContext, db, require_perm
from saw.core.application.investigations import NotFound
from saw.core.application.provenance import canonical
from saw.detection import governance as gov
from saw.detection import service, testing
from saw.detection.policy_models import Activation, PolicyBinding

router = APIRouter(tags=["detection"])


def _bounded(body):
    if len(canonical(body).encode()) > 65536:
        raise HTTPException(422, "detection_request_too_large")
    return body


def invoke(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except gov.Conflict as exc:
        raise HTTPException(409, str(exc)) from None


@router.get("/detector-specs")
def specs(ctx: AuthContext = Depends(require_perm("knowledge.read"))):
    from saw.detection.specs import get_spec
    return {"items": [get_spec(k) for k in ("fw.observation", "waf.observation", "ips.observation",
                                           "ddos.observation", "ndr.observation", "sigma")]}


@router.get("/detector-specs/{detector_id}")
def spec(detector_id: str, ctx: AuthContext = Depends(require_perm("knowledge.read"))):
    return gov._spec(detector_id)


@router.get("/detector-specs/{detector_id}/effective")
def effective(detector_id: str, org_unit_id: str | None = None, device_id: str | None = None,
              ctx: AuthContext = Depends(require_perm("knowledge.read")), s: Session = Depends(db, scope="function")):
    scope = {"kind": "device", "org_unit_id": org_unit_id, "device_id": device_id} if device_id else (
        {"kind": "org", "org_unit_id": org_unit_id} if org_unit_id else {"kind": "group"})
    return {"spec": gov._spec(detector_id), "effective": invoke(gov.resolve_effective, s, detector_id, scope, p=ctx.principal)}


@router.get("/detections/{det_id}/versions/{version_id}")
def rule_version(det_id: str, version_id: str, ctx: AuthContext = Depends(require_perm("knowledge.read")),
                 s: Session = Depends(db, scope="function")):
    return invoke(gov.exact_version_dict, s, ctx.principal, det_id, version_id)


@router.post("/detections/{det_id}/activate")
def activate_rule(det_id: str, body: dict = Body(...), ctx: AuthContext = Depends(require_perm("detection.approve")),
                  s: Session = Depends(db, scope="function")):
    row = invoke(gov.activate_rule, s, ctx.principal, det_id, _bounded(body))
    return service.to_dict(s, row, full=True, p=ctx.principal)


@router.post("/detections/{det_id}/rollback")
def rollback_rule(det_id: str, body: dict = Body(...), ctx: AuthContext = Depends(require_perm("detection.approve")),
                  s: Session = Depends(db, scope="function")):
    row = invoke(gov.rollback_rule, s, ctx.principal, det_id, _bounded(body))
    return service.to_dict(s, row, full=True, p=ctx.principal)


def _history(s, p, kind, ident, before, limit):
    owner = s.get(service.Detection if kind == "rule" else PolicyBinding, ident)
    if owner is None:
        raise NotFound("detection not found")
    if kind == "policy":
        gov._scope(s, p, owner.scope)
    gov._read_sources(s, p, gov._source_ids(s, kind, owner))
    query = select(Activation).where(Activation.subject_kind == kind, Activation.subject_id == ident)
    if before:
        query = query.where(Activation.revision < before)
    rows = list(s.scalars(query.order_by(Activation.revision.desc()).limit(limit + 1)))
    return {"items": [{"id": r.id, "revision": r.revision, "action": r.action, "from_version_id": r.from_version_id,
                      "to_version_id": r.to_version_id, "approval_id": r.approval_id, "reason": r.reason,
                      "actor_name": r.actor_name, "created_at": r.created_at} for r in rows[:limit]],
            "next_cursor": rows[limit - 1].revision if len(rows) > limit else None}


@router.get("/detections/{det_id}/activations")
def rule_history(det_id: str, before_revision: int | None = None, limit: int = Query(50, ge=1, le=100),
                 ctx: AuthContext = Depends(require_perm("knowledge.read")), s: Session = Depends(db, scope="function")):
    return _history(s, ctx.principal, "rule", det_id, before_revision, limit)


@router.get("/detection-policies")
def policies(detector_id: str | None = None, scope_key: str | None = None,
             ctx: AuthContext = Depends(require_perm("knowledge.read")), s: Session = Depends(db, scope="function")):
    items = invoke(gov.list_policies, s, ctx.principal, detector_id)
    if scope_key:
        items = [v for v in items if gov._scope(s, ctx.principal, v["scope"])[1] == scope_key]
    return {"items": items, "next_cursor": None}


@router.post("/detection-policies/drafts", status_code=201)
def draft(body: dict = Body(...), ctx: AuthContext = Depends(require_perm("detection.write")),
          s: Session = Depends(db, scope="function")):
    row = invoke(gov.draft_policy, s, ctx.principal, _bounded(body))
    return gov.policy_to_dict(s, ctx.principal, row)


@router.get("/detection-policies/{binding_id}")
def policy(binding_id: str, ctx: AuthContext = Depends(require_perm("knowledge.read")),
           s: Session = Depends(db, scope="function")):
    row = s.get(PolicyBinding, binding_id)
    if row is None:
        raise NotFound("policy not found")
    return invoke(gov.policy_to_dict, s, ctx.principal, row)


@router.post("/detection-policies/{binding_id}/test")
def test_policy(binding_id: str, body: testing.SelectedTestInput, ctx: AuthContext = Depends(require_perm("detection.write")),
                s: Session = Depends(db, scope="function")):
    row = invoke(testing.run_selected, s, ctx.principal, binding_id, body.model_dump(),
                 subject_kind="policy", session_id=ctx.session.id)
    return testing.serialized_test(s, ctx.principal, row)


@router.post("/detection-policies/{binding_id}/approve")
def approve_policy(binding_id: str, body: dict = Body(...), ctx: AuthContext = Depends(require_perm("detection.approve")),
                   s: Session = Depends(db, scope="function")):
    row = invoke(gov.approve_policy, s, ctx.principal, binding_id, _bounded(body))
    return gov.policy_to_dict(s, ctx.principal, row)


@router.post("/detection-policies/{binding_id}/activate")
def activate_policy(binding_id: str, body: dict = Body(...), ctx: AuthContext = Depends(require_perm("detection.approve")),
                    s: Session = Depends(db, scope="function")):
    row = invoke(gov.activate_policy, s, ctx.principal, binding_id, _bounded(body))
    return gov.policy_to_dict(s, ctx.principal, row)


@router.post("/detection-policies/{binding_id}/rollback")
def rollback_policy(binding_id: str, body: dict = Body(...), ctx: AuthContext = Depends(require_perm("detection.approve")),
                    s: Session = Depends(db, scope="function")):
    row = invoke(gov.rollback_policy, s, ctx.principal, binding_id, _bounded(body))
    return gov.policy_to_dict(s, ctx.principal, row)


@router.get("/detection-policies/{binding_id}/activations")
def policy_history(binding_id: str, before_revision: int | None = None, limit: int = Query(50, ge=1, le=100),
                   ctx: AuthContext = Depends(require_perm("knowledge.read")), s: Session = Depends(db, scope="function")):
    return _history(s, ctx.principal, "policy", binding_id, before_revision, limit)
