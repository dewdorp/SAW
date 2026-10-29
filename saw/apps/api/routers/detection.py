from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Body, Depends, HTTPException
from fastapi.responses import PlainTextResponse, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from saw.apps.api.deps import AuthContext, auth, db, require_perm
from saw.core.application import audit
from saw.core.application.investigations import Forbidden, NotFound, require
from saw.core.security.authz import permissions_for
from saw.detection import service as svc
from saw.detection import testing
from saw.detection.governance_router import invoke
from saw.detection.governance_router import router as governance_router
from saw.detection.truth_router import router as truth_router

router = APIRouter(tags=["detection"])


class DetIn(BaseModel):
    title: str | None = None
    description: str | None = None
    data_source: str | None = None
    format: str | None = None
    logic: str | None = None
    threshold: dict | None = None
    exceptions: list[dict] | None = None
    false_positive: str | None = None
    severity: str | None = None
    confidence: str | None = None
    test_events: list[dict] | None = None
    attack: list[str] | None = None
    expected_draft_version_id: str | None = None
    base_version_id: str | None = None


class TestIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    method: Literal["legacy_investigation_verdict"] = "legacy_investigation_verdict"
    investigation_ids: list[str] | None = None


class DeployIn(BaseModel):
    target: str = Field(min_length=1, max_length=256)
    note: str = ""
    version_id: str | None = None


class ValidateIn(BaseModel):
    format: str = "sigma"
    logic: str
    threshold: dict = Field(default_factory=dict)
    exceptions: list[dict] = Field(default_factory=list, max_length=32)


@router.get("/detections")
def list_(ctx: AuthContext = Depends(require_perm("knowledge.read")), s: Session = Depends(db, scope="function")):
    result = []
    for d in s.scalars(select(svc.Detection).order_by(svc.Detection.updated_at.desc())):
        try:
            result.append(svc.to_dict(s, d, p=ctx.principal))
        except (Forbidden, NotFound):
            continue
    return result


@router.post("/detections", status_code=201)
def create(body: DetIn, ctx: AuthContext = Depends(require_perm("detection.write")), s: Session = Depends(db, scope="function")):
    if not body.logic:
        raise HTTPException(400, "logic is required")
    return svc.to_dict(s, svc.create(s, ctx.principal, body.model_dump(exclude_none=True)), full=True, p=ctx.principal)


@router.post("/detections/from-finding/{finding_id}", status_code=201)
def from_finding(finding_id: str, ctx: AuthContext = Depends(require_perm("detection.write")), s: Session = Depends(db, scope="function")):
    return svc.to_dict(s, svc.from_finding(s, ctx.principal, finding_id), full=True, p=ctx.principal)


@router.post("/detections/validate")
def validate(body: ValidateIn, ctx: AuthContext = Depends(require_perm("detection.write"))):
    errs = svc._validate(body.format, body.logic)  # noqa: SLF001
    from saw.core.schemas.query import Filter
    from saw.detection.sigma_eval import validate_threshold
    try:
        validate_threshold(body.threshold)
        for item in body.exceptions:
            Filter.model_validate(item)
    except ValueError as exc:
        errs.append(str(exc))
    out = {"valid": not errs, "errors": errs}
    if not errs and body.format == "sigma":
        out["opensearch"] = svc.to_opensearch_lucene(body.logic)
    return out


@router.get("/detections/export")
def export_all(format: Literal["json"] = "json", ctx: AuthContext = Depends(require_perm("knowledge.read")),
               s: Session = Depends(db, scope="function")):
    from saw.detection import exporting

    document = exporting.custom(s, p=ctx.principal)
    text, media = exporting.encode(document, format)
    audit.record(s, "detection.bundle_export", actor_id=ctx.principal.user_id, actor_name=ctx.principal.username,
                 target_type="detection", detail={"format": format, "count": document["count"]})
    return Response(text, media_type=media, headers={"Content-Disposition": 'attachment; filename="saw-current-rules.json"',
                                                    "Cache-Control": "no-store"})


@router.get("/detections/{det_id}")
def get(det_id: str, ctx: AuthContext = Depends(require_perm("knowledge.read")), s: Session = Depends(db, scope="function")):
    d = s.get(svc.Detection, det_id)
    if d is None:
        raise NotFound("detection not found")
    return svc.to_dict(s, d, full=True, p=ctx.principal)


@router.patch("/detections/{det_id}")
def update(det_id: str, body: DetIn, ctx: AuthContext = Depends(require_perm("detection.write")), s: Session = Depends(db, scope="function")):
    return svc.to_dict(s, svc.update(s, ctx.principal, det_id, body.model_dump(exclude_none=True)), full=True, p=ctx.principal)


@router.post("/detections/{det_id}/test")
def test(det_id: str, body: testing.SelectedTestInput | TestIn, ctx: AuthContext = Depends(require_perm("detection.write")), s: Session = Depends(db, scope="function")):
    if isinstance(body, testing.SelectedTestInput):
        tr = testing.run_selected(s, ctx.principal, det_id, body.model_dump(), session_id=ctx.session.id)
        return testing.serialized_test(s, ctx.principal, tr)
    tr = svc.run_test(s, ctx.principal, det_id, body.investigation_ids, session_id=ctx.session.id)
    return {"id": tr.id, "version": tr.version, "passed": tr.passed,
            "scope": {**tr.scope, "method": "legacy_investigation_verdict"}, "result": tr.result, "proof": None}


@router.post("/detections/{det_id}/approve")
def approve(det_id: str, body: dict | None = Body(None), ctx: AuthContext = Depends(require_perm("detection.approve")), s: Session = Depends(db, scope="function")):
    return svc.to_dict(s, invoke(svc.approve, s, ctx.principal, det_id, body), full=True, p=ctx.principal)


@router.post("/detections/{det_id}/deployed")
def deployed(det_id: str, body: DeployIn, ctx: AuthContext = Depends(require_perm("detection.approve")), s: Session = Depends(db, scope="function")):
    return svc.to_dict(s, invoke(svc.record_deployment, s, ctx.principal, det_id, body.target, body.note, version_id=body.version_id), full=True, p=ctx.principal)


@router.post("/detections/{det_id}/deprecate")
def deprecate(det_id: str, ctx: AuthContext = Depends(require_perm("detection.approve")), s: Session = Depends(db, scope="function")):
    return svc.to_dict(s, svc.deprecate(s, ctx.principal, det_id), full=True, p=ctx.principal)


@router.get("/detections/{det_id}/export", response_class=PlainTextResponse)
def export(det_id: str, fmt: str = "native", version_id: str | None = None, ctx: AuthContext = Depends(require_perm("knowledge.read")), s: Session = Depends(db, scope="function")):
    d = s.get(svc.Detection, det_id)
    if d is None:
        raise NotFound("detection not found")
    from saw.detection.derived_access import require_snapshot
    require_snapshot(s, ctx.principal, d.source or {})
    if (d.source or {}).get("investigation_id"):
        require(s, ctx.principal, "investigation.read", d.source["investigation_id"])
    try:
        text, _ = svc.export(s, det_id, fmt, version_id=version_id)
    except NotImplementedError as e:
        raise HTTPException(501, str(e)) from None
    audit.record(s, "detection.export", actor_id=ctx.principal.user_id, actor_name=ctx.principal.username, target_type="detection",
                 target_id=det_id, detail={"format": fmt})
    import re

    from saw.detection.exporting import MAX_EXPORT_BYTES
    if len(text.encode("utf-8")) > MAX_EXPORT_BYTES:
        raise ValueError("개별 룰 파일이 2MiB 한도를 넘습니다.")
    safe_id = re.sub(r"[^A-Za-z0-9_-]", "_", det_id)[:64]
    from saw.detection import governance
    selected = governance._version(s, "rule", d, version_id or d.draft_version_id or d.approved_version_id or d.active_version_id) if (
        version_id or d.draft_version_id or d.approved_version_id or d.active_version_id) else svc._latest(s, det_id)
    suffix = "yaml" if fmt == "native" and selected.format == "sigma" else "txt"
    return PlainTextResponse(text, headers={"Content-Disposition": f'attachment; filename="saw-rule-{safe_id}.{suffix}"',
                                           "Cache-Control": "no-store"})


@router.get("/coverage/attack")
def coverage(ctx: AuthContext = Depends(require_perm("knowledge.read")), s: Session = Depends(db, scope="function")):
    return svc.coverage(s, ctx.principal)


@router.get("/coverage/attack/navigator-layer")
def coverage_layer(ctx: AuthContext = Depends(require_perm("knowledge.read")), s: Session = Depends(db, scope="function")):
    return svc.coverage_layer(svc.coverage(s, ctx.principal))


# ---------------------------------------------------------------- shipped detection content (detectors, signatures, flows)
class SignatureSwitchIn(BaseModel):
    enabled: bool
    note: str = ""


@router.get("/detection-catalog")
def detection_catalog(ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    """Everything the platform looks for out of the box: behaviour detectors (code), signatures and attack flows
    (data files), with the per-site switch of each signature."""
    from sqlalchemy import select

    from saw.core.application.analysis import all_detectors
    from saw.core.application.briefing import CATEGORY_KO
    from saw.detectors import ndr_policy, scenarios, signatures
    from saw.storage.models import SignatureSetting

    sw = {r.sig_id: r for r in s.execute(select(SignatureSetting)).scalars()}
    from saw.detection.exporting import signature_states
    states = signature_states(s, ctx.principal)
    sigs = []
    for x in signatures.catalog():
        r = sw.get(x["id"])
        sigs.append(x | {"enabled": r.enabled if r else True, "note": r.note if r else "",
                         "updated_by": r.updated_by if r else "", "updated_at": r.updated_at if r else None,
                         **states.get(x["id"], {"effective_scope": {"kind": "group"}, "provenance": "shipped_defaults"})})
    dets = [{"id": d.id, "title": CATEGORY_KO.get(d.category, d.category), "stage": d.stage, "data_sources": sorted(d.data_sources)}
            for d in all_detectors() if d.id != "sig.match"]
    return {"detectors": dets, "signatures": sigs, "scenarios": scenarios.catalog(), "network_rules": ndr_policy.catalog(),
            "can_switch": "detection.approve" in permissions_for(ctx.principal.roles)}


@router.put("/detection-catalog/signatures/{sig_id}")
def switch_signature(sig_id: str, body: SignatureSwitchIn, ctx: AuthContext = Depends(require_perm("detection.approve")),
                     s: Session = Depends(db, scope="function")):
    """Legacy switches require an exact independently reviewed policy."""
    raise HTTPException(409, "governed_policy_required: signature:" + sig_id)


@router.get("/detection-catalog/export")
def export_catalog(format: Literal["json", "yaml"] = "json", ctx: AuthContext = Depends(auth),
                   s: Session = Depends(db, scope="function")):
    from saw.detection import exporting

    document = exporting.shipped(s, p=ctx.principal)
    text, media = exporting.encode(document, format)
    audit.record(s, "detection.catalog_export", actor_id=ctx.principal.user_id, actor_name=ctx.principal.username,
                 target_type="detection_catalog", detail={"format": format, "count": len(document["signatures"])})
    return Response(text, media_type=media, headers={
        "Content-Disposition": f'attachment; filename="saw-detection-catalog.{format}"', "Cache-Control": "no-store"})

router.include_router(truth_router)
router.include_router(governance_router)
