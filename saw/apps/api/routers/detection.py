from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from saw.apps.api.deps import AuthContext, auth, db, require_perm
from saw.core.application import audit
from saw.core.application.investigations import NotFound
from saw.core.security.authz import permissions_for
from saw.detection import service as svc

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


class TestIn(BaseModel):
    investigation_ids: list[str] | None = None


class DeployIn(BaseModel):
    target: str = Field(min_length=1, max_length=256)
    note: str = ""


class ValidateIn(BaseModel):
    format: str = "sigma"
    logic: str


@router.get("/detections")
def list_(ctx: AuthContext = Depends(require_perm("knowledge.read")), s: Session = Depends(db, scope="function")):
    return [svc.to_dict(s, d) for d in s.execute(select(svc.Detection).order_by(svc.Detection.updated_at.desc())).scalars()]


@router.post("/detections", status_code=201)
def create(body: DetIn, ctx: AuthContext = Depends(require_perm("detection.write")), s: Session = Depends(db, scope="function")):
    if not body.logic:
        raise HTTPException(400, "logic is required")
    return svc.to_dict(s, svc.create(s, ctx.principal, body.model_dump(exclude_none=True)), full=True)


@router.post("/detections/from-finding/{finding_id}", status_code=201)
def from_finding(finding_id: str, ctx: AuthContext = Depends(require_perm("detection.write")), s: Session = Depends(db, scope="function")):
    return svc.to_dict(s, svc.from_finding(s, ctx.principal, finding_id), full=True)


@router.post("/detections/validate")
def validate(body: ValidateIn, ctx: AuthContext = Depends(require_perm("detection.write"))):
    errs = svc._validate(body.format, body.logic)  # noqa: SLF001
    out = {"valid": not errs, "errors": errs}
    if not errs and body.format == "sigma":
        out["opensearch"] = svc.to_opensearch_lucene(body.logic)
    return out


@router.get("/detections/{det_id}")
def get(det_id: str, ctx: AuthContext = Depends(require_perm("knowledge.read")), s: Session = Depends(db, scope="function")):
    d = s.get(svc.Detection, det_id)
    if d is None:
        raise NotFound("detection not found")
    return svc.to_dict(s, d, full=True)


@router.patch("/detections/{det_id}")
def update(det_id: str, body: DetIn, ctx: AuthContext = Depends(require_perm("detection.write")), s: Session = Depends(db, scope="function")):
    return svc.to_dict(s, svc.update(s, ctx.principal, det_id, body.model_dump(exclude_none=True)), full=True)


@router.post("/detections/{det_id}/test")
def test(det_id: str, body: TestIn, ctx: AuthContext = Depends(require_perm("detection.write")), s: Session = Depends(db, scope="function")):
    tr = svc.run_test(s, ctx.principal, det_id, body.investigation_ids)
    return {"id": tr.id, "passed": tr.passed, "result": tr.result}


@router.post("/detections/{det_id}/approve")
def approve(det_id: str, ctx: AuthContext = Depends(require_perm("detection.approve")), s: Session = Depends(db, scope="function")):
    return svc.to_dict(s, svc.approve(s, ctx.principal, det_id), full=True)


@router.post("/detections/{det_id}/deployed")
def deployed(det_id: str, body: DeployIn, ctx: AuthContext = Depends(require_perm("detection.approve")), s: Session = Depends(db, scope="function")):
    return svc.to_dict(s, svc.record_deployment(s, ctx.principal, det_id, body.target, body.note), full=True)


@router.post("/detections/{det_id}/deprecate")
def deprecate(det_id: str, ctx: AuthContext = Depends(require_perm("detection.approve")), s: Session = Depends(db, scope="function")):
    return svc.to_dict(s, svc.deprecate(s, ctx.principal, det_id), full=True)


@router.get("/detections/{det_id}/export", response_class=PlainTextResponse)
def export(det_id: str, fmt: str = "native", ctx: AuthContext = Depends(require_perm("knowledge.read")), s: Session = Depends(db, scope="function")):
    try:
        text, _ = svc.export(s, det_id, fmt)
    except NotImplementedError as e:
        raise HTTPException(501, str(e)) from None
    audit.record(s, "detection.export", actor_id=ctx.principal.user_id, actor_name=ctx.principal.username, target_type="detection",
                 target_id=det_id, detail={"format": fmt})
    return text


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
    sigs = []
    for x in signatures.catalog():
        r = sw.get(x["id"])
        sigs.append(x | {"enabled": r.enabled if r else True, "note": r.note if r else "",
                         "updated_by": r.updated_by if r else "", "updated_at": r.updated_at if r else None})
    dets = [{"id": d.id, "title": CATEGORY_KO.get(d.category, d.category), "stage": d.stage, "data_sources": sorted(d.data_sources)}
            for d in all_detectors() if d.id != "sig.match"]
    return {"detectors": dets, "signatures": sigs, "scenarios": scenarios.catalog(), "network_rules": ndr_policy.catalog(),
            "can_switch": "detection.approve" in permissions_for(ctx.principal.roles)}


@router.put("/detection-catalog/signatures/{sig_id}")
def switch_signature(sig_id: str, body: SignatureSwitchIn, ctx: AuthContext = Depends(require_perm("detection.approve")),
                     s: Session = Depends(db, scope="function")):
    """Turn one signature off (or on again) for this site. Events keep their tags; only findings are affected, from
    the next analysis on, so the switch is fully reversible."""
    from saw.core.application import audit
    from saw.detectors import signatures
    from saw.storage.db import utcnow
    from saw.storage.models import SignatureSetting

    if sig_id not in signatures.by_id():
        raise NotFound("signature not found")
    if not body.enabled and len(body.note.strip()) < 5:
        raise ValueError("끄는 이유를 한 줄 적어 주세요(다른 사람이 왜 꺼져 있는지 알 수 있게)")
    r = s.get(SignatureSetting, sig_id)
    if r is None:
        r = SignatureSetting(sig_id=sig_id)
        s.add(r)
    r.enabled, r.note, r.updated_by, r.updated_at = body.enabled, body.note.strip()[:512], ctx.principal.username, utcnow()
    audit.record(s, "detection.signature_switch", actor_id=ctx.principal.user_id, actor_name=ctx.principal.username,
                 target_type="signature", target_id=sig_id, detail={"enabled": body.enabled, "note": r.note})
    return {"id": sig_id, "enabled": r.enabled, "note": r.note, "updated_by": r.updated_by}
