"""Source context registry API. All device and evidence reads require source ACL."""
from datetime import UTC

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from saw.apps.api.deps import AuthContext, auth, db
from saw.source_context import service
from saw.source_context.schemas import ContextInput, DeviceInput, DeviceProfileInput, OrgUnitInput

router = APIRouter(prefix="/source-context", tags=["source-context"])


def org_out(row):
    return {"id": row.id, "display_name": row.display_name, "state": row.state}


def device_out(row):
    return {"id": row.id, "investigation_id": row.investigation_id, "display_name": row.display_name}


def profile_out(row):
    return {"id": row.id, "device_id": row.device_id, "version": row.version, "profile": row.payload,
            "sha256": row.sha256, "created_at": row.created_at.replace(tzinfo=UTC)}


def context_out(row):
    return {"id": row.id, "evidence_id": row.evidence_id, "investigation_id": row.investigation_id,
            "snapshot": service.snapshot_payload(row), "sha256": row.sha256, "created_at": row.created_at.replace(tzinfo=UTC)}


@router.post("/org-units", status_code=201)
def create_org(body: OrgUnitInput, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    return org_out(service.create_org(s, ctx.principal, body))


@router.get("/org-units")
def list_orgs(after: str | None = None, limit: int = Query(100, ge=1, le=200),
              ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    return [org_out(r) for r in service.list_orgs(s, ctx.principal, after=after, limit=limit)]


@router.get("/investigations/{inv_id}/profile-templates")
def profile_templates(inv_id: str, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    return {"items": service.list_templates(s, ctx.principal, inv_id)}


@router.post("/investigations/{inv_id}/devices/from-template", status_code=201)
def device_from_template(inv_id: str, body: dict, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    return service.device_from_template(s, ctx.principal, inv_id, str(body.get("profile_version_id") or ""),
                                        str(body.get("display_name") or "")[:128])


@router.post("/investigations/{inv_id}/devices", status_code=201)
def create_device(inv_id: str, body: DeviceInput, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    return device_out(service.create_device(s, ctx.principal, inv_id, body))


@router.get("/investigations/{inv_id}/devices")
def list_devices(inv_id: str, after: str | None = None, limit: int = Query(100, ge=1, le=200),
                 ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    return [device_out(r) for r in service.list_devices(s, ctx.principal, inv_id, after=after, limit=limit)]


@router.post("/devices/{device_id}/profiles", status_code=201)
def create_profile(device_id: str, body: DeviceProfileInput, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    return profile_out(service.create_profile(s, ctx.principal, device_id, body))


@router.get("/devices/{device_id}/profiles")
def list_profiles(device_id: str, before_version: int | None = Query(None, ge=1), limit: int = Query(100, ge=1, le=200),
                  ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    return [profile_out(r) for r in service.list_profiles(s, ctx.principal, device_id, before_version=before_version, limit=limit)]


@router.post("/evidence/{evidence_id}/context", status_code=201)
def attach_context(evidence_id: str, body: ContextInput, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    return context_out(service.attach_evidence_context(s, ctx.principal, evidence_id, body))


@router.get("/evidence/{evidence_id}/context")
def get_context(evidence_id: str, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    row = service.get_evidence_context(s, ctx.principal, evidence_id)
    return context_out(row) if row else None