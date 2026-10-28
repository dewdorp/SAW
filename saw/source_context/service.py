"""Context registry operations; investigation selection never asserts row affiliation."""
from __future__ import annotations

import copy
import hashlib
import json

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from saw.core.application import audit, investigations
from saw.core.security.authz import Principal, can
from saw.source_context.models import (
    Device,
    DeviceProfileVersion,
    EvidenceContextSnapshot,
    OrgUnit,
    OrgUnitAssignment,
)
from saw.source_context.schemas import ContextInput, DeviceInput, DeviceProfileInput, OrgUnitInput
from saw.storage.models import Evidence, Investigation, Job, ProcessingRun


def digest(payload: dict) -> str:
    return hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _permission(p: Principal, permission: str):
    if not can(p, permission):
        raise investigations.Forbidden(permission)


def _audit(s, p, action, target, inv_id=None, detail=None):
    audit.record(s, "source_context." + action, actor_id=p.user_id, actor_name=p.username,
                 target_type="source_context", target_id=target, investigation_id=inv_id, detail=detail)


def org_by_id(s: Session, org_unit_id: str) -> OrgUnit:
    org = s.get(OrgUnit, org_unit_id)
    if org is None or org.state != "active":
        raise ValueError("organization not found or inactive")
    return org


def resolve_org(s: Session, org_unit: str, org_unit_id: str | None) -> tuple[str, str | None]:
    if len(org_unit) > 64:
        raise ValueError("organization name is too long")
    if org_unit_id is None:
        return org_unit, None
    org = org_by_id(s, org_unit_id)
    if org_unit and org_unit != org.display_name:
        raise ValueError("organization name conflicts with selected organization ID")
    return org_unit or org.display_name, org.id


def record_org_assignment(s: Session, p: Principal, inv: Investigation, legacy_value: str):
    s.add(OrgUnitAssignment(investigation_id=inv.id, legacy_value=legacy_value, org_unit_id=inv.org_unit_id,
                            state="mapped" if inv.org_unit_id else "unresolved", created_by=p.user_id))


def set_investigation_org(s: Session, p: Principal, inv_id: str, org_unit: str | None, org_unit_id: str | None):
    inv = investigations.require(s, p, "investigation.write", inv_id)
    label, org_id = resolve_org(s, org_unit or "", org_unit_id)
    if inv.org_unit_id and org_id != inv.org_unit_id:
        # One investigation holds one affiliate's data. Labelling an unassigned legacy investigation is allowed,
        # but moving data that is already attributed to one affiliate onto another (or onto none) is not.
        if s.scalar(select(Evidence.id).where(Evidence.investigation_id == inv.id).limit(1)) is not None:
            raise ValueError("affiliate cannot change after evidence is added; create a new investigation")
    legacy_value = inv.org_unit
    # This affects future attachments only. Frozen evidence snapshots remain unchanged.
    inv.org_unit, inv.org_unit_id = label, org_id
    record_org_assignment(s, p, inv, legacy_value)
    _audit(s, p, "investigation.update", inv_id, inv_id, {"org_unit_id": org_id})
    return inv


def create_org(s: Session, p: Principal, body: OrgUnitInput | dict) -> OrgUnit:
    _permission(p, "org.manage")
    body = OrgUnitInput.model_validate(body)
    row = OrgUnit(display_name=body.display_name, created_by=p.user_id)
    s.add(row)
    s.flush()
    _audit(s, p, "org.create", row.id)
    return row


def list_orgs(s: Session, p: Principal, *, after: str | None = None, limit: int = 100) -> list[OrgUnit]:
    if not (can(p, "investigation.read") or can(p, "org.manage")):
        raise investigations.Forbidden("investigation.read")
    q = select(OrgUnit).where(OrgUnit.state == "active").order_by(OrgUnit.id).limit(min(max(limit, 1), 200))
    if after:
        q = q.where(OrgUnit.id > after)
    return list(s.scalars(q))


def create_device(s: Session, p: Principal, inv_id: str, body: DeviceInput | dict) -> Device:
    investigations.require(s, p, "investigation.write", inv_id)
    body = DeviceInput.model_validate(body)
    row = Device(investigation_id=inv_id, display_name=body.display_name, created_by=p.user_id)
    s.add(row)
    s.flush()
    _audit(s, p, "device.create", row.id, inv_id)
    return row


def list_devices(s: Session, p: Principal, inv_id: str, *, after: str | None = None, limit: int = 100) -> list[Device]:
    investigations.require(s, p, "investigation.read", inv_id)
    q = select(Device).where(Device.investigation_id == inv_id).order_by(Device.id).limit(min(max(limit, 1), 200))
    if after:
        q = q.where(Device.id > after)
    return list(s.scalars(q))


def _device(s: Session, p: Principal, device_id: str, permission: str) -> Device:
    row = s.get(Device, device_id)
    if row is None:
        raise investigations.NotFound("device not found")
    investigations.require(s, p, permission, row.investigation_id)
    return row


def create_profile(s: Session, p: Principal, device_id: str, body: DeviceProfileInput | dict) -> DeviceProfileVersion:
    dev = _device(s, p, device_id, "investigation.write")
    body = DeviceProfileInput.model_validate(body)
    for org_id in (body.owner_org_unit_id, body.operator_org_unit_id):
        if org_id:
            org_by_id(s, org_id)
    payload = body.model_dump(mode="json")
    version = (s.scalar(select(func.max(DeviceProfileVersion.version)).where(DeviceProfileVersion.device_id == device_id)) or 0) + 1
    row = DeviceProfileVersion(device_id=device_id, version=version, payload=payload, sha256=digest(payload), created_by=p.user_id)
    s.add(row)
    s.flush()
    _audit(s, p, "profile.create", row.id, dev.investigation_id, {"version": version, "sha256": row.sha256})
    return row


def list_profiles(s: Session, p: Principal, device_id: str, *, before_version: int | None = None, limit: int = 100):
    _device(s, p, device_id, "investigation.read")
    q = select(DeviceProfileVersion).where(DeviceProfileVersion.device_id == device_id).order_by(DeviceProfileVersion.version.desc()).limit(min(max(limit, 1), 200))
    if before_version is not None:
        q = q.where(DeviceProfileVersion.version < before_version)
    return list(s.scalars(q))


def _evidence(s: Session, p: Principal, evidence_id: str, permission: str):
    row = s.get(Evidence, evidence_id)
    if row is None:
        raise investigations.NotFound("evidence not found")
    inv = investigations.require(s, p, permission, row.investigation_id)
    return row, inv


def attach_evidence_context(s: Session, p: Principal, evidence_id: str, context: ContextInput | dict) -> EvidenceContextSnapshot:
    ev, inv = _evidence(s, p, evidence_id, "evidence.upload")
    context = ContextInput.model_validate(context)
    if ev.status not in {"pending", "uploaded"} or s.scalar(select(ProcessingRun.id).where(ProcessingRun.evidence_id == evidence_id).limit(1)):
        raise ValueError("context must be attached before first ingestion")
    if s.scalar(select(Job.id).where(Job.evidence_id == evidence_id, Job.kind == "ingest", Job.state != "UPLOADING").limit(1)):
        raise ValueError("context must be attached before first ingestion job")
    if ev.context_snapshot_id or s.scalar(select(EvidenceContextSnapshot.id).where(EvidenceContextSnapshot.evidence_id == evidence_id)):
        raise ValueError("evidence context is immutable; create new evidence for a new context")
    observer = {"device_id": None, "device_profile_version_id": None, "network": "", "virtual_domain": ""}
    profile = DeviceProfileInput().model_dump(mode="json")
    if context.device_profile_version_id:
        row = s.get(DeviceProfileVersion, context.device_profile_version_id)
        if row is None:
            raise ValueError("device profile not found")
        dev = s.get(Device, row.device_id)
        if dev is None or dev.investigation_id != inv.id:
            raise ValueError("device profile does not belong to this investigation")
        if digest(row.payload) != row.sha256:
            raise ValueError("device profile integrity check failed")
        profile = DeviceProfileInput.model_validate(row.payload).model_dump(mode="json")
        observer.update({"device_id": dev.id, "device_profile_version_id": row.id})
    observer.update({k: profile[k] for k in ("network", "virtual_domain", "owner_org_unit_id", "operator_org_unit_id", "vendor", "product", "product_version", "functions", "observation_point", "collection_path")})
    subject = context.subject.model_dump(mode="json")
    if subject["org_unit_id"]:
        org_by_id(s, subject["org_unit_id"])
    subject["observed_org_unit_id"] = subject["org_unit_id"]
    if subject["org_unit_id"] and inv.org_unit_id and subject["org_unit_id"] != inv.org_unit_id:
        subject["status"] = "conflicting"
    subject["org_unit_id"] = subject["org_unit_id"] if subject["status"] == "verified" else None
    payload = {"schema_version": 1, "investigation_org_unit_id": inv.org_unit_id,
               "subject": subject, "observer": observer, "profile": profile,
               "collection": context.collection.model_dump(mode="json"), "org_unit_id": subject["org_unit_id"],
               **{k: observer[k] for k in ("device_id", "device_profile_version_id", "network", "virtual_domain")},
               **{k: profile[k] for k in ("measurement_profile", "source_fields", "action_map")}}
    row = EvidenceContextSnapshot(evidence_id=ev.id, investigation_id=inv.id,
                                  device_profile_version_id=context.device_profile_version_id,
                                  snapshot=payload, sha256=digest(payload), created_by=p.user_id)
    s.add(row)
    s.flush()
    ev.context_snapshot_id = row.id
    _audit(s, p, "attach", row.id, inv.id, {"evidence_id": ev.id, "sha256": row.sha256})
    return row


def snapshot_payload(snapshot: EvidenceContextSnapshot) -> dict:
    if digest(snapshot.snapshot) != snapshot.sha256:
        raise ValueError("evidence context integrity check failed")
    return copy.deepcopy(snapshot.snapshot)


def get_evidence_context(s: Session, p: Principal, evidence_id: str) -> EvidenceContextSnapshot | None:
    ev, inv = _evidence(s, p, evidence_id, "investigation.read")
    row = s.get(EvidenceContextSnapshot, ev.context_snapshot_id) if ev.context_snapshot_id else None
    if row is not None:
        if row.evidence_id != ev.id or row.investigation_id != inv.id:
            raise ValueError("evidence context reference mismatch")
        snapshot_payload(row)
    return row