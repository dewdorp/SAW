"""Synthetic context registry contracts: ACL, version pinning and unknown affiliation."""
import hashlib
import json

import pytest
from sqlalchemy import select

from saw.storage.db import session_scope
from saw.storage.models import AuditEvent, Evidence
from tests.conftest import Api, make_user


def org(api, name="Synthetic A"):
    r = api.post("/source-context/org-units", json={"display_name": name})
    assert r.status_code == 201, r.text
    return r.json()


def investigation(api, org_id=None, **kw):
    r = api.post("/investigations", json={"title": "Synthetic context", "org_unit_id": org_id, **kw})
    assert r.status_code == 201, r.text
    return r.json()


def device(api, inv_id):
    r = api.post(f"/source-context/investigations/{inv_id}/devices", json={"display_name": "FW-01"})
    assert r.status_code == 201, r.text
    return r.json()


def profile(api, device_id, **kw):
    r = api.post(f"/source-context/devices/{device_id}/profiles", json={
        "vendor": "Synthetic", "product": "Firewall", "functions": ["FW"],
        "network": "net-a", "virtual_domain": "default", "source_fields": {"src_bytes": "sent"},
        "measurement_profile": {"counter_semantics": "cumulative", "direction": "src_to_dst", "unit": "bytes",
                                "verified": True, "basis": "Synthetic vendor schema v1"}, **kw})
    assert r.status_code == 201, r.text
    return r.json()


def evidence(api, inv_id):
    with session_scope() as s:
        from saw.storage.models import Investigation
        inv = s.get(Investigation, inv_id)
        e = Evidence(investigation_id=inv_id, uploaded_by=inv.owner_id, kind="log")
        s.add(e)
        s.flush()
        return e.id


def test_org_ids_remain_distinct_and_legacy_conflicts_rejected(senior):
    a, b = org(senior), org(senior)
    assert a["id"] != b["id"]
    inv = investigation(senior, a["id"])
    assert inv["org_unit_id"] == a["id"] and inv["org_unit"] == "Synthetic A"
    r = senior.post("/investigations", json={"title": "conflict", "org_unit_id": a["id"], "org_unit": "Other"})
    assert r.status_code == 400
    unknown = investigation(senior, org_unit="Legacy unidentified")
    assert unknown["org_unit_id"] is None and unknown["org_unit"] == "Legacy unidentified"
    listed = senior.get("/investigations", params={"org_unit_id": b["id"]})
    assert listed.status_code == 200 and listed.json() == []


def test_context_is_pinned_and_target_does_not_override_observed_affiliation(senior):
    a, b = org(senior), org(senior, "Synthetic B")
    inv = investigation(senior, a["id"])
    dev = device(senior, inv["id"])
    p1 = profile(senior, dev["id"])
    ev = evidence(senior, inv["id"])
    r = senior.post(f"/source-context/evidence/{ev}/context", json={
        "device_profile_version_id": p1["id"],
        "subject": {"org_unit_id": b["id"], "status": "verified", "basis": "Synthetic row affiliation"}})
    assert r.status_code == 201, r.text
    frozen = r.json()
    payload = frozen["snapshot"]
    assert payload["subject"]["status"] == "conflicting"
    assert payload["subject"]["observed_org_unit_id"] == b["id"]
    assert payload["org_unit_id"] is None
    assert payload["investigation_org_unit_id"] == a["id"]
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    assert frozen["sha256"] == hashlib.sha256(canonical.encode()).hexdigest()
    p2 = profile(senior, dev["id"], network="net-updated")
    assert p2["version"] == 2
    assert senior.patch(f"/investigations/{inv['id']}", json={"org_unit_id": b["id"]}).status_code == 200
    assert senior.get(f"/source-context/evidence/{ev}/context").json() == frozen
    assert senior.post(f"/source-context/evidence/{ev}/context", json={"device_profile_version_id": p2["id"]}).status_code == 400
    with session_scope() as s:
        row = s.get(Evidence, ev)
        assert row.context_snapshot_id == frozen["id"]
        actions = set(s.scalars(select(AuditEvent.action)))
        assert {"source_context.org.create", "source_context.profile.create", "source_context.attach"} <= actions


def test_unknown_affiliation_and_counter_semantics_cannot_be_marked_verified(senior):
    a = org(senior)
    inv = investigation(senior, a["id"])
    dev = device(senior, inv["id"])
    invalid = senior.post(f"/source-context/devices/{dev['id']}/profiles", json={
        "measurement_profile": {"verified": True, "counter_semantics": "unknown", "basis": "unsupported"}})
    assert invalid.status_code == 422
    p = profile(senior, dev["id"])
    ev = evidence(senior, inv["id"])
    invalid = senior.post(f"/source-context/evidence/{ev}/context", json={
        "subject": {"status": "verified"}})
    assert invalid.status_code == 422
    out = senior.post(f"/source-context/evidence/{ev}/context", json={"device_profile_version_id": p["id"]}).json()
    assert out["snapshot"]["subject"]["status"] == "unknown"
    assert out["snapshot"]["org_unit_id"] is None


def test_cross_investigation_and_admin_access_denied(senior, app):
    inv = investigation(senior)
    dev = device(senior, inv["id"])
    p = profile(senior, dev["id"])
    ev = evidence(senior, inv["id"])
    make_user("context-other", ["analyst"])
    other = Api(app, "context-other")
    other_inv = investigation(other)
    assert other.get(f"/source-context/investigations/{inv['id']}/devices").status_code == 403
    assert other.get(f"/source-context/evidence/{ev}/context").status_code == 403
    other_ev = evidence(other, other_inv["id"])
    assert other.post(f"/source-context/evidence/{other_ev}/context", json={"device_profile_version_id": p["id"]}).status_code == 400
    make_user("context-admin", ["admin"])
    admin = Api(app, "context-admin")
    assert admin.get(f"/source-context/investigations/{inv['id']}/devices").status_code == 403
    assert admin.post("/source-context/org-units", json={"display_name": "Denied"}).status_code == 403


def test_profile_and_snapshot_are_append_only(senior):
    inv = investigation(senior)
    dev = device(senior, inv["id"])
    p = profile(senior, dev["id"])
    ev = evidence(senior, inv["id"])
    frozen = senior.post(f"/source-context/evidence/{ev}/context", json={"device_profile_version_id": p["id"]}).json()
    from saw.source_context.models import DeviceProfileVersion, EvidenceContextSnapshot
    for model, row_id, field in [(DeviceProfileVersion, p["id"], "payload"),
                                  (EvidenceContextSnapshot, frozen["id"], "snapshot")]:
        with pytest.raises(ValueError, match="immutable"), session_scope() as s:
            row = s.get(model, row_id)
            setattr(row, field, {"changed": True})
            s.flush()
        with pytest.raises(ValueError, match="immutable"), session_scope() as s:
            s.delete(s.get(model, row_id))
            s.flush()

def test_context_registry_does_not_block_approved_investigation_deletion(senior, admin):
    from tests.api.test_admin_data import execute, preview
    inv = investigation(senior)
    dev = device(senior, inv["id"])
    p = profile(senior, dev["id"])
    ev = evidence(senior, inv["id"])
    frozen = senior.post(f"/source-context/evidence/{ev}/context", json={"device_profile_version_id": p["id"]}).json()
    result = execute(admin, preview(admin, "investigation", inv["id"]))
    assert result.status_code == 200, result.text
    assert result.json()["state"] == "COMPLETED"
    assert senior.get(f"/source-context/evidence/{ev}/context").status_code == 404
    assert senior.get(f"/source-context/devices/{dev['id']}/profiles").status_code == 404
    from saw.source_context.models import EvidenceContextSnapshot
    with session_scope() as s:
        assert s.get(EvidenceContextSnapshot, frozen["id"]).sha256 == frozen["sha256"]


def test_legacy_org_mapping_preserves_original_label_and_selected_id(senior):
    from saw.source_context.models import OrgUnitAssignment
    inv = investigation(senior, org_unit="Unresolved original")
    a = org(senior)
    assert senior.patch(f"/investigations/{inv['id']}", json={"org_unit_id": a["id"]}).status_code == 200
    with session_scope() as s:
        assignments = list(s.scalars(select(OrgUnitAssignment).where(OrgUnitAssignment.investigation_id == inv["id"]).order_by(OrgUnitAssignment.created_at)))
        assert assignments[-1].legacy_value == "Unresolved original"
        assert assignments[-1].org_unit_id == a["id"]
        assert assignments[-1].state == "mapped"


def test_context_cannot_be_attached_to_already_processed_legacy_evidence(senior):
    inv = investigation(senior)
    ev = evidence(senior, inv["id"])
    with session_scope() as s:
        s.get(Evidence, ev).status = "done"
    assert senior.post(f"/source-context/evidence/{ev}/context", json={}).status_code == 400

def test_first_upload_can_attach_but_queued_ingestion_cannot(senior):
    from saw.storage.models import Investigation, Job
    inv = investigation(senior)
    for state, expected in [("UPLOADING", 201), ("QUEUED", 400)]:
        ev = evidence(senior, inv["id"])
        with session_scope() as s:
            s.add(Job(investigation_id=inv["id"], evidence_id=ev, kind="ingest", state=state,
                      requested_by=s.get(Investigation, inv["id"]).owner_id))
        assert senior.post(f"/source-context/evidence/{ev}/context", json={}).status_code == expected


def test_verified_time_requires_nonempty_precision(senior):
    inv = investigation(senior)
    dev = device(senior, inv["id"])
    r = senior.post(f"/source-context/devices/{dev['id']}/profiles", json={
        "source_fields": {"timestamp": "event_time"},
        "time": {"verified": True, "role": "occurred", "timezone": "Asia/Seoul", "precision": "", "basis": "Synthetic"}})
    assert r.status_code == 422


def test_context_snapshot_pointer_cannot_be_replaced(senior):
    inv = investigation(senior)
    first, second = evidence(senior, inv["id"]), evidence(senior, inv["id"])
    for ev in (first, second):
        assert senior.post(f"/source-context/evidence/{ev}/context", json={}).status_code == 201
    with pytest.raises(ValueError, match="immutable"), session_scope() as s:
        s.get(Evidence, first).context_snapshot_id = s.get(Evidence, second).context_snapshot_id
        s.flush()

def test_profile_explicit_duration_unit_is_pinned(senior):
    inv = investigation(senior)
    dev = device(senior, inv["id"])
    p = profile(senior, dev["id"], measurement_profile={
        "counter_semantics": "cumulative", "direction": "src_to_dst", "unit": "bytes",
        "duration_unit": "milliseconds", "verified": True, "basis": "Synthetic vendor schema"})
    ev = evidence(senior, inv["id"])
    frozen = senior.post(f"/source-context/evidence/{ev}/context", json={"device_profile_version_id": p["id"]}).json()
    assert frozen["snapshot"]["measurement_profile"]["duration_unit"] == "milliseconds"

def test_profile_explicit_record_kind_mapping_is_frozen(senior):
    inv = investigation(senior)
    dev = device(senior, inv["id"])
    p = profile(senior, dev["id"], record_kind_map={"start": "session_start", "interim": "session_interim", "end": "session_end"})
    ev = evidence(senior, inv["id"])
    frozen = senior.post(f"/source-context/evidence/{ev}/context", json={"device_profile_version_id": p["id"]}).json()
    assert frozen["snapshot"]["profile"]["record_kind_map"] == {"start": "session_start", "interim": "session_interim", "end": "session_end"}

def test_internal_investigation_scope_keeps_existing_large_limit(analyst):
    from saw.core.application import identity, investigations
    from saw.storage.models import Investigation, InvestigationMember, User
    with session_scope() as s:
        user = s.scalar(select(User).where(User.username == "analyst1"))
        rows = [Investigation(display_id=f"INV-SYNTHETIC-{n}", title="Synthetic", owner_id=user.id) for n in range(205)]
        s.add_all(rows)
        s.flush()
        s.add_all([InvestigationMember(investigation_id=r.id, user_id=user.id, access="owner") for r in rows])
        s.flush()
        assert len(investigations.list_for(s, identity.principal_of(user), 205)) == 205
    assert len(analyst.get("/investigations", params={"limit": 200}).json()) == 200