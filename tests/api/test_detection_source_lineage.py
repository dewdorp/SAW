"""Derived definitions retain the full private source authority after copying."""
import pytest
from sqlalchemy import func, select

from saw.core.application import identity
from saw.detection import governance, service
from saw.storage.db import session_scope
from saw.storage.models import InvestigationMember, User
from tests.api.test_derived_finding_access import generated
from tests.conftest import Api, make_user


def test_from_finding_requires_private_proof_source_before_writing(analyst, manager, app):
    uid = make_user("derived-rule-reader", ["analyst"])
    with session_scope() as s:
        _source, target, finding, _run = generated(s)
        s.add(InvestigationMember(investigation_id=target.id, user_id=uid, access="editor"))
        fid = finding.id
        count = s.scalar(select(func.count()).select_from(service.Detection))
    reader = Api(app, "derived-rule-reader")
    response = reader.post(f"/detections/from-finding/{fid}")
    assert response.status_code in {403, 404}
    with session_scope() as s:
        assert s.scalar(select(func.count()).select_from(service.Detection)) == count


def test_derived_rule_keeps_sources_and_revocation_blocks_definitions(analyst, manager, app):
    uid = make_user("derived-rule-author", ["analyst"])
    with session_scope() as s:
        source, target, finding, _run = generated(s)
        for iid in (source.id, target.id):
            s.add(InvestigationMember(investigation_id=iid, user_id=uid, access="editor"))
        fid, source_id, target_id = finding.id, source.id, target.id
    reader = Api(app, "derived-rule-author")
    response = reader.post(f"/detections/from-finding/{fid}")
    assert response.status_code == 201, response.text
    ident = response.json()["id"]
    with session_scope() as s:
        detection = s.get(service.Detection, ident)
        assert set(detection.source["source_investigation_ids"]) == {source_id, target_id}
        p = identity.principal_of(s.get(User, uid))
        assert set(governance._source_ids(s, "rule", detection)) == {source_id, target_id}
        s.delete(s.get(InvestigationMember, (source_id, uid)))
    assert reader.get(f"/detections/{ident}").status_code in {403, 404}
    assert reader.patch(f"/detections/{ident}", json={"title": "Cannot copy private definition"}).status_code in {403, 404}
    assert reader.post(f"/detections/{ident}/test", json={}).status_code in {403, 404}
    with session_scope() as s:
        detection = s.get(service.Detection, ident)
        assert detection.current_version == 1


@pytest.mark.parametrize("kind", ["active_outside_budget", "private_inactive"])
def test_compatibility_absence_cannot_retire_unexamined_private_or_active_rule(analyst, manager, monkeypatch, kind):
    from saw.detection import auto
    from saw.core.application.analysis import _finding_from_draft, _drop_unsupported
    from tests.api.test_sigma_auto import setup_rule
    from saw.core.application import investigations
    outside = make_user("private-rule-source-owner", ["analyst"]) if kind == "private_inactive" else None
    with session_scope() as s:
        inv, detection, _version, ctx = setup_rule(s)
        drafts, _ = auto.run_approved(s, ctx)
        finding = _finding_from_draft(s, inv.id, drafts[0])
        s.flush()
        if kind == "active_outside_budget":
            monkeypatch.setattr(auto, "MAX_RULES", 0)
        else:
            p = identity.principal_of(s.get(User, outside))
            private = investigations.create(s, p, "Synthetic hidden private source")
            detection.source = {"investigation_id": inv.id, "source_investigation_ids": [private.id]}
            detection.active_version_id, detection.active_approval_id = None, None
        ctx.params.clear()
        _new, settled = auto.run_approved(s, ctx)
        assert finding.detector_id not in settled
        assert _drop_unsupported(s, inv.id, settled, set()) == 0


def test_coverage_does_not_count_private_derived_finding_attack_tags(analyst, manager, app):
    uid = make_user("derived-coverage-reader", ["analyst"])
    with session_scope() as s:
        _source, target, finding, _run = generated(s)
        target.verdict = "attack"
        finding.attack = [{"technique_id": "T1190", "confidence": "medium"}]
        s.add(InvestigationMember(investigation_id=target.id, user_id=uid, access="read"))
    reader = Api(app, "derived-coverage-reader")
    response = reader.get("/coverage/attack")
    assert response.status_code == 200
    cell = next(row for row in response.json()["cells"] if row["technique_id"] == "T1190")
    assert cell["observed"] == 0
