"""Private sources and immutable follow-up history cannot be hidden by a readable anchor."""
from copy import deepcopy

import pytest
from sqlalchemy import select, update

from saw import container
from saw.core.application.identity import principal_of
from saw.core.application.investigations import Forbidden
from saw.event_generations.reads import actor_scope
from saw.followups import service
from saw.followups.check_revisions import (
    Conflict, capture_check, collect_check_sources, get_check_revision, snapshot_checks,
)
from saw.followups.models import CheckRevision, FollowUpVersion
from saw.storage.db import session_scope, utcnow
from saw.storage.models import Check, InvestigationMember, User
from tests.api.test_followups import setup, create
from tests.api.test_checks import two
from tests.conftest import Api, make_user


def test_hidden_citation_transition_preserves_history_without_granting_access(analyst, two):
    source, target, reader = two["a"], two["b"], two["other"]
    cited = reader.post(f"/investigations/{target['id']}/checks/cite",
        json={"source_id": two["shared"]["id"], "note": "Reference only"})
    assert cited.status_code == 201, cited.text
    row_id = cited.json()["id"]
    with session_scope() as s:
        row = s.get(Check, row_id)
        before = s.scalar(select(CheckRevision).where(CheckRevision.check_id == row_id))
        original, original_hash = deepcopy(before.payload), before.payload_sha256
    changed = analyst.post(f"/investigations/{source['id']}/checks/{two['shared']['id']}/cancel",
                           json={"note": "Withdrawn source"})
    assert changed.status_code == 200, changed.text
    with session_scope() as s:
        p = principal_of(s.scalar(select(User).where(User.username == "analyst1")))
        rows = list(s.scalars(select(CheckRevision).where(CheckRevision.check_id == row_id)
                             .order_by(CheckRevision.revision)))
        assert rows[0].payload == original and rows[0].payload_sha256 == original_hash
        assert rows[-1].payload["source_state"] == "retracted"
        assert set(rows[-1].source_investigation_ids) == {source["id"], target["id"]}
        with pytest.raises(Forbidden):
            get_check_revision(s, p, target["id"], rows[-1].id)


def test_exact_followup_read_and_snapshot_recheck_private_check_source(analyst, two):
    source, target, reader = two["a"], two["b"], two["other"]
    cited = reader.post(f"/investigations/{target['id']}/checks/cite",
        json={"source_id": two["shared"]["id"], "note": "Reference only"}).json()
    url = f"/investigations/{target['id']}/follow-ups"
    got = create(reader, url, cited)
    with session_scope() as s:
        user = s.scalar(select(User).where(User.username == "a2"))
        p = principal_of(user)
        result = service.snapshot_followups(s, p, target["id"], version_ids=[got["current"]["id"]])
        assert set(result["source_investigation_ids"]) == {source["id"], target["id"]}
        assert result["checks"][0]["revision_id"] == got["current"]["payload"]["check_ref"]["revision_id"]
        s.delete(s.get(InvestigationMember, (source["id"], user.id)))
    assert reader.get(f"{url}/{got['id']}/versions/{got['current']['id']}").status_code == 403
    assert reader.get(url).json()["items"] == []
    with session_scope() as s:
        p = principal_of(s.scalar(select(User).where(User.username == "a2")))
        with pytest.raises(Forbidden):
            service.snapshot_followups(s, p, target["id"], version_ids=[got["current"]["id"]])


def test_real_event_verification_edit_and_old_snapshot_remain_separate(analyst):
    inv, check, url = setup(analyst)
    event = {"event_id": "followup-real-event", "investigation_id": inv["id"],
             "timestamp": utcnow().isoformat(), "src_ip": "198.51.100.8",
             "data_source": "synthetic", "raw_event": "transaction rejected"}
    container.get().events.index([event])
    got = create(analyst, url, check)
    endpoint = f"{url}/{got['id']}"
    refs = [{"investigation_id": inv["id"], "event_id": event["event_id"]}]
    reply = analyst.post(endpoint + "/reply", json={"expected_version_id": got["current"]["id"],
        "reason": "Transaction reply", "note": "Source transaction rejected", "evidence": refs}).json()
    assert reply["current"]["payload"]["status"] == "replied"
    verified = analyst.post(endpoint + "/verify", json={"expected_version_id": reply["current"]["id"],
        "reason": "Checked source", "outcome": "not_confirmed", "basis": "Source transaction was rejected",
        "evidence": refs})
    assert verified.status_code == 200, verified.text
    version = verified.json()["current"]
    assert version["payload"]["status"] == "verified"
    assert len(version["payload"]["verification"]["evidence"][0]["sha256"]) == 64
    edited = analyst.patch(endpoint, json={"expected_version_id": version["id"], "patch": {"items": ["Check another transaction"]}})
    assert edited.status_code == 200
    assert edited.json()["current"]["payload"]["verification"] is None
    assert analyst.get(endpoint + "/versions/" + version["id"]).json()["version"]["payload"] == version["payload"]
    with actor_scope(analyst.get("/auth/me").json()["id"]), session_scope() as s:
        p = principal_of(s.scalar(select(User).where(User.username == "analyst1")))
        exact = service.snapshot_followups(s, p, inv["id"], version_ids=[version["id"]])
        assert exact["followups"][0]["payload"]["status"] == "verified"
        assert exact["followups"][0]["revision_id"] == version["id"]


def test_legacy_capture_does_not_invent_old_revisions_and_orm_changes_block(analyst):
    inv, _, _ = setup(analyst)
    with session_scope() as s:
        p = principal_of(s.scalar(select(User).where(User.username == "analyst1")))
        row = Check(investigation_id=inv["id"], target_type="entity", target_key="ip:192.0.2.7",
                    questions=["impact"], author_id=p.user_id, note="Legacy")
        s.add(row)
        s.flush()
        captured = capture_check(s, p, row)
        ident = captured.id
        assert captured.origin == "legacy_capture" and captured.revision == 1
        assert capture_check(s, p, row).id == ident
    with session_scope() as s:
        row = s.get(CheckRevision, ident)
        row.payload = {**row.payload, "note": "Changed"}
        with pytest.raises(ValueError, match="immutable"):
            s.flush()
        s.rollback()


def test_derived_finding_check_keeps_transitive_sources(analyst, manager):
    from tests.api.test_derived_finding_access import generated
    with actor_scope(analyst.get("/auth/me").json()["id"]), session_scope() as s:
        source, target, finding, _ = generated(s)
        p = principal_of(s.scalar(select(User).where(User.username == "manager1")))
        row = Check(investigation_id=target.id, target_type="finding", target_key=finding.id,
                    questions=["nature"], author_id=p.user_id)
        s.add(row)
        s.flush()
        assert collect_check_sources(s, row) == {target.id, source.id}
        s.info["snapshot_source_ids"] = {target.id}
        with pytest.raises(Conflict, match="source_scope_changed"):
            capture_check(s, p, row)


def test_source_hash_corruption_fails_exact_read(analyst):
    _, check, url = setup(analyst)
    got = create(analyst, url, check)
    with session_scope() as s:
        row = s.get(FollowUpVersion, got["current"]["id"])
        s.execute(update(FollowUpVersion).where(FollowUpVersion.id == row.id)
                  .values(payload={**row.payload, "question": "Tampered at storage boundary"}))
    response = analyst.get(f"{url}/{got['id']}/versions/{got['current']['id']}")
    assert response.status_code == 409


def test_analysis_manifest_only_source_is_retained_in_check_closure(analyst):
    from saw.analysis_runs.models import AnalysisRun
    from saw.core.application.provenance import digest
    inv, check, _ = setup(analyst)
    source = analyst.post("/investigations", json={"title": "Pinned policy proof source"}).json()
    with session_scope() as s:
        manifest = {"runtime_pin": {"source_investigation_ids": [source["id"]]}}
        run = AnalysisRun(investigation_id=inv["id"], version=1, input_manifest=manifest,
                          input_sha256=digest(manifest), status="complete")
        s.add(run)
        s.flush()
        row = s.get(Check, check["id"])
        row.context = {"analysis_run_id": run.id}
        assert collect_check_sources(s, row) == {inv["id"], source["id"]}


def test_pinned_citation_revision_corruption_is_rejected(analyst, two):
    target, reader = two["b"], two["other"]
    cited = reader.post(f"/investigations/{target['id']}/checks/cite",
        json={"source_id": two["shared"]["id"], "note": "Reference only"}).json()
    url = f"/investigations/{target['id']}/follow-ups"
    got = create(reader, url, cited)
    with session_scope() as s:
        pinned = s.get(CheckRevision, got["current"]["payload"]["check_ref"]["revision_id"])
        source = s.get(CheckRevision, pinned.payload["source_check_revision"]["revision_id"])
        s.execute(update(CheckRevision).where(CheckRevision.id == source.id)
                  .values(payload={**source.payload, "note": "Changed source snapshot"}))
    with session_scope() as s:
        p = principal_of(s.scalar(select(User).where(User.username == "a2")))
        with pytest.raises(Conflict, match="corrupt"):
            service.snapshot_followups(s, p, target["id"], version_ids=[got["current"]["id"]])


def test_report_snapshot_rejects_changed_followup_evidence(analyst):
    inv, check, url = setup(analyst)
    event = {"event_id": "changing-followup-evidence", "investigation_id": inv["id"],
             "timestamp": utcnow().isoformat(), "data_source": "synthetic", "raw_event": "Original"}
    container.get().events.index([event])
    got = create(analyst, url, check)
    reply = analyst.post(f"{url}/{got['id']}/reply", json={"expected_version_id": got["current"]["id"],
        "reason": "Reply source", "note": "Check original evidence",
        "evidence": [{"investigation_id": inv["id"], "event_id": event["event_id"]}]}).json()
    container.get().events.index([{**event, "raw_event": "Reprocessed content"}])
    with actor_scope(analyst.get("/auth/me").json()["id"]), session_scope() as s:
        p = principal_of(s.scalar(select(User).where(User.username == "analyst1")))
        with pytest.raises(Conflict, match="evidence_changed"):
            service.snapshot_followups(s, p, inv["id"], version_ids=[reply["current"]["id"]])
