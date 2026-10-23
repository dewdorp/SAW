"""Release freezes, CAS and strict request boundaries."""
import importlib
from copy import deepcopy
import pytest
from fastapi import HTTPException
from sqlalchemy import select
from saw.core.application.identity import principal_of
from saw.core.application.provenance import digest
from saw.knowledge.golden_governance_models import GoldenRelease, GoldenProfileVersion
from saw.knowledge.golden_schemas import ReleaseRequest
from saw.storage.db import session_scope
from saw.storage.models import User
from tests.api.test_golden_governance import adopted_candidate, release_request


def test_freeze_pins_profiles_sources_contributors_and_reservation_cas(analyst, manager):
    inv, _, g = adopted_candidate(analyst, manager)
    request = release_request(analyst, g)
    service = importlib.import_module("saw.knowledge.golden_releases")
    with session_scope() as s:
        p = principal_of(s.scalar(select(User).where(User.username == "analyst1")))
        preflight = service.preflight_sources(s, p, request)
        assert preflight["anchor_investigation_id"] == inv["id"]
        assert preflight["request_sha256"] == digest({k: v for k, v in request.items() if k != "idempotency_key"})
        frozen = service.freeze_build(s, p, request)
        assert frozen["examples"][0]["content_sha256"] == g["content_sha256"]
        assert frozen["profiles"]["pseudonymization"]["id"] == request["pseudonymization_profile"]["id"]
        reviewer = s.scalar(select(User).where(User.username == "manager1"))
        assert reviewer.id in frozen["contributor_ids"]  # Legacy reviewer edits cannot be distinguished.
        release = service.reserve_build(s, p, request)
        release.pending_job_id = "synthetic-pending"
        s.flush()
        with pytest.raises(HTTPException) as err:
            service.reserve_build(s, p, request, release_id=release.id)
        assert err.value.status_code == 409


def test_release_schema_never_accepts_holdout_combined_digest(analyst, manager):
    _, _, g = adopted_candidate(analyst, manager)
    request = release_request(analyst, g)
    request.update(split="holdout", artifact_kind="holdout_input", purpose="external_evaluation")
    with pytest.raises(ValueError, match="digest_kind"):
        ReleaseRequest.model_validate(request)


def test_profile_rows_cannot_be_rewritten(analyst):
    profile = analyst.get("/knowledge/golden/profiles?kind=pseudonymization").json()["items"][0]
    with pytest.raises(ValueError, match="immutable"):
        with session_scope() as s:
            row = s.get(GoldenProfileVersion, profile["id"])
            row.payload = {**row.payload, "time_transform": "offset"}


def _release_for_source_reader(app, analyst, manager):
    from tests.conftest import Api, make_user
    inv, _, golden = adopted_candidate(analyst, manager)
    reader_id = make_user("release-source-reader", ["analyst"])
    reader = Api(app, "release-source-reader")
    assert analyst.post(f"/investigations/{inv['id']}/members", json={"user_id": reader_id, "access": "viewer"}).status_code == 200
    first = analyst.post("/knowledge/golden/releases", json=release_request(analyst, golden)).json()
    other, _, second = adopted_candidate(analyst, manager)
    return reader, first, other, second


def test_historical_version_does_not_disclose_inaccessible_current_pointer(app, analyst, manager):
    reader, first, _, second = _release_for_source_reader(app, analyst, manager)
    rid, vid = first["release_id"], first["current_version_id"]
    request = release_request(analyst, second, key="second-source-version")
    request["expected_current_version_id"] = vid
    built = analyst.post(f"/knowledge/golden/releases/{rid}/versions", json=request)
    assert built.status_code == 202, built.text
    new_id = built.json()["current_version_id"]
    assert new_id != vid
    got = reader.get(f"/knowledge/golden/releases/{rid}/versions/{vid}")
    assert got.status_code == 200, got.text
    assert got.json()["version"]["id"] == vid
    assert got.json()["current_version_id"] is None
    assert new_id not in got.text
    history = reader.get(f"/knowledge/golden/releases/{rid}/versions")
    assert history.status_code == 200 and [v["id"] for v in history.json()["items"]] == [vid]


def test_current_and_historical_envelopes_hide_inaccessible_pending_job(app, analyst, manager):
    from saw.storage.models import Job
    from saw.reports.models import JobSourceInvestigation
    reader, first, other, _ = _release_for_source_reader(app, analyst, manager)
    rid, vid = first["release_id"], first["current_version_id"]
    with session_scope() as s:
        owner = s.scalar(select(User.id).where(User.username == "analyst1"))
        pending = Job(investigation_id=other["id"], kind="golden_export", requested_by=owner, state="QUEUED",
            stages={"source_ids": [other["id"]], "golden_export": {"release_id": rid}})
        s.add(pending)
        s.flush()
        s.add(JobSourceInvestigation(job_id=pending.id, investigation_id=other["id"]))
        s.get(GoldenRelease, rid).pending_job_id = pending.id
        pending_id = pending.id
    for path in (f"/knowledge/golden/releases/{rid}", f"/knowledge/golden/releases/{rid}/versions/{vid}"):
        got = reader.get(path)
        assert got.status_code == 200, got.text
        assert got.json()["pending_job"] is None
        assert got.json()["state"] != "building"
        assert pending_id not in got.text


def test_replacement_requires_old_source_access_and_exact_current_cas(app, analyst, manager):
    from tests.conftest import Api, make_user
    _, first, other, golden = _release_for_source_reader(app, analyst, manager)
    uid = make_user("new-source-only", ["analyst"])
    new_only = Api(app, "new-source-only")
    analyst.post(f"/investigations/{other['id']}/members", json={"user_id": uid, "access": "viewer"})
    request = release_request(analyst, golden, key="denied-current-source")
    request["expected_current_version_id"] = first["current_version_id"]
    url = f"/knowledge/golden/releases/{first['release_id']}/versions"
    assert new_only.post(url, json=request).status_code == 403
    request["idempotency_key"] = "stale-current-source"
    request["expected_current_version_id"] = None
    assert analyst.post(url, json=request).status_code == 409


def test_cross_source_failed_replacement_retry_preserves_exact_new_input_ledger(app, analyst, manager, monkeypatch):
    from saw.knowledge import golden_artifact, golden_jobs
    from saw.storage.models import Job
    from saw.reports.models import JobSourceInvestigation
    _, first, other, golden = _release_for_source_reader(app, analyst, manager)
    build = golden_artifact.build_release
    def fail(*args, **kwargs):
        raise ValueError("synthetic_artifact_failure")
    monkeypatch.setattr(golden_artifact, "build_release", fail)
    request = release_request(analyst, golden, key="failed-cross-source-version")
    request["expected_current_version_id"] = first["current_version_id"]
    failed = analyst.post(f"/knowledge/golden/releases/{first['release_id']}/versions", json=request)
    assert failed.status_code == 202, failed.text
    result = failed.json()
    assert result["job"]["state"] == "FAILED" and result["current_version_id"] == first["current_version_id"]
    with session_scope() as s:
        original = deepcopy(s.get(Job, result["job_id"]).stages["input_ref"])
    monkeypatch.setattr(golden_artifact, "build_release", build)
    retried = analyst.post(f"/jobs/{result['job_id']}/retry")
    assert retried.status_code == 200, retried.text
    newer = retried.json()
    assert newer["state"] == "COMPLETED", newer
    with session_scope() as s:
        job = s.get(Job, newer["id"])
        assert job.stages["source_ids"] == [other["id"]]
        assert set(s.scalars(select(JobSourceInvestigation.investigation_id).where(
            JobSourceInvestigation.job_id == job.id))) == {other["id"]}
        new_ref = deepcopy(job.stages["input_ref"])
    assert golden_jobs._read_ref(original) == golden_jobs._read_ref(new_ref)
