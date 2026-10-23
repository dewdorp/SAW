"""Durable admission, cancellation and publication use actual private artifacts."""
from copy import deepcopy

import pytest
from sqlalchemy import select

from saw import container
from saw.knowledge import golden_jobs
from saw.knowledge.golden_governance_models import GoldenRelease
from saw.storage.db import session_scope
from saw.storage.models import Investigation, Job
from tests.api.test_golden_governance import adopted_candidate, release_request


def queued_release(analyst, manager, monkeypatch):
    inv, _, golden = adopted_candidate(analyst, manager)
    request = release_request(analyst, golden)
    monkeypatch.setattr(container.get().runner, "submit", lambda *a, **kw: None)
    response = analyst.post("/knowledge/golden/releases", json=request)
    assert response.status_code == 202, response.text
    result = response.json()
    assert result["job"]["state"] == "QUEUED"
    return inv, request, result


def test_admission_idempotency_conflict_and_bounded_queue(analyst, manager, monkeypatch):
    _, request, first = queued_release(analyst, manager, monkeypatch)
    duplicate = analyst.post("/knowledge/golden/releases", json=request)
    assert duplicate.status_code == 202 and duplicate.json()["job_id"] == first["job_id"]
    conflict = deepcopy(request)
    conflict["purpose_text"] = "A different request"
    assert analyst.post("/knowledge/golden/releases", json=conflict).status_code == 409
    for number in range(1, 8):
        request["idempotency_key"] = f"synthetic-queued-{number}"
        response = analyst.post("/knowledge/golden/releases", json=request)
        assert response.status_code == 202, response.text
    request["idempotency_key"] = "synthetic-queued-over-limit"
    assert analyst.post("/knowledge/golden/releases", json=request).status_code == 429
    request["idempotency_key"] = "synthetic-release-1"
    assert analyst.post("/knowledge/golden/releases", json=request).status_code == 202


def test_cancel_and_retry_reuses_verified_frozen_bytes_then_publishes(analyst, manager, monkeypatch):
    _, _, first = queued_release(analyst, manager, monkeypatch)
    jid = first["job_id"]
    with session_scope() as s:
        original = deepcopy(s.get(Job, jid).stages["input_ref"])
    assert analyst.post(f"/jobs/{jid}/cancel").status_code == 200
    retried = analyst.post(f"/jobs/{jid}/retry")
    assert retried.status_code == 200, retried.text
    newer = retried.json()
    assert newer["id"] != jid
    with session_scope() as s:
        ref = deepcopy(s.get(Job, newer["id"]).stages["input_ref"])
    assert ref["key"] != original["key"]
    assert golden_jobs._read_ref(ref) == golden_jobs._read_ref(original)
    golden_jobs.run(newer["id"])
    assert analyst.get(f"/jobs/{newer['id']}").json()["state"] == "COMPLETED"
    assert analyst.post(f"/jobs/{newer['id']}/cancel").status_code == 409


def test_input_pending_recovery_cannot_be_resurrected_by_late_put(analyst, manager, monkeypatch):
    _, _, golden = adopted_candidate(analyst, manager)
    original = golden_jobs._put_bytes
    def recover_after_put(key, data):
        result = original(key, data)
        if "/inputs/" in key:
            jid = key.split("/")[1]
            with session_scope() as s:
                assert golden_jobs.recover_input_pending(s, s.get(Job, jid))
        return result
    monkeypatch.setattr(golden_jobs, "_put_bytes", recover_after_put)
    response = analyst.post("/knowledge/golden/releases", json=release_request(analyst, golden))
    assert response.status_code == 202, response.text
    result = response.json()
    assert result["job"]["state"] == "FAILED" and result["current_version_id"] is None
    with session_scope() as s:
        release = s.get(GoldenRelease, result["release_id"])
        job = s.get(Job, result["job_id"])
        assert release.pending_job_id is None
        assert job.stages["input_state"] == "input_pending"
        assert job.error["type"] == "InputIncomplete"
    assert analyst.post(f"/jobs/{result['job_id']}/retry").status_code == 409


@pytest.mark.parametrize("change", ["cancel", "epoch", "lease"])
def test_artifact_io_changes_cannot_publish_stale_worker(analyst, manager, monkeypatch, change):
    inv, _, first = queued_release(analyst, manager, monkeypatch)
    original = golden_jobs._put_bytes
    def change_after_write(key, data):
        result = original(key, data)
        if "/artifact/" in key:
            with session_scope() as s:
                job = s.get(Job, first["job_id"])
                if change == "cancel":
                    job.cancel_requested = True
                elif change == "epoch":
                    source = s.get(Investigation, inv["id"])
                    source.settings = {**(source.settings or {}), "data_epoch": 1}
                else:
                    job.attempt += 1
                    job.current_item = "newer worker owns this job"
        return result
    monkeypatch.setattr(golden_jobs, "_put_bytes", change_after_write)
    golden_jobs.run(first["job_id"])
    with session_scope() as s:
        release = s.get(GoldenRelease, first["release_id"])
        job = s.get(Job, first["job_id"])
        assert release.current_version_id is None
        assert job.state == {"cancel": "CANCELLED", "epoch": "FAILED", "lease": "ANALYZING"}[change]
        if change == "lease":
            assert release.pending_job_id == job.id
            assert job.current_item == "newer worker owns this job"
        else:
            assert release.pending_job_id is None


def test_corrupted_frozen_input_is_not_retried_or_published(analyst, manager, monkeypatch):
    _, _, first = queued_release(analyst, manager, monkeypatch)
    with session_scope() as s:
        ref = deepcopy(s.get(Job, first["job_id"]).stages["input_ref"])
    golden_jobs._put_bytes(ref["key"], b"{}")
    golden_jobs.run(first["job_id"])
    result = analyst.get(f"/jobs/{first['job_id']}").json()
    assert result["state"] == "FAILED"
    assert result["stages"]["golden_export"]["version_id"] is None


def test_private_input_reference_must_belong_to_exact_job(analyst, manager, monkeypatch):
    _, _, first = queued_release(analyst, manager, monkeypatch)
    with session_scope() as s:
        job = s.get(Job, first["job_id"])
        ref = deepcopy(job.stages["input_ref"])
    data = golden_jobs._read_ref(ref)
    foreign = golden_jobs._put_bytes("golden/foreign-job/inputs/" + ref["sha256"] + ".json", data)
    with session_scope() as s:
        job = s.get(Job, first["job_id"])
        job.stages = {**job.stages, "input_ref": foreign}
    golden_jobs.run(first["job_id"])
    result = analyst.get(f"/jobs/{first['job_id']}").json()
    assert result["state"] == "FAILED"
    assert result["stages"]["golden_export"]["version_id"] is None


def test_failed_new_build_keeps_previous_approved_bytes(analyst, manager, senior, monkeypatch):
    from saw.knowledge import golden_artifact
    from saw.knowledge.golden_governance_models import GoldenReleaseVersion
    from tests.api.test_golden_holdout_governance import approved_release
    url, approved = approved_release(analyst, manager, senior, split="dev")
    original = analyst.get(url + "/download")
    assert original.status_code == 200
    with session_scope() as s:
        prior = s.get(GoldenReleaseVersion, approved["version"]["id"])
        request = deepcopy(prior.request)
    request["expected_current_version_id"] = prior.id
    request["idempotency_key"] = "synthetic-new-version-failure"
    def fail_build(*args, **kwargs):
        raise ValueError("synthetic_builder_failure")
    monkeypatch.setattr(golden_artifact, "build_release", fail_build)
    response = analyst.post(f"/knowledge/golden/releases/{approved['id']}/versions", json=request)
    assert response.status_code == 202, response.text
    result = response.json()
    assert result["job"]["state"] == "FAILED"
    assert result["current_version_id"] == approved["version"]["id"]
    with session_scope() as s:
        release = s.get(GoldenRelease, approved["id"])
        assert release.pending_job_id is None
        assert release.current_revision == 1
    retained = analyst.get(url + "/download")
    assert retained.status_code == 200 and retained.content == original.content
