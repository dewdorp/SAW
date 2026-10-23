"""Holdout is a persisted evaluation ledger, never an untracked answer export."""
from sqlalchemy import select
from saw.storage.db import session_scope
from saw.storage.models import User
from tests.api.test_golden_governance import adopted_candidate, release_request


def approved_release(analyst, manager, senior, *, split="holdout"):
    inv, _, golden = adopted_candidate(analyst, manager, split=split, v2=True)
    with session_scope() as s:
        uid = s.scalar(select(User.id).where(User.username == "senior1"))
    assert analyst.post(f"/investigations/{inv['id']}/members", json={"user_id": uid, "access": "viewer"}).status_code == 200
    response = analyst.post("/knowledge/golden/releases", json=release_request(analyst, golden, split=split))
    assert response.status_code == 202, response.text
    built = response.json()
    assert built["job"]["state"] == "COMPLETED", built
    rid, vid = built["release_id"], built["current_version_id"]
    url = f"/knowledge/golden/releases/{rid}/versions/{vid}"
    preview = senior.get(url + "/preview")
    assert preview.status_code == 200, preview.text
    data = preview.json()
    approved = senior.post(url + "/approve", json={
        "expected_current_version_id": vid, "expected_payload_sha256": data["payload_sha256"],
        "expected_artifact_sha256": data["artifact_sha256"], "expected_decision_id": None,
        "decision": "approve", "reason": "Synthetic independent artifact inspection",
        "confirmations": {"preview_reviewed": True, "redistribution_rights": True,
            "recipient_and_purpose": True, "limits_accepted": True}})
    assert approved.status_code == 200, approved.text
    return url, approved.json()


def test_holdout_consumption_result_answer_order_and_renamed_target_denied(analyst, manager, senior):
    url, release = approved_release(analyst, manager, senior)
    version = release["version"]
    body = {"release_version_id": version["id"], "expected_artifact_sha256": version["artifact"]["sha256"],
        "target": {"kind": "model", "name": "Synthetic target", "version": "1", "artifact_sha256": "a" * 64},
        "purpose_text": "Synthetic result tracking", "idempotency_key": "holdout-test-1"}
    created = analyst.post("/knowledge/golden/holdout-attempts", json=body)
    assert created.status_code == 201, created.text
    attempt = created.json()
    assert attempt["release_id"] == release["id"]
    result_url = f"/knowledge/golden/holdout-attempts/{attempt['id']}/result"
    result = {"expected_result_sha256": None, "artifact_sha256": "b" * 64, "summary": "Operator reported fixture only"}
    assert analyst.post(result_url, json=result).status_code == 409
    assert senior.get(f"/knowledge/golden/holdout-attempts/{attempt['id']}/answers").status_code == 409
    first = analyst.get(url + f"/download?attempt_id={attempt['id']}")
    assert first.status_code == 200, first.text
    assert analyst.get(url + f"/download?attempt_id={attempt['id']}").status_code == 200
    recorded = analyst.post(result_url, json=result)
    assert recorded.status_code == 200, recorded.text
    assert recorded.json()["result"]["status"] == "operator_reported"
    assert recorded.json()["input_access"]["count"] == 2
    assert analyst.get(f"/knowledge/golden/holdout-attempts/{attempt['id']}/answers").status_code == 403
    answers = senior.get(f"/knowledge/golden/holdout-attempts/{attempt['id']}/answers")
    assert answers.status_code == 200 and "EVALUATOR_ONLY_SECRET" in answers.text
    assert analyst.post(result_url, json={**result, "summary": "Changed"}).status_code == 409
    body["idempotency_key"] = "holdout-test-2"
    body["target"]["name"] = "Renamed same artifact"
    denied = analyst.post("/knowledge/golden/holdout-attempts", json=body)
    assert denied.status_code == 409 and "repeat" in denied.text
    public = analyst.get(url).json()
    assert "content_sha256" not in str(public)
    assert "EVALUATOR_ONLY_SECRET" not in str(public)
    assert public["version"]["applicability"]["validations"] == []


def test_release_requires_independent_preview_and_revocation_blocks_download(analyst, manager, senior):
    url, release = approved_release(analyst, manager, senior, split="dev")
    assert analyst.get(url + "/download").status_code == 200
    revoked = senior.post(url + "/revoke", json={"expected_decision_id": release["approval"]["id"], "reason": "Stop fixture distribution"})
    assert revoked.status_code == 200, revoked.text
    assert analyst.get(url + "/download").status_code == 409


def test_decline_eligibility_needs_independence_but_no_preview(analyst, manager, senior):
    inv, _, golden = adopted_candidate(analyst, manager)
    with session_scope() as s:
        uid = s.scalar(select(User.id).where(User.username == "senior1"))
    analyst.post(f"/investigations/{inv['id']}/members", json={"user_id": uid, "access": "viewer"})
    built = analyst.post("/knowledge/golden/releases", json=release_request(analyst, golden)).json()
    url = f"/knowledge/golden/releases/{built['release_id']}/versions/{built['current_version_id']}"
    independent = senior.get(url).json()
    assert independent["eligibility"]["decline"]["enabled"] is True
    assert independent["eligibility"]["approve"]["enabled"] is False
    assert analyst.get(url).json()["eligibility"]["decline"]["enabled"] is False


def test_revoked_version_cannot_be_declined_then_reapproved(analyst, manager, senior):
    url, release = approved_release(analyst, manager, senior, split="dev")
    revoked = senior.post(url + "/revoke", json={
        "expected_decision_id": release["approval"]["id"], "reason": "Stop distribution"}).json()
    assert revoked["eligibility"]["decline"]["enabled"] is False
    version = revoked["version"]
    body = {"expected_current_version_id": version["id"],
        "expected_payload_sha256": version["payload_sha256"],
        "expected_artifact_sha256": version["artifact"]["sha256"],
        "expected_decision_id": revoked["approval"]["id"], "decision": "decline", "reason": "Cannot reopen",
        "confirmations": {"preview_reviewed": True, "redistribution_rights": True,
            "recipient_and_purpose": True, "limits_accepted": True}}
    assert senior.post(url + "/approve", json=body).status_code == 409
    body["decision"] = "approve"
    assert senior.post(url + "/approve", json=body).status_code == 409
    assert senior.get(url).json()["state"] == "revoked"


def test_holdout_public_seal_excludes_private_validation_digests(analyst, manager, senior, monkeypatch):
    from saw.knowledge import golden_artifact
    from saw.knowledge.golden_governance_models import GoldenReleaseVersion, GoldenValidation
    from saw.core.application.provenance import digest
    original = golden_artifact.build_release
    def build(*args, **kwargs):
        result = original(*args, **kwargs)
        source = args[0]["examples"][0]
        result["validations"] = [{"golden_ref": {"id": source["version_id"],
            "content_sha256": source["content_sha256"]}, "validator_version": "test-private-validation/1",
            "private_answer_sha256": "a" * 64}]
        result["validation"]["checks"].append({"code": "private_fixture", "state": "passed",
            "detail": "PRIVATE_ANSWER_DIGEST", "expected_sha256": "b" * 64})
        return result
    monkeypatch.setattr(golden_artifact, "build_release", build)
    _, release = approved_release(analyst, manager, senior)
    with session_scope() as s:
        row = s.get(GoldenReleaseVersion, release["version"]["id"])
        assert row.validation_refs
        private = s.get(GoldenValidation, row.validation_refs[0]["id"])
        assert private.payload["private_answer_sha256"] == "a" * 64
        assert row.payload_sha256 == digest(row.payload)
        assert row.payload["applicability"]["validations"] == []
        assert private.payload_sha256 not in str(row.payload)
        assert private.subject_sha256 not in str(row.payload)
        assert "PRIVATE_ANSWER_DIGEST" not in str(row.payload)
        assert "expected_sha256" not in str(row.payload["validation"])
    assert "content_sha256" not in str(release)
