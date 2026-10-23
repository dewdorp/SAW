"""Real legacy prepare/adopt answers survive independently approved public releases."""
from __future__ import annotations

import hashlib
import io
import json
import zipfile
from datetime import datetime

import pytest

from saw.knowledge import golden as golden_service
from saw.knowledge.golden_models import GoldenVersion
from saw.storage.db import session_scope
from tests.api.test_golden import approve
from tests.api.test_golden_governance import release_request
from tests.api.test_guidance import IP, answer_body, make_case, preview

DUE_AT = "2026-11-01T00:00:00+00:00"
PRIVATE_NOTE = "SYNTHETIC_LEGACY_REVIEWED_NOTE"
PRIVATE_TARGET = "SYNTHETIC_LEGACY_FOLLOWUP_TARGET"


def _ok(response, status=200):
    assert response.status_code == status, response.text
    return response.json()


def _stored_payload(version_id):
    with session_scope() as session:
        row = session.get(GoldenVersion, version_id)
        payload = golden_service._bytes(golden_service._payload(row))
        return payload, row.content_sha256


def _adopt_legacy(analyst, manager, senior):
    inv = make_case(analyst, count=6)
    reviewer_id = _ok(senior.get("/auth/me"))["id"]
    _ok(analyst.post(f"/investigations/{inv['id']}/members",
                       json={"user_id": reviewer_id, "access": "viewer"}))
    guidance = preview(analyst, inv)
    body = answer_body(guidance, follow_up={
        "target": PRIVATE_TARGET, "due_at": DUE_AT, "priority": "high",
        "needed_data": ["SYNTHETIC_LEGACY_NEEDED_DATA"],
        "items": ["SYNTHETIC_LEGACY_FOLLOWUP_ITEM"],
    })
    body.update(judgement="normal", note=PRIVATE_NOTE)
    check = _ok(analyst.post(f"/investigations/{inv['id']}/checks", json=body), 201)
    assert check["judgement"] == "normal"
    assert check["capture"]["selected_events"]
    closed = _ok(analyst.post(f"/investigations/{inv['id']}/close", json={
        "verdict": "normal", "reason": PRIVATE_NOTE, "save_experience": True,
        "limits": "Synthetic reviewed exercise only; supporting service records are not collected.",
    }))
    experience_id = closed["experience_id"]
    experience = _ok(analyst.get(f"/experiences/{experience_id}"))
    source = _ok(analyst.post(f"/knowledge/golden/experience/{experience_id}/prepare",
                             json={"expected_experience_rev": experience["rev"]}), 201)
    assert source["schema_version"] == "saw.golden.v1"
    assert source["answers"]["judgement"]["behavior"] == "normal"
    assert source["answers"]["judgement"]["evidence_refs"]
    assert source["answers"]["required_facts_actions"]
    assert len(source["answers"]["followups"]) == 1
    _ok(analyst.post(f"/experiences/{experience_id}/submit"))
    _ok(approve(manager, experience_id, source, split="dev"))
    source = next(row for row in _ok(manager.get(
        f"/knowledge/golden/experience/{experience_id}"))["versions"] if row["id"] == source["id"])
    assert source["status"] == "adopted"
    return source


def _download_reviewed_release(analyst, senior, source, implementation):
    request = release_request(analyst, source, key="real-legacy-" + implementation.replace("/", "-"))
    profile = next(row for row in _ok(analyst.get(
        "/knowledge/golden/profiles?kind=model_conversion"))["items"] if row["implementation"] == implementation)
    request["model_conversion_profile"] = {"id": profile["id"], "sha256": profile["payload_sha256"]}
    assert request["projection"] == "v1"
    built = _ok(analyst.post("/knowledge/golden/releases", json=request), 202)
    assert built["job"]["state"] == "COMPLETED", built
    url = f"/knowledge/golden/releases/{built['release_id']}/versions/{built['current_version_id']}"
    inspected = _ok(senior.get(url + "/preview"))
    _ok(senior.post(url + "/approve", json={
        "expected_current_version_id": built["current_version_id"],
        "expected_payload_sha256": inspected["payload_sha256"],
        "expected_artifact_sha256": inspected["artifact_sha256"], "expected_decision_id": None,
        "decision": "approve", "reason": "Independent review of synthetic legacy output.",
        "confirmations": {"preview_reviewed": True, "redistribution_rights": True,
                          "recipient_and_purpose": True, "limits_accepted": True},
    }))
    downloaded = analyst.get(url + "/download")
    assert downloaded.status_code == 200, downloaded.text
    assert hashlib.sha256(downloaded.content).hexdigest() == inspected["artifact_sha256"]
    return downloaded.content


@pytest.mark.parametrize("implementation", ["golden-native/1", "input-output-jsonl/1"])
def test_real_legacy_v1_answers_keep_reviewed_semantics_and_frozen_source(
        analyst, manager, senior, implementation):
    source = _adopt_legacy(analyst, manager, senior)
    frozen = _stored_payload(source["id"])
    assert hashlib.sha256(frozen[0]).hexdigest() == frozen[1] == source["content_sha256"]
    exported = _download_reviewed_release(analyst, senior, source, implementation)
    assert _stored_payload(source["id"]) == frozen

    with zipfile.ZipFile(io.BytesIO(exported)) as archive:
        names = archive.namelist()
        answer_paths = [name for name in names if name.startswith("answers/")]
        input_paths = [name for name in names if name.startswith("input/")]
        assert len(answer_paths) == len(input_paths) == 1
        answers = json.loads(archive.read(answer_paths[0]))
        public_input = json.loads(archive.read(input_paths[0]))
        evidence = {
            name.removeprefix("evidence/").removesuffix(".json"): json.loads(archive.read(name))
            for name in names if name.startswith("evidence/")
        }
        assert evidence
        for ref in public_input["evidence"]:
            assert ref["sha256"] in evidence
            assert ref["path"] in names
        assert any(blob.get("event") for blob in evidence.values())
        assert all(blob["event"].get("src_ip") != IP for blob in evidence.values() if blob.get("event"))

        assert answers["schema"] == "saw.golden.answers.v1"
        assert "investigation_truth" not in answers
        assert answers["judgement"]["behavior"] == "normal"
        refs = answers["judgement"]["evidence_refs"]
        assert refs and set(refs) <= evidence.keys()
        assert not set(refs) & set(source["answers"]["judgement"]["evidence_refs"])
        assert "unapproved_free_text_omitted" in answers["limits"]

        assert len(answers["followups"]) == 1
        followup = answers["followups"][0]
        assert followup["priority"] == "high"
        assert datetime.fromisoformat(followup["due_at"]) == datetime.fromisoformat(DUE_AT)
        assert followup["text_state"] == "unapproved_free_text_omitted"
        assert followup["needed_data_count"] == followup["items_count"] == 1
        facts = answers["required_facts_actions"]
        assert len(facts) == len(source["answers"]["required_facts_actions"])
        for fact in facts:
            assert fact["text_state"] == "unapproved_free_text_omitted"
            assert fact["evidence_refs"] and set(fact["evidence_refs"]) <= evidence.keys()

        conversion_paths = [name for name in names if name.startswith("conversion/")]
        if implementation == "input-output-jsonl/1":
            assert len(conversion_paths) == 1
            records = archive.read(conversion_paths[0]).splitlines()
            assert len(records) == 1
            assert json.loads(records[0]) == {"input": public_input, "output": answers}
        else:
            assert conversion_paths == []
        public_text = b"".join(archive.read(name) for name in names).decode("utf-8")
        for omitted in (PRIVATE_NOTE, PRIVATE_TARGET, "SYNTHETIC_LEGACY_NEEDED_DATA",
                        "SYNTHETIC_LEGACY_FOLLOWUP_ITEM"):
            assert omitted not in public_text
