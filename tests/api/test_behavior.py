"""Synthetic behavior lifecycle, immutable snapshots and approval boundaries."""
from __future__ import annotations
import json
from sqlalchemy import select
from saw import container
from saw.event_generations.reads import actor_scope
from saw.storage.db import session_scope
from saw.storage.models import Job, EvidenceFile
from tests.api.test_guidance import make_case, IP
from tests.api.test_phase5_bulk import upload
from tests.conftest import Api, make_user

def run(api, inv, **kw):
    response = api.post(f"/investigations/{inv['id']}/behavior", json={"ips": [IP], **kw})
    assert response.status_code == 202, response.text
    job = api.get(f"/jobs/{response.json()['id']}").json()
    assert job["state"] == "COMPLETED", job
    rows = api.get(f"/investigations/{inv['id']}/behavior").json()["results"]
    return api.get(f"/investigations/{inv['id']}/behavior/{rows[0]['id']}").json()

def attachment(result, **kw):
    return {"result_id": result["id"], "result_sha256": result["result_sha256"],
            "metric_ids": ["requests_10s"], "answer_status": "follow_up",
            "follow_up": {"target": "서비스 담당", "needed_data": ["원본 로그"], "items": ["결과 확인"]}, **kw}

def test_behavior_run_scope_versions_hash_and_masking(analyst):
    inv = make_case(analyst, 35)
    result = run(analyst, inv)
    assert result["version"] == 1
    assert result["result"]["observations"]["summary"]["count"] == 35
    assert len(result["result_sha256"]) == 64
    assert result["result"]["source_manifest"]["evidence"]
    assert "evidence_events" not in result["result"]["observations"]
    assert result["result"]["selected_evidence"]
    assert run(analyst, inv)["version"] == 2
    assert analyst.get(f"/investigations/{inv['id']}/behavior/{result['id']}").json() == result

def test_behavior_idempotency_acl_and_limits(analyst, app):
    inv = make_case(analyst, 3)
    body = {"ips": [IP], "idempotency_key": "same-behavior"}
    a = analyst.post(f"/investigations/{inv['id']}/behavior", json=body)
    assert a.status_code == 202
    b = analyst.post(f"/investigations/{inv['id']}/behavior", json=body)
    assert b.json()["id"] == a.json()["id"]
    changed = analyst.post(f"/investigations/{inv['id']}/behavior", json={**body, "role": "dst"})
    assert changed.status_code == 409
    make_user("outsider", ["analyst"])
    outsider = Api(app, "outsider")
    assert outsider.get(f"/investigations/{inv['id']}/behavior").status_code == 403
    assert analyst.post(f"/investigations/{inv['id']}/behavior", json={"ips": ["bad"]}).status_code == 422

def test_behavior_check_and_close_pin_exact_result(analyst):
    inv = make_case(analyst, 3)
    result = run(analyst, inv)
    body = {"behavior": attachment(result), "note": "관찰은 있으나 영향은 미확인"}
    r = analyst.post(f"/investigations/{inv['id']}/checks", json=body)
    assert r.status_code == 201, r.text
    check = r.json()
    assert check["behavior"]["result_id"] == result["id"]
    assert check["guidance"] is None
    updated = analyst.put(f"/investigations/{inv['id']}/checks/{check['id']}", json={"note": "별도 분석가 정답"})
    assert updated.status_code == 200, updated.text
    assert updated.json()["behavior"] == check["behavior"]
    bad = analyst.post(f"/investigations/{inv['id']}/checks",
        json={"behavior": attachment(result, result_sha256="0"*64), "note": "변조"})
    assert bad.status_code == 400
    close = analyst.post(f"/investigations/{inv['id']}/close",
        json={"verdict": "unknown", "reason": "후속 확인 대기", "save_experience": True})
    assert close.status_code == 200, close.text
    from saw.knowledge.models import Experience
    with session_scope() as s:
        exp = s.scalar(select(Experience).where(Experience.source_investigation_id == inv["id"]))
        assert exp.data["behavior_results"][0]["result_sha256"] == result["result_sha256"]

def test_behavior_active_source_job_is_rejected(analyst):
    inv = make_case(analyst, 3)
    with session_scope() as s:
        source = s.scalar(select(Job).where(Job.investigation_id == inv["id"]))
        source.state = "PARSING"
    r = analyst.post(f"/investigations/{inv['id']}/behavior", json={})
    assert r.status_code == 409

def test_behavior_source_mutation_never_publishes(analyst, monkeypatch):
    inv = make_case(analyst, 3)
    import saw.behavior.worker as worker
    real = worker.calculate
    def mutate(*args, **kwargs):
        result = real(*args, **kwargs)
        with session_scope() as s:
            file = s.scalar(select(EvidenceFile))
            file.sha256 = "f"*64
        return result
    monkeypatch.setattr(worker, "calculate", mutate)
    response = analyst.post(f"/investigations/{inv['id']}/behavior", json={})
    assert response.status_code == 202
    job = analyst.get(f"/jobs/{response.json()['id']}").json()
    assert job["state"] == "FAILED"
    assert analyst.get(f"/investigations/{inv['id']}/behavior").json()["results"] == []

def test_behavior_cancel_and_stale_lease_never_publish(analyst, monkeypatch):
    inv = make_case(analyst, 3)
    import saw.behavior.worker as worker
    real = worker.calculate
    for stale in (False, True):
        def interrupt(*args, **kwargs):
            result = real(*args, **kwargs)
            with session_scope() as s:
                job = s.scalar(select(Job).where(Job.kind == "behavior").order_by(Job.created_at.desc()))
                if stale:
                    job.attempt += 1
                else:
                    job.cancel_requested = True
            return result
        monkeypatch.setattr(worker, "calculate", interrupt)
        response = analyst.post(f"/investigations/{inv['id']}/behavior", json={})
        assert response.status_code == 202
        job = analyst.get(f"/jobs/{response.json()['id']}").json()
        assert job["state"] != "COMPLETED"
        assert analyst.get(f"/investigations/{inv['id']}/behavior").json()["results"] == []

def test_behavior_result_tamper_read_rejected(analyst):
    inv = make_case(analyst, 3)
    result = run(analyst, inv)
    from saw.behavior.models import BehaviorResult
    with session_scope() as s:
        row = s.get(BehaviorResult, result["id"])
        row.result = {**row.result, "observations": {}}
    assert analyst.get(f"/investigations/{inv['id']}/behavior/{result['id']}").status_code == 400

def behavior_candidate(analyst, marker="BEHAVIOR_EVALUATOR_ONLY"):
    inv = make_case(analyst, 35)
    result = run(analyst, inv)
    response = analyst.post(f"/investigations/{inv['id']}/checks",
        json={"behavior": attachment(result), "note": marker})
    assert response.status_code == 201, response.text
    closed = analyst.post(f"/investigations/{inv['id']}/close",
        json={"verdict": "unknown", "reason": marker, "save_experience": True})
    assert closed.status_code == 200, closed.text
    eid = closed.json()["experience_id"]
    prepared = analyst.post(f"/knowledge/golden/experience/{eid}/prepare", json={"expected_experience_rev": 1})
    assert prepared.status_code == 201, prepared.text
    return inv, result, eid, prepared.json()

def test_behavior_golden_exact_metrics_separates_answers(analyst, manager):
    from tests.api.test_golden import approve
    from saw.knowledge.golden_models import GoldenBlob
    inv, result, eid, golden = behavior_candidate(analyst)
    with session_scope() as s:
        observation = s.get(GoldenBlob, golden["input"]["observations"][0]).content
        assert observation["schema"] == "saw.golden.behavior-observation.v1"
        assert observation["observations"]["metrics"] == result["result"]["observations"]["metrics"]
        assert observation["observations"]["followups"] == result["result"]["observations"]["followups"]
        assert observation["methodology"]["question_version"] == "saw-web-behavior-questions/1.0"
        assert "BEHAVIOR_EVALUATOR_ONLY" not in json.dumps(observation)
    analyst.post(f"/experiences/{eid}/submit")
    assert approve(manager, eid, golden).status_code == 200
    from tests.api.test_golden import frozen_input
    agent, blobs = frozen_input(golden["id"])
    assert "BEHAVIOR_EVALUATOR_ONLY" not in json.dumps([agent, blobs])
    body = {"version_ids": [golden["id"]], "split": "dev", "format": "jsonl", "audience": "evaluator",
        "schema_version": "saw.golden.export.v2", "purpose": "internal_evaluation"}
    assert "BEHAVIOR_EVALUATOR_ONLY" in manager.post("/knowledge/golden/export", json=body).text
    assert manager.post("/knowledge/golden/export", json={**body, "split": "holdout"}).status_code == 409


def test_behavior_golden_snapshot_loss_and_stale_revision(analyst, manager):
    from tests.api.test_golden import approve
    from saw.knowledge.golden_models import GoldenBlob
    inv, result, eid, golden = behavior_candidate(analyst)
    wrong = analyst.post(f"/knowledge/golden/experience/{eid}/prepare", json={"expected_experience_rev": 2})
    assert wrong.status_code == 400
    analyst.post(f"/experiences/{eid}/submit")
    with session_scope() as s:
        s.delete(s.get(GoldenBlob, golden["input"]["observations"][0]))
    assert approve(manager, eid, golden).status_code == 400

def test_behavior_result_author_is_golden_contributor(analyst, manager):
    from tests.api.test_golden import approve
    inv = make_case(analyst, 35)
    result = run(manager, inv)
    analyst.post(f"/investigations/{inv['id']}/checks", json={"behavior": attachment(result), "note": "분석가 판단"})
    closed = analyst.post(f"/investigations/{inv['id']}/close",
        json={"verdict": "unknown", "reason": "승인 대기", "save_experience": True}).json()
    eid = closed["experience_id"]
    golden = analyst.post(f"/knowledge/golden/experience/{eid}/prepare",
        json={"expected_experience_rev": 1}).json()
    analyst.post(f"/experiences/{eid}/submit")
    response = approve(manager, eid, golden)
    assert response.status_code == 403
    assert "4-eyes" in response.text

def test_behavior_source_hash_change_blocks_golden(analyst):
    inv, result, eid, golden = behavior_candidate(analyst)
    with session_scope() as s:
        f = s.scalar(select(EvidenceFile))
        f.sha256 = "a"*64
    response = analyst.post(f"/knowledge/golden/experience/{eid}/prepare", json={"expected_experience_rev": 1})
    assert response.status_code == 400 and "source" in response.text

def test_behavior_later_check_cannot_enter_pinned_experience(analyst):
    inv, result, eid, golden = behavior_candidate(analyst)
    newer = run(analyst, inv)
    response = analyst.post(f"/investigations/{inv['id']}/checks", json={"behavior": attachment(newer), "note": "새 판단"})
    assert response.status_code == 201
    prepared = analyst.post(f"/knowledge/golden/experience/{eid}/prepare", json={"expected_experience_rev": 1})
    assert prepared.status_code == 400 and "revision" in prepared.text

def test_behavior_either_scope_keeps_missing_source_and_deduplicates_overlap(analyst):
    inv = analyst.post("/investigations", json={"title": "Synthetic behavior either scope"}).json()
    rows = ["timestamp,src_ip,dst_ip,dst_port,method,uri,status,action",
            f"2026-10-01T00:00:00Z,,{IP},443,GET,/health,200,allow",
            f"2026-10-01T00:00:01Z,{IP},{IP},443,GET,/health,200,allow",
            f"2026-10-01T00:00:02Z,{IP},10.0.0.8,443,GET,/health,200,allow"]
    source = upload(analyst, inv["id"], "synthetic-either.csv", "\n".join(rows).encode())
    analyst.post(f"/evidence/{source['evidence_id']}/process").raise_for_status()
    with actor_scope(analyst.get("/auth/me").json()["id"]):
        events = container.get().events.search(inv["id"], [], limit=10)["events"]
    assert len(events) == 3
    assert any(not event.get("src_ip") and event.get("dst_ip") == IP for event in events)
    assert any(event.get("src_ip") == event.get("dst_ip") == IP for event in events)
    result = run(analyst, inv, role="either")
    assert result["result"]["observations"]["summary"]["count"] == 3

def test_behavior_rejects_calculated_values_in_check_attachment(analyst):
    inv = make_case(analyst, 3)
    result = run(analyst, inv)
    bad = analyst.post(f"/investigations/{inv['id']}/checks",
        json={"behavior": attachment(result, metrics=[{"value": 999}]), "note": "위조"})
    assert bad.status_code == 400
    bad = analyst.post(f"/investigations/{inv['id']}/checks",
        json={"behavior": attachment(result), "evidence": ["outside-event"], "note": "범위 밖"})
    assert bad.status_code == 400

def test_behavior_snapshot_masking_keeps_hash_links_and_still_masks_text():
    from saw.knowledge.golden import masked
    sha = "a" + "01012345678" + "b"*52
    value = {"sha256": sha, "result_sha256": sha, "evidence_refs": [sha],
             "note": "call 01012345678", "raw_event": "password=123456"}
    result = masked(value)
    assert result["sha256"] == sha
    assert result["result_sha256"] == sha
    assert result["evidence_refs"] == [sha]
    assert "01012345678" not in result["note"]
    assert "123456" not in result["raw_event"]

def test_behavior_masked_snapshot_hashes_stay_valid_and_dynamic_keys_are_safe(analyst):
    from saw.core.application.provenance import digest
    inv = analyst.post("/investigations", json={"title": "Synthetic behavior secret masking"}).json()
    raw = {"timestamp": "2026-10-01T00:00:00Z", "src_ip": IP, "dst_ip": "10.0.0.8",
           "method": "GET", "uri": "/check?token=SECRET_VALUE_123", "status": 200,
           "user_agent": "Bearer SECRET_VALUE_123", "Cookie": "session=SECRET_VALUE_123"}
    source = upload(analyst, inv["id"], "synthetic-secret.jsonl", (json.dumps(raw) + "\n").encode())
    analyst.post(f"/evidence/{source['evidence_id']}/process").raise_for_status()
    with actor_scope(analyst.get("/auth/me").json()["id"]):
        event = container.get().events.search(inv["id"], [], limit=1)["events"][0]
    assert "SECRET_VALUE_123" in event["raw_event"]
    result = run(analyst, inv)
    assert "SECRET_VALUE_123" not in json.dumps(result)
    for item in result["result"]["selected_evidence"]:
        assert digest(item["event"]) == item["sha256"]
    response = analyst.post(f"/investigations/{inv['id']}/checks",
        json={"behavior": attachment(result), "note": "합성 민감값 검사"})
    assert response.status_code == 201, response.text
    closed = analyst.post(f"/investigations/{inv['id']}/close",
        json={"verdict": "unknown", "reason": "합성", "save_experience": True})
    eid = closed.json()["experience_id"]
    prepared = analyst.post(f"/knowledge/golden/experience/{eid}/prepare", json={"expected_experience_rev": 1})
    assert prepared.status_code == 201, prepared.text

def test_behavior_source_changed_after_prepare_cannot_be_adopted(analyst, manager):
    from tests.api.test_golden import approve
    inv, result, eid, golden = behavior_candidate(analyst)
    analyst.post(f"/experiences/{eid}/submit")
    with session_scope() as s:
        s.scalar(select(EvidenceFile)).sha256 = "f"*64
    response = approve(manager, eid, golden)
    assert response.status_code == 400 and "source" in response.text

def test_behavior_mixed_guidance_keeps_both_methodologies(analyst, manager):
    from tests.api.test_guidance import preview, answer_body
    from saw.knowledge.golden_models import GoldenBlob, GoldenVersion
    inv = make_case(analyst, 35)
    result = run(analyst, inv)
    analyst.post(f"/investigations/{inv['id']}/checks", json={"behavior": attachment(result), "note": "행위 관찰"})
    guidance = preview(analyst, inv)
    response = analyst.post(f"/investigations/{inv['id']}/checks", json=answer_body(guidance))
    assert response.status_code == 201, response.text
    closed = analyst.post(f"/investigations/{inv['id']}/close",
        json={"verdict": "unknown", "reason": "혼합 관찰", "save_experience": True}).json()
    prepared = analyst.post(f"/knowledge/golden/experience/{closed['experience_id']}/prepare",
        json={"expected_experience_rev": 1})
    assert prepared.status_code == 201, prepared.text
    golden = prepared.json()
    assert golden["methodology_version"] == "saw.mixed-observations/1"
    with session_scope() as s:
        kinds = {s.get(GoldenBlob, sha).content["schema"] for sha in golden["input"]["observations"]}
        assert kinds == {"saw.golden.observation.v1", "saw.golden.behavior-observation.v1"}
        assert len(s.get(GoldenVersion, golden["id"]).metadata_json["methodologies"]) == 2


def test_a_run_stopped_at_its_input_limit_says_how_much_of_the_scope_it_analysed(analyst, monkeypatch):
    """PPA-07: a capped run finished but covered part of the scope; result and job must say so."""
    from saw.behavior import worker
    monkeypatch.setattr(worker, "MAX_EVENTS", 10)
    inv = make_case(analyst, 35)
    response = analyst.post(f"/investigations/{inv['id']}/behavior", json={"ips": [IP]})
    job = analyst.get(f"/jobs/{response.json()['id']}").json()
    stage = job["stages"]["behavior_result"]
    assert stage["coverage"] == "partial" and stage["processed"] == 10 and stage["target_total"] == 35
    assert stage["reason"] == "max_events"
    result = analyst.get(f"/investigations/{inv['id']}/behavior/{stage['id']}").json()
    execution = result["result"]["observations"]["execution"]
    assert execution["coverage"] == "partial" and execution["target_total"] == 35
