"""Golden adoption security contracts; synthetic capture fixtures only."""
from __future__ import annotations

import io
import json
import zipfile
from datetime import timedelta

from sqlalchemy import select

from saw.storage.db import session_scope, utcnow
from saw.storage.models import Check, User

CONFIRM = {"required_facts_actions": True, "judgement_evidence": True, "followups": True, "forbidden_claims": True}


def candidate(api, title="합성 WAF", marker="EVALUATOR_ONLY_SECRET"):
    inv = api.post("/investigations", json={"title": title}).json()
    now = utcnow()
    scope = {"target_type": "entity", "target_key": "ip:198.51.100.8", "role": "src",
             "filters": [], "time": None, "effective_time": None, "as_of": now.isoformat(),
             "scope_key": "synthetic-scope", "evidence_manifest": []}
    capture = {"schema_version": 1, "captured_at": now.isoformat(), "known_at": now.isoformat(),
               "as_of": now.isoformat(), "temporally_valid": True,
               "methodology": {"id": "soc-guidance", "version": "1.0", "digest": "a" * 64},
               "scope": scope, "input": {"request": scope,
                   "facts": [{"id": "waf", "label": "WAF 요청", "value": 120, "data_state": "available"}],
                   "unknowns": [{"source": "WAS", "state": "not_collected", "reason": "처리 결과 없음"}],
                   "queries": [], "limits": ["WAS 미수집"]}, "evidence_refs": [], "selected_events": []}
    with session_scope() as s:
        user = s.scalar(select(User).where(User.username == "analyst1"))
        c = Check(investigation_id=inv["id"], target_type="entity", target_key="ip:198.51.100.8",
                  questions=["success"], judgement="undetermined", note=marker,
                  scope={"coverage": "all", "guidance": {"rule_id": "A", "follow_up": "WAS 처리 결과 요청",
                         "data_states": [{"source": "was", "state": "not_collected", "reason": "WAS missing"}]}},
                  context={"guidance": capture}, author_id=user.id, author_name=user.username, evidence=[])
        s.add(c)
    closed = api.post(f"/investigations/{inv['id']}/close", json={
        "verdict": "unknown", "reason": marker, "save_experience": True,
        "limits": "WAS 처리 결과 미확인"}).json()
    eid = closed["experience_id"]
    prepared = api.post(f"/knowledge/golden/experience/{eid}/prepare", json={"expected_experience_rev": 1})
    assert prepared.status_code == 201, prepared.text
    return inv, eid, prepared.json()


def frozen_input(version_id):
    from saw.knowledge import golden
    from saw.knowledge.golden_models import GoldenVersion
    with session_scope() as s:
        row = s.get(GoldenVersion, version_id)
        blobs = golden._verify(s, row)
        return golden.agent_input(row, blobs), blobs


def approve(api, eid, g, split="dev"):
    return api.post(f"/experiences/{eid}/approve", json={"golden": {
        "version_id": g["id"], "expected_content_sha256": g["content_sha256"],
        "decision": "adopt", "split": split, "confirmations": CONFIRM}})


def test_golden_list_starts_empty(analyst):
    response = analyst.get("/knowledge/golden")
    assert response.status_code == 200
    assert response.json() == []


def test_adoption_separates_input_answers_and_preserves_revisions(analyst, manager):
    inv, eid, g = candidate(analyst)
    analyst.post(f"/experiences/{eid}/submit")
    assert approve(manager, eid, g).status_code == 200
    out = manager.post("/knowledge/golden/export", json={
        "version_ids": [g["id"]], "split": "dev", "format": "bundle", "audience": "agent"})
    assert out.status_code == 409 and "external_release_approval_required" in out.text
    agent, blobs = frozen_input(g["id"])
    all_text = json.dumps([agent, blobs])
    assert "EVALUATOR_ONLY_SECRET" not in all_text
    assert "not_collected" in all_text and "120" in all_text
    answers = manager.post("/knowledge/golden/export", json={
        "version_ids": [g["id"]], "split": "dev", "format": "jsonl", "audience": "evaluator", "schema_version": "saw.golden.export.v2", "purpose": "internal_evaluation"})
    assert "EVALUATOR_ONLY_SECRET" in answers.text
    assert json.loads(answers.text)["schema"] == "saw.golden.evaluator-answer.v2"
    assert "golden" not in analyst.get(f"/experiences/{eid}").json()["data"]
    edited = analyst.patch(f"/knowledge/golden/{g['id']}", json={
        "expected_content_sha256": g["content_sha256"], "answers": {
            **g["answers"], "forbidden_claims": ["전부 차단되었다"]}})
    assert edited.status_code == 200, edited.text
    assert edited.json()["status"] == "draft" and edited.json()["version"] == 2
    old = manager.get(f"/knowledge/golden/experience/{eid}").json()["versions"]
    assert next(v for v in old if v["id"] == g["id"])["status"] == "adopted"


def test_no_automatic_adoption_and_unapproved_export_fails(analyst, manager):
    _, eid, g = candidate(analyst)
    analyst.post(f"/experiences/{eid}/submit")
    assert manager.post(f"/experiences/{eid}/approve", json={}).status_code == 200
    exported = manager.post("/knowledge/golden/export", json={
        "version_ids": [g["id"]], "split": "dev", "format": "jsonl", "audience": "agent"})
    assert exported.status_code == 409
    assert manager.post(f"/knowledge/golden/{g['id']}/review", json={
        "expected_content_sha256": g["content_sha256"], "decision": "adopt",
        "split": "dev", "confirmations": CONFIRM}).status_code == 200


def test_source_access_and_self_approval_enforced(app, analyst, senior, manager):
    inv, eid, g = candidate(analyst)
    assert senior.get(f"/knowledge/golden/experience/{eid}").status_code == 403
    analyst.post(f"/experiences/{eid}/submit")
    assert approve(senior, eid, g).status_code == 403
    # A review author is a contributor and cannot later approve their own edited candidate.
    changed = manager.patch(f"/knowledge/golden/{g['id']}", json={
        "expected_content_sha256": g["content_sha256"], "answers": g["answers"]}).json()
    assert approve(manager, eid, changed).status_code == 403
    assert analyst.get(f"/experiences/{eid}").json()["status"] == "review"


def test_missing_tampered_snapshots_and_cutoff_fail_closed(analyst, manager):
    _, eid, g = candidate(analyst)
    analyst.post(f"/experiences/{eid}/submit")
    from saw.knowledge.golden_models import GoldenBlob
    with session_scope() as s:
        blob = s.get(GoldenBlob, g["manifest"][0]["sha256"])
        blob.content = {"tampered": True}
    assert approve(manager, eid, g).status_code == 400
    with session_scope() as s:
        s.delete(s.get(GoldenBlob, g["manifest"][0]["sha256"]))
    assert approve(manager, eid, g).status_code == 400


def test_family_split_cannot_be_bypassed_by_new_case_link(analyst, manager):
    inv1, eid1, g1 = candidate(analyst)
    inv2, eid2, g2 = candidate(analyst, "합성 두 번째")
    for eid in (eid1, eid2):
        analyst.post(f"/experiences/{eid}/submit")
    assert approve(manager, eid1, g1, "train").status_code == 200
    assert approve(manager, eid2, g2, "holdout").status_code == 200
    r = analyst.post("/cases", json={"title": "같은 사건", "investigation_ids": [inv1["id"], inv2["id"]]})
    assert r.status_code == 201, r.text
    from tests.api.test_golden_governance import release_request
    for g, split in ((g1, "train"), (g2, "holdout")):
        exact = next(x for x in manager.get(f"/knowledge/golden/experience/{g['experience_id']}").json()["versions"] if x["id"] == g["id"])
        out = manager.post("/knowledge/golden/releases", json=release_request(manager, exact, split=split))
        assert out.status_code in {400, 409} and "family" in out.text


def test_csv_masks_and_escapes_formula_and_wrong_split(analyst, manager):
    _, eid, g = candidate(analyst, "=HYPERLINK(1)")
    analyst.post(f"/experiences/{eid}/submit")
    assert approve(manager, eid, g, "dev").status_code == 200
    body = {"version_ids": [g["id"]], "split": "dev", "format": "csv", "audience": "evaluator", "schema_version": "saw.golden.export.v2", "purpose": "internal_evaluation"}
    out = manager.post("/knowledge/golden/export", json=body)
    assert out.status_code == 200 and "'=HYPERLINK" in out.text
    body["split"] = "train"
    assert manager.post("/knowledge/golden/export", json=body).status_code == 400

def test_case_a_actual_guidance_to_golden_and_no_fabricated_reviews(analyst, manager):
    from tests.api.test_guidance import make_case, preview, answer_body
    inv = make_case(analyst)
    d = preview(analyst, inv)
    c = analyst.post(f"/investigations/{inv['id']}/checks", json=answer_body(d)).json()
    closed = analyst.post(f"/investigations/{inv['id']}/close", json={
        "verdict": "attack", "reason": "공격 시도; 실제 처리 결과 미확인", "save_experience": True}).json()
    eid = closed["experience_id"]
    exp = analyst.get(f"/experiences/{eid}").json()
    assert exp["data"]["analysis_steps"] and all("check_id" in x for x in exp["data"]["analysis_steps"])
    assert any(x["check_id"] == c["id"] for x in exp["data"]["analysis_steps"])
    prepared = analyst.post(f"/knowledge/golden/experience/{eid}/prepare",
                            json={"expected_experience_rev": exp["rev"]})
    assert prepared.status_code == 201, prepared.text
    g = prepared.json()
    assert g["answers"]["forbidden_claims"] == ["모두 차단됨", "당사 영향 없음"]
    analyst.post(f"/experiences/{eid}/submit")
    response = approve(manager, eid, g)
    assert response.status_code == 200, response.text
    agent, blobs = frozen_input(g["id"])
    facts = {f["id"]: f["value"] for obs in agent["observations"] for f in obs["facts"]}
    assert (facts["events"], facts["blocked"], facts["allowed"]) == (120, 118, 2)
    assert agent["evidence"] and all(x["sha256"] in blobs for x in agent["evidence"])
    assert "forbidden_claims" not in json.dumps(agent)
    assert "공격 시도; 실제 처리 결과 미확인" not in json.dumps(agent, ensure_ascii=False)


def test_masked_input_allowlist_removes_derived_fields_and_preserves_relations(analyst, manager):
    _, eid, _ = candidate(analyst)
    from saw.core.application.provenance import digest
    with session_scope() as s:
        c = s.scalars(select(Check)).first()
        cap = dict(c.context["guidance"])
        ev = {"event_id": "synthetic-event", "timestamp": "2026-10-01T01:02:03Z",
              "src_ip": "198.51.100.8", "dst_ip": "10.0.0.8", "enforcement_action": "allowed",
              "raw_event": "GET /api?token=secret-token-value cookie=session-secret",
              "ext": {"derived_summary": "EVALUATOR_DERIVED_MARKER"},
              "tags": ["EVALUATOR_DERIVED_MARKER"], "analyst_note": "EVALUATOR_DERIVED_MARKER"}
        cap["selected_events"] = [{"event_id": ev["event_id"], "event": ev, "sha256": digest(ev), "known_at": cap["known_at"]}]
        cap["evidence_refs"] = [ev["event_id"]]
        cap["input"] = {**cap["input"], "answers": "EVALUATOR_DERIVED_MARKER"}
        c.context = {"guidance": cap}
    g = analyst.post(f"/knowledge/golden/experience/{eid}/prepare", json={"expected_experience_rev": 1}).json()
    analyst.post(f"/experiences/{eid}/submit")
    assert approve(manager, eid, g).status_code == 200
    agent, blobs = frozen_input(g["id"])
    text = json.dumps([agent, blobs])
    assert "EVALUATOR_DERIVED_MARKER" not in text
    assert "secret-token-value" not in text and "session-secret" not in text
    ev = blobs[agent["evidence"][0]["sha256"]]["event"]
    assert ev["src_ip"] == "198.51.100.8" and ev["dst_ip"] == "10.0.0.8"
    assert ev["timestamp"] == "2026-10-01T01:02:03Z" and ev["enforcement_action"] == "allowed"
    assert analyst.post("/knowledge/golden/export", json={
        "version_ids": [g["id"]], "split": "dev", "format": "jsonl", "audience": "evaluator", "schema_version": "saw.golden.export.v2", "purpose": "internal_evaluation"}).status_code == 403


def test_capture_cutoff_missing_event_snapshot_and_size_limits(analyst):
    _, eid, _ = candidate(analyst)
    with session_scope() as s:
        c = s.scalars(select(Check)).first()
        cap = dict(c.context["guidance"])
        original = json.loads(json.dumps(cap))
        cap["as_of"] = (utcnow() - timedelta(days=1)).isoformat()
        c.context = {"guidance": cap}
    url = f"/knowledge/golden/experience/{eid}/prepare"
    assert analyst.post(url, json={"expected_experience_rev": 1}).status_code == 400
    with session_scope() as s:
        c = s.scalars(select(Check)).first()
        c.context = {"guidance": {**original, "evidence_refs": ["missing-event"]}}
    assert analyst.post(url, json={"expected_experience_rev": 1}).status_code == 400
    with session_scope() as s:
        c = s.scalars(select(Check)).first()
        c.context = {"guidance": {**original, "input": {**original["input"], "limits": ["x" * 300000]}}}
    assert analyst.post(url, json={"expected_experience_rev": 1}).status_code == 400


def test_family_membership_survives_case_unlink_and_blobs_deduplicate(analyst, manager):
    inv1, eid1, g1 = candidate(analyst)
    inv2, eid2, g2 = candidate(analyst)
    case = analyst.post("/cases", json={"title": "same event", "investigation_ids": [inv1["id"], inv2["id"]]}).json()
    analyst.post(f"/experiences/{eid1}/submit")
    assert approve(manager, eid1, g1, "train").status_code == 200
    from saw.storage.models import Case
    from saw.knowledge.golden_models import GoldenBlob
    with session_scope() as s:
        s.get(Case, case["id"]).investigation_ids = []
        before = len(s.scalars(select(GoldenBlob)).all())
    analyst.post(f"/knowledge/golden/experience/{eid2}/prepare", json={"expected_experience_rev": 1})
    with session_scope() as s:
        assert len(s.scalars(select(GoldenBlob)).all()) == before
    analyst.post(f"/experiences/{eid2}/submit")
    denied = approve(manager, eid2, g2, "holdout")
    assert denied.status_code == 400 and "family" in denied.text
    assert analyst.get(f"/experiences/{eid2}").json()["status"] == "review"


def test_reviewer_confirmation_stale_revision_and_no_live_retrieval(analyst, manager):
    _, eid, g = candidate(analyst)
    analyst.post(f"/experiences/{eid}/submit")
    request = {"golden": {"version_id": g["id"], "expected_content_sha256": g["content_sha256"],
                         "decision": "adopt", "split": "dev", "confirmations": {}}}
    assert manager.post(f"/experiences/{eid}/approve", json=request).status_code == 400
    assert analyst.get(f"/experiences/{eid}").json()["status"] == "review"
    analyst.patch(f"/experiences/{eid}", json={"data": {"reason": "new revision"}})
    analyst.post(f"/experiences/{eid}/submit")
    assert approve(manager, eid, g).status_code == 400
    assert manager.post("/knowledge/golden/export", json={
        "version_ids": [g["id"]], "split": "dev", "format": "jsonl", "audience": "agent",
        "live_retrieval": True}).status_code == 422

def test_reviewer_cannot_change_judgement_during_adoption(analyst, manager):
    _, eid, g = candidate(analyst)
    analyst.post(f"/experiences/{eid}/submit")
    payload = {"golden": {"version_id": g["id"], "expected_content_sha256": g["content_sha256"],
        "decision": "adopt", "split": "dev", "confirmations": CONFIRM,
        "review_answers": {"judgement": {**g["answers"]["judgement"], "impact": "침해 성공"}}}}
    denied = manager.post(f"/experiences/{eid}/approve", json=payload)
    assert denied.status_code == 400 and "judgement" in denied.text
    assert analyst.get(f"/experiences/{eid}").json()["status"] == "review"
    payload["golden"]["review_answers"] = {"forbidden_claims": ["전부 차단이라고 단정하지 않는다"]}
    assert manager.post(f"/experiences/{eid}/approve", json=payload).status_code == 200


def test_edit_cannot_rebind_stale_answers_to_new_experience_revision(analyst):
    _, eid, g = candidate(analyst)
    analyst.patch(f"/experiences/{eid}", json={"data": {"reason": "different new assessment"}})
    denied = analyst.patch(f"/knowledge/golden/{g['id']}", json={
        "expected_content_sha256": g["content_sha256"], "answers": g["answers"]})
    assert denied.status_code == 400 and "prepare" in denied.text

def test_case_item_link_without_investigation_array_still_blocks_split(analyst, manager):
    inv1, eid1, g1 = candidate(analyst)
    inv2, eid2, g2 = candidate(analyst)
    for eid in (eid1, eid2):
        analyst.post(f"/experiences/{eid}/submit")
    assert approve(manager, eid1, g1, "train").status_code == 200
    assert approve(manager, eid2, g2, "holdout").status_code == 200
    from saw import container
    container.get().events.index([{"event_id": "linked-event", "investigation_id": inv2["id"],
        "timestamp": "2026-10-01T01:00:00Z", "data_source": "synthetic", "src_ip": "198.51.100.9"}])
    case = analyst.post("/cases", json={"title": "case item link", "investigation_ids": [inv1["id"]]}).json()
    added = analyst.post(f"/cases/{case['id']}/items", json={
        "item_type": "event_ref", "ref_id": "linked-event", "investigation_id": inv2["id"]})
    assert added.status_code == 201, added.text
    from tests.api.test_golden_governance import release_request
    exact = next(x for x in manager.get(f"/knowledge/golden/experience/{eid1}").json()["versions"] if x["id"] == g1["id"])
    out = manager.post("/knowledge/golden/releases", json=release_request(manager, exact, split="train"))
    assert out.status_code in {400, 409} and "family" in out.text


def test_missing_approved_snapshot_is_shown_as_not_evaluable(analyst, manager):
    _, eid, g = candidate(analyst)
    analyst.post(f"/experiences/{eid}/submit")
    assert approve(manager, eid, g).status_code == 200
    from saw.knowledge.golden_models import GoldenBlob
    with session_scope() as s:
        s.delete(s.get(GoldenBlob, g["manifest"][0]["sha256"]))
    row = next(x for x in manager.get("/knowledge/golden").json() if x["id"] == g["id"])
    assert row["evaluable"] is False and row["evaluation_blocker"] == "golden_snapshot_missing"


def test_prepare_keeps_experience_closure_after_other_reviewer_recloses(analyst, manager):
    inv, eid, _ = candidate(analyst)
    original = analyst.get(f"/experiences/{eid}").json()["data"]
    later = manager.post(f"/investigations/{inv['id']}/close", json={
        "verdict": "unknown", "reason": "Synthetic later closure",
        "impact_assessment": "SYNTHETIC_REVIEWER_SELF_AUTHORED_IMPACT",
        "limits": "SYNTHETIC_LATER_LIMIT", "save_experience": False})
    assert later.status_code == 200, later.text
    prepared = analyst.post(f"/knowledge/golden/experience/{eid}/prepare",
                            json={"expected_experience_rev": 1})
    assert prepared.status_code == 201, prepared.text
    g = prepared.json()
    assert g["answers"]["judgement"]["impact"] == original["impact_assessment"]
    assert g["answers"]["limits"] == original["limits"]
    assert "SYNTHETIC_REVIEWER_SELF_AUTHORED_IMPACT" not in json.dumps(g["answers"])
    analyst.post(f"/experiences/{eid}/submit")
    assert approve(manager, eid, g).status_code == 200


def test_empty_default_followups_require_explicit_reviewed_reason(analyst, manager):
    inv = analyst.post("/investigations", json={"title": "Synthetic no applicable material"}).json()
    check = analyst.post(f"/investigations/{inv['id']}/checks", json={
        "target_type": "set", "target_key": inv["id"], "judgement": "undetermined",
        "note": "Synthetic not applicable", "guidance": {
            "rule_id": "F", "scope": {"target_type": "investigation", "target_key": inv["id"]},
            "answer_status": "not_applicable", "answer": "Synthetic not applicable"}})
    assert check.status_code == 201, check.text
    closed = analyst.post(f"/investigations/{inv['id']}/close", json={
        "verdict": "unknown", "reason": "Synthetic material is not applicable", "save_experience": True}).json()
    eid = closed["experience_id"]
    prepared = analyst.post(f"/knowledge/golden/experience/{eid}/prepare", json={"expected_experience_rev": 1})
    assert prepared.status_code == 201, prepared.text
    g = prepared.json()
    assert g["answers"]["followups"] == []
    analyst.post(f"/experiences/{eid}/submit")
    denied = approve(manager, eid, g)
    assert denied.status_code == 400 and "followups" in denied.text
    assert analyst.get(f"/experiences/{eid}").json()["status"] == "review"
    reviewed = manager.post(f"/experiences/{eid}/approve", json={"golden": {
        "version_id": g["id"], "expected_content_sha256": g["content_sha256"],
        "decision": "adopt", "split": "dev", "confirmations": CONFIRM,
        "review_answers": {"no_followups_reason": "Synthetic review confirms no applicable follow-up"}}})
    assert reviewed.status_code == 200, reviewed.text


def test_review_does_not_accept_priority_or_blank_text_as_followup(analyst, manager):
    _, eid, g = candidate(analyst)
    analyst.post(f"/experiences/{eid}/submit")
    for empty in ([{"target": "", "needed_data": [], "items": [], "priority": "normal"}],
                  ["   "], [{"target": "Synthetic team", "items": [" "]}]):
        denied = manager.post(f"/experiences/{eid}/approve", json={"golden": {
            "version_id": g["id"], "expected_content_sha256": g["content_sha256"],
            "decision": "adopt", "split": "dev", "confirmations": CONFIRM,
            "review_answers": {"followups": empty, "no_followups_reason": ""}}})
        assert denied.status_code == 400 and "followups" in denied.text
        assert analyst.get(f"/experiences/{eid}").json()["status"] == "review"
