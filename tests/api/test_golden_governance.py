"""P4 exact capture and governance; synthetic fixtures only."""
from copy import deepcopy
from datetime import timedelta

from saw.storage.db import session_scope, utcnow
from saw.storage.models import Check
from tests.api.test_golden import candidate, CONFIRM


def adopted_candidate(analyst, manager, *, split="dev", v2=False):
    inv, eid, g = candidate(analyst)
    if v2:
        response = analyst.post(f"/knowledge/golden/experience/{eid}/prepare", json={
            "expected_experience_rev": 1, "schema_version": "saw.golden.v2"})
        assert response.status_code == 201, response.text
        g = response.json()
        answer = deepcopy(g["answers"])
        answer["investigation_truth"]["no_followups_reason"] = "Synthetic observation requires no additional fixture work."
        response = analyst.patch(f"/knowledge/golden/{g['id']}", json={
            "expected_content_sha256": g["content_sha256"], "answers": answer})
        assert response.status_code == 200, response.text
        g = response.json()
    analyst.post(f"/experiences/{eid}/submit")
    assert manager.post(f"/experiences/{eid}/approve", json={}).status_code == 200
    response = manager.post(f"/knowledge/golden/{g['id']}/review", json={
        "expected_content_sha256": g["content_sha256"], "decision": "adopt",
        "split": split, "confirmations": CONFIRM})
    assert response.status_code == 200, response.text
    return inv, eid, response.json()


def release_request(api, golden, *, split="dev", key="synthetic-release-1"):
    profiles = {}
    for kind in ("pseudonymization", "model_conversion"):
        response = api.get(f"/knowledge/golden/profiles?kind={kind}")
        assert response.status_code == 200, response.text
        profiles[kind] = response.json()["items"][0]
    selector = "input_sha256" if split == "holdout" else "content_sha256"
    return {
        "schema_version": "saw.golden.release.v2", "expected_current_version_id": None,
        "idempotency_key": key, "purpose": {"dev": "external_development", "train": "external_training",
            "holdout": "external_evaluation"}[split], "purpose_text": "Synthetic fixture",
        "recipient": {"name": "Synthetic receiver", "organization": "Synthetic lab"},
        "usage_conditions": ["Synthetic testing only"],
        "expires_at": (utcnow() + timedelta(days=1)).isoformat(),
        "examples": [{"version_id": golden["id"], selector: golden[selector]}],
        "split": split, "artifact_kind": "holdout_input" if split == "holdout" else split,
        "projection": "v2" if golden.get("schema_version") == "saw.golden.v2" else "v1",
        "pseudonymization_profile": {"id": profiles["pseudonymization"]["id"],
            "sha256": profiles["pseudonymization"]["payload_sha256"]},
        "model_conversion_profile": {"id": profiles["model_conversion"]["id"],
            "sha256": profiles["model_conversion"]["payload_sha256"]},
        "redistribution": {"confirmed": True, "basis": "New synthetic fixture"},
        "applicability_request": {"mode": "interpretation_only", "complete_scopes": []},
    }


def test_new_experience_pins_exact_check_revision_and_v2_rejects_changed_check(analyst):
    _, eid, _ = candidate(analyst)
    experience = analyst.get(f"/experiences/{eid}").json()
    pins = experience["data"].get("golden_capture")
    assert pins and pins["check_revisions"]
    ref = pins["check_revisions"][0]
    good = analyst.post(f"/knowledge/golden/experience/{eid}/prepare", json={
        "expected_experience_rev": 1, "schema_version": "saw.golden.v2",
        "check_revision_ids": [ref["revision_id"]]})
    assert good.status_code == 201, good.text
    assert good.json()["schema_version"] == "saw.golden.v2"
    assert good.json()["answers"]["detection_truth"]["status"] == "not_labeled"
    with session_scope() as s:
        c = s.get(Check, ref["check_id"])
        c.note = "Later changed record"
    stale = analyst.post(f"/knowledge/golden/experience/{eid}/prepare", json={
        "expected_experience_rev": 1, "schema_version": "saw.golden.v2"})
    assert stale.status_code == 409 and "changed" in stale.text
    assert analyst.get(f"/experiences/{eid}").json()["data"]["golden_capture"] == pins


def test_profile_registry_is_exact_and_rejects_unbounded_implementation(analyst):
    response = analyst.get("/knowledge/golden/profiles?kind=pseudonymization")
    assert response.status_code == 200, response.text
    profile = response.json()["items"][0]
    body = {"kind": "pseudonymization", "profile_key": "synthetic", "expected_latest_id": None,
        "implementation": profile["implementation"], "payload": profile["payload"]}
    made = analyst.post("/knowledge/golden/profiles", json=body)
    assert made.status_code == 201, made.text
    assert analyst.post("/knowledge/golden/profiles", json=body).status_code == 409
    body["expected_latest_id"] = made.json()["id"]
    body["payload"] = {**body["payload"], "expression": "__import__('os')"}
    assert analyst.post("/knowledge/golden/profiles", json=body).status_code in (400, 422)


def test_direct_external_export_requires_release_approval(analyst, manager):
    _, _, g = adopted_candidate(analyst, manager)
    response = analyst.post("/knowledge/golden/export", json={
        "version_ids": [g["id"]], "split": "dev", "format": "jsonl", "audience": "agent"})
    assert response.status_code == 409 and "external_release_approval_required" in response.text


def test_adopted_holdout_ordinary_dto_hides_answer_derived_metadata(analyst, manager):
    _, eid, g = adopted_candidate(analyst, manager, split="holdout", v2=True)
    assert "input_sha256" in g and len(g["input_sha256"]) == 64
    all_versions = analyst.get(f"/knowledge/golden/experience/{eid}").json()["versions"]
    assert len(all_versions) >= 3
    for data in [g, *manager.get("/knowledge/golden").json(), *all_versions]:
        assert not {"title", "category", "verdict", "answers", "content_sha256"} & data.keys()
        assert data["answers_access"] == {"available": False, "requires_holdout_attempt": True}
        assert data["can_edit"] is False and data["can_review"] is False


def test_holdout_experience_and_similarity_do_not_bypass_tracked_truth(analyst, manager):
    _, eid, _ = adopted_candidate(analyst, manager, split="holdout", v2=True)
    for path in (f"/experiences/{eid}", f"/experiences/{eid}/revisions", "/experiences?q=EVALUATOR_ONLY_SECRET"):
        response = manager.get(path)
        assert response.status_code == 200, response.text
        assert "EVALUATOR_ONLY_SECRET" not in response.text
    result = manager.post("/similar/search", json={"text": "EVALUATOR_ONLY_SECRET"})
    assert result.status_code == 200
    assert "EVALUATOR_ONLY_SECRET" not in result.text


def test_v2_truth_axes_and_all_unit_kinds_are_exact_and_truth_author_cannot_adopt(analyst, manager):
    from saw.core.application.provenance import digest
    from saw.detection.truth_models import DetectionCase, DetectionCaseVersion
    from saw.storage.models import User
    from sqlalchemy import select
    inv, eid, _ = candidate(analyst)
    units = [{"unit_id": kind, "unit_kind": kind, "event_ids": [], "filters": [], "time": None,
        "detection_truth": "expected_match", "investigation_truth": "approved_activity",
        "basis": "Synthetic approved activity still matches."} for kind in ("event", "window", "entity", "sequence")]
    with session_scope() as s:
        author = s.scalar(select(User).where(User.username == "manager1"))
        case = DetectionCase(investigation_id=inv["id"], current_version=1, created_by=author.id)
        s.add(case)
        s.flush()
        payload = {"title": "Synthetic truth", "investigation_id": inv["id"], "units": units, "filters": [], "time": None}
        version = DetectionCaseVersion(case_id=case.id, version=1, investigation_id=inv["id"],
            payload=payload, sha256=digest(payload), source_manifest={}, input_sha256="a" * 64,
            input_count=0, contributor_ids=[author.id], created_by=author.id)
        s.add(version)
        s.flush()
        tid = version.id
    made = analyst.post(f"/knowledge/golden/experience/{eid}/prepare", json={
        "expected_experience_rev": 1, "schema_version": "saw.golden.v2", "truth_case_version_ids": [tid]})
    assert made.status_code == 201, made.text
    g = made.json()
    assert g["answers"]["detection_truth"]["units"] == [{**unit, "case_version_id": tid} for unit in units]
    changed = deepcopy(g["answers"])
    changed["detection_truth"]["units"][0]["investigation_truth"] = "attack"
    assert analyst.patch(f"/knowledge/golden/{g['id']}", json={"expected_content_sha256": g["content_sha256"],
        "answers": changed}).status_code == 400
    analyst.post(f"/experiences/{eid}/submit")
    assert manager.post(f"/experiences/{eid}/approve", json={}).status_code == 200
    denied = manager.post(f"/knowledge/golden/{g['id']}/review", json={
        "expected_content_sha256": g["content_sha256"], "decision": "adopt", "split": "dev", "confirmations": CONFIRM})
    assert denied.status_code == 403


def test_v2_old_unpinned_experience_and_boolean_revision_are_rejected(analyst):
    from saw.knowledge.models import Experience
    _, eid, _ = candidate(analyst)
    with session_scope() as s:
        e = s.get(Experience, eid)
        e.data = {k: v for k, v in e.data.items() if k != "golden_capture"}
    endpoint = f"/knowledge/golden/experience/{eid}/prepare"
    assert analyst.post(endpoint, json={"expected_experience_rev": True}).status_code == 422
    response = analyst.post(endpoint, json={"expected_experience_rev": 1, "schema_version": "saw.golden.v2"})
    assert response.status_code == 409 and "historic_pin_missing" in response.text


def test_v2_adoption_rejects_corrupted_exact_check_revision(analyst, manager):
    from sqlalchemy import update
    from saw.followups.models import CheckRevision
    _, eid, _ = candidate(analyst)
    made = analyst.post(f"/knowledge/golden/experience/{eid}/prepare", json={
        "expected_experience_rev": 1, "schema_version": "saw.golden.v2"}).json()
    edited = deepcopy(made["answers"])
    edited["investigation_truth"]["no_followups_reason"] = "Synthetic fixture"
    made = analyst.patch(f"/knowledge/golden/{made['id']}", json={
        "expected_content_sha256": made["content_sha256"], "answers": edited}).json()
    analyst.post(f"/experiences/{eid}/submit")
    manager.post(f"/experiences/{eid}/approve", json={})
    ref = made["answers"]["analyst_records"][0]
    with session_scope() as s:
        s.execute(update(CheckRevision).where(CheckRevision.id == ref["revision_id"]).values(payload={"tampered": True}))
    response = manager.post(f"/knowledge/golden/{made['id']}/review", json={
        "expected_content_sha256": made["content_sha256"], "decision": "adopt", "split": "dev", "confirmations": CONFIRM})
    assert response.status_code == 409, response.text


def test_v2_followup_exact_records_and_later_fact_evidence_stay_answer_only(analyst):
    from saw import container
    from sqlalchemy import select
    from tests.api.test_followups import create
    from saw.knowledge.golden_models import GoldenBlob
    from saw.storage.models import Check
    from saw.knowledge.golden_projection import input_graph_sha256
    inv, eid, _ = candidate(analyst)
    with session_scope() as s:
        check_id = s.scalar(select(Check.id).where(Check.investigation_id == inv["id"]))
    url = f"/investigations/{inv['id']}/follow-ups"
    fu = create(analyst, url, {"id": check_id})
    event = {"event_id": "late-confirmation", "investigation_id": inv["id"],
        "timestamp": "2026-10-01T01:00:00Z", "src_ip": "198.51.100.8", "data_source": "synthetic"}
    container.get().events.index([event])
    evidence = [{"investigation_id": inv["id"], "event_id": event["event_id"]}]
    reply = analyst.post(f"{url}/{fu['id']}/reply", json={"expected_version_id": fu["current"]["id"],
        "reason": "Synthetic reply", "note": "Application checked", "evidence": evidence}).json()
    verified = analyst.post(f"{url}/{fu['id']}/verify", json={"expected_version_id": reply["current"]["id"],
        "reason": "Synthetic verification", "outcome": "confirmed",
        "basis": "LATER_ANSWER_ONLY_FACT", "evidence": evidence})
    assert verified.status_code == 200, verified.text
    exact = verified.json()["current"]
    revision = analyst.patch(f"/experiences/{eid}", json={"data": {"reason": "New exact closure"}}).json()["rev"]
    made = analyst.post(f"/knowledge/golden/experience/{eid}/prepare", json={
        "expected_experience_rev": revision, "schema_version": "saw.golden.v2"})
    assert made.status_code == 201, made.text
    golden = made.json()
    records = golden["answers"]["investigation_truth"]["followups"]
    record = next(x for x in records if isinstance(x, dict) and x.get("version_id") == exact["id"])
    assert record["payload"] == exact["payload"]
    later = golden["answers"]["later_confirmed_facts"][0]
    assert later["fact"] == "LATER_ANSWER_ONLY_FACT" and later["evidence_refs"]
    with session_scope() as s:
        blobs = {m["sha256"]: s.get(GoldenBlob, m["sha256"]).content for m in golden["manifest"]}
    assert all(blobs[sha]["schema"] == "saw.golden.event.v2" for sha in later["evidence_refs"])
    assert not set(later["evidence_refs"]) & set(golden["input"]["evidence"])
    input_only = {sha: val for sha, val in blobs.items() if sha not in later["evidence_refs"]}
    assert input_graph_sha256(golden["input"], blobs) == input_graph_sha256(golden["input"], input_only)


def test_reused_check_citation_merges_family_but_generic_policy_sources_do_not(analyst, manager):
    from sqlalchemy import select
    from saw.storage.models import Check
    from saw.knowledge import golden
    from tests.api.test_golden import approve
    inv1, eid1, first = candidate(analyst)
    inv2, eid2, second = candidate(analyst)
    analyst.post(f"/experiences/{eid1}/submit")
    assert approve(manager, eid1, first, "train").status_code == 200
    with session_scope() as s:
        original = s.scalar(select(Check).where(Check.investigation_id == inv1["id"]))
        copied = s.scalar(select(Check).where(Check.investigation_id == inv2["id"]))
        copied.context = {**copied.context, "policy": {"source_investigation_ids": [inv1["id"]]}}
    with session_scope() as s:
        assert golden._component(s, inv2["id"])[0] == {inv2["id"]}
        original = s.scalar(select(Check).where(Check.investigation_id == inv1["id"]))
        copied = s.scalar(select(Check).where(Check.investigation_id == inv2["id"]))
        copied.kind, copied.source_check_id = "cited", original.id
    analyst.post(f"/experiences/{eid2}/submit")
    denied = approve(manager, eid2, second, "holdout")
    assert denied.status_code in {400, 409} and "family" in denied.text


def test_selected_check_rejects_another_finished_run_with_different_scope(analyst):
    from sqlalchemy import select
    from saw.analysis_runs.models import AnalysisRun
    from saw.core.application.provenance import digest
    inv, eid, _ = candidate(analyst)
    with session_scope() as s:
        original = s.scalar(select(Check).where(Check.investigation_id == inv["id"]))
        capture = deepcopy(original.context["guidance"])
        capture["scope"]["target_key"] = "ip:198.51.100.99"
        capture["scope"]["time"] = {"start": "2026-09-01T00:00:00Z", "end": "2026-09-02T00:00:00Z"}
        capture["scope"]["effective_time"] = capture["scope"]["time"]
        capture["input"]["request"] = deepcopy(capture["scope"])
        copied = Check(investigation_id=inv["id"], target_type="entity", target_key="ip:198.51.100.99",
            questions=original.questions, judgement=original.judgement, note="Unrelated target",
            scope=deepcopy(original.scope), context={"guidance": capture},
            author_id=original.author_id, author_name=original.author_name, evidence=[])
        s.add(copied)
        s.flush()
        first_id, second_id = original.id, copied.id
        run_ids = []
        for i, ip, window in ((1, "198.51.100.8", None), (2, "198.51.100.99", capture["scope"]["time"])):
            row = AnalysisRun(investigation_id=inv["id"], version=i, created_by=original.author_id,
                input_manifest={}, input_sha256=digest({}), status="complete",
                scope={"filters": [{"field": "src_ip", "op": "is", "value": ip}], "time": window},
                finished_at=utcnow() - timedelta(days=2))
            s.add(row)
            s.flush()
            run_ids.append(row.id)
    updated = analyst.patch(f"/experiences/{eid}", json={"data": {"check_ids": [first_id, second_id]}})
    assert updated.status_code == 200, updated.text
    exp = updated.json()
    assert {r["id"] for r in exp["data"]["golden_capture"]["analysis_runs"]} == set(run_ids)
    endpoint = f"/knowledge/golden/experience/{eid}/prepare"
    body = {"expected_experience_rev": exp["rev"], "schema_version": "saw.golden.v2", "check_ids": [first_id]}
    wrong = analyst.post(endpoint, json={**body, "analysis_run_id": run_ids[1]})
    assert wrong.status_code == 409, wrong.text
    correct = analyst.post(endpoint, json={**body, "analysis_run_id": run_ids[0]})
    assert correct.status_code == 201, correct.text
    assert correct.json()["input"]["versions"]["analysis_run"]["id"] == run_ids[0]


def test_p2_matching_semantics_are_frozen_and_evaluator_does_not_invent_them(analyst, manager):
    import json
    from saw import container
    from saw.core.application.provenance import digest
    from saw.detection import testing
    inv, eid, _ = candidate(analyst)
    container.get().events.index([{"event_id": "semantics-event", "investigation_id": inv["id"],
        "timestamp": "2026-10-01T01:00:00Z", "src_ip": "198.51.100.8", "data_source": "synthetic"}])
    unit = {"unit_id": "event-unit", "unit_kind": "event", "event_ids": ["semantics-event"], "filters": [],
        "time": None, "detection_truth": "expected_match", "investigation_truth": "approved_activity", "basis": "Actual P2 unit"}
    created = analyst.post("/detection-cases", json={"title": "Actual P2 semantics", "investigation_id": inv["id"],
        "filters": [], "time": None, "units": [unit]})
    assert created.status_code == 201, created.text
    truth = created.json()
    made = analyst.post(f"/knowledge/golden/experience/{eid}/prepare", json={
        "expected_experience_rev": 1, "schema_version": "saw.golden.v2", "truth_case_version_ids": [truth["id"]]})
    assert made.status_code == 201, made.text
    golden = made.json()
    matching = golden["answers"]["detection_truth"]["matching_policy"]
    assert matching.get("method") == "selected_truth_v1", matching
    assert matching["definition_sha256"] == digest(matching["definition"])
    assert matching["definition"]["engines"]["device_policy"]["supported_units"] == ["window"]
    assert matching["definition"]["scoring"]["axis"] == "detection_truth"
    assert matching["definition"]["duplicate_policy"]["key"] == ["case_version_id", "unit_id"]
    assert matching["case_scopes"][0]["case_version_id"] == truth["id"]
    metrics = testing.metrics([{**unit, "status": "complete", "prediction": True},
        {**unit, "unit_id": "unsupported", "status": "unsupported_unit", "prediction": None}])
    assert metrics["tp"] == 1 and metrics["labeled"] == 1 and metrics["tn"] == 0
    from time import monotonic
    from saw.detection.truth_models import DetectionCaseVersion
    with session_scope() as s:
        exact_payload = deepcopy(s.get(DetectionCaseVersion, truth["id"]).payload)
    evaluated = testing._policy_case({"policy": {"exclusions": [], "values": {"enabled": False}},
        "spec": {"id": "fw.observation"}}, exact_payload,
        [{**unit, "unit_id": "window", "unit_kind": "window", "event_ids": []},
         {**unit, "unit_id": "entity", "unit_kind": "entity", "event_ids": []}], monotonic() + 10)
    assert evaluated["window"]["status"] == "complete" and evaluated["window"]["prediction"] is False
    assert evaluated["window"]["input_count"] == 1
    assert evaluated["entity"]["status"] == "unsupported_unit" and evaluated["entity"]["prediction"] is None
    analyst.post(f"/experiences/{eid}/submit")
    assert manager.post(f"/experiences/{eid}/approve", json={}).status_code == 200
    adopted = manager.post(f"/knowledge/golden/{golden['id']}/review", json={
        "expected_content_sha256": golden["content_sha256"], "decision": "adopt", "split": "dev", "confirmations": CONFIRM})
    assert adopted.status_code == 200, adopted.text
    exported = manager.post("/knowledge/golden/export", json={"version_ids": [golden["id"]], "split": "dev",
        "format": "jsonl", "audience": "evaluator", "schema_version": "saw.golden.export.v2", "purpose": "internal_evaluation"})
    assert exported.status_code == 200, exported.text
    assert json.loads(exported.text)["answers"]["detection_truth"]["matching_policy"] == matching
    import pytest
    from fastapi import HTTPException
    from saw.knowledge import golden as service
    from saw.knowledge.golden_models import GoldenVersion
    with session_scope() as s:
        row = s.get(GoldenVersion, golden["id"])
        changed = deepcopy(row.answers)
        changed["detection_truth"]["matching_policy"]["definition"]["version"] = "unknown-semantics"
        row.answers = changed
        service._seal(row)
        with pytest.raises(HTTPException, match="golden_matching_policy_changed_or_unsupported"):
            service._verify(s, row)
        s.rollback()
