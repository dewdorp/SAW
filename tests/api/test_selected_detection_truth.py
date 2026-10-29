"""Selected-unit truth never reuses an investigation verdict as a detection label."""
from __future__ import annotations

import pytest
from sqlalchemy import select
from saw import container
from saw.core.application.identity import principal_of
from saw.detection import testing
from saw.storage.db import session_scope
from saw.storage.models import User

RULE = "title: Synthetic selected rule\nlogsource: {category: webserver}\ndetection:\n  s:\n    sc-status: 403\n  condition: s\nlevel: low\n"


def setup_case(api, *, units=None, rows=None):
    inv = api.post("/investigations", json={"title": "Synthetic selected truth"}).json()
    rows = rows if rows is not None else [
        {"event_id": "hit", "status_code": 403, "src_ip": "192.0.2.1"},
        {"event_id": "ok", "status_code": 200, "src_ip": "192.0.2.1"},
        {"event_id": "unknown", "src_ip": "192.0.2.1"},
    ]
    container.get().events.index([{**row, "investigation_id": inv["id"], "data_source": "web",
                                  "timestamp": "2026-10-20T00:00:00Z"} for row in rows])
    body = {"title": "Synthetic reviewed examples", "investigation_id": inv["id"],
            "units": units or [
                {"unit_id": "hit", "unit_kind": "event", "event_ids": ["hit"],
                 "detection_truth": "expected_match", "investigation_truth": "attempt", "basis": "Blocked request matches this rule"},
                {"unit_id": "ok", "unit_kind": "event", "event_ids": ["ok"],
                 "detection_truth": "expected_no_match", "investigation_truth": "normal", "basis": "Ordinary request"},
            ]}
    result = api.post("/detection-cases", json=body)
    assert result.status_code == 201, result.text
    return inv, body, result.json()


def rule(api, **extra):
    r = api.post("/detections", json={"title": "Synthetic", "logic": RULE, **extra})
    assert r.status_code == 201, r.text
    return r.json()


def test_case_versions_are_immutable_and_scoped(analyst, senior):
    inv, body, case = setup_case(analyst)
    assert case["version"] == 1 and len(case["sha256"]) == 64
    body["units"][0]["detection_truth"] = "unlabeled"
    changed = analyst.post(f"/detection-cases/{case['case_id']}/versions", json=body)
    assert changed.status_code == 201, changed.text
    assert changed.json()["version"] == 2
    old = analyst.get(f"/detection-cases/versions/{case['id']}").json()
    assert old["units"][0]["detection_truth"] == "expected_match"
    with session_scope() as s:
        from saw.detection.truth_models import DetectionCaseVersion
        row = s.get(DetectionCaseVersion, case["id"])
        row.payload = {**row.payload, "title": "mutated"}
        with pytest.raises(ValueError, match="immutable"):
            s.flush()
        s.rollback()


def run_selected(api, d, case, units=None, **extra):
    ref = d["pointers"]["draft"]
    return api.post(f"/detections/{d['id']}/test", json={
        "method": "selected_truth_v1", "version_id": ref["id"], "payload_sha256": ref["payload_sha256"],
        "context_scope": {"kind": "group"},
        "units": [{"case_version_id": case["id"], "unit_id": u["unit_id"]} for u in (units or case["units"])], **extra})


def test_selected_truth_uses_units_and_separate_investigation_truth(analyst):
    _, _, case = setup_case(analyst)
    d = rule(analyst)
    response = run_selected(analyst, d, case)
    assert response.status_code == 200, response.text
    t = response.json()
    assert t["passed"] and t["scope"]["method"] == "selected_truth_v1"
    assert t["result"]["metrics"] == {
        "tp": 1, "fp": 0, "fn": 0, "tn": 1, "labeled": 2, "unlabeled": 0,
        "precision": {"numerator": 1, "denominator": 1, "value": 1.0},
        "recall": {"numerator": 1, "denominator": 1, "value": 1.0}}
    assert t["result"]["units"][0]["investigation_truth"] == "attempt"
    assert t["proof"]["status"] == "complete"
    assert analyst.get(f"/detections/{d['id']}").json()["test_runs"][0]["proof"]["proof_sha256"] == t["proof"]["proof_sha256"]


def test_missing_and_unlabeled_do_not_become_true_negatives(analyst):
    units = [
        {"unit_id": "missing", "unit_kind": "event", "event_ids": ["unknown"],
         "detection_truth": "expected_no_match", "investigation_truth": "insufficient_data", "basis": "Missing status"},
        {"unit_id": "unlabeled", "unit_kind": "event", "event_ids": ["ok"],
         "detection_truth": "unlabeled", "investigation_truth": "undetermined", "basis": "Pending review"}]
    _, _, case = setup_case(analyst, units=units)
    r = run_selected(analyst, rule(analyst), case)
    assert r.status_code == 200, r.text
    t = r.json()
    assert not t["passed"] and t["proof"] is None
    assert t["result"]["metrics"]["tn"] == 0
    assert t["result"]["metrics"]["unlabeled"] == 1
    assert t["result"]["metrics"]["precision"]["value"] is None
    assert t["result"]["units"][0]["status"] == "insufficient_data"


def test_threshold_evaluates_case_context_before_projecting_event_unit(analyst):
    units = [{"unit_id": "one", "unit_kind": "event", "event_ids": ["a"],
              "detection_truth": "expected_match", "investigation_truth": "attempt", "basis": "Part of a two-hit window"}]
    _, _, case = setup_case(analyst, units=units, rows=[
        {"event_id": "a", "status_code": 403, "src_ip": "192.0.2.9"},
        {"event_id": "b", "status_code": 403, "src_ip": "192.0.2.9"}])
    d = rule(analyst, threshold={"group_by": ["src_ip"], "timespan_sec": 60, "count_gte": 2})
    r = run_selected(analyst, d, case)
    assert r.status_code == 200, r.text
    assert r.json()["passed"]
    assert r.json()["result"]["units"][0]["matching_event_ids"] == ["a"]


def test_truth_revision_and_input_change_invalidate_old_proof(analyst):
    inv, body, case = setup_case(analyst)
    d = rule(analyst)
    r = run_selected(analyst, d, case)
    assert r.status_code == 200, r.text
    assert r.json()["proof"]
    body["title"] = "A new review"
    assert analyst.post(f"/detection-cases/{case['case_id']}/versions", json=body).status_code == 201
    current = analyst.get(f"/detections/{d['id']}").json()
    assert current["test_runs"][0]["proof"] is None
    failed = run_selected(analyst, d, case)
    assert failed.status_code == 409


def test_case_without_selection_and_sequence_unit_cannot_authorize(analyst):
    _, _, case = setup_case(analyst, units=[{
        "unit_id": "seq", "unit_kind": "sequence", "event_ids": ["hit", "ok"],
        "detection_truth": "expected_match", "investigation_truth": "attempt", "basis": "Requires ordering"}])
    r = run_selected(analyst, rule(analyst), case)
    assert r.status_code == 200, r.text
    assert r.json()["result"]["units"][0]["status"] == "unsupported_unit"
    assert not r.json()["passed"]
    invalid = analyst.post("/detection-cases", json={"title": "Empty", "investigation_id": case["investigation_id"], "units": []})
    assert invalid.status_code == 422


def test_source_acl_hides_case_and_saved_proof(analyst, senior):
    from sqlalchemy import delete
    from saw.storage.models import InvestigationMember
    inv, _, case = setup_case(analyst)
    d = rule(analyst)
    assert run_selected(analyst, d, case).json()["proof"]
    with session_scope() as s:
        uid = s.scalar(select(User.id).where(User.username == "analyst1"))
        s.execute(delete(InvestigationMember).where(InvestigationMember.investigation_id == inv["id"], InvestigationMember.user_id == uid))
    assert analyst.get(f"/detection-cases/versions/{case['id']}").status_code in (403, 404)
    data = analyst.get(f"/detections/{d['id']}").json()
    assert data.get("test_runs") == []


def test_synthetic_input_mutation_is_detected_without_epoch_change(analyst):
    inv, _, case = setup_case(analyst)
    container.get().events.index([{"event_id": "hit", "investigation_id": inv["id"],
        "data_source": "web", "timestamp": "2026-10-20T00:00:00Z", "status_code": 200, "src_ip": "192.0.2.1"}])
    r = run_selected(analyst, rule(analyst), case)
    assert r.status_code == 409, r.text

def test_negative_only_has_null_precision_but_valid_explicit_no_match(analyst):
    _, _, case = setup_case(analyst)
    d = rule(analyst)
    r = run_selected(analyst, d, case, units=[case["units"][1]])
    assert r.status_code == 200, r.text
    result = r.json()
    assert result["passed"]
    assert result["result"]["metrics"]["precision"]["value"] is None
    assert result["result"]["metrics"]["recall"]["value"] is None
    assert result["result"]["metrics"]["tn"] == 1


def test_selected_approval_apply_and_rollback_keep_exact_versions(analyst, senior):
    inv, _, case = setup_case(analyst)
    from saw.storage.models import InvestigationMember
    with session_scope() as s:
        reviewer = s.scalar(select(User).where(User.username == "senior1"))
        s.add(InvestigationMember(investigation_id=inv["id"], user_id=reviewer.id, access="write"))
    d = rule(analyst)
    t = run_selected(analyst, d, case).json()
    v1 = d["pointers"]["draft"]
    def approve(version, test):
        result = senior.post(f"/detections/{d['id']}/approve", json={
            "version_id": version["id"], "payload_sha256": version["payload_sha256"],
            "expected_draft_version_id": version["id"], "test_run_id": test["id"],
            "rule_policy_sha256": test["proof"]["rule_policy_sha256"],
            "expected_proof_sha256": test["proof"]["proof_sha256"],
            "context_scope": test["scope"]["context_scope"], "reason": "Independent synthetic review"})
        assert result.status_code == 200, result.text
        return result.json()
    approved = approve(v1, t)
    assert approved["pointers"]["active"] is None
    a1 = approved["pointers"]["approved_approval_id"]
    r = senior.post(f"/detections/{d['id']}/activate", json={"version_id": v1["id"], "approval_id": a1,
        "expected_active_version_id": None, "expected_activation_revision": 0, "reason": "Apply reviewed synthetic rule"})
    assert r.status_code == 200, r.text
    changed = analyst.patch(f"/detections/{d['id']}", json={"severity": "high",
        "expected_draft_version_id": None, "base_version_id": v1["id"]})
    assert changed.status_code == 200, changed.text
    d2 = changed.json()
    assert d2["pointers"]["active"]["id"] == v1["id"]
    v2 = d2["pointers"]["draft"]
    t2 = run_selected(analyst, d2, case, reference_version_id=v1["id"]).json()
    approved2 = approve(v2, t2)
    assert approved2["pointers"]["active"]["id"] == v1["id"]
    a2 = approved2["pointers"]["approved_approval_id"]
    r = senior.post(f"/detections/{d['id']}/activate", json={"version_id": v2["id"], "approval_id": a2,
        "expected_active_version_id": v1["id"], "expected_activation_revision": 1, "reason": "Apply reviewed v2"})
    assert r.status_code == 200, r.text
    back = senior.post(f"/detections/{d['id']}/rollback", json={"version_id": v1["id"], "approval_id": a1,
        "expected_active_version_id": v2["id"], "expected_activation_revision": 2, "reason": "Return to approved v1"})
    assert back.status_code == 200, back.text
    assert back.json()["pointers"]["active"]["id"] == v1["id"]
    assert len(back.json()["versions"]) == 2
    assert back.json()["pointers"]["activation_revision"] == 3


def test_selected_during_input_mutation_discards_publication(analyst, monkeypatch):
    inv, _, case = setup_case(analyst)
    d = rule(analyst)
    original = testing._sigma_case
    def changed(*args, **kwargs):
        result = original(*args, **kwargs)
        container.get().events.index([{"event_id": "hit", "investigation_id": inv["id"],
            "data_source": "web", "timestamp": "2026-10-20T00:00:00Z", "status_code": 200}])
        return result
    monkeypatch.setattr(testing, "_sigma_case", changed)
    r = run_selected(analyst, d, case)
    assert r.status_code == 409, r.text
    assert analyst.get(f"/detections/{d['id']}").json()["test_runs"] == []


def test_selected_budget_cannot_become_passing_no_match(analyst, monkeypatch):
    _, _, case = setup_case(analyst)
    d = rule(analyst)
    monkeypatch.setattr(testing, "MAX_RECORDS", 1)
    r = run_selected(analyst, d, case)
    assert r.status_code == 409
    assert analyst.get(f"/detections/{d['id']}").json()["test_runs"] == []


def test_firewall_sigma_includes_producer_connection_records(analyst):
    inv, _, _ = setup_case(analyst)
    container.get().events.index([
        {"investigation_id": inv["id"], "event_id": "flow", "data_source": "connection",
         "timestamp": "2026-10-20T00:00:00Z", "src_ip": "192.0.2.9"}])
    case = analyst.post("/detection-cases", json={"title": "Synthetic native FW flow",
        "investigation_id": inv["id"], "filters": [{"field": "data_source", "op": "is", "value": "connection"}],
        "units": [{"unit_id": "flow", "unit_kind": "event", "event_ids": ["flow"],
                   "detection_truth": "expected_match", "investigation_truth": "attempt",
                   "basis": "Normalized generic connection source"}]}).json()
    d = rule(analyst, logic="title: Synthetic FW\nlogsource: {category: firewall}\ndetection:\n  s:\n    src_ip: 192.0.2.9\n  condition: s\n")
    actual = run_selected(analyst, d, case)
    assert actual.status_code == 200, actual.text
    assert actual.json()["passed"] and actual.json()["result"]["metrics"]["tp"] == 1
