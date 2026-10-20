"""Real selected policy execution and source-scoped proofs."""
from sqlalchemy import select

from saw import container
from saw.detectors import signatures
from saw.storage.db import session_scope
from saw.storage.models import InvestigationMember, User
from tests.api.test_selected_detection_truth import setup_case
from tests.unit.test_signature_pack import event_for


def grant_review(inv, reviewer="senior1"):
    with session_scope() as s:
        user = s.scalar(select(User).where(User.username == reviewer))
        s.add(InvestigationMember(investigation_id=inv, user_id=user.id, access="write"))


def test_signature_disable_uses_actual_examples_and_explicit_apply(analyst, senior):
    signature = next(v for v in signatures.load_pack() if v.examples and v.where == "path")
    inv, _, case = setup_case(analyst, rows=[
        {**event_for(signature, signature.examples[0]), "event_id": "hit", "status_code": 200}],
        units=[{"unit_id": "muted", "unit_kind": "event", "event_ids": ["hit"],
                "detection_truth": "expected_no_match", "investigation_truth": "approved_activity",
                "basis": "Synthetic scoped disable exercise"}])
    grant_review(inv["id"])
    assert signature.id in signatures.sig_ids(container.get().events.get(inv["id"], "hit"))
    response = analyst.post("/detection-policies/drafts", json={"detector_id": "signature:" + signature.id,
        "scope": {"kind": "group"}, "expected_draft_version_id": None, "base_version_id": None,
        "changes": {"set": {"enabled": False}, "inherit": []}, "exclusions": {"mode": "inherit"},
        "reason": "Synthetic review"})
    assert response.status_code == 201, response.text
    policy = response.json()
    v = policy["pointers"]["draft"]
    response = analyst.post(f"/detection-policies/{policy['id']}/test", json={
        "method": "selected_truth_v1", "version_id": v["id"], "payload_sha256": v["payload_sha256"],
        "units": [{"case_version_id": case["id"], "unit_id": "muted"}], "context_scope": {"kind": "group"}})
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["passed"] and result["result"]["metrics"]["tn"] == 1
    approved = senior.post(f"/detection-policies/{policy['id']}/approve", json={
        "version_id": v["id"], "payload_sha256": v["payload_sha256"], "expected_draft_version_id": v["id"],
        "test_run_id": result["id"], "rule_policy_sha256": result["proof"]["rule_policy_sha256"],
        "expected_proof_sha256": result["proof"]["proof_sha256"], "reason": "Independent review"})
    assert approved.status_code == 200, approved.text
    assert approved.json()["pointers"]["active"] is None
    active = senior.post(f"/detection-policies/{policy['id']}/activate", json={
        "version_id": v["id"], "approval_id": approved.json()["pointers"]["approved_approval_id"],
        "expected_active_version_id": None, "expected_activation_revision": 0, "reason": "Apply reviewed policy"})
    assert active.status_code == 200, active.text
    effective = analyst.get("/detector-specs/signature:" + signature.id + "/effective").json()["effective"]
    assert effective["values"]["enabled"] is False
    catalog = analyst.get("/detection-catalog").json()
    assert next(r for r in catalog["signatures"] if r["id"] == signature.id)["enabled"] is False
    exported = analyst.get("/detection-catalog/export").json()
    assert next(r for r in exported["signatures"] if r["id"] == signature.id)["enabled"] is False


def test_device_event_units_never_use_sampled_evidence_as_true_negative(analyst):
    _, _, case = setup_case(analyst)
    policy = analyst.post("/detection-policies/drafts", json={"detector_id": "fw.observation",
        "scope": {"kind": "group"}, "expected_draft_version_id": None,
        "changes": {"set": {"enabled": True}}, "reason": "Synthetic device"}).json()
    v = policy["pointers"]["draft"]
    response = analyst.post(f"/detection-policies/{policy['id']}/test", json={
        "method": "selected_truth_v1", "version_id": v["id"], "payload_sha256": v["payload_sha256"],
        "units": [{"case_version_id": case["id"], "unit_id": "ok"}], "context_scope": {"kind": "group"}})
    assert response.status_code == 200, response.text
    assert response.json()["result"]["units"][0]["status"] == "unsupported_unit"
    assert response.json()["result"]["metrics"]["tn"] == 0
    assert response.json()["proof"] is None


def test_actual_waf_window_threshold_is_compared_before_approval(senior):
    from tests.api.test_multi_device_runtime import device_case
    inv, organization, dev, _ = device_case(senior, "WAF", "request", [
        {"kind": "request", "request_id": str(i), "uri": f"/api/user/{i}?x=../etc/passwd",
         "user_agent": "curl/8.0", "action": "allow", "edge_status": 200, "origin_status": 200}
        for i in range(6)])
    case = senior.post("/detection-cases", json={
        "title": "Synthetic WAF window", "investigation_id": inv["id"],
        "org_unit_id": organization["id"], "device_id": dev["id"],
        "units": [{"unit_id": "window", "unit_kind": "window", "detection_truth": "expected_match",
                   "investigation_truth": "attempt", "basis": "Synthetic attack plus repeated paths"}]})
    assert case.status_code == 201, case.text
    policy = senior.post("/detection-policies/drafts", json={"detector_id": "waf.observation",
        "scope": {"kind": "device", "org_unit_id": organization["id"], "device_id": dev["id"]},
        "expected_draft_version_id": None, "changes": {"set": {"enabled": True}},
        "reason": "Synthetic threshold execution"})
    assert policy.status_code == 201, policy.text
    ref = policy.json()["pointers"]["draft"]
    result = senior.post(f"/detection-policies/{policy.json()['id']}/test", json={
        "method": "selected_truth_v1", "version_id": ref["id"], "payload_sha256": ref["payload_sha256"],
        "context_scope": {"kind": "device", "org_unit_id": organization["id"], "device_id": dev["id"]},
        "units": [{"case_version_id": case.json()["id"], "unit_id": "window"}]})
    assert result.status_code == 200, result.text
    actual = result.json()
    assert actual["passed"] and actual["result"]["metrics"]["tp"] == 1, actual
    unit = actual["result"]["units"][0]
    assert unit["input_count"] == 6 and unit["prediction"] is True
    assert actual["proof"]["status"] == "complete"
