"""Independent regression probes against root-owned selected-truth engines."""
from tests.api.test_selected_detection_truth import setup_case


def draft_policy(api, detector, enabled=True):
    r = api.post("/detection-policies/drafts", json={"detector_id": detector, "scope": {"kind": "group"},
        "expected_draft_version_id": None, "changes": {"set": {"enabled": enabled}, "inherit": []},
        "reason": "Synthetic independent boundary review"})
    assert r.status_code == 201, r.text
    return r.json()


def selected(api, policy, case):
    ref = policy["pointers"]["draft"]
    r = api.post(f"/detection-policies/{policy['id']}/test", json={"method": "selected_truth_v1",
        "version_id": ref["id"], "payload_sha256": ref["payload_sha256"], "context_scope": {"kind": "group"},
        "units": [{"case_version_id": case["id"], "unit_id": unit["unit_id"]} for unit in case["units"]]})
    assert r.status_code == 200, r.text
    return r.json()


def test_method_specific_signature_missing_method_is_not_true_negative(analyst):
    from saw.detectors.signatures import by_id
    sid = next(key for key in by_id() if key.endswith(".trace_method"))
    _, _, case = setup_case(analyst, rows=[{"event_id": "unknown", "uri": "/", "status_code": 200}],
        units=[{"unit_id": "unknown", "unit_kind": "event", "event_ids": ["unknown"],
                "detection_truth": "expected_no_match", "investigation_truth": "insufficient_data",
                "basis": "The HTTP method was not collected"}])
    trial = selected(analyst, draft_policy(analyst, "signature:" + sid), case)
    assert trial["result"]["units"][0]["status"] == "insufficient_data"
    assert not trial["passed"] and trial["result"]["metrics"]["tn"] == 0


def test_device_window_missing_selected_ids_does_not_authorize_policy(analyst):
    _, _, case = setup_case(analyst, rows=[{"event_id": "present", "status_code": 200}],
        units=[{"unit_id": "empty-window", "unit_kind": "window", "event_ids": ["absent"],
                "detection_truth": "expected_no_match", "investigation_truth": "insufficient_data",
                "basis": "Selected event is missing"}])
    trial = selected(analyst, draft_policy(analyst, "fw.observation", enabled=False), case)
    assert trial["result"]["units"][0]["status"] in {"insufficient_data", "unsupported_unit"}
    assert not trial["passed"] and trial["proof"] is None


def test_selected_request_cannot_fall_back_to_legacy_when_method_missing(analyst):
    from tests.api.test_selected_detection_truth import rule as create_rule
    from tests.api.test_selected_detection_truth import setup_case
    _, _, case = setup_case(analyst)
    rule = create_rule(analyst)
    response = analyst.post(f"/detections/{rule['id']}/test", json={
        "version_id": rule["pointers"]["draft"]["id"],
        "units": [{"case_version_id": case["id"], "unit_id": "ok"}]})
    assert response.status_code == 422, response.text
