"""Full release failures expose fixed actionable codes through actual HTTP Jobs."""
import pytest

from saw.core.application.provenance import digest
from tests.api.test_golden_full_recalculation import IP, _golden, _ok, _source, _time
from tests.api.test_golden_governance import release_request
from tests.conftest import Api, make_user


@pytest.mark.parametrize("reason", ["unsupported_truth_unit", "truth_window_empty"])
def test_full_release_failure_reason_survives_actual_job_http(app, analyst, senior, reason):
    make_user("failure-reviewer", ["senior_analyst"])
    reviewer = Api(app, "failure-reviewer")
    inv, scope, run = _source(analyst, senior, reviewer)
    units = [{"unit_id": str(i), "unit_kind": "entity" if reason == "unsupported_truth_unit" else "window",
        "event_ids": [], "filters": [{"field": "src_ip", "op": "is", "value": IP}],
        "time": {"start": _time(1000+i*200), "end": _time(1100+i*200)} if reason == "truth_window_empty" else None,
        "detection_truth": label, "investigation_truth": "undetermined", "basis": "Synthetic explicit unsupported or empty unit"}
        for i, label in enumerate(["expected_match", "expected_no_match"])]
    golden = _golden(analyst, senior, inv, scope, run, truth_units=units)
    request = release_request(analyst, golden, key="failed-full-" + reason)
    request["applicability_request"] = {"mode": "full_recalculation", "complete_scopes": [{
        "golden_version_id": golden["id"], "analysis_run_id": run["id"], "scope_sha256": digest(run["scope"])}]}
    built = _ok(analyst.post("/knowledge/golden/releases", json=request), 202)
    assert built["job"]["state"] == "FAILED" and built["current_version_id"] is None, built
    job = _ok(analyst.get(f"/jobs/{built['job_id']}"))
    assert job["stages"]["golden_export"]["failure_reasons"] == [reason]
    assert job["error"]["reasons"] == [reason]
    message = job["error"]["message"]
    assert "해석 전용" in message
    assert not any(secret in str(job["error"]) for secret in (IP, inv["id"], golden["id"], run["id"]))
