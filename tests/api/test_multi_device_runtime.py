"""Synthetic device jobs execute pinned profiles without mutating prior snapshots."""
from copy import deepcopy

import pytest

from saw import container
from saw.event_generations.reads import actor_scope
from saw.observation.connection import connection_observation
from saw.observation.device import device_observation
from saw.storage.db import session_scope
from tests.api.test_scoped_device_analysis import submit
from tests.api.test_source_context import device, investigation, org
from tests.unit.test_device_observation import profile, rows


def device_case(api, function, kind, entries):
    organization = org(api)
    inv = investigation(api, organization["id"])
    dev = device(api, inv["id"])
    context = profile(function, kind, response_location="edge")
    context["subject"]["org_unit_id"] = organization["id"]
    context["observer"]["device_id"] = dev["id"]
    data = rows(context, entries)
    for row in data:
        row["investigation_id"] = inv["id"]
        row["ext"]["observation"] = connection_observation(row, context_snapshot=context)
        row["ext"]["device_observation"] = device_observation(row, context_snapshot=context)
    container.get().events.index(data)
    return inv, organization, dev, data


@pytest.mark.parametrize("function,kind,detector", [
    ("WAF", "request", "waf.observation"), ("IPS", "alert", "ips.observation"),
    ("DDoS", "interval_summary", "ddos.observation"), ("NDR", "dns", "ndr.observation")])
def test_device_selection_runs_exact_engine_and_preserves_pin(senior, function, kind, detector):
    inv, organization, dev, data = device_case(senior, function, kind, [
        {"kind": {"WAF": "request", "IPS": "alert", "DDoS": "interval", "NDR": "dns"}[function],
         "request_id": f"R{i}", "signature_id": "synthetic-alert", "uri": "/page/" + str(i),
         "user_agent": "Mozilla/5.0", "action": "allow", "domain": "example.test",
         "rate": 1000 + i, "begin": f"2026-10-20T00:0{i}:00Z", "end": f"2026-10-20T00:0{i+1}:00Z",
         "edge_status": 200, "origin_status": 200} for i in range(5)])
    job, result = submit(senior, inv["id"], detector_id=detector, org_unit_id=organization["id"], device_id=dev["id"])
    assert job["state"] == "COMPLETED", job
    assert len(result["executions"]) == 1
    execution = result["executions"][0]
    assert execution["detector_id"] == detector
    assert execution["input_count"] == 5
    assert execution["detail"]["effective_pins"][0]["detector_id"] == detector
    assert result["input_manifest"]["runtime_pin"]["sha256"]
    old = deepcopy(result)
    submit(senior, inv["id"], detector_id=detector)
    assert senior.get(f"/investigations/{inv['id']}/analysis-runs/{result['id']}").json() == old


def test_normal_analysis_uses_pinned_devices_and_signature_runtime(senior):
    from saw.core.application.analysis import run_detectors
    inv, organization, dev, data = device_case(senior, "WAF", "request", [
        {"kind": "request", "request_id": f"R{i}", "uri": "/page/" + str(i),
         "user_agent": "Mozilla/5.0", "action": "allow", "edge_status": 200, "origin_status": 200}
        for i in range(6)])
    with actor_scope(senior.get("/auth/me").json()["id"]), session_scope() as s:
        run_detectors(s, inv["id"])
    run = senior.get(f"/investigations/{inv['id']}/analysis-runs").json()["runs"][0]
    detail = senior.get(f"/investigations/{inv['id']}/analysis-runs/{run['id']}").json()
    assert detail["input_manifest"]["runtime_pin"]["schema"] == "det-runtime-set/1"
    actual = next(e for e in detail["executions"] if e["detector_id"] == "waf.observation")
    assert actual["status"] == "complete", actual
    assert actual["input_count"] == 6
    assert actual["detail"]["counts"]["requests"] == 6
    assert actual["match_count"] >= 1


def test_wrong_device_job_is_not_applicable_not_zero_match(senior):
    inv, organization, dev, _ = device_case(senior, "WAF", "request", [
        {"kind": "request", "request_id": "R1", "uri": "/normal", "user_agent": "Mozilla",
         "action": "allow", "edge_status": 200, "origin_status": 200}])
    job, result = submit(senior, inv["id"], detector_id="ips.observation",
                         org_unit_id=organization["id"], device_id=dev["id"])
    assert job["state"] == "COMPLETED"
    actual = result["executions"][0]
    assert actual["status"] == "not_applicable", actual
    assert actual["match_count"] is None
