"""Actual HTTP pipeline: synthetic CSV to exact full Golden release and downloaded ZIP."""
from __future__ import annotations

import hashlib
import io
import json
import zipfile
from datetime import UTC, datetime, timedelta

from saw.core.application.provenance import digest
from saw.knowledge.golden_archive import inspect_archive
from saw.observation.firewall import analyze_firewall
from tests.api.test_golden import CONFIRM
from tests.api.test_golden_governance import release_request
from tests.api.test_phase5_bulk import upload
from tests.conftest import Api, make_user

START = datetime(2026, 10, 20, tzinfo=UTC)
IP = "192.0.2.10"


def _time(seconds):
    return (START + timedelta(seconds=seconds)).isoformat()


def _ok(response, status=200):
    assert response.status_code == status, response.text
    return response.json()


def _csv():
    lines = ["timestamp,src_ip,src_port,dst_ip,dst_port,protocol,record_type,session_id,sent_bytes,received_bytes,action"]
    for session in range(7):
        start = session * 5 if session < 6 else 600
        port = 443 + session if session < 6 else 443
        for offset, kind, sent, received in [(0, "start", 0, 0), (20, "interim", 100, 900), (40, "end", 300, 1200)]:
            lines.append(f"{_time(start + offset)},{IP},{50000 + session},198.51.100.20,{port},tcp,"
                         f"{kind},synthetic-session-{session},{sent},{received},allow")
    return ("\n".join(lines) + "\n").encode()


def _source(analyst, senior, reviewer):
    org = _ok(senior.post("/source-context/org-units", json={"display_name": "Synthetic P4 full lab"}), 201)
    inv = _ok(analyst.post("/investigations", json={"title": "Synthetic P4 full flow", "org_unit_id": org["id"]}), 201)
    for api in (senior, reviewer):
        uid = _ok(api.get("/auth/me"))["id"]
        _ok(analyst.post(f"/investigations/{inv['id']}/members", json={"user_id": uid, "access": "viewer"}))
    device = _ok(analyst.post(f"/source-context/investigations/{inv['id']}/devices",
                             json={"display_name": "Synthetic P4 firewall"}), 201)
    profile = _ok(analyst.post(f"/source-context/devices/{device['id']}/profiles", json={
        "owner_org_unit_id": org["id"], "functions": ["FW"], "network": "test-lab",
        "source_fields": {"record_kind": "record_type", "session_id": "session_id", "timestamp": "timestamp",
                          "action": "action", "src_bytes": "sent_bytes", "dst_bytes": "received_bytes"},
        "record_kind_map": {"start": "session_start", "interim": "session_interim", "end": "session_end"},
        "action_map": {"allow": "allowed", "deny": "blocked"}, "action_verified": True,
        "action_basis": "Synthetic generator explicitly defines these words",
        "measurement_profile": {"counter_semantics": "cumulative", "direction": "src_to_dst", "unit": "bytes",
                                "verified": True, "basis": "Synthetic cumulative counters"},
        "time": {"role": "occurred", "timezone": "UTC", "precision": "second", "verified": True,
                 "basis": "Synthetic UTC timestamps"}}), 201)
    uploaded = upload(analyst, inv["id"], "synthetic-p4-full.csv", _csv())
    _ok(analyst.post(f"/source-context/evidence/{uploaded['evidence_id']}/context", json={
        "device_profile_version_id": profile["id"],
        "subject": {"org_unit_id": org["id"], "status": "verified", "basis": "Synthetic generated fixture"},
        "collection": {"scope": "full", "loss": "known"}}), 201)
    processing = _ok(analyst.post(f"/evidence/{uploaded['evidence_id']}/process"))
    processed = _ok(analyst.get(f"/jobs/{processing['id']}"))
    assert processed["state"] == "COMPLETED", processed
    scope = {"detector_id": "fw.observation", "org_unit_id": org["id"], "device_id": device["id"],
             "filters": [{"field": "src_ip", "op": "is", "value": IP}], "time": {"start": _time(0), "end": _time(900)}}
    job = _ok(analyst.post(f"/investigations/{inv['id']}/analysis-runs",
                          json={**scope, "idempotency_key": "p4-full-exact-fw"}), 202)
    assert job["state"] == "COMPLETED", job
    run_id = job["stages"]["analysis_run_id"]
    run = _ok(analyst.get(f"/investigations/{inv['id']}/analysis-runs/{run_id}"))
    assert run["status"] == "complete" and len(run["executions"]) == 1, run
    execution = run["executions"][0]
    assert execution["status"] == "complete" and execution["detector_id"] == "fw.observation"
    detail = execution["detail"]
    assert detail["counts"]["records"] == 21 and detail["counts"]["sessions"] == 7, detail
    assert all(s["src_to_dst_bytes"] == 300 and s["dst_to_src_bytes"] == 1200 for s in detail["sessions"])
    assert all(s["duration_seconds"] == 40 for s in detail["sessions"])
    scans = [c for c in detail["candidates"] if c["kind"] == "scan"]
    assert len(scans) == 1 and scans[0]["metrics"]["unique_ports"] == 6, detail
    return inv, scope, run


def _golden(analyst, senior, inv, scope, run, *, split="dev", truth_units=None):
    units = []
    for ident, start, end, label, basis in [
        ("ports-window", 0, 300, "expected_match", "Six ports meet the pinned threshold; intent is not established."),
        ("ordinary-window", 600, 900, "expected_no_match", "One-port window does not meet the scan threshold.")]:
        units.append({"unit_id": ident, "unit_kind": "window", "event_ids": [],
            "filters": [{"field": "src_ip", "op": "is", "value": IP}],
            "time": {"start": _time(start), "end": _time(end)},
            "detection_truth": label, "investigation_truth": "undetermined", "basis": basis})
    if truth_units is not None:
        units = truth_units
    truth = _ok(analyst.post("/detection-cases", json={
        "title": "Synthetic P4 FW windows", "investigation_id": inv["id"],
        **{k: v for k, v in scope.items() if k != "detector_id"}, "units": units}), 201)
    guidance_scope = {"target_type": "entity", "target_key": "ip:" + IP, "role": "src",
        "filters": [{"field": "ext.observation.context." + key, "op": "is", "value": scope[key]}
                    for key in ("org_unit_id", "device_id")],
        "time": scope["time"], "as_of": None, "methodology_version": "soc-guidance/1.0"}
    preview = _ok(analyst.post(f"/investigations/{inv['id']}/guidance/preview", json=guidance_scope))
    assert next(f for f in preview["facts"] if f["id"] == "events")["value"] == 21, preview
    rules = {q["rule_id"] for q in preview["questions"]}
    rule = "C" if "C" in rules else "F"
    assert rule in rules
    check = _ok(analyst.post(f"/investigations/{inv['id']}/checks", json={
        "target_type": "entity", "target_key": "ip:" + IP, "questions": ["nature", "business"],
        "judgement": "undetermined", "note": "Synthetic port dispersion; process and business approval are unknown.",
        "evidence": preview["queries"][0]["evidence_refs"][:2],
        "guidance": {"methodology_version": "soc-guidance/1.0", "rule_id": rule, "scope": guidance_scope,
            "answer_status": "follow_up", "answer": "Connection observations require additional process and approval evidence.",
            "data_states": [{"source": "endpoint_process", "state": "not_collected", "reason": "Synthetic CSV only"}],
            "follow_up": {"target": "Synthetic asset owner", "due_at": None,
                "needed_data": ["Process and account records from the same interval"],
                "items": ["Verify business approval scope"], "priority": "normal"}}}), 201)
    assert len(check["capture"]["selected_events"]) == 2
    closure = _ok(analyst.get(f"/investigations/{inv['id']}/guidance/closure-draft"))
    assert check["id"] in closure["check_ids"]
    closed = _ok(analyst.post(f"/investigations/{inv['id']}/close", json={
        "verdict": "unknown", "reason": "Synthetic port dispersion; intent and impact remain unknown.",
        "checks": [], "response": "Additional evidence required", "limits": "FW records only; no process or approval evidence.",
        "save_experience": True, "behavior_assessment": "Port dispersion observed in a fixed window.",
        "impact_assessment": "Execution success and impact cannot be established.", "follow_up": []}))
    eid = closed["experience_id"]
    experience = _ok(analyst.get(f"/experiences/{eid}"))
    _ok(analyst.post(f"/experiences/{eid}/submit"))
    _ok(senior.post(f"/experiences/{eid}/approve", json={"comment": "Reviewed synthetic evidence and uncertainty",
                                                        "ack_fp_conflicts": False}))
    golden = _ok(analyst.post(f"/knowledge/golden/experience/{eid}/prepare", json={
        "expected_experience_rev": experience["rev"], "schema_version": "saw.golden.v2", "check_ids": [check["id"]],
        "analysis_run_id": run["id"], "truth_case_version_ids": [truth["id"]]}), 201)
    assert golden["applicability"]["mode"] == "interpretation_only"
    actual = golden["answers"]["detection_truth"]["units"]
    assert [u["detection_truth"] for u in actual] == ["expected_match", "expected_no_match"]
    assert {u["investigation_truth"] for u in actual} == {"undetermined"}
    golden = _ok(senior.post(f"/knowledge/golden/{golden['id']}/review", json={
        "expected_content_sha256": golden["content_sha256"], "decision": "adopt", "split": split, "confirmations": CONFIRM}))
    return golden


def test_actual_full_release_recalculates_21_records_and_preserves_two_windows(app, analyst, senior):
    make_user("p4-release-reviewer", ["senior_analyst"])
    reviewer = Api(app, "p4-release-reviewer")
    inv, scope, run = _source(analyst, senior, reviewer)
    golden = _golden(analyst, senior, inv, scope, run)
    assert golden["analysis_run_ref"] == {"id": run["id"], "sha256": run["input_sha256"], "scope_sha256": digest(run["scope"])}
    request = release_request(analyst, golden, key="p4-full-release")
    profiles = _ok(analyst.get("/knowledge/golden/profiles?kind=model_conversion"))["items"]
    native = next(p for p in profiles if p["implementation"] == "golden-native/1")
    request["model_conversion_profile"] = {"id": native["id"], "sha256": native["payload_sha256"]}
    request["applicability_request"] = {"mode": "full_recalculation", "complete_scopes": [{
        "golden_version_id": golden["id"], "analysis_run_id": run["id"], "scope_sha256": digest(run["scope"])}]}
    built = _ok(analyst.post("/knowledge/golden/releases", json=request), 202)
    assert built["job"]["state"] == "COMPLETED", json.dumps(built, ensure_ascii=False)
    url = f"/knowledge/golden/releases/{built['release_id']}/versions/{built['current_version_id']}"
    version = _ok(reviewer.get(url))["version"]
    assert version["applicability"]["mode"] == "full_recalculation", version
    assert version["applicability"]["validations"], version
    preview = _ok(reviewer.get(url + "/preview"))
    decision = {"expected_current_version_id": version["id"],
        "expected_payload_sha256": preview["payload_sha256"], "expected_artifact_sha256": preview["artifact_sha256"],
        "expected_decision_id": None, "decision": "approve", "reason": "Reviewed synthetic actual ZIP and bounds.",
        "confirmations": {"preview_reviewed": True, "redistribution_rights": True,
                          "recipient_and_purpose": True, "limits_accepted": True}}
    assert analyst.post(url + "/approve", json=decision).status_code == 403
    approved = _ok(reviewer.post(url + "/approve", json=decision))
    downloaded = analyst.get(url + "/download")
    assert downloaded.status_code == 200, downloaded.text
    assert hashlib.sha256(downloaded.content).hexdigest() == preview["artifact_sha256"]
    inspect_archive(io.BytesIO(downloaded.content), expected_manifest=version["manifest"])
    with zipfile.ZipFile(io.BytesIO(downloaded.content)) as archive:
        inputs = [json.loads(archive.read(n)) for n in archive.namelist() if n.startswith("input/") and "-part-" not in n]
        assert len(inputs) == 1 and inputs[0]["calculation"]["input_count"] == 21
        events = [json.loads(line) for p in inputs[0]["parts"] for line in archive.read(p["path"]).splitlines()]
        assert len(events) == 21
        assert all(e["src_ip"] != IP for e in events)
        result = analyze_firewall(iter(events), policy=inputs[0]["calculation"]["policy"])
        assert result["counts"]["records"] == 21 and result["counts"]["sessions"] == 7
        assert len([c for c in result["candidates"] if c["kind"] == "scan"]) == 1
        answers = json.loads(archive.read(next(n for n in archive.namelist() if n.startswith("answers/"))))
        assert [u["detection_truth"] for u in answers["detection_truth"]["units"]] == ["expected_match", "expected_no_match"]
        assert {u["investigation_truth"] for u in answers["detection_truth"]["units"]} == {"undetermined"}
        for unit in answers["detection_truth"]["units"]:
            start, end = (datetime.fromisoformat(unit["time"][k]) for k in ("start", "end"))
            members = [e for e in events if start <= datetime.fromisoformat(e["timestamp"]) < end]
            outcome = analyze_firewall(iter(members), policy=inputs[0]["calculation"]["policy"])
            assert bool(outcome["counts"]["candidates"]) == (unit["detection_truth"] == "expected_match")
    _ok(reviewer.post(url + "/revoke", json={"expected_decision_id": approved["approval"]["id"],
                                           "reason": "Synthetic fixture distribution complete"}))
    assert analyst.get(url + "/download").status_code == 409
