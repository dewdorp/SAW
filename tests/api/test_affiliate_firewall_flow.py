"""Run a real upload/parser/job flow with hand-checked cumulative firewall records."""
from saw import container
from saw.storage.db import session_scope
from saw.storage.models import Job
from tests.api.test_phase5_bulk import upload

CSV = ("timestamp,src_ip,src_port,dst_ip,dst_port,protocol,record_type,session_id,sent_bytes,received_bytes,action\n"
       "2026-10-20T00:00:00Z,10.1.0.1,50000,10.2.0.1,443,tcp,start,S1,0,0,allow\n"
       "2026-10-20T00:01:00Z,10.1.0.1,50000,10.2.0.1,443,tcp,interim,S1,100,900,allow\n"
       "2026-10-20T00:02:00Z,10.1.0.1,50000,10.2.0.1,443,tcp,end,S1,300,1200,allow\n").encode()


def test_context_to_parser_to_saved_fw_run(analyst, senior):
    org = senior.post("/source-context/org-units", json={"display_name": "Synthetic A"}).json()
    inv = analyst.post("/investigations", json={"title": "FW synthetic", "org_unit_id": org["id"]}).json()["id"]
    device = analyst.post(f"/source-context/investigations/{inv}/devices",
                          json={"display_name": "synthetic-fw"}).json()
    profile = analyst.post(f"/source-context/devices/{device['id']}/profiles", json={
        "owner_org_unit_id": org["id"], "functions": ["FW"], "network": "test-lab",
        "source_fields": {"record_kind": "record_type", "session_id": "session_id", "timestamp": "timestamp",
                          "action": "action", "src_bytes": "sent_bytes", "dst_bytes": "received_bytes"},
        "record_kind_map": {"start": "session_start", "interim": "session_interim", "end": "session_end"},
        "action_map": {"allow": "allowed", "deny": "blocked"}, "action_verified": True,
        "action_basis": "synthetic fixture explicitly defines these words",
        "measurement_profile": {"counter_semantics": "cumulative", "direction": "src_to_dst",
            "unit": "bytes", "verified": True, "basis": "synthetic cumulative fixture"},
        "time": {"role": "occurred", "timezone": "UTC", "precision": "second",
                 "verified": True, "basis": "synthetic UTC fixture"}})
    assert profile.status_code == 201, profile.text
    uploaded = upload(analyst, inv, "synthetic-fw.csv", CSV)
    attached = analyst.post(f"/source-context/evidence/{uploaded['evidence_id']}/context", json={
        "device_profile_version_id": profile.json()["id"],
        "subject": {"org_unit_id": org["id"], "status": "verified", "basis": "synthetic only"},
        "collection": {"scope": "full", "loss": "known"}})
    assert attached.status_code == 201, attached.text
    processed = analyst.post(f"/evidence/{uploaded['evidence_id']}/process")
    assert processed.status_code == 200, processed.text
    with session_scope() as s:
        job = s.get(Job, processed.json()["id"])
        assert job.state == "COMPLETED", job.error
        assert job.stages["analyze"]["status"] in {"complete", "partial"}
    events = list(container.get().events.iterate(inv, []))
    assert len(events) == 3 and all(e["data_source"] == "connection" for e in events)
    assert all(e["ext"]["observation"]["context"]["org_unit_id"] == org["id"] for e in events)
    runs = analyst.get(f"/investigations/{inv}/analysis-runs").json()["runs"]
    result = analyst.get(f"/investigations/{inv}/analysis-runs/{runs[0]['id']}").json()
    fw = next(e for e in result["executions"] if e["detector_id"] == "fw.observation")
    assert fw["detail"]["counts"]["records"] == 3
    assert fw["detail"]["counts"]["sessions"] == 1
    session = fw["detail"]["sessions"][0]
    assert session["src_to_dst_bytes"] == 300
    assert session["dst_to_src_bytes"] == 1200
    assert len(session["event_refs"]) == 3
    report = analyst.post(f"/investigations/{inv}/report-versions",
                          json={"analysis_run_id": runs[0]["id"]})
    assert report.status_code == 201, report.text
    assert report.json()["content"]["analysis"]["input_manifest"]["org_unit_id"] == org["id"]
