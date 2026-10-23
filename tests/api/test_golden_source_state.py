"""Complete captures use server acquisition/processing records, never event time."""
from datetime import timedelta
from sqlalchemy import select
import pytest

from saw.storage.db import session_scope, utcnow
from saw.storage.models import ProcessingRun
from tests.api.test_affiliate_firewall_flow import CSV
from tests.api.test_phase5_bulk import upload


def processed_source(analyst, senior):
    org = senior.post("/source-context/org-units",json={"display_name":"Synthetic capture"}).json()["id"]
    inv = analyst.post("/investigations",json={"title":"Synthetic server known-at","org_unit_id":org}).json()["id"]
    device = analyst.post(f"/source-context/investigations/{inv}/devices",json={"display_name":"Synthetic FW"}).json()["id"]
    profile = analyst.post(f"/source-context/devices/{device}/profiles",json={
        "owner_org_unit_id":org,"functions":["FW"],"network":"synthetic-net",
        "source_fields":{"record_kind":"record_type","session_id":"session_id","timestamp":"timestamp",
            "action":"action","src_bytes":"sent_bytes","dst_bytes":"received_bytes"},
        "record_kind_map":{"start":"session_start","interim":"session_interim","end":"session_end"},
        "action_map":{"allow":"allowed"},"action_verified":True,"action_basis":"Synthetic explicit actions",
        "measurement_profile":{"counter_semantics":"cumulative","direction":"src_to_dst","unit":"bytes",
            "verified":True,"basis":"Synthetic cumulative fixture"},
        "time":{"role":"occurred","timezone":"UTC","precision":"second","verified":True,"basis":"Synthetic UTC"}
    }).json()["id"]
    evidence = upload(analyst,inv,"synthetic.csv",CSV)
    attached = analyst.post(f"/source-context/evidence/{evidence['evidence_id']}/context",json={
        "device_profile_version_id":profile,"subject":{"org_unit_id":org,"status":"verified","basis":"Synthetic"},
        "collection":{"scope":"full","loss":"known"}})
    assert attached.status_code == 201, attached.text
    assert analyst.post(f"/evidence/{evidence['evidence_id']}/process").status_code == 200
    job = analyst.post(f"/investigations/{inv}/analysis-runs",json={
        "detector_id":"fw.observation","filters":[],"org_unit_id":org,"device_id":device}).json()
    assert job["state"] == "COMPLETED",job
    run = analyst.get(f"/investigations/{inv}/analysis-runs/{job['stages']['analysis_run_id']}").json()
    assert run["status"] == "complete"
    run["investigation_id"] = inv
    return {"analysis_run":run,"cutoff":utcnow().isoformat()}


def test_known_at_uses_actual_upload_processing_and_profile_times(analyst,senior):
    from saw.knowledge.golden_job_source import known_at
    scope = processed_source(analyst,senior)
    with session_scope() as s:
        result = known_at(s,scope)
    assert result["basis"] == "server_records"
    assert len(result["acquired_at"]) == 1 and len(result["processed_at"]) == 1
    assert len(result["profile_available_at"]) >= 1
    assert all(not stamp.startswith("2026-10-20T00:") for stamp in
               result["acquired_at"]+result["processed_at"]+result["profile_available_at"])


def test_missing_actual_processing_provenance_cannot_claim_complete(analyst,senior):
    from saw.knowledge.golden_job_source import known_at
    scope = processed_source(analyst,senior)
    with session_scope() as s:
        row = s.scalar(select(ProcessingRun).where(ProcessingRun.investigation_id==scope["analysis_run"]["investigation_id"]))
        s.delete(row)
    with session_scope() as s, pytest.raises(ValueError, match="processing"):
        known_at(s,scope)


def test_future_processing_record_cannot_be_backdated_to_event_time(analyst,senior):
    from saw.knowledge.golden_job_source import known_at
    scope = processed_source(analyst,senior)
    with session_scope() as s:
        row = s.scalar(select(ProcessingRun).where(ProcessingRun.investigation_id==scope["analysis_run"]["investigation_id"]))
        row.finished_at = utcnow()+timedelta(days=1)
    with session_scope() as s, pytest.raises(ValueError):
        known_at(s,scope)
