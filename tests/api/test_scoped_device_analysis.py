"""Synthetic API regressions for independent scoped firewall calculations."""
from copy import deepcopy

import pytest
from sqlalchemy import select

from saw import container
from saw.storage.db import session_scope
from saw.storage.models import Job, User
from tests.api.test_source_context import device, investigation, org
from tests.conftest import Api, make_user
from tests.unit.test_connection_observation import context, events


def case(api):
    organization = org(api)
    inv = investigation(api, organization["id"])
    dev = device(api, inv["id"])
    from saw.observation.connection import connection_observation
    trusted = context()
    trusted["subject"]["org_unit_id"] = organization["id"]
    trusted["observer"]["device_id"] = dev["id"]
    rows = events([f"2026-10-20T00:0{i}:00Z,10.0.0.1,192.0.2.1,443,S7,{kind},allow,{a},{b},2026-10-20T00:00:00Z"
                   for i, kind, a, b in [(0,"session_start",0,0),(1,"session_interim",100,900),(2,"session_end",300,1200)]])
    for row in rows:
        row["investigation_id"] = inv["id"]
        row["ext"]["observation"] = connection_observation(row, context_snapshot=trusted)
    container.get().events.index(rows)
    return inv["id"], organization["id"], dev["id"], rows


def submit(api, inv, **body):
    response = api.post(f"/investigations/{inv}/analysis-runs", json=body)
    assert response.status_code == 202, response.text
    job = api.get(f"/jobs/{response.json()['id']}").json()
    rows = api.get(f"/investigations/{inv}/analysis-runs").json()["runs"]
    row = next(r for r in rows if r["job_id"] == job["id"])
    return job, api.get(f"/investigations/{inv}/analysis-runs/{row['id']}").json()


def fw(result):
    assert len(result["executions"]) == 1
    return result["executions"][0]


def test_scoped_filter_time_and_device_bounds(senior):
    inv, organization, dev, rows = case(senior)
    other = senior.post("/investigations", json={"title": "Unrelated synthetic device"}).json()["id"]
    foreign = deepcopy(rows[0])
    foreign.update(event_id="foreign", investigation_id=other)
    container.get().events.index([foreign])
    body = {"org_unit_id":organization, "device_id":dev,
            "filters":[{"field":"src_ip","op":"is","value":"10.0.0.1"}],
            "time":{"start":"2026-10-20T00:01:00Z","end":"2026-10-20T00:03:00Z"}}
    job, result = submit(senior, inv, **body)
    assert job["state"] == "COMPLETED", job
    assert fw(result)["input_count"] == 2
    assert fw(result)["detail"]["sessions"][0]["record_count"] == 2
    assert result["scope"] == body
    assert result["findings"] == []
    _, full = submit(senior, inv, org_unit_id=organization, device_id=dev)
    assert fw(full)["input_count"] == 3
    assert fw(full)["detail"]["sessions"][0]["src_to_dst_bytes"] == 300


def test_scoped_zero_match_unknown_and_empty_distinct(senior):
    inv, _, _, rows = case(senior)
    _, complete = submit(senior, inv)
    assert fw(complete)["status"] == "complete"
    assert fw(complete)["match_count"] == 0
    assert fw(complete)["detail"]["status"] == "completed_no_match"
    _, empty = submit(senior, inv, filters=[{"field":"src_ip","value":"192.0.2.99"}])
    assert fw(empty)["input_count"] == 0
    assert empty["status"] == fw(empty)["status"] == "insufficient_data"
    assert fw(empty)["match_count"] is None
    for row in rows:
        row["ext"].pop("observation")
    container.get().events.index(rows)
    _, unknown = submit(senior, inv)
    assert fw(unknown)["input_count"] == 3
    assert unknown["status"] == fw(unknown)["status"] == "insufficient_data"
    assert fw(unknown)["match_count"] is None


def test_scoped_idempotency_and_old_run_immutable(senior):
    inv, _, _, _ = case(senior)
    first, old = submit(senior, inv, idempotency_key="scoped-key")
    second, same = submit(senior, inv, idempotency_key="scoped-key")
    assert first["id"] == second["id"] and old == same
    conflict = senior.post(f"/investigations/{inv}/analysis-runs", json={
        "idempotency_key":"scoped-key","filters":[{"field":"dst_port","value":80}]})
    assert conflict.status_code == 409
    submit(senior, inv)
    assert senior.get(f"/investigations/{inv}/analysis-runs/{old['id']}").json() == old


def test_scoped_acl_and_validation(senior, app):
    inv, _, _, _ = case(senior)
    make_user("scoped-outsider", ["analyst"])
    assert Api(app,"scoped-outsider").post(f"/investigations/{inv}/analysis-runs",json={}).status_code == 403
    for body in ({"time":{"start":"2026-10-20T00:00:00"}},
                 {"time":{"start":"2026-10-21T00:00:00Z","end":"2026-10-20T00:00:00Z"}},
                 {"context_snapshot":{"verified":True}},
                 {"filters":[{"field":"raw_event","value":"x"*33000}]}):
        assert senior.post(f"/investigations/{inv}/analysis-runs",json=body).status_code == 422


def test_scoped_active_ingest_rejected(senior):
    inv, _, _, _ = case(senior)
    with session_scope() as s:
        user = s.scalar(select(User).where(User.username=="senior1"))
        s.add(Job(investigation_id=inv,kind="ingest",state="PARSING",requested_by=user.id))
    assert senior.post(f"/investigations/{inv}/analysis-runs",json={}).status_code == 409


@pytest.mark.parametrize("change", ["cancel","source","acl"])
def test_scoped_mutation_during_calculation_never_publishes(senior, monkeypatch, change):
    inv, _, _, _ = case(senior)
    from saw.analysis_runs import scoped
    real = scoped.run_for_request
    def mutate(*args, **kwargs):
        result = real(*args, **kwargs)
        with session_scope() as s:
            job = s.scalar(select(Job).where(Job.kind=="device_analysis"))
            if change=="cancel":
                job.cancel_requested=True
            elif change=="source":
                from saw.storage.models import Investigation
                row=s.get(Investigation,inv)
                row.settings={**row.settings,"data_epoch":1}
            else:
                s.get(User,job.requested_by).roles=["viewer"]
        return result
    monkeypatch.setattr(scoped,"run_for_request",mutate)
    job, result = submit(senior,inv)
    assert job["state"] == ("CANCELLED" if change=="cancel" else "FAILED"), job
    assert result["status"] == job["state"].lower()
    assert fw(result)["status"] == result["status"]
    assert fw(result)["detail"].get("candidates",[]) == []
    assert result["findings"] == []


def test_scoped_queued_cancel_records_ledger(senior, monkeypatch):
    inv, _, _, _ = case(senior)
    monkeypatch.setattr(container.get().runner,"submit",lambda *a,**kw:None)
    response=senior.post(f"/investigations/{inv}/analysis-runs",json={})
    assert response.status_code==202
    with session_scope() as s:
        s.get(Job,response.json()["id"]).cancel_requested=True
    from saw.analysis_runs.scoped import device_analysis_run
    device_analysis_run(response.json()["id"])
    rows=senior.get(f"/investigations/{inv}/analysis-runs").json()["runs"]
    result=senior.get(f"/investigations/{inv}/analysis-runs/{rows[0]['id']}").json()
    assert result["status"] == fw(result)["status"] == "cancelled"



def test_scoped_api_queued_cancel_seals_run(senior, monkeypatch):
    inv, _, _, _ = case(senior)
    monkeypatch.setattr(container.get().runner,"submit",lambda *a,**kw:None)
    response=senior.post(f"/investigations/{inv}/analysis-runs",json={})
    cancelled=senior.post(f"/jobs/{response.json()['id']}/cancel")
    assert cancelled.status_code==200
    rows=senior.get(f"/investigations/{inv}/analysis-runs").json()["runs"]
    result=senior.get(f"/investigations/{inv}/analysis-runs/{rows[0]['id']}").json()
    assert result["status"] == fw(result)["status"] == "cancelled"


def test_scoped_limit_is_partial_and_failed_execution_is_recorded(senior, monkeypatch):
    inv, _, _, _ = case(senior)
    from saw.analysis_runs import scoped
    monkeypatch.setattr(scoped,"MAX_EVENTS",2)
    _, result=submit(senior,inv)
    assert result["status"] == fw(result)["status"] == "partial"
    assert fw(result)["input_count"]==2
    assert fw(result)["detail"]["limits"]["coverage_complete"] is False
    def broken(*args,**kw):
        raise ValueError("synthetic analyzer failure")
    monkeypatch.setattr(scoped,"run_for_request",broken)
    job, failure=submit(senior,inv)
    assert job["state"]=="FAILED"
    assert failure["status"]==fw(failure)["status"]=="failed"


def test_scoped_retry_creates_new_run_without_rewriting_old(senior, monkeypatch):
    inv, _, _, _ = case(senior)
    from saw.analysis_runs import scoped
    real=scoped.run_for_request
    def broken(*args,**kw):
        raise ValueError("synthetic analyzer failure")
    monkeypatch.setattr(scoped,"run_for_request",broken)
    job, old=submit(senior,inv)
    monkeypatch.setattr(scoped,"run_for_request",real)
    response=senior.post(f"/jobs/{job['id']}/retry")
    assert response.status_code==200,response.text
    assert senior.get(f"/jobs/{job['id']}").json()["state"]=="COMPLETED"
    rows=senior.get(f"/investigations/{inv}/analysis-runs").json()["runs"]
    assert len(rows)==2 and rows[0]["status"]=="complete"
    assert senior.get(f"/investigations/{inv}/analysis-runs/{old['id']}").json()==old


def test_scoped_duplicate_delivery_does_not_steal_live_lease(senior, monkeypatch):
    inv, _, _, _ = case(senior)
    from saw.analysis_runs import scoped
    real=scoped.run_for_request
    def duplicate(*args,**kw):
        with session_scope() as s:
            job=s.scalar(select(Job).where(Job.kind=="device_analysis"))
            job_id,epoch=job.id,job.attempt
        scoped.device_analysis_run(job_id)
        with session_scope() as s:
            assert s.get(Job,job_id).attempt==epoch
        return real(*args,**kw)
    monkeypatch.setattr(scoped,"run_for_request",duplicate)
    job,result=submit(senior,inv)
    assert job["state"]=="COMPLETED"
    assert result["version"]==1


def test_scoped_candidates_do_not_mutate_current_findings(senior):
    inv, _, _, rows = case(senior)
    from saw.core.application.analysis import finding_dict
    from saw.storage.models import Finding
    with session_scope() as s:
        finding=Finding(investigation_id=inv,display_id="SYNTHETIC-1",detector_id="synthetic",
            detector_version="1",title="Existing analyst record",category="network",
            risk_level="low",risk_score=1,confidence="low",dedup_key="synthetic-existing",
            status="confirmed",metrics=[{"value":7}])
        s.add(finding)
        s.flush()
        finding_id=finding.id
        before=finding_dict(finding)
    rows[-1]["ext"]["observation"]["counters"]["src_to_dst_bytes"]["value"]=60_000_000
    container.get().events.index(rows)
    _,result=submit(senior,inv)
    execution=fw(result)
    assert execution["status"]=="complete" and execution["match_count"]==1
    assert execution["detail"]["candidates"][0]["kind"]=="transfer_asymmetry"
    assert result["findings"]==[]
    with session_scope() as s:
        assert finding_dict(s.get(Finding,finding_id))==before
        assert len(list(s.scalars(select(Finding).where(Finding.investigation_id==inv))))==1
