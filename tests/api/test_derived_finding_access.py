"""Narrow final integration probes: current result source ACL and partial cleanup."""
import pytest

from saw import container
from saw.event_generations.reads import actor_scope
from saw.analysis_runs import service as history
from saw.analysis_runs.models import AnalysisRun
from saw.core.application import identity, investigations
from saw.core.application.analysis import _drop_unsupported, _finding_from_draft, _run_pinned_sigma, run_story
from saw.core.application.provenance import digest
from saw.detection import governance as g
from saw.detection.auto import run_approved
from saw.detectors.base import DetectorContext
from saw.storage.db import session_scope
from saw.storage.models import InvestigationMember, User
from tests.api.test_sigma_auto import setup_rule
from tests.conftest import Api, make_user


def generated(s):
    source,det,_,_=setup_rule(s,data={"title":"Synthetic private-proof marker"})
    p=identity.principal_of(s.get(User,det.created_by))
    target=investigations.create(s,p,"Synthetic publication target")
    s.commit()  # The separately checked event facade must see the new target.
    original=list(container.get().events.iterate(source.id,[]))
    for event in original:
        event["event_id"]="target-"+event["event_id"]
        event["investigation_id"]=target.id
    container.get().events.index(original)
    pin=g.pin_runtime(s,p,target.id,[{"kind":"group"}])
    ctx=DetectorContext(target.id,container.get().events,params={"runtime_pin":pin},data_sources={"web"})
    drafts,_,_=_run_pinned_sigma(s,ctx,pin,run_approved)
    assert len(drafts)==1
    finding=_finding_from_draft(s,target.id,drafts[0])
    s.flush()
    manifest={"runtime_pin":pin,"data_epoch":0}
    run=AnalysisRun(investigation_id=target.id,version=1,created_by=p.user_id,
                    status="complete",input_manifest=manifest,input_sha256=digest(manifest))
    s.add(run)
    s.flush()
    history.capture_findings(s,run,[finding])
    run_story(s,target.id)
    s.flush()
    return source,target,finding,run


@pytest.mark.parametrize("mode",["never","revoked"])
def test_current_finding_and_story_do_not_expose_unreadable_proof_source(analyst,manager,app,mode):
    uid=make_user("target-reader",["analyst"])
    with actor_scope(analyst.get("/auth/me").json()["id"]), session_scope() as s:
        source,target,finding,run=generated(s)
        s.add(InvestigationMember(investigation_id=target.id,user_id=uid,access="read"))
        if mode=="revoked":
            s.add(InvestigationMember(investigation_id=source.id,user_id=uid,access="read"))
        target_id,fid,rid,source_id=target.id,finding.id,run.id,source.id
    reader=Api(app,"target-reader")
    if mode=="revoked":
        assert reader.get(f"/investigations/{target_id}/analysis-runs/{rid}").status_code==200
        with actor_scope(analyst.get("/auth/me").json()["id"]), session_scope() as s:
            s.delete(s.get(InvestigationMember,(source_id,uid)))
    history_response=reader.get(f"/investigations/{target_id}/analysis-runs/{rid}")
    assert history_response.status_code in {403,404}
    list_response=reader.get(f"/investigations/{target_id}/findings")
    detail=reader.get(f"/investigations/{target_id}/findings/{fid}")
    story=reader.get(f"/investigations/{target_id}/story")
    observed={"history_status":history_response.status_code,"list_has_marker":"Synthetic private-proof marker" in list_response.text,
              "detail_status":detail.status_code,"story_has_marker":"Synthetic private-proof marker" in story.text}
    assert not observed["list_has_marker"] and detail.status_code in {403,404} and not observed["story_has_marker"],observed


def test_global_capture_rule_limit_cannot_settle_or_delete_omitted_prior_finding(analyst,manager):
    with actor_scope(analyst.get("/auth/me").json()["id"]), session_scope() as s:
        _source,target,finding,_run=generated(s)
        pin={"schema":"det-runtime-set/1","rules":[],
             "execution_reports":[{"detector_id":"sigma.approved","status":"partial","reason":"runtime_rule_limit"}]}
        ctx=DetectorContext(target.id,container.get().events,data_sources={"web"})
        drafts,settled,reports=_run_pinned_sigma(s,ctx,pin,run_approved)
        assert any(row["status"]=="partial" for row in reports)
        observed={"omitted_was_settled":finding.detector_id in settled,
                  "deleted":_drop_unsupported(s,target.id,settled,set())}
        assert not observed["omitted_was_settled"] and observed["deleted"]==0,observed


def test_derived_public_projections_hide_lineage_but_raw_target_events_stay_readable(analyst,manager,app):
    from saw.knowledge import experience,similar
    uid=make_user("derived-view-reader",["analyst"])
    with actor_scope(analyst.get("/auth/me").json()["id"]), session_scope() as s:
        _source,target,finding,_run=generated(s)
        owner=identity.principal_of(s.get(User,target.owner_id))
        s.add(InvestigationMember(investigation_id=target.id,user_id=uid,access="read"))
        exp=experience.create(s,owner,{"title":"Synthetic durable private marker"},source_inv=target.id)
        exp.approved_data=dict(exp.data)
        exp.approved_rev=1
        similar.index_investigation(s,target)
        target_id,fid,eid=target.id,finding.id,exp.id
    case=analyst.post("/cases",json={"title":"Synthetic derived case","investigation_ids":[target_id]})
    assert case.status_code==201,case.text
    cid=case.json()["id"]
    assert analyst.post(f"/cases/{cid}/items",json={"item_type":"finding","ref_id":fid}).status_code==201
    reader=Api(app,"derived-view-reader")
    assert "Synthetic private-proof marker" not in reader.get("/findings/recent").text
    assert reader.get(f"/investigations/{target_id}/briefing").status_code in {403,404}
    assert reader.get(f"/cases/{cid}").status_code in {403,404}
    assert reader.get(f"/cases/{cid}/export").status_code in {403,404}
    assert cid not in reader.get("/cases").text
    assert reader.get(f"/experiences/{eid}").status_code in {403,404}
    assert "Synthetic durable private marker" not in reader.get("/experiences").text
    cached=reader.post("/similar/search",json={"features":{},"text":"Synthetic private","k":10})
    assert cached.status_code==200,cached.text
    assert target_id not in cached.text
    overview=reader.get(f"/investigations/{target_id}")
    assert overview.status_code==200,overview.text
    assert overview.json()["finding_counts"]=={}
    assert overview.json()["risk_level"]=="unknown" and overview.json()["risk_score"] is None
    raw=reader.post(f"/investigations/{target_id}/query/events",json={"filters":[],"limit":20})
    assert raw.status_code==200,raw.text
    assert len(raw.json()["events"])==3


def test_story_editor_cannot_drop_frozen_source_ledger(analyst,manager,app):
    from copy import deepcopy
    uid=make_user("story-view-reader",["analyst"])
    with actor_scope(analyst.get("/auth/me").json()["id"]), session_scope() as s:
        _source,target,_finding,_run=generated(s)
        s.add(InvestigationMember(investigation_id=target.id,user_id=uid,access="read"))
        target_id=target.id
    story=analyst.get(f"/investigations/{target_id}/story").json()["story"]
    graph=deepcopy(story["graph"])
    assert graph.pop("_source_investigation_ids")
    edited=analyst.put(f"/investigations/{target_id}/story",json={"graph":graph})
    assert edited.status_code==200,edited.text
    reader=Api(app,"story-view-reader")
    response=reader.get(f"/investigations/{target_id}/story")
    assert response.status_code in {403,404}
