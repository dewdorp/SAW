"""Runtime scope wrappers use the actual store query semantics and cannot escape investigation."""
import importlib.util
from copy import deepcopy
from types import SimpleNamespace

import pytest

from saw.core.schemas.query import AggRequest, Filter, TimeRange
from saw.storage.eventstore import SQLiteEventStore
from tests.unit.test_device_observation import profile, rows


def runtime():
    assert importlib.util.find_spec("saw.detection.runtime"), "runtime scope integration missing"
    from saw.detection.runtime import (
        ScopedEventStore,
        discover_context_scopes,
        run_device_scopes,
        run_for_request,
    )
    return ScopedEventStore, discover_context_scopes, run_device_scopes, run_for_request


def store(tmp_path, events):
    backend = SQLiteEventStore(tmp_path/"events.sqlite")
    backend.index(events)
    return backend


def test_runtime_scopes_use_producer_ids_not_investigation_labels_and_bound_cardinality(tmp_path):
    _, discover, _, _ = runtime()
    a = rows(profile("IPS", "alert"), [{"kind": "alert", "signature_id": "s"}])[0]
    b = deepcopy(a)
    b["event_id"] = "b"
    b["ext"]["observation"]["context"].update(org_unit_id="B", device_id="dev2")
    unknown = deepcopy(a)
    unknown["event_id"] = "unknown"
    unknown["ext"]["observation"]["context"]["resolved"] = False
    backend = store(tmp_path, [a,b,unknown])
    scopes = discover(backend, "i")
    assert {"kind": "device", "org_unit_id": "A", "device_id": "dev1"} in scopes
    assert {"kind": "device", "org_unit_id": "B", "device_id": "dev2"} in scopes
    assert {"kind": "group"} in scopes
    with pytest.raises(ValueError):
        discover(backend, "i", max_scopes=1)


def test_scoped_store_applies_every_query_time_and_conjunctive_exclusions(tmp_path):
    View, _, _, _ = runtime()
    events = rows(profile("WAF", "request"), [
        {"kind": "request", "request_id": str(i), "uri": "/x" if i<2 else "/y",
         "timestamp": f"2026-10-20T00:0{i}:00Z", "action": "allow" if i==0 else "drop"} for i in range(4)])
    backend = store(tmp_path, events)
    excluded = [[Filter(field="uri", value="/x"), Filter(field="enforcement_action", value="allowed")]]
    with View(backend, "i", time=TimeRange(start="2026-10-20T00:00:00Z",end="2026-10-20T00:02:00Z"),
              exclude_groups=excluded) as view:
        assert view.count("i", []) == 2
        assert view.get("i", events[0]["event_id"]) is None
        assert view.get("i", events[3]["event_id"]) is None
        assert len(view.search("i", [], limit=20)["events"]) == 2
        assert sum(b["count"] for b in view.aggregate("i", [], AggRequest(type="terms",field="uri"))["buckets"]) == 2
        assert len(view.group_by("i", [], ["uri"], [],size=10)) == 2
        assert view.time_bounds("i") == ("2026-10-20T00:01:00.000Z", "2026-10-20T00:02:00.000Z")
        with pytest.raises(ValueError):
            view.count("other-investigation", [])
        assert not hasattr(view, "delete_by_investigation")


def test_runtime_device_policy_partition_pins_cannot_affect_other_affiliate(tmp_path):
    _, _, run, _ = runtime()
    from saw.detectors.device_observation import IpsObservation
    context = profile("IPS", "alert", packet_available=True)
    a = rows(context, [{"kind": "alert", "signature_id": "s", "action": "drop"} for _ in range(2)])
    other = deepcopy(context)
    other["subject"]["org_unit_id"] = "B"
    other["observer"]["device_id"] = "dev2"
    b = rows(other, [{"kind": "alert", "signature_id": "s", "action": "drop"} for _ in range(2)])
    for index,event in enumerate(b):
        event["event_id"] = "b"+str(index)
    backend = store(tmp_path,a+b)
    pinset = {"schema": "det-runtime-set/1", "devices":[
        {"detector_id":"ips.observation","context_scope":{"kind":"device","org_unit_id":"A","device_id":"dev1"},
         "policy":{"values":{"enabled":True,"repeat_count":2},"exclusions":[]}},
        {"detector_id":"ips.observation","context_scope":{"kind":"device","org_unit_id":"B","device_id":"dev2"},
         "policy":{"values":{"enabled":True,"repeat_count":5},"exclusions":[]}}]}
    ctx = SimpleNamespace(investigation_id="i",events=backend,params={})
    found = run(IpsObservation(),ctx,pinset)
    assert len(found) == 1
    assert set(found[0].sample_event_ids) == {event["event_id"] for event in a}
    detail = ctx.params["execution_reports"]["ips.observation"]
    assert len(detail["partitions"]) == 2 and detail["counts"]["candidates"] == 1


def test_runtime_ips_join_keeps_same_network_other_device_flows(tmp_path):
    _, _, _, run = runtime()
    context=profile("IPS","alert",packet_available=True)
    alerts=rows(context,[{"kind":"alert","signature_id":"s","action":"drop"}])
    other=profile("NDR","flow",capture_kind="flows")
    other["observer"]["device_id"]="flow-sensor"
    flows=rows(other,[{"timestamp":"2026-10-20T00:01:00Z","kind":"flow","action":"allow"}])
    flows[0]["event_id"]="flow"
    backend=store(tmp_path,alerts+flows)
    pinset={"schema":"det-runtime-set/1","devices":[
        {"detector_id":"ips.observation","context_scope":{"kind":"device","org_unit_id":"A","device_id":"dev1"},
         "policy":{"values":{"enabled":True},"exclusions":[]}}]}
    result=run(backend,"i",{"detector_id":"ips.observation","device_id":"dev1","filters":[]},pinset)
    assert any(c["kind"]=="followup_communication" for c in result["candidates"])
    assert result["counts"]["alerts"]==1

def test_runtime_partition_complete_results_and_empty_fw_sessions_are_preserved(tmp_path):
    _, _, run, request = runtime()
    from saw.detectors.device_observation import IpsObservation
    alerts=rows(profile("IPS","alert",packet_available=True),
                [{"kind":"alert","signature_id":"s","action":"drop"}]*2)
    backend=store(tmp_path,alerts)
    pins={"devices":[{"detector_id":"ips.observation","context_scope":{"kind":"device","org_unit_id":"A","device_id":"dev1"},
                      "policy":{"values":{"enabled":True,"repeat_count":2},"exclusions":[]}}]}
    ctx=SimpleNamespace(investigation_id="i",events=backend,params={})
    run(IpsObservation(),ctx,pins)
    result=ctx.params["execution_reports"]["ips.observation"]
    assert result["status"]=="completed_match" and result["limits"]["coverage_complete"]
    fw=request(backend,"i",{"detector_id":"fw.observation","filters":[{"field":"event_id","value":"absent"}]}, {"devices":[]})
    assert fw["status"]=="insufficient_data" and fw["sessions"]==[]
    assert not fw["limits"]["coverage_complete"]


def test_runtime_missing_exact_pin_and_record_budget_fail_explicitly(tmp_path):
    View, _, run, _=runtime()
    from saw.detectors.device_observation import IpsObservation
    events=rows(profile("IPS","alert"),[{"kind":"alert"}]*3)
    backend=store(tmp_path,events)
    with pytest.raises(ValueError,match="runtime_policy_pin_missing"):
        run(IpsObservation(),SimpleNamespace(investigation_id="i",events=backend,params={}),{"devices":[]})
    with View(backend,"i",max_records=1,exclude_groups=[[Filter(field="event_id",value="absent")]]) as view:
        assert view.count("i",[])==2
        assert view.truncated
    assert view._temp is None


def test_runtime_signature_default_pack_is_pinned_and_scope_exclusions_stay_local(tmp_path):
    _, _, run, _=runtime()
    from saw.core.application.provenance import digest
    from saw.detection.specs import get_spec
    from saw.detectors.signatures import SignatureMatch, by_id, sig_ids, sig_tags
    context=profile("WAF","request")
    events=rows(context,[{"kind":"request","request_id":"1","uri":"/v1.45/containers/lab/archive?path=/etc/shadow","method":"GET","status":200}])
    ident=next(iter(sig_ids(events[0])),None)
    assert ident is not None
    events[0]["tags"]=sig_tags(events[0])
    other=deepcopy(events[0])
    other["event_id"]="b"
    other["ext"]["observation"]["context"].update(org_unit_id="B",device_id="dev2")
    backend=store(tmp_path,events+[other])
    scopes=[{"kind":"device","org_unit_id":"A","device_id":"dev1"},{"kind":"device","org_unit_id":"B","device_id":"dev2"}]
    pins={"devices":[{"context_scope":scope} for scope in scopes],
          "signature_defaults":{"available":True,"enabled":True,"engine_version":"1.1.0",
            "pack_sha256":digest([{"id":i,"payload_sha256":get_spec("signature:"+i)["payload_sha256"]} for i in sorted(by_id())])},
          "signatures":[{"detector_id":"signature:"+ident,"context_scope":scopes[0],
                         "policy":{"values":{"enabled":True},"exclusions":[{"field":"event_id","value":events[0]["event_id"]}]}}]}
    ctx=SimpleNamespace(investigation_id="i",events=backend,params={"sig_disabled":[ident]})
    found=run(SignatureMatch(),ctx,pins)
    matching=[draft for draft in found if draft.detector_id=="sig.match" and draft.sample_event_ids==["b"]]
    assert matching
    assert all(draft.evidence_query["filters"][0]["field"]=="event_id" for draft in found)
    assert len({draft.dedup_key for draft in found})==len(found)

def test_runtime_native_scope_queries_clip_time_without_copying(tmp_path):
    View, _, _, _=runtime()
    events=rows(profile("WAF","request"),[
        {"kind":"request","request_id":str(i),"timestamp":f"2026-10-20T00:0{i}:00Z","uri":"/"+str(i)} for i in range(4)])
    backend=store(tmp_path,events)
    with View(backend,"i",[Filter(field="data_source",value="custom")],
              TimeRange(start="2026-10-20T00:01:00Z",end="2026-10-20T00:02:00Z")) as view:
        assert view.count("i",[],TimeRange(start="2026-10-20T00:00:00Z",end="2026-10-20T00:01:00Z"))==1
        assert view.get("i",events[0]["event_id"]) is None
        assert len(list(view.iterate("i",[])))==2
        assert view.aggregate("i",[],AggRequest(type="count"))["value"]==2
        assert len(view.group_by("i",[],["uri"],[],size=10))==2
        assert view.time_bounds("i")==("2026-10-20T00:01:00.000Z","2026-10-20T00:02:00.000Z")
        assert view._temp is None
        assert view.count("i",[],TimeRange(start="2026-10-20T00:03:00Z"))==0


def test_multiple_complete_partitions_do_not_become_partial(tmp_path):
    _,_,run,_=runtime()
    from saw.detectors.device_observation import IpsObservation
    a=rows(profile("IPS","alert",packet_available=True),[{"kind":"alert","signature_id":"s","action":"drop"}]*2)
    b=deepcopy(a)
    for i,event in enumerate(b):
        event["event_id"]="b"+str(i)
        for key in ("observation","device_observation"):
            event["ext"][key]["context"].update(org_unit_id="B",device_id="dev2")
    pins={"devices":[{"detector_id":"ips.observation","context_scope":{"kind":"device","org_unit_id":org,"device_id":device},
                      "policy":{"values":{"enabled":True,"repeat_count":2},"exclusions":[]}} for org,device in (("A","dev1"),("B","dev2"))]}
    ctx=SimpleNamespace(investigation_id="i",events=store(tmp_path,a+b),params={})
    assert len(run(IpsObservation(),ctx,pins))==2
    report=ctx.params["execution_reports"]["ips.observation"]
    assert report["status"]=="completed_match" and report["limits"]["coverage_complete"]
    assert report["counts"]["candidates"]==2

def test_runtime_native_budget_preserves_processed_prefix_and_partial(tmp_path):
    _,_,_,run=runtime()
    events=rows(profile("IPS","alert",packet_available=True),[{"kind":"alert","signature_id":"s","action":"drop"}]*4)
    pins={"devices":[{"detector_id":"ips.observation","context_scope":{"kind":"device","org_unit_id":"A","device_id":"dev1"},
                      "policy":{"values":{"enabled":True,"repeat_count":2},"exclusions":[]}}]}
    result=run(store(tmp_path,events),"i",{"detector_id":"ips.observation"},pins,max_records=2)
    assert result["status"]=="partial"
    assert result["counts"]["records"]==2 and result["counts"]["candidates"]==1
    assert not result["limits"]["coverage_complete"]

def test_mixed_complete_and_insufficient_partitions_never_report_complete_negative(tmp_path):
    _,_,run,_=runtime()
    from saw.detectors.device_observation import IpsObservation
    a=rows(profile("IPS","alert",packet_available=True),[{"kind":"alert","signature_id":"s","action":"drop"}])
    b=deepcopy(a)
    b[0]["event_id"]="unknown-b"
    for key in ("observation","device_observation"):
        b[0]["ext"][key]["context"].update(org_unit_id="B",device_id="dev2")
    b[0]["ext"]["device_observation"]["verified"]=False
    pins={"devices":[{"detector_id":"ips.observation","context_scope":{"kind":"device","org_unit_id":org,"device_id":device},
                      "policy":{"values":{"enabled":True},"exclusions":[]}} for org,device in (("A","dev1"),("B","dev2"))]}
    ctx=SimpleNamespace(investigation_id="i",events=store(tmp_path,a+b),params={})
    assert run(IpsObservation(),ctx,pins)==[]
    result=ctx.params["execution_reports"]["ips.observation"]
    assert [part["status"] for part in result["partitions"]]==["completed_no_match","insufficient_data"]
    assert result["status"]=="partial" and not result["limits"]["coverage_complete"]
    assert result["counts"]["records"]==2 and result["counts"]["eligible_records"]==1
