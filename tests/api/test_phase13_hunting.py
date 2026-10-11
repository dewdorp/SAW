from __future__ import annotations

from saw.devtools.sample_data import gz_bytes, scenario_weblog
from tests.api.test_phase5_bulk import upload


def _inv(api):
    inv = api.post("/investigations", json={"title": "hunt"}).json()
    up = upload(api, inv["id"], "a.log.gz", gz_bytes(scenario_weblog(normal=300, enum_count=400)))
    api.post(f"/evidence/{up['evidence_id']}/process")
    return inv


def test_hunt_loop_with_rationale_pivots_and_finding(analyst):
    inv = _inv(analyst)
    h = analyst.post("/hunts", json={"hypothesis": "동일 UA(python-httpx)를 쓰는 다른 Cloud IP 존재 여부",
                                     "investigation_id": inv["id"], "seed": {"technique_id": "T1213"}}).json()
    assert h["display_id"].startswith("H-")
    q1 = {"filters": [{"field": "user_agent", "op": "is", "value": "python-httpx/0.27"}],
          "aggs": [{"type": "terms", "field": "src_as_org", "size": 10}, {"type": "terms", "field": "uri_template", "size": 5}]}
    assert analyst.post(f"/hunts/{h['id']}/steps", json={"query": q1, "rationale": " "}).status_code == 422 or \
        analyst.post(f"/hunts/{h['id']}/steps", json={"query": q1, "rationale": " "}).status_code == 400
    h = analyst.post(f"/hunts/{h['id']}/steps", json={"query": q1, "rationale": "공격 인프라 공통 UA"}).json()
    s1 = h["steps"][0]
    assert s1["result"]["total"] > 300 and s1["actor"] == "analyst"
    assert any(p["field"] == "uri_template" for p in s1["pivots"])  # concentration -> pivot candidate with reason
    piv = next(p for p in s1["pivots"] if p["field"] == "uri_template")
    q2 = {"filters": q1["filters"] + [{"field": piv["field"], "op": "is", "value": piv["value"]}],
          "aggs": [{"type": "terms", "field": "src_ip", "size": 50}]}
    h = analyst.post(f"/hunts/{h['id']}/steps", json={"query": q2, "rationale": piv["reason"], "actor": "ai", "parent_seq": 1}).json()
    assert h["steps"][1]["actor"] == "ai" and h["steps"][1]["accepted_by"] == "analyst1" and h["steps"][1]["parent_seq"] == 1
    fid = analyst.post(f"/hunts/{h['id']}/finding", json={"seq": 2, "title": "Cloud IP API enumeration cluster"}).json()["finding_id"]
    f = analyst.get(f"/investigations/{inv['id']}/findings/{fid}").json()
    assert f["title"].startswith("Potential") and f["attack"][0]["source"] == "analyst"
    h = analyst.post(f"/hunts/{h['id']}/conclude", json={"outcome": "confirmed", "summary": "동일 UA 클러스터 확인"}).json()
    assert h["status"] == "concluded"
    assert analyst.post(f"/hunts/{h['id']}/steps", json={"query": q1, "rationale": "x"}).status_code == 400


def test_hunt_scope_and_budget(analyst, senior):
    assert analyst.post("/hunts", json={"hypothesis": "global hunt", "scope": "global"}).status_code == 403
    g = senior.post("/hunts", json={"hypothesis": "global hunt", "scope": "global"}).json()
    bad = senior.post(f"/hunts/{g['id']}/steps", json={"query": {"filters": [], "time": {"start": "2026-01-01T00:00:00Z", "end": "2026-10-01T00:00:00Z"}}, "rationale": "too long"})
    assert bad.status_code == 400 and "90 days" in bad.text
    inj = senior.post(f"/hunts/{g['id']}/steps", json={"query": {"filters": [{"field": "a') OR 1=1 --", "op": "is", "value": 1}]}, "rationale": "x"})
    assert inj.status_code == 422  # field names validated -> no query injection
