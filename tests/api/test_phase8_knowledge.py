from __future__ import annotations

from saw.devtools.sample_data import gz_bytes, scenario_weblog
from tests.api.test_phase5_bulk import upload
from tests.conftest import Api, make_user


def _inv_with_logs(api, title="API 열거", org_unit_id=None, **kw):
    inv = api.post("/investigations", json={"title": title, "org_unit": "Synthetic A", **({"org_unit_id": org_unit_id} if org_unit_id else {})}).json()
    up = upload(api, inv["id"], "a.log.gz", gz_bytes(scenario_weblog(**kw)))
    api.post(f"/evidence/{up['evidence_id']}/process")
    return inv


def test_experience_lifecycle_four_eyes(app, analyst, senior):
    inv = _inv_with_logs(analyst, normal=300, enum_count=400)
    r = analyst.post(f"/investigations/{inv['id']}/close", json={
        "verdict": "attack", "reason": "동일 UA 클라우드 분산 순차 열거", "checks": ["배치 스케줄 확인"],
        "response": "WAF rate-limit 요청", "detection_idea": "uri_template별 10분 500회", "save_experience": True}).json()
    eid = r["experience_id"]
    e = analyst.get(f"/experiences/{eid}").json()
    assert e["status"] == "draft" and e["data"]["behavior_features"]["param_sequential"] is True
    assert e["data"]["recommended_checks"][0]["check"] == "배치 스케줄 확인"
    # drafts are private: another analyst cannot see it; reviewer can
    make_user("a2", ["analyst"])
    other = Api(app, "a2")
    assert other.get(f"/experiences/{eid}").status_code == 404
    assert analyst.post(f"/experiences/{eid}/submit").json()["status"] == "review"
    # author cannot approve own (and analysts lack permission anyway)
    assert analyst.post(f"/experiences/{eid}/approve", json={}).status_code == 403
    from sqlalchemy import select
    from saw.storage.db import session_scope
    from saw.storage.models import User
    with session_scope() as s:
        senior_id = s.scalar(select(User.id).where(User.username == "senior1"))
        other_id = s.scalar(select(User.id).where(User.username == "a2"))
    assert analyst.post(f"/investigations/{inv['id']}/members", json={"user_id": senior_id, "access": "viewer"}).status_code == 200
    queue = senior.get("/experiences?status=review_queue").json()
    assert any(x["id"] == eid for x in queue)
    ap = senior.post(f"/experiences/{eid}/approve", json={"comment": "근거 충분"}).json()
    assert ap["status"] == "approved" and ap["approved"]["title"] and ap["expires_at"]
    assert other.get(f"/experiences/{eid}").status_code == 404
    assert analyst.post(f"/investigations/{inv['id']}/members", json={"user_id": other_id, "access": "viewer"}).status_code == 200
    assert other.get(f"/experiences/{eid}").status_code == 200  # approved knowledge still requires all source access
    # editing an approved experience keeps the approved copy live
    ed = analyst.patch(f"/experiences/{eid}", json={"data": {"reason": "수정된 근거"}}).json()
    assert ed["status"] == "draft" and ed["approved"]["reason"] == "동일 UA 클라우드 분산 순차 열거"
    revs = analyst.get(f"/experiences/{eid}/revisions").json()
    assert len(revs) >= 4 and revs[-1]["note"] == "edited"


def test_senior_cannot_approve_own(senior):
    e = senior.post("/experiences", json={"data": {"title": "x", "category": "attack"}}).json()
    senior.post(f"/experiences/{e['id']}/submit")
    r = senior.post(f"/experiences/{e['id']}/approve", json={})
    assert r.status_code == 403 and "4-eyes" in r.text


def test_fp_rule_conflict_with_confirmed_attack(app, analyst, senior, manager):
    inv = _inv_with_logs(analyst, normal=100, enum_count=300)
    analyst.post(f"/investigations/{inv['id']}/close", json={"verdict": "attack", "reason": "confirmed"})
    cond = [{"field": "user_agent", "op": "is", "value": "python-httpx/0.27"}]
    r = analyst.post("/fp-rules", json={"title": "httpx is our batch", "conditions": cond, "reason": "batch"}).json()
    assert r["conflicts"]["matches"] > 0  # would hide a confirmed attack
    assert senior.post(f"/fp-rules/{r['id']}/approve", json={}).status_code == 400
    ok = senior.post(f"/fp-rules/{r['id']}/approve", json={"ack_fp_conflicts": True}).json()
    assert ok["status"] == "approved"
    # FP rule flags but never suppresses findings
    inv2 = _inv_with_logs(analyst, title="new", normal=100, enum_count=300)
    fs = analyst.get(f"/investigations/{inv2['id']}/findings").json()
    enum = next(f for f in fs if f["category"] == "web.api_enumeration")
    d = analyst.get(f"/investigations/{inv2['id']}/findings/{enum['id']}").json()
    assert d["fp_matches"] and d["fp_matches"][0]["display_id"].startswith("FP-")


def test_asset_baseline_and_context(analyst, senior):
    assert analyst.post("/assets", json={"asset_id": "X", "service": "x"}).status_code == 403  # Senior+ only
    org = senior.post("/source-context/org-units", json={"display_name": "Synthetic A"}).json()
    r = senior.post("/assets", json={"asset_id": "AST-API-0012", "service": "Customer Lookup API", "criticality": "high", "data": {
        "org_unit_id": org["id"], "company": "Synthetic A",
        "expected_uri": ["/api/customer"], "expected_request_rate": {"per_min": {"min": 18, "max": 32}},
        "expected_access_time": {"weekday": "07:00-23:00"}, "expected_country": ["KR"], "owner": "홍길동",
        "batch_schedule": [{"name": "Customer Sync", "cron": "0 3 * * *", "src": "10.20.3.5", "uri": "/internal/sync"}]}})
    assert r.status_code == 201 and r.json()["owner_masked"] == "홍**"
    imp = senior.post("/assets/import", json={"csv": "asset_id,service,criticality,ip,expected_uri\nAST-2,Login,critical,10.10.1.21,/api/auth\nAST-3,Bad,critical,not-an-ip,/x"}).json()
    assert imp["imported"] == 1 and imp["errors"][0]["line"] == 3
    inv = _inv_with_logs(analyst, normal=200, enum_count=400, org_unit_id=org["id"])
    fs = analyst.get(f"/investigations/{inv['id']}/findings").json()
    enum = next(f for f in fs if f["category"] == "web.api_enumeration")
    rate = next(m for m in enum["metrics"] if m["name"] == "request_rate_per_min")
    assert rate["baseline"]["source"] == "asset:AST-API-0012" and rate["ratio"] > 1
    assert any(c["label"] == "Known batch window" for c in enum["checks"])
    assert enum["risk_factors"][2]["value"] == "high"  # asset criticality factor applied
    ctxr = analyst.post(f"/investigations/{inv['id']}/context", json={"finding_id": enum["id"]}).json()
    a = ctxr["assets"][0]
    assert a["service"] == "Customer Lookup API"
    labels = {c["label"]: c for c in a["comparisons"]}
    assert labels["Request rate"]["deviates"] and labels["Access time"]["deviates"]
    assert a["batch_schedule"][0]["matches"] is False


def test_similar_case_hybrid(analyst, senior):
    inv1 = _inv_with_logs(analyst, title="first enum", normal=200, enum_count=400)
    analyst.post(f"/investigations/{inv1['id']}/close", json={"verdict": "attack", "reason": "열거 확인", "save_experience": True})
    inv2 = _inv_with_logs(analyst, title="second enum", normal=250, enum_count=350)
    res = analyst.post("/similar/search", json={"investigation_id": inv2["id"]}).json()
    top = res["results"][0]
    assert top["ref_id"] == inv1["id"] and top["score"] > 0.5
    assert set(top["breakdown"]) == {"feature", "vector", "keyword"}
    assert "uri_template" in top["same"] and "param_sequential" in top["same"]
    ctxr = analyst.post(f"/investigations/{inv2['id']}/context", json={}).json()
    assert ctxr["similar"] and ctxr["similar"][0]["display_id"] == inv1["display_id"]
    assert analyst.post("/similar/feedback", json={"query_ref": inv2["id"], "result_ref": inv1["id"], "useful": True}).json()["ok"]
