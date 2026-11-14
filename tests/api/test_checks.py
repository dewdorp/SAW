"""Confirmation records (what was checked, by whom, how far) and reuse of results across investigations."""
from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import select

from saw.core.application import checks
from saw.devtools.sample_data import gz_bytes, scenario_weblog
from saw.storage.db import session_scope, utcnow
from saw.storage.models import AuditEvent, Check, Finding
from tests.api.test_phase5_bulk import upload
from tests.conftest import Api, make_user


def _inv(api, title="조사", **kw):
    inv = api.post("/investigations", json={"title": title}).json()
    up = upload(api, inv["id"], "a.log.gz", gz_bytes(scenario_weblog(**(kw or {"normal": 300, "enum_count": 400}))))
    api.post(f"/evidence/{up['evidence_id']}/process")
    return inv


def _top_ip(api, inv_id: str) -> str:
    r = api.post(f"/investigations/{inv_id}/query/aggregate", json={"filters": [], "agg": {"type": "terms", "field": "src_ip", "size": 1}})
    return r.json()["buckets"][0]["key"]


def _event(api, inv_id: str, ip: str) -> dict:
    return api.post(f"/investigations/{inv_id}/query/events",
                    json={"filters": [{"field": "src_ip", "op": "is", "value": ip}], "limit": 5}).json()["events"][0]


def test_a_check_answers_a_question_and_does_not_touch_detections(analyst):
    inv = _inv(analyst)
    ip = _top_ip(analyst, inv["id"])
    ev = _event(analyst, inv["id"], ip)
    before = len(analyst.get(f"/investigations/{inv['id']}/findings").json())
    url = f"/investigations/{inv['id']}/checks"
    # "the request is malicious" without saying anything about whether it worked
    c = analyst.post(url, json={"target_type": "event", "target_key": ev["event_id"], "target_label": "요청 1건",
                                "questions": ["nature"], "judgement": "malicious", "note": "순차 번호 조회 요청"}).json()
    assert c["question_labels"] == ["요청 성격"] and c["judgement_ko"] == "악성" and c["coverage"] == "one"
    assert c["kind"] == "direct" and c["shared"] is False and c["state"] == "active"
    # a check without a judgement is fine ("looked at it, cannot tell yet"); a judgement without a reason is not
    assert analyst.post(url, json={"target_type": "event", "target_key": ev["event_id"], "questions": ["success"]}).status_code == 201
    assert analyst.post(url, json={"target_type": "event", "target_key": ev["event_id"], "questions": ["success"],
                                   "judgement": "normal"}).status_code == 400
    assert analyst.post(url, json={"target_type": "event", "target_key": ev["event_id"], "questions": []}).status_code == 400
    got = analyst.get(url).json()
    assert got["summary"]["direct"] == 2 and got["summary"]["by_question"] == {"nature": 1, "success": 1, "impact": 0, "business": 0}
    assert got["summary"]["by_judgement"] == {"malicious": 1, "none": 1}
    # marking never removes or silences a detection
    assert len(analyst.get(f"/investigations/{inv['id']}/findings").json()) == before


def test_sample_is_not_the_whole_and_an_address_mark_is_not_a_record_mark(analyst):
    inv = _inv(analyst)
    ip = _top_ip(analyst, inv["id"])
    page = analyst.post(f"/investigations/{inv['id']}/query/events",
                        json={"filters": [{"field": "src_ip", "op": "is", "value": ip}], "limit": 30}).json()["events"]
    ids = [e["event_id"] for e in page]
    url = f"/investigations/{inv['id']}/checks"
    q = {"filters": [{"field": "src_ip", "op": "is", "value": ip}], "time": None}
    real = analyst.post(f"/investigations/{inv['id']}/query/aggregate",
                        json={"filters": q["filters"], "agg": {"type": "count", "field": "event_id"}}).json()["value"]
    assert real > 30
    bad = analyst.post(url, json={"target_type": "set", "questions": ["nature"],
                                  "scope": {"coverage": "sample", "query": q, "event_ids": ids, "total": real,
                                            "checked": real, "loaded": real}})
    assert bad.status_code == 400                                        # all of them is not a sample
    # UX-03: what was looked at is bounded by what was loaded; a claimed 50,000 of 30 loaded rows is refused.
    inflated = analyst.post(url, json={"target_type": "set", "questions": ["nature"],
                                       "scope": {"coverage": "sample", "query": q, "event_ids": ids[:10],
                                                 "checked": real - 1, "loaded": 30, "total": 100000}})
    assert inflated.status_code == 400 and "불러온" in inflated.text
    s1 = analyst.post(url, json={"target_type": "set", "target_label": "출발지 기록", "questions": ["nature"],
                                 "scope": {"coverage": "sample", "query": q, "event_ids": ids[:10], "total": 400,
                                           "loaded": 30}}).json()
    # The total is the server's own count of the search, never the number the client sent.
    assert s1["coverage"] == "sample" and s1["checked"] == 10 and s1["total"] == real and s1["target_key"].startswith("set:")
    assert analyst.get(url).json()["summary"]["sample_only"] == 1
    analyst.post(url, json={"target_type": "entity", "target_key": f"ip:{ip}", "questions": ["business"], "judgement": "normal",
                            "note": "DB팀 확인: 정산 배치"}).raise_for_status()
    look = analyst.post(f"{url}/lookup", json={"event_ids": ids, "entity_keys": [f"ip:{ip}"]}).json()
    assert set(look["events"]) == set(ids[:10])                          # only the records named in the sample
    assert all(b["coverage"] == "sample" for b in look["events"][ids[0]])
    assert [b["judgement"] for b in look["entities"][f"ip:{ip}"]] == ["normal"]   # parent reference, kept apart
    assert ids[20] not in look["events"]


def test_change_keeps_history_and_only_the_author_changes_it(analyst, manager, app):
    inv = _inv(analyst)
    ip = _top_ip(analyst, inv["id"])
    url = f"/investigations/{inv['id']}/checks"
    c = analyst.post(url, json={"target_type": "entity", "target_key": f"ip:{ip}", "questions": ["nature"],
                                "judgement": "suspicious", "note": "자동화 도구"}).json()
    assert manager.put(f"{url}/{c['id']}", json={"judgement": "normal", "note": "x"}).status_code == 400   # add your own instead
    n = analyst.put(f"{url}/{c['id']}", json={"judgement": "malicious", "note": "성공 응답 확인", "questions": ["nature", "success"]}).json()
    assert n["id"] != c["id"] and n["supersedes_id"] == c["id"] and n["judgement"] == "malicious"
    assert analyst.put(f"{url}/{c['id']}", json={"judgement": "normal", "note": "y"}).status_code == 409   # stale copy
    hist = analyst.get(f"{url}?target_key=ip:{ip}&history=true").json()["checks"]
    assert [(x["state"], x["judgement"]) for x in hist] == [("active", "malicious"), ("superseded", "suspicious")]
    own = manager.post(url, json={"target_type": "entity", "target_key": f"ip:{ip}", "questions": ["nature"],
                                  "judgement": "normal", "note": "매니저 의견"}).json()
    active = analyst.get(f"{url}?target_key=ip:{ip}").json()["checks"]
    assert {(x["author"], x["judgement"]) for x in active} == {("analyst1", "malicious"), ("manager1", "normal")}  # both kept
    assert analyst.post(f"{url}/{own['id']}/cancel", json={"note": ""}).status_code == 400                # not theirs
    done = analyst.post(f"{url}/{n['id']}/cancel", json={"note": "잘못 표시"}).json()
    assert done["state"] == "cancelled" and done["state_note"] == "잘못 표시"
    assert analyst.post(f"{url}/{n['id']}/cancel", json={"note": ""}).status_code == 409
    with session_scope() as s:
        acts = [a for (a,) in s.execute(select(AuditEvent.action).where(AuditEvent.action.like("check.%")))]
    assert acts.count("check.create") == 2 and acts.count("check.change") == 1 and acts.count("check.cancel") == 1


@pytest.fixture
def two(app, analyst):
    """Analyst 1 shared an address check in A; analyst 2 reads A as a viewer and meets the address in B."""
    a = _inv(analyst, "A 조사")
    ip = _top_ip(analyst, a["id"])
    ev = _event(analyst, a["id"], ip)
    shared = analyst.post(f"/investigations/{a['id']}/checks", json={
        "target_type": "entity", "target_key": f"ip:{ip}", "target_label": ip, "questions": ["business"], "judgement": "normal",
        "note": "DB팀 확인", "evidence": [ev["event_id"]], "shared": True,
        "share": {"fact": "정산 배치 서버로 사용됨", "confirmed_scope": "새벽 고객 조회 API 호출", "unconfirmed_scope": "그 밖의 시간·경로"}}).json()
    reader_id = make_user("a2", ["analyst"])
    analyst.post(f"/investigations/{a['id']}/members", json={"user_id": reader_id, "access": "viewer"}).raise_for_status()
    other = Api(app, "a2")
    b = _inv(other, "B 조사")
    return {"a": a, "b": b, "ip": ip, "shared": shared, "other": other, "event": ev}


def test_shared_result_is_a_reference_with_its_conditions_compared(analyst, two):
    other, b, ip, shared = two["other"], two["b"], two["ip"], two["shared"]
    assert shared["share_status"] == "unreviewed" and shared["valid_until"] and shared["context"]["events"] > 0
    items = other.post(f"/investigations/{b['id']}/checks/team", json={"keys": [f"ip:{ip}", "ip:192.0.2.250"]}).json()["items"]
    assert len(items) == 1
    t = items[0]
    assert t["share"]["fact"] == "정산 배치 서버로 사용됨" and t["share"]["unconfirmed_scope"] == "그 밖의 시간·경로"
    assert t["author"] == "analyst1" and t["share_status_ko"] == "미검토 참고" and t["expired"] is False
    assert t["source"]["display_id"] and t["source"]["can_open"] is True and t["source"]["title"] == "A 조사"
    assert "evidence" not in t and t["evidence_count"] == 1
    assert {c["label"] for c in t["comparison"]} >= {"시간대", "상대 주소", "경로"}
    assert all(c["result"] in ("match", "differ", "unknown") for c in t["comparison"])
    # the reference changes nothing in B: no check, no judgement, detections untouched
    assert other.get(f"/investigations/{b['id']}/checks").json()["summary"]["total"] == 0
    # the author's own investigation does not list it as "team" information
    assert analyst.post(f"/investigations/{two['a']['id']}/checks/team", json={"keys": [f"ip:{ip}"]}).json()["items"] == []
    # a record of a search result or a single event cannot be shared (no way to recognise it elsewhere)
    bad = analyst.post(f"/investigations/{two['a']['id']}/checks", json={
        "target_type": "event", "target_key": two["event"]["event_id"], "questions": ["nature"], "shared": True,
        "share": {"fact": "x", "confirmed_scope": "y"}})
    assert bad.status_code == 400


def test_condition_comparison_never_calls_unknown_a_match():
    then = {"events": 10, "hours_kst": [2, 3], "peers": ["10.0.0.5"], "ports": ["8080"], "paths": ["/api/customer"]}
    same = checks.compare(then, {"events": 5, "hours_kst": [2], "peers": ["10.0.0.5"], "ports": ["8080"], "paths": ["/api/customer"]})
    assert [c["result"] for c in same] == ["match"] * 4
    diff = checks.compare(then, {"events": 5, "hours_kst": [14], "peers": ["10.0.0.9"], "ports": [], "paths": ["/api/customer"]})
    assert {c["label"]: c["result"] for c in diff} == {"시간대": "differ", "상대 주소": "differ", "포트": "unknown", "경로": "match"}
    assert "14시" in diff[0]["text"]
    assert checks.compare(then, {"events": 0})[0]["result"] == "unknown"
    assert checks.compare({}, {"events": 3})[0]["result"] == "unknown"


def test_citing_is_recorded_as_relying_on_someone_and_follows_corrections(analyst, two):
    other, b, a, ip, shared = two["other"], two["b"], two["a"], two["ip"], two["shared"]
    cited = other.post(f"/investigations/{b['id']}/checks/cite", json={"source_id": shared["id"], "note": "같은 배치로 보임"}).json()
    assert cited["kind"] == "cited" and cited["judgement"] is None and cited["source_check_id"] == shared["id"]
    assert other.post(f"/investigations/{b['id']}/checks/cite", json={"source_id": shared["id"]}).json()["id"] == cited["id"]  # once
    s = other.get(f"/investigations/{b['id']}/checks").json()["summary"]
    assert s["direct"] == 0 and s["cited"] == 1                              # not counted as B's own confirmation
    t = other.post(f"/investigations/{b['id']}/checks/team", json={"keys": [f"ip:{ip}"]}).json()["items"][0]
    assert t["citations"] == 1 and t["cited_here"] is True
    # the author corrects the shared result: B is told and follows the new record
    new = analyst.put(f"/investigations/{a['id']}/checks/{shared['id']}", json={"note": "배치 시간 변경됨", "shared": True,
                      "share": {"fact": "정산 배치 서버", "confirmed_scope": "02~03시 호출만"}}).json()
    mine = other.get(f"/investigations/{b['id']}/checks").json()
    assert mine["checks"][0]["source_state"] == "changed" and mine["checks"][0]["source_check_id"] == new["id"]
    assert mine["summary"]["source_changed"] == 1
    assert other.get("/team-checks/inbox").json()["source_changed"][0]["id"] == cited["id"]
    # ...and withdraws it: no longer offered, B sees "retracted"
    analyst.post(f"/investigations/{a['id']}/checks/{new['id']}/cancel", json={"note": "서버 용도 변경"}).raise_for_status()
    assert other.post(f"/investigations/{b['id']}/checks/team", json={"keys": [f"ip:{ip}"]}).json()["items"] == []
    assert other.get(f"/investigations/{b['id']}/checks").json()["checks"][0]["source_state"] == "retracted"


def test_expired_or_questioned_results_cannot_be_relied_on(analyst, two):
    other, b, ip, shared = two["other"], two["b"], two["ip"], two["shared"]
    assert other.post(f"/team-checks/{shared['id']}/recheck", json={"note": ""}).status_code == 400
    r = other.post(f"/team-checks/{shared['id']}/recheck", json={"note": "낮 시간에도 접속함"}).json()
    assert r["share_status"] == "recheck"
    assert analyst.get("/team-checks/inbox").json()["recheck"][0]["id"] == shared["id"]       # the author is asked
    assert other.post(f"/investigations/{b['id']}/checks/cite", json={"source_id": shared["id"]}).status_code == 400
    with session_scope() as s:
        c = s.get(Check, shared["id"])
        c.share_status, c.valid_until = "unreviewed", utcnow() - timedelta(days=1)
    t = other.post(f"/investigations/{b['id']}/checks/team", json={"keys": [f"ip:{ip}"]}).json()["items"][0]
    assert t["expired"] is True                                               # still shown, marked as old
    assert other.post(f"/investigations/{b['id']}/checks/cite", json={"source_id": shared["id"]}).status_code == 400


def test_evidence_of_a_shared_result_is_only_those_records_masked_and_audited(analyst, two, app):
    other, a, shared, ev = two["other"], two["a"], two["shared"], two["event"]
    assert other.get(f"/investigations/{a['id']}/events/{ev['event_id']}").status_code == 200
    got = other.get(f"/team-checks/{shared['id']}/evidence").json()
    assert [e["event_id"] for e in got["events"]] == [ev["event_id"]] and "raw_event" not in got["events"][0]
    make_user("adm", ["admin"])
    assert Api(app, "adm").get(f"/team-checks/{shared['id']}/evidence").status_code == 200   # the administrator can use every function
    with session_scope() as s:
        rows = s.execute(select(AuditEvent).where(AuditEvent.action == "check.evidence_view")).scalars().all()
        # Both views are audited, the administrator's too.
        assert sorted(r.actor_name for r in rows) == ["a2", "adm"] and all(r.investigation_id == a["id"] for r in rows)
        assert s.execute(select(Finding).where(Finding.investigation_id == a["id"])).scalars().first() is not None
