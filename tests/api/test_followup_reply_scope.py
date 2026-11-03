"""Out-of-scope or partial replies can neither verify as 'confirmed' nor let the case close as normal."""
import uuid

from saw import container
from saw.storage.db import utcnow

PERIOD = {"start": "2026-10-13T10:00:00+09:00", "end": "2026-10-13T10:05:18+09:00"}


def _case(api):
    org = api.post("/source-context/org-units", json={"display_name": f"Reply scope {uuid.uuid4().hex[:6]}"}).json()
    inv = api.post("/investigations", json={"title": "reply scope", "org_unit_id": org["id"],
                                           "period_start": "2026-09-29T00:00:00+09:00",
                                           "period_end": "2026-10-28T23:59:59+09:00"}).json()
    check = api.post(f"/investigations/{inv['id']}/checks", json={
        "target_type": "entity", "target_key": "ip:198.51.100.23", "questions": ["nature"],
        "note": "Directory scan seen; scheduled assessment not confirmed"}).json()
    url = f"/investigations/{inv['id']}/follow-ups"
    created = api.post(url, json={
        "check_id": check["id"], "question": "Was this the scheduled vulnerability assessment?",
        "reason": "Scanner traffic alone does not show authorization",
        "needed_data": ["Assessment work order with source, target and time"],
        "target": {"org_unit_id": org["id"], "src_ips": ["198.51.100.23"], "dst_ips": ["10.20.1.10"],
                   "dst_ports": [443], "behavior": "HTTP path discovery (404 burst)"},
        "period": PERIOD})
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["current"]["payload"]["target"]["dst_ports"] == [443]
    return org, inv, url, body


def _event(inv, when):
    event_id = f"reply-{uuid.uuid4().hex[:8]}"
    container.get().events.index([{"event_id": event_id, "investigation_id": inv["id"], "timestamp": when,
                                   "data_source": "synthetic", "src_ip": "198.51.100.23", "dst_ip": "10.20.1.10",
                                   "dst_port": 443, "raw_event": "synthetic work record reference"}])
    return {"investigation_id": inv["id"], "event_id": event_id}


def _reply(api, url, item, scope, evidence):
    r = api.post(f"{url}/{item['id']}/reply", json={"expected_version_id": item["current"]["id"],
                                                    "reason": "Reply received", "note": "Work order attached",
                                                    "evidence": evidence, "scope": scope})
    assert r.status_code == 200, r.text
    return r.json()


def _verify(api, url, item, evidence, outcome="confirmed"):
    return api.post(f"{url}/{item['id']}/verify", json={"expected_version_id": item["current"]["id"],
                                                        "reason": "Checked", "outcome": outcome,
                                                        "basis": "Work order compared", "evidence": evidence})


def _close(api, inv, verdict):
    return api.post(f"/investigations/{inv['id']}/close", json={"verdict": verdict, "reason": "analyst conclusion"})


def test_reply_for_another_day_cannot_explain_the_activity(senior):
    org, inv, url, item = _case(senior)
    evidence = [_event(inv, "2026-10-20T01:00:00+00:00")]
    replied = _reply(senior, url, item, {"org_unit_id": org["id"], "src_ips": ["198.51.100.23"], "dst_ips": ["10.20.1.10"],
                                           "dst_ports": [443], "start": "2026-10-20T09:00:00+09:00",
                                           "end": "2026-10-20T11:00:00+09:00"}, evidence)
    assert replied["current"]["payload"]["reply"]["scope_check"]["result"] == "mismatch"
    refused = _verify(senior, url, replied, evidence)
    assert refused.status_code == 400 and "확인됨" in refused.text
    blocked = _close(senior, inv, "normal")
    assert blocked.status_code == 400 and "정상·오탐으로 종결할 수 없습니다" in blocked.text
    # Recording that more information is needed is always possible.
    assert _close(senior, inv, "insufficient_evidence").status_code == 200


def test_partly_covering_reply_keeps_the_remaining_question(senior):
    org, inv, url, item = _case(senior)
    evidence = [_event(inv, "2026-10-13T01:01:00+00:00")]
    replied = _reply(senior, url, item, {"org_unit_id": org["id"], "src_ips": ["198.51.100.23"], "dst_ips": ["10.20.1.10"],
                                           "dst_ports": [443], "start": "2026-10-13T10:00:00+09:00",
                                           "end": "2026-10-13T10:02:00+09:00"}, evidence)
    verified = _verify(senior, url, replied, evidence)
    assert verified.status_code == 200, verified.text
    verification = verified.json()["current"]["payload"]["verification"]
    assert verification["outcome"] == "partially_confirmed" and verification["remaining_questions"]
    assert _close(senior, inv, "normal").status_code == 400


def test_matching_reply_verifies_and_allows_a_normal_conclusion(senior):
    org, inv, url, item = _case(senior)
    evidence = [_event(inv, "2026-10-13T01:01:00+00:00")]
    replied = _reply(senior, url, item, {"org_unit_id": org["id"], "src_ips": ["198.51.100.23"], "dst_ips": ["10.20.1.10"],
                                           "dst_ports": [443], "start": "2026-10-13T09:59:00+09:00",
                                           "end": "2026-10-13T10:06:00+09:00"}, evidence)
    assert replied["current"]["payload"]["reply"]["scope_check"]["result"] == "matches"
    verified = _verify(senior, url, replied, evidence)
    assert verified.status_code == 200, verified.text
    assert verified.json()["current"]["payload"]["verification"]["outcome"] == "confirmed"
    closed = _close(senior, inv, "normal")
    assert closed.status_code == 200, closed.text
    assert closed.json()["verdict"] == "normal"


def test_new_conclusion_states_are_accepted_and_attack_states_ask_for_review(senior):
    for verdict in ("attack_attempt", "compromise_confirmed", "data_quality_limited"):
        inv = senior.post("/investigations", json={"title": f"state {verdict}"}).json()
        closed = _close(senior, inv, verdict)
        assert closed.status_code == 200, closed.text
        assert closed.json()["verdict"] == verdict
        assert bool(closed.json()["review_needed"]) is (verdict != "data_quality_limited")


def _connection_case(api):
    org = api.post("/source-context/org-units", json={"display_name": f"Connections {uuid.uuid4().hex[:6]}"}).json()
    inv = api.post("/investigations", json={"title": "connections", "org_unit_id": org["id"],
                                           "period_start": "2026-09-29T00:00:00+09:00",
                                           "period_end": "2026-10-28T23:59:59+09:00"}).json()
    check = api.post(f"/investigations/{inv['id']}/checks", json={
        "target_type": "entity", "target_key": "ip:10.31.1.30", "questions": ["nature"], "note": "Two connections"}).json()
    url = f"/investigations/{inv['id']}/follow-ups"
    asked = [{"src_ip": "10.31.1.30", "dst_ip": "10.31.0.30", "dst_port": 443},
             {"src_ip": "10.31.1.30", "dst_ip": "10.31.0.31", "dst_port": 3389}]
    created = api.post(url, json={
        "check_id": check["id"], "question": "Were these two connections the assessment?", "reason": "Lists are not enough",
        "needed_data": ["Work order"], "period": PERIOD,
        "target": {"org_unit_id": org["id"], "src_ips": ["10.31.1.30"], "dst_ips": ["10.31.0.30", "10.31.0.31"],
                   "dst_ports": [443, 3389], "connections": asked}})
    assert created.status_code == 201, created.text
    assert created.json()["current"]["payload"]["target"]["connections"] == asked
    return org, url, created.json()


def test_a_reply_must_match_each_requested_connection_not_just_the_lists(senior):
    """Asked A:443 and B:3389, answered A:3389 and B:443: every list matches, no connection does."""
    org, url, item = _connection_case(senior)
    scope = {"org_unit_id": org["id"], "start": PERIOD["start"], "end": PERIOD["end"], "src_ips": ["10.31.1.30"],
             "dst_ips": ["10.31.0.30", "10.31.0.31"], "dst_ports": [443, 3389],
             "connections": [{"src_ip": "10.31.1.30", "dst_ip": "10.31.0.30", "dst_port": 3389},
                             {"src_ip": "10.31.1.30", "dst_ip": "10.31.0.31", "dst_port": 443}]}
    check = _reply(senior, url, item, scope, [])["current"]["payload"]["reply"]["scope_check"]
    assert check["result"] == "mismatch" and check["components"]["connections"]["detail"].startswith("요청한 연결 2개 중 0개 일치")


def test_a_reply_with_lists_only_leaves_each_connection_unconfirmed(senior):
    org, url, item = _connection_case(senior)
    scope = {"org_unit_id": org["id"], "start": PERIOD["start"], "end": PERIOD["end"], "src_ips": ["10.31.1.30"],
             "dst_ips": ["10.31.0.30", "10.31.0.31"], "dst_ports": [443, 3389]}
    check = _reply(senior, url, item, scope, [])["current"]["payload"]["reply"]["scope_check"]
    assert check["result"] == "partial" and "개별 연결 미확인" in check["components"]["connections"]["detail"]


def test_a_routine_maintenance_reply_without_scope_does_not_make_the_activity_normal(senior):
    """'정기 점검' with no source, target or time is a claim, not an explanation of the observed connections."""
    org, inv, url, item = _case(senior)
    evidence = [_event(inv, "2026-10-13T01:01:00+00:00")]
    r = senior.post(f"{url}/{item['id']}/reply", json={"expected_version_id": item["current"]["id"],
                                                       "reason": "Reply received", "note": "정기 점검입니다",
                                                       "evidence": evidence, "scope": None})
    assert r.status_code == 200, r.text
    replied = r.json()
    assert replied["current"]["payload"]["status"] == "replied"
    assert replied["current"]["payload"]["reply"]["scope_check"]["result"] == "not_stated"
    # Received is not verified: the case cannot close as normal on the reply alone.
    assert _close(senior, inv, "normal").status_code == 400
    refused = _verify(senior, url, replied, evidence)
    assert refused.status_code == 400 and "확인됨" in refused.text
    assert _close(senior, inv, "normal").status_code == 400


def test_a_reply_stating_every_requested_connection_matches(senior):
    org, url, item = _connection_case(senior)
    scope = {"org_unit_id": org["id"], "start": PERIOD["start"], "end": PERIOD["end"], "src_ips": ["10.31.1.30"],
             "dst_ips": ["10.31.0.30", "10.31.0.31"], "dst_ports": [443, 3389],
             "connections": [{"src_ip": "10.31.1.30", "dst_ip": "10.31.0.31", "dst_port": 3389},
                             {"src_ip": "10.31.1.30", "dst_ip": "10.31.0.30", "dst_port": 443}]}
    check = _reply(senior, url, item, scope, [])["current"]["payload"]["reply"]["scope_check"]
    assert check["result"] == "matches", check
    assert check["components"]["connections"]["detail"] == "요청한 연결 2개 중 2개 일치"
