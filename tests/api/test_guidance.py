"""Synthetic contextual guidance: scopes, real receipts and retained analyst answers."""
from __future__ import annotations

from datetime import timedelta

from saw import container
from saw.storage.db import session_scope, utcnow
from saw.storage.models import Check
from tests.api.test_phase5_bulk import upload

IP = "203.0.113.44"
VERSION = "soc-guidance/1.0"


def make_case(api, count=120):
    inv = api.post("/investigations", json={"title": "합성 WAF 조사"}).json()
    lines = ["timestamp,src_ip,dst_ip,dst_port,method,uri,status,action"]
    for i in range(count):
        lines.append(f"2026-10-01T00:{i // 60:02d}:{i % 60:02d}Z,{IP},10.0.0.8,443,GET,/../../etc/passwd,200,{'block' if i < count-2 else 'allow'}")
    up = upload(api, inv["id"], "synthetic-waf.csv", "\n".join(lines).encode())
    api.post(f"/evidence/{up['evidence_id']}/process").raise_for_status()
    return inv


def scope(**kw):
    return {"target_type": "entity", "target_key": f"ip:{IP}", "role": "either",
            "filters": [], "time": None, "as_of": None, "methodology_version": VERSION, **kw}


def preview(api, inv, **kw):
    r = api.post(f"/investigations/{inv['id']}/guidance/preview", json=scope(**kw))
    assert r.status_code == 200, r.text
    return r.json()


def answer_body(d, **kw):
    evidence = d["queries"][0].get("evidence_refs", [])[:2]
    return {"target_type": "entity", "target_key": f"ip:{IP}", "questions": [],
            "judgement": "undetermined", "note": "허용 요청의 처리 결과는 확보하지 못함", "evidence": evidence,
            "guidance": {"methodology_version": VERSION, "rule_id": "A", "scope": scope(),
                "answer_status": "follow_up", "answer": "허용 요청의 처리 결과는 확보하지 못함",
                "data_states": [{"source": "origin_service", "state": "not_collected", "reason": "원본 WAS 자료 없음"}],
                "follow_up": {"target": "웹 서비스 담당자", "due_at": None, "needed_data": ["WAS 처리 로그"],
                    "items": ["허용 2건 처리 결과 확인"], "priority": "high"}, **kw}}


def test_case_a_exact_counts_no_click_verification(analyst):
    inv = make_case(analyst)
    d = preview(analyst, inv)
    facts = {x["id"]: x for x in d["facts"]}
    assert facts["events"]["value"] == 120
    assert facts["blocked"]["value"] == 118
    assert facts["allowed"]["value"] == 2
    assert facts["events"]["data_state"] == "available"
    assert {"A", "B", "E", "F"} <= {x["rule_id"] for x in d["questions"]}
    assert all(x["status"] == "open" for x in d["questions"])
    assert any(x["source"] == "origin_service" and x["state"] == "not_collected" for x in d["unknowns"])
    assert analyst.get(f"/investigations/{inv['id']}/checks").json()["checks"] == []


def test_guidance_scope_filters_time_either_has_no_duplicates(analyst):
    inv = make_case(analyst)
    d = preview(analyst, inv, time={"start": "2026-10-01T00:01:58Z", "end": "2026-10-01T00:01:59Z"})
    assert {x["id"]: x["value"] for x in d["facts"]}["events"] == 2
    assert {x["id"]: x["value"] for x in preview(analyst, inv, role="dst")["facts"]}["events"] == 0
    es = container.get().events
    ev = es.search(inv["id"], [], limit=1)["events"][0]
    ev["dst_ip"] = IP
    es.index([ev])
    assert {x["id"]: x["value"] for x in preview(analyst, inv)["facts"]}["events"] == 120


def test_answer_persists_real_capture_reuses_closure_and_revision(analyst):
    inv = make_case(analyst)
    d = preview(analyst, inv)
    r = analyst.post(f"/investigations/{inv['id']}/checks", json=answer_body(d))
    assert r.status_code == 201, r.text
    c = r.json()
    assert c["guidance"]["rule_id"] == "A"
    assert c["capture"]["temporally_valid"]
    assert c["capture"]["input"]["queries"][0]["matched_count"] == 120
    assert c["capture"]["selected_events"]
    assert "judgement" not in c["capture"]["input"] and "answer" not in c["capture"]["input"]
    assert next(x for x in preview(analyst, inv)["questions"] if x["rule_id"] == "A")["status"] == "follow_up"
    draft = analyst.get(f"/investigations/{inv['id']}/guidance/closure-draft").json()
    assert c["id"] in draft["check_ids"] and draft["follow_up"]
    assert "처리 결과" in draft["impact_assessment"]
    changed = analyst.put(f"/investigations/{inv['id']}/checks/{c['id']}", json={"note": "후속 자료 대기"}).json()
    assert changed["supersedes_id"] == c["id"] and changed["guidance"]["rule_id"] == "A"
    with session_scope() as s:
        assert s.get(Check, c["id"]).state == "superseded"
        assert s.get(Check, c["id"]).context["guidance"]["selected_events"]


def test_forged_receipt_and_other_scope_evidence_are_rejected(analyst):
    inv, other = make_case(analyst), make_case(analyst)
    d = preview(analyst, inv)
    bad = answer_body(d, receipts=[{"matched_count": 0}])
    assert analyst.post(f"/investigations/{inv['id']}/checks", json=bad).status_code in (400, 422)
    bad = answer_body(d)
    bad["evidence"] = [container.get().events.search(other["id"], [], limit=1)["events"][0]["event_id"]]
    assert analyst.post(f"/investigations/{inv['id']}/checks", json=bad).status_code == 400


def test_old_cutoff_not_evaluable_query_failure_not_zero(analyst, monkeypatch):
    inv = make_case(analyst)
    old = (utcnow() - timedelta(days=1)).isoformat()
    d = preview(analyst, inv, as_of=old)
    body = answer_body(d)
    body["guidance"]["scope"] = scope(as_of=old)
    body["evidence"] = []
    c = analyst.post(f"/investigations/{inv['id']}/checks", json=body)
    assert c.status_code == 201, c.text
    assert not c.json()["capture"]["temporally_valid"]
    def fail(*args, **kw):
        raise RuntimeError("synthetic unavailable")
    monkeypatch.setattr(container.get().events, "count", fail)
    q = preview(analyst, inv)
    assert q["queries"][0]["data_state"] == "query_failed"
    assert q["queries"][0]["matched_count"] is None


def test_unauthorized_and_invalid_scope_denied(analyst, senior):
    inv = make_case(analyst)
    assert senior.post(f"/investigations/{inv['id']}/guidance/preview", json=scope()).status_code == 403
    assert analyst.post(f"/investigations/{inv['id']}/guidance/preview", json=scope(
        time={"start": "2026-10-02T00:00:00Z", "end": "2026-10-01T00:00:00Z"})).status_code in (400, 422)


def test_explicit_waf_action_is_not_http_status():
    from saw.analyzers.log.normalize import finalize
    assert finalize({"data_source": "waf", "ext": {"action": "allow"}, "status_code": 403})["enforcement_action"] == "allowed"
    assert finalize({"data_source": "waf", "ext": {"차단여부": "차단"}, "status_code": 200})["enforcement_action"] == "blocked"
    assert "enforcement_action" not in finalize({"data_source": "waf", "status_code": 403})

def test_case_b_scope_bound_approval_and_case_c_permission_statement(analyst):
    inv = make_case(analyst)
    d = preview(analyst, inv)
    body = answer_body(d, rule_id="D", answer_status="answered",
        answer="승인 점검: 출발지·대상·시간·방법이 이번 범위와 일치", data_states=[
            {"source": "authorization", "state": "available", "reason": "합성 승인 기록과 범위 일치"}])
    body.update(questions=["business"], judgement="normal", note="합성 승인 점검 근거와 범위 일치")
    saved = analyst.post(f"/investigations/{inv['id']}/checks", json=body)
    assert saved.status_code == 201, saved.text
    assert next(q for q in preview(analyst, inv)["questions"] if q["rule_id"] == "D")["status"] == "answered"
    narrow = preview(analyst, inv, time={"start": "2026-10-01T00:01:58Z", "end": "2026-10-01T00:01:59Z"})
    assert "D" not in {q["rule_id"] for q in narrow["questions"]}
    body = answer_body(d, rule_id="C", data_states=[
        {"source": "edr", "state": "forbidden", "reason": "EDR 권한 없음. 자산 담당자 확인 필요"}])
    c = analyst.post(f"/investigations/{inv['id']}/checks", json=body)
    assert c.status_code == 201, c.text
    found = [x for x in preview(analyst, inv)["unknowns"] if x["source"] == "edr"]
    assert found[-1]["state"] == "forbidden" and found[-1]["source_kind"] == "analyst_statement"
    assert all(x["state"] != "forbidden" for x in c.json()["capture"]["input"]["unknowns"])
    assert c.json()["guidance"]["scope"] == scope()


def test_http_evidence_does_not_become_direct_compromise(analyst):
    inv = make_case(analyst)
    d = preview(analyst, inv)
    body = answer_body(d, answer_status="answered")
    body["judgement"] = "malicious"
    r = analyst.post(f"/investigations/{inv['id']}/checks", json=body)
    assert r.status_code == 201, r.text
    assert "G" not in {q["rule_id"] for q in preview(analyst, inv)["questions"]}

def test_fact_navigation_uses_matching_allowed_records(analyst):
    inv = make_case(analyst)
    d = preview(analyst, inv)
    fact = next(x for x in d["facts"] if x["id"] == "allowed")
    query = next(q for q in d["queries"] if q["id"] == fact["query_ref"])
    assert query["matched_count"] == 2
    assert len(fact["evidence_refs"]) == 2
    assert all(container.get().events.get(inv["id"], eid)["enforcement_action"] == "allowed" for eid in fact["evidence_refs"])
    assert any(f["field"] == "enforcement_action" and f["value"] == "allowed" for f in query["query"]["branches"][0])


def test_external_only_and_real_repeated_connection_case_c(analyst):
    empty = analyst.post("/investigations", json={"title": "합성 외부정보 조사"}).json()
    d = preview(analyst, empty)
    assert d["queries"][0]["data_state"] == "not_collected"
    assert d["queries"][0]["matched_count"] is None
    inv = analyst.post("/investigations", json={"title": "합성 반복 통신"}).json()
    lines = ["timestamp,src_ip,dst_ip,dst_port,bytes_out"]
    lines += [f"2026-10-01T00:{i:02d}:00Z,{IP},8.8.8.8,443,64" for i in range(8)]
    up = upload(analyst, inv["id"], "synthetic-network.csv", "\n".join(lines).encode())
    analyst.post(f"/evidence/{up['evidence_id']}/process").raise_for_status()
    d = preview(analyst, inv)
    assert "C" in {q["rule_id"] for q in d["questions"]}
    assert any(x["source"] == "process" and x["state"] == "not_collected" for x in d["unknowns"])


def test_selected_evidence_bound_is_not_silently_truncated(analyst):
    inv = make_case(analyst)
    d = preview(analyst, inv)
    body = answer_body(d)
    body["evidence"] = [e["event_id"] for e in container.get().events.search(inv["id"], [], limit=21)["events"]]
    assert analyst.post(f"/investigations/{inv['id']}/checks", json=body).status_code in (400, 422)

def test_legacy_business_query_reused_only_for_same_scope(analyst):
    inv = make_case(analyst)
    d = preview(analyst, inv, role="src")
    r = analyst.post(f"/investigations/{inv['id']}/checks", json={
        "target_type": "set", "questions": ["business"], "judgement": "normal",
        "note": "합성 점검 승인: 출발지·대상·시간·방법 확인", "evidence": d["queries"][0]["evidence_refs"][:1],
        "scope": {"coverage": "selected", "query": {"filters": [{"field": "src_ip", "op": "is", "value": IP}], "time": None}}})
    assert r.status_code == 201, r.text
    assert "D" in {q["rule_id"] for q in preview(analyst, inv, role="src")["questions"]}
    assert "D" not in {q["rule_id"] for q in preview(analyst, inv, role="dst")["questions"]}


def test_guidance_revision_cannot_swap_evidence_without_new_capture(analyst):
    inv, other = make_case(analyst), make_case(analyst)
    c = analyst.post(f"/investigations/{inv['id']}/checks", json=answer_body(preview(analyst, inv))).json()
    foreign = container.get().events.search(other["id"], [], limit=1)["events"][0]["event_id"]
    assert analyst.put(f"/investigations/{inv['id']}/checks/{c['id']}", json={"evidence": [foreign]}).status_code == 400
    files = [f for e in c["capture"]["scope"]["evidence_manifest"] for f in e["files"]]
    assert files and files[0]["processing_run"]["run_digest"]

def test_closure_prefill_does_not_duplicate_recorded_followup(analyst):
    inv = make_case(analyst)
    c = analyst.post(f"/investigations/{inv['id']}/checks", json=answer_body(preview(analyst, inv))).json()
    draft = analyst.get(f"/investigations/{inv['id']}/guidance/closure-draft").json()
    result = analyst.post(f"/investigations/{inv['id']}/close", json={
        "verdict": "unknown", "reason": "허용 요청 처리 결과 미확인", "follow_up": draft["follow_up"],
        "behavior_assessment": "공격 시도 관측", "impact_assessment": "실제 침해 미확인"})
    assert result.status_code == 200, result.text
    from saw.storage.models import Investigation
    with session_scope() as s:
        saved = s.get(Investigation, inv["id"]).close_detail["guidance"]
        assert saved["check_ids"] == [c["id"]]
        assert len(saved["follow_up"]) == 1
        assert saved["impact_assessment"] == "실제 침해 미확인"


def test_attack_guidance_queries_beyond_first_general_sample(analyst):
    inv = make_case(analyst)
    es = container.get().events
    events = es.search(inv["id"], [], sort="asc", limit=120)["events"]
    for index, event in enumerate(events):
        event["uri"] = "/health" if index < 20 else "/../../etc/passwd"
        event["tags"] = []
    es.index(events)
    d = preview(analyst, inv)
    assert all(es.get(inv["id"], eid)["uri"] == "/health" for eid in d["queries"][0]["evidence_refs"])
    assert "B" in {q["rule_id"] for q in d["questions"]}
    fact = next(f for f in d["facts"] if f["id"] == "attack_request_evidence")
    assert fact["evidence_refs"]
    assert all(es.get(inv["id"], eid)["uri"] != "/health" for eid in fact["evidence_refs"])
    assert any(q["matched_count"] == 100 and any(
        f["field"] == "uri" and f["op"] == "contains" for branch in q["query"]["branches"] for f in branch
    ) for q in d["queries"])
    early = preview(analyst, inv, time={"start": "2026-10-01T00:00:00Z", "end": "2026-10-01T00:00:19Z"})
    assert "B" not in {q["rule_id"] for q in early["questions"]}
    assert "B" not in {q["rule_id"] for q in preview(analyst, inv, role="dst")["questions"]}
    for event in events:
        event["uri"] = "/union-members"
    es.index(events)
    assert "B" not in {q["rule_id"] for q in preview(analyst, inv)["questions"]}


def test_query_failure_and_forbidden_propagate_to_derived_sources(analyst, monkeypatch):
    inv = make_case(analyst)
    def unavailable(*args, **kwargs):
        raise RuntimeError("synthetic unavailable")
    monkeypatch.setattr(container.get().events, "count", unavailable)
    d = preview(analyst, inv)
    sources = {x["source"]: x for x in d["unknowns"]}
    assert sources["origin_service"]["state"] == sources["process"]["state"] == "query_failed"
    assert sources["origin_service"]["observed_count"] is None
    assert sources["process"]["observed_count"] is None
    def denied(*args, **kwargs):
        raise PermissionError("synthetic denied")
    monkeypatch.setattr(container.get().events, "count", denied)
    d = preview(analyst, inv)
    assert d["queries"][0]["data_state"] == "forbidden"
    assert d["queries"][0]["matched_count"] is None
    assert all(x["state"] == "forbidden" for x in d["unknowns"] if x["source"] in ("origin_service", "process"))


def test_partial_read_does_not_claim_derived_sources_absent(analyst):
    from sqlalchemy import select
    from saw.storage.models import Evidence, EvidenceFile
    inv = make_case(analyst)
    with session_scope() as s:
        file = s.scalars(select(EvidenceFile).join(Evidence, Evidence.id == EvidenceFile.evidence_id).where(Evidence.investigation_id == inv["id"])).first()
        file.parse_status = "degraded"
    d = preview(analyst, inv)
    states = {x["source"]: x for x in d["unknowns"]}
    assert d["queries"][0]["data_state"] == "partial"
    assert states["origin_service"]["state"] == states["process"]["state"] == "partial"
    assert states["origin_service"]["observed_count"] == states["process"]["observed_count"] == 0
    event = container.get().events.search(inv["id"], [], limit=1)["events"][0]
    event.update(data_source="web", process="synthetic-worker")
    container.get().events.index([event])
    d = preview(analyst, inv)
    states = {x["source"]: x for x in d["unknowns"]}
    assert states["origin_service"]["state"] == states["process"]["state"] == "partial"
    assert states["origin_service"]["observed_count"] == states["process"]["observed_count"] == 1
