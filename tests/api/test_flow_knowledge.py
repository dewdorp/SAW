"""Analyst knowledge applied to new records: meaning, authentication -> lookup flows, device links, versions."""
import uuid

from saw.devtools import flow_samples
from tests.api.test_text_uploads import _process


def _org(api, name="Flow"):
    return api.post("/source-context/org-units", json={"display_name": f"{name} {uuid.uuid4().hex[:6]}"}).json()


def _inv(api, org, title="Flow investigation"):
    r = api.post("/investigations", json={"title": title, "org_unit_id": org["id"],
                                          "period_start": "2026-10-19T00:00:00+09:00",
                                          "period_end": "2026-10-25T23:59:59+09:00"})
    assert r.status_code in (200, 201), r.text
    return r.json()


def _upload(api, inv, sample, names=("ndr.csv", "app.csv", "waf.csv", "ips.csv", "ddos.csv", "fw.csv")):
    for name in names:
        _process(api, inv["id"], name, sample[name].encode("utf-8"))


def _register(api, org=None, **service):
    """Register the service knowledge through the API, then a flow that uses the saved activities."""
    saved = []
    for body in flow_samples.knowledge(**service):
        r = api.post("/knowledge/flow-items", json={**body, "org_unit_id": org["id"] if org else None})
        assert r.status_code == 201, r.text
        saved.append(r.json())
    by = {k["content"].get("meaning"): k for k in saved if k["kind"] == "activity"}
    flow = api.post("/knowledge/flow-items", json={"kind": "flow", "org_unit_id": org["id"] if org else None, "content": {
        "host": saved[0]["host"], "name": "인증 후 본인정보 조회", "classification": "normal",
        "steps": [{"activity": by["인증 화면 접근"]["id"], "optional": True},
                  {"activity": by["인증 시도"]["id"], "state": "success"},
                  {"activity": by["회원정보 조회"]["id"], "repeat": True}]}})
    assert flow.status_code == 201, flow.text
    return {**by, "flow": flow.json(), "link": next(k for k in saved if k["kind"] == "link")}


def _flows(api, inv):
    body = api.get(f"/investigations/{inv['id']}/flows").json()
    assert body["run"] is not None, body
    return body


def _detail(api, inv, run, flow):
    r = api.get(f"/investigations/{inv['id']}/flows/runs/{run['id']}/flow", params={"key": flow["key"]})
    assert r.status_code == 200, r.text
    return r.json()


def _by_account(run, account):
    return next(f for f in run["result"]["flows"] if account in f["accounts"] + f["attempted_accounts"])


def test_saved_knowledge_is_applied_to_records_uploaded_afterwards(senior):
    """1, 3, 4, 5, 6, 11, 12, 13: the whole representative scenario on records the knowledge has never seen."""
    org = _org(senior)
    _register(senior)
    inv = _inv(senior, org)
    sample = flow_samples.build(background_sessions=15)
    _upload(senior, inv, sample)  # analysis runs by itself after each upload
    body = _flows(senior, inv)
    run, result = body["run"], body["run"]["result"]
    assert run["reason"] == "ingest" and run["status"] == "complete" and body["stale"]["stale"] is False
    counts = result["counts"]
    assert counts["duplicates"] == sample["truth"]["duplicates"]
    assert counts["labeled"] > 0 and counts["sessions_candidate"] == 0
    assert result["time"]["basis"].startswith("기록의 발생 시각")

    # A: success confirmed by the application record, the same session, the same account.
    a = _by_account(run, "U17")
    assert a["link"] == "session" and a["auth"]["success_confirmed"] and a["flags"] == []
    assert "계정 U17" in a["summary"] and "동일 세션" in a["summary"] and "세션 일치와 계정 일치" in a["summary"]
    assert [c["status"] for c in a["conformance"]] == ["matched"]
    steps = _detail(senior, inv, run, a)["steps"]
    assert [s["meaning"] for s in steps] == ["인증 화면 접근", "인증 시도", "회원정보 조회"]  # shuffled upload, ordered result
    assert steps[0]["outcome"] == "unknown"  # reaching the page is not an authentication result
    assert steps[1]["outcome"] == "success" and "요청 ID 일치" in steps[1]["outcome_basis"]
    assert steps[2]["outcome"] == "success" and steps[2]["object_relation"] == "self"

    # B: HTTP 200, yet the authentication failed; the lookup after it is flagged, never called a bypass.
    b = _by_account(run, "U20")
    assert b["accounts"] == [] and b["attempted_accounts"] == ["U20"]
    assert {"http_200_but_failed", "lookup_after_failed_auth", "device_block_vs_success"} <= set(b["flags"])
    assert any("HTTP 응답은 200이지만 인증 결과는 실패" in line for line in b["confirmed"])
    b_detail = _detail(senior, inv, run, b)
    lookups = [s for s in b_detail["steps"] if s["role"] == "lookup"]
    assert [s["status_code"] for s in lookups] == [403, 200] and all(s["outcome"] == "unknown" for s in lookups)
    # The WAF record is the same request as the 403 one and only a candidate for the retry: never merged.
    links = {(d["link"], d["step_event_id"] == lookups[0]["event_id"]) for d in b_detail["devices"]}
    assert ("same_request", True) in links and ("candidate", False) in links
    device = b_detail["devices"][0]
    assert device["alert_name"] == "Parameter Tampering" and device["device_action"] == "block"
    assert device["enforcement_action"] == "blocked" and device["http_status"] == 403
    assert device["signature"]["registered"] is False  # no similar-name guess
    assert any("같은 요청인지 확인되지 않았습니다" in line for line in b["unknown"])

    # C: no authentication record in the window is not "unauthenticated".
    c = next(f for f in result["flows"] if "no_prior_auth_observed" in f["flags"])
    assert "lookup_after_failed_auth" not in c["flags"] and c["attention"] <= 2
    assert any("인증되지 않은 상태가 확인된 것은 아닙니다" in line for line in c["unknown"])

    # D: one address, two sessions, two accounts: two flows.
    d1, d2 = _by_account(run, "U21"), _by_account(run, "U22")
    assert d1["key"] != d2["key"] and d1["src_ips"] == d2["src_ips"] == ["10.20.9.9"]
    assert d1["accounts"] == ["U21"] and d2["accounts"] == ["U22"]

    # E: logout, then a lookup with no new authentication.
    e = _by_account(run, "U40")
    assert "lookup_after_logout" in e["flags"]

    # 12: the DDoS interval is a service-level period; flows only refer to it.
    assert len(result["ddos"]) == 1 and result["ddos"][0]["vector"] == "SYN Flood"
    assert result["ddos"][0]["requests"] > 0
    assert b["ddos_interval_ids"] == ["D1"] and "DDoS" not in b["summary"]
    assert any("이 흐름의 행위로 연결하지 않았습니다" in line for line in b["inferred"])

    # FW records between the same addresses are shown as communication, not as the same request.
    assert a["network"]["records"] >= 1 and "같은 요청이라는 근거는 아닙니다" in a["network"]["text"]


def test_another_service_with_other_urls_accounts_and_cookie_works_without_code_changes(senior):
    """2, 8: nothing about one service is fixed; knowledge of one service is not applied to another."""
    org = _org(senior)
    service = {"host": "loan.example.test", "auth_path": "/sso/signin.do", "info_path": "/api/v2/customer",
               "cookie": "LOANSESS"}
    _register(senior, org, **service)
    inv = _inv(senior, org)
    _upload(senior, inv, flow_samples.build(seed=11, account_prefix="CUST-", background_sessions=5, **service))
    # The same paths on a service nobody registered stay unlabelled.
    other = flow_samples.build(seed=12, host="other.example.test", auth_path="/sso/signin.do",
                               info_path="/api/v2/customer", cookie="LOANSESS", background_sessions=2)
    _process(senior, inv["id"], "other-ndr.csv", other["ndr.csv"].encode())
    result = _flows(senior, inv)["run"]["result"]
    a = next(f for f in result["flows"] if f["accounts"] == ["CUST-17"])
    assert "계정 CUST-17" in a["summary"] and a["host"] == "loan.example.test"
    hosts = {svc["host"]: svc for svc in result["services"]}
    assert hosts["loan.example.test"]["labeled"] > 0 and hosts["other.example.test"]["labeled"] == 0
    assert all(f["host"] == "loan.example.test" for f in result["flows"])
    unregistered = [u for u in result["unregistered"] if u["host"] == "other.example.test"]
    assert unregistered and all(u["suggestion"] is None or "자동 적용하지 않았습니다" in u["suggestion"]["text"]
                                for u in unregistered)
    assert any(u["suggestion"] for u in unregistered)  # a hint only


def test_without_a_confirmed_session_cookie_flows_are_candidates_and_uuid_is_not_trusted(senior):
    """7: an unconfirmed uuid or cookie links nothing; it is shown as a candidate with what is unknown."""
    org = _org(senior)
    for body in flow_samples.knowledge()[:4]:  # meanings only, no link knowledge
        assert senior.post("/knowledge/flow-items", json=body).status_code == 201
    inv = _inv(senior, org)
    _upload(senior, inv, flow_samples.build(background_sessions=3))
    result = _flows(senior, inv)["run"]["result"]
    assert result["counts"]["sessions_confirmed"] == 0 and result["counts"]["sessions_candidate"] > 0
    link = next(svc for svc in result["services"] if svc["host"] == "portal.example.test")["link"]
    assert "확인되지 않았습니다" in link["text"] and link["request_id_confirmed"] is False
    nat = [f for f in result["flows"] if f["src_ips"] == ["10.20.9.9"]]
    assert len(nat) == 1 and nat[0]["link"] == "candidate"  # grouped only as a candidate, and said so
    assert any("같은 세션인지 확인되지 않았습니다" in line for line in nat[0]["unknown"])
    b = next(f for f in result["flows"] if f["src_ips"] == ["10.20.1.44"])
    # The WAF record shares the uuid value, but uuid is not confirmed as a request id: candidate only.
    assert "device_block_vs_success" in b["flags"]
    assert not any("같은 요청으로 연결됩니다" in line for line in b["confirmed"])


def test_knowledge_change_conflict_restore_and_reanalysis_keep_earlier_results(senior):
    """9, 14: versions, conflicts, stop/restore, stale marker, new run with the reason, old run untouched."""
    org = _org(senior)
    k = _register(senior)
    inv = _inv(senior, org)
    _upload(senior, inv, flow_samples.build(background_sessions=3))
    first = _flows(senior, inv)["run"]
    lookup = k["회원정보 조회"]

    # A judgement belongs to this incident and records the knowledge versions it was made under.
    a = _by_account(first, "U17")
    j = senior.post(f"/investigations/{inv['id']}/flows/judgements", json={
        "run_id": first["id"], "flow_key": a["key"], "verdict": "normal", "note": "본인 조회로 확인"})
    assert j.status_code == 201 and j.json()["knowledge"][lookup["id"]] == 1
    assert "이 사건에만" in j.json()["scope_text"]

    # Same scope, different meaning: refused unless the analyst keeps both as a conflict.
    twin = {"kind": "activity", "content": {**lookup["content"], "meaning": "공지사항 조회", "role": "other"}}
    refused = senior.post("/knowledge/flow-items", json=twin)
    assert refused.status_code == 409 and refused.json()["conflicts"][0]["id"] == lookup["id"]
    kept = senior.post("/knowledge/flow-items", json={**twin, "allow_conflict": True})
    assert kept.status_code == 201 and kept.json()["conflicts_with"] == [lookup["id"]]
    stale = _flows(senior, inv)
    assert stale["stale"]["stale"] is True and "지식이 바뀌었습니다" in stale["stale"]["reasons"][0]

    second = senior.post(f"/investigations/{inv['id']}/flows/run", json={"reason": "knowledge_changed"}).json()
    assert second["version"] == first["version"] + 1 and second["reused"] is False
    assert second["result"]["conflicts"] and "서로 다르게 등록" in second["result"]["conflicts"][0]["text"]
    assert second["changes"]["labeled"]["after"] < second["changes"]["labeled"]["before"]  # neither is applied
    assert second["changes"]["reasons"] and second["changes"]["knowledge"]
    # The earlier run is unchanged and still readable.
    again = senior.get(f"/investigations/{inv['id']}/flows/runs/{first['id']}").json()
    assert again["knowledge"] == first["knowledge"] and again["summary"] == first["summary"]

    # Stop the conflicting definition; a stale edit is rejected; history keeps every version.
    stale_edit = senior.post(f"/knowledge/flow-items/{kept.json()['id']}/stop", json={"expected_version": 9})
    assert stale_edit.status_code == 409
    stopped = senior.post(f"/knowledge/flow-items/{kept.json()['id']}/stop",
                          json={"expected_version": 1, "change_note": "잘못 등록"}).json()
    assert stopped["status"] == "stopped" and stopped["version"] == 2
    third = senior.post(f"/investigations/{inv['id']}/flows/run", json={}).json()
    assert third["result"]["conflicts"] == [] and third["summary"]["labeled"] == first["summary"]["labeled"]
    assert third["version"] == first["version"] + 2
    # The same request again reuses the run instead of making a duplicate.
    assert senior.post(f"/investigations/{inv['id']}/flows/run", json={}).json()["reused"] is True
    assert len(senior.get(f"/investigations/{inv['id']}/flows/runs").json()["runs"]) == first["version"] + 2

    # Edit the meaning, then bring the first version back.
    edited = senior.put(f"/knowledge/flow-items/{lookup['id']}", json={
        "expected_version": 1, "change_note": "용어 정리",
        "content": {**lookup["content"], "meaning": "고객정보 조회"}}).json()
    assert edited["version"] == 2
    restored = senior.post(f"/knowledge/flow-items/{lookup['id']}/versions/1/restore", json={"expected_version": 2}).json()
    assert restored["version"] == 3 and restored["content"]["meaning"] == "회원정보 조회"
    history = senior.get(f"/knowledge/flow-items/{lookup['id']}/history").json()["versions"]
    assert [v["version"] for v in history] == [3, 2, 1] and history[1]["change_note"] == "용어 정리"
    assert history[0]["changed_by"] == "senior1"
    affected = senior.get(f"/knowledge/flow-items/{lookup['id']}/affected").json()["investigations"]
    assert [i["investigation_id"] for i in affected] == [inv["id"]]

    # A new investigation is analysed afresh: the earlier "normal" judgement is not carried over.
    inv2 = _inv(senior, org, "Second")
    _upload(senior, inv2, flow_samples.build(seed=21, background_sessions=2))
    fresh = _flows(senior, inv2)["run"]
    assert all(f["judgement"] is None for f in fresh["result"]["flows"])
    assert _by_account(_flows(senior, inv)["run"], "U17")["judgement"]["verdict"] == "normal"


def test_registered_flow_deviations_and_newly_seen_transitions(senior):
    """10: the registered flow is checked, and transitions nothing explains are found in the records."""
    org = _org(senior)
    _register(senior)
    inv = _inv(senior, org)
    _upload(senior, inv, flow_samples.build(background_sessions=10))
    result = _flows(senior, inv)["run"]["result"]
    b = _by_account(_flows(senior, inv)["run"], "U20")
    assert b["conformance"][0]["status"] == "deviates"
    assert any("결과가 성공이어야 하나 실패" in d for d in b["conformance"][0]["deviations"])
    transitions = result["discovery"]["transitions"]
    explained = {(t["from"], t["to"]) for t in transitions if t["explained_by_registered_flow"]}
    assert ("인증 시도", "회원정보 조회") in explained
    new = [t for t in transitions if not t["explained_by_registered_flow"] and t["unregistered_step"]]
    export = next(t for t in new if t["to"].endswith("/export/all.do"))
    assert export["from"] == "회원정보 조회" and export["sessions"] == 1 and export["example_event_ids"]
    assert "공격이라는 뜻이 아니고" in result["discovery"]["baseline"]["note"]
    path = next(u for u in result["unregistered"] if u["path"] == "/export/all.do")
    # The analyst turns the discovered step into knowledge from where it was found; the next run applies it.
    remembered = senior.post(f"/investigations/{inv['id']}/flows/remember", json={"items": [{
        "kind": "activity", "content": {"host": path["host"], "method": "GET", "path": path["path"],
                                        "meaning": "전체 내려받기", "role": "lookup"},
        "evidence": {"event_ids": [path["example_event_id"]], "source": "discovery"}}]})
    assert remembered.status_code == 201, remembered.text
    run = remembered.json()["run"]
    assert run["changes"]["knowledge"][0]["title"].startswith("전체 내려받기")
    after = _flows(senior, inv)["run"]["result"]
    assert ("회원정보 조회", "전체 내려받기") in {(t["from"], t["to"]) for t in after["discovery"]["transitions"]}
    assert not [u for u in after["unregistered"] if u["path"] == "/export/all.do"]
    # A baseline uses only records before the evaluated ones.
    split = senior.post(f"/investigations/{inv['id']}/flows/run", json={"baseline_end": "2026-10-20T00:20:00+00:00"}).json()
    marks = {(t["from"], t["to"]): t["new_since_baseline"] for t in split["result"]["discovery"]["transitions"]}
    assert marks[("인증 시도", "회원정보 조회")] is False and marks[("회원정보 조회", "전체 내려받기")] is True


def test_affiliates_do_not_share_private_knowledge_and_readers_cannot_write(senior, app):
    """5, 8: an affiliate's own knowledge applies to that affiliate only."""
    from tests.api.test_golden_candidates import _reader

    mine, theirs = _org(senior, "Mine"), _org(senior, "Theirs")
    _register(senior, mine)
    inv_theirs = _inv(senior, theirs)
    _upload(senior, inv_theirs, flow_samples.build(background_sessions=2), names=("ndr.csv", "app.csv"))
    result = _flows(senior, inv_theirs)["run"]["result"]
    assert result["counts"]["labeled"] == 0 and result["flows"] == []
    assert "적용할 지식이 없습니다" in result["knowledge_note"]
    viewer = _reader(app, roles=("viewer",))
    assert viewer.post("/knowledge/flow-items", json=flow_samples.knowledge()[0]).status_code == 403
    assert viewer.get("/knowledge/flow-items").status_code == 200
    outsider = _reader(app)
    assert outsider.get(f"/investigations/{inv_theirs['id']}/flows").status_code == 403


def test_a_memo_becomes_a_draft_and_the_judgement_stays_with_the_incident(senior):
    """4-knowledge: the reusable meaning and this incident's judgement are separated; nothing is saved by extract."""
    draft = senior.post("/knowledge/flow-items/extract", json={
        "host": "portal.example.test",
        "text": "auth.html은 인증 관련 기능이고 /memberinfo는 사용자정보 조회 기능이다. 이번 요청은 정상"}).json()
    kinds = {(d["content"]["path"], d["content"]["role"], d["content"]["meaning"]) for d in draft["drafts"]}
    assert ("/auth.html", "auth_attempt", "인증 관련 기능") in kinds
    assert ("/memberinfo", "lookup", "사용자정보 조회 기능") in kinds
    assert draft["judgement"]["verdict"] == "normal" and "이번 사건에만" in draft["judgement"]["text"]
    assert senior.get("/knowledge/flow-items").json()["items"] == []
    # A definition for a whole service is refused: one meaning cannot cover every path.
    broad = senior.post("/knowledge/flow-items", json={"kind": "activity", "content": {
        "host": "portal.example.test", "path": "/", "match": "prefix", "meaning": "정상", "role": "other"}})
    assert broad.status_code == 422 or broad.status_code == 400


def test_preview_shows_which_records_a_definition_would_cover_before_saving(senior):
    org = _org(senior)
    inv = _inv(senior, org)
    _upload(senior, inv, flow_samples.build(background_sessions=4), names=("ndr.csv",))
    body = {"kind": "activity", "content": {"host": "portal.example.test", "method": "", "path": "/memberinfo",
                                            "meaning": "회원정보 조회", "role": "lookup"}}
    p = senior.post(f"/investigations/{inv['id']}/flow-knowledge/preview", json=body).json()
    assert p["matches"] > 0 and p["samples"][0]["path"] == "/memberinfo" and p["partial"] is False
    assert any(n["path"] == "/auth.html" for n in p["not_matched_examples"])
    assert senior.get("/knowledge/flow-items").json()["items"] == []
