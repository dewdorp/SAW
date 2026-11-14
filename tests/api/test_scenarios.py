"""Scenarios without code: build from a template, try on current data, save, and have the next hunt use it."""
import uuid

from saw.devtools import flow_samples
from tests.api.test_flow_knowledge import _inv, _org
from tests.api.test_text_uploads import _process

H = flow_samples.NDR_HEADER + "\n"


def _row(t, ip, method, path, query, uid=None, session="-"):
    cookie = f"SID={session}" if session != "-" else "-"
    return (f"2026-10-20 {t},site,http,http,TCP,{ip},50000,KR,10.40.1.10,443,KR,10.40.0.2,ndr-syn-01,{method},svc.example.test,"
            f"{path},{query},UA,-,{cookie},{uid or 'u-' + uuid.uuid4().hex[:8]},200,900,300\n")


def _data():
    rows = [
        # A: auth, then six different members within ten minutes (one request delivered twice).
        _row("09:00:00", "10.60.1.10", "POST", "/auth.html", "-"),
        *[_row(f"09:0{k}:00", "10.60.1.10", "GET", "/memberinfo", f"id=M{k}", uid=f"a-{k}") for k in range(1, 7)],
        _row("09:06:00", "10.60.1.10", "GET", "/memberinfo", "id=M6", uid="a-6"),
        # B: lookups first, auth afterwards (reversed order).
        *[_row(f"10:0{k}:00", "10.60.1.20", "GET", "/memberinfo", f"id=N{k}") for k in range(1, 7)],
        _row("10:08:00", "10.60.1.20", "POST", "/auth.html", "-"),
        # C: auth, then six members but the sixth arrives just outside the window (10 min 1 s).
        _row("11:00:00", "10.60.1.30", "POST", "/auth.html", "-"),
        *[_row(f"11:0{k}:00", "10.60.1.30", "GET", "/memberinfo", f"id=P{k}") for k in range(1, 6)],
        _row("11:10:01", "10.60.1.30", "GET", "/memberinfo", "id=P6"),
        # D: an ordinary batch reading the same member six times.
        _row("12:00:00", "10.60.1.40", "POST", "/auth.html", "-"),
        *[_row(f"12:0{k}:00", "10.60.1.40", "GET", "/memberinfo", "id=SAME") for k in range(1, 7)],
        # E: the same paths on another service.
        *[_row(f"13:0{k}:00", "10.60.1.50", "GET", "/memberinfo", f"id=Q{k}").replace("svc.example.test", "other.example.test") for k in range(1, 9)],
    ]
    return H + "".join(rows)


def _definition(senior):
    template = next(t for t in senior.get("/scenarios").json()["templates"] if t["id"] == "auth_then_lookup_variation")
    assert template["executable"] and "인증 '성공'은 이 시나리오로 알 수 없습니다" in template["caution"]
    return {"name": "인증 뒤 회원 조회 대상 변화", "purpose": template["purpose"], "kind": template["kind"], "host": "svc.example.test",
            "template": template["id"], "normal_note": template["normal_note"], **template["defaults"], "min_count": 6}


def test_a_scenario_is_built_from_a_template_tried_saved_and_used_by_the_next_hunt(senior):
    """Acceptance 9, 11, 12, 18, 20: no code, no model; reversed order, window edge, duplicates and a normal batch."""
    org = _org(senior)
    inv = _inv(senior, org, "scenario")
    _process(senior, inv["id"], "ndr.csv", _data().encode())
    definition = _definition(senior)
    said = senior.post("/scenarios/describe", json={"content": definition}).json()
    assert said["description"] == ("같은 출발지 IP(같은 사용자라는 근거는 아님)에서 '인증 관련 접근'(모든 메서드 /auth.html) 뒤 10분 안에 "
                                   "'회원정보 조회'(모든 메서드 /memberinfo)을(를) 서로 다른 id 값 6개 이상 요청한 흐름")
    assert said["unit"] == "서로 다른 id 값의 수"

    p = senior.post(f"/investigations/{inv['id']}/scenarios/preview", json={"content": definition}).json()
    assert p["status"] == "found" and p["scope"]["range"] == "이 헌팅의 전체 자료"
    assert [(m["entity"], m["count"]) for m in p["matches"]] == [("10.60.1.10", 6)]  # the duplicate is one request, six members
    kinds = {n["kind"]: n for n in p["near"]}
    assert kinds["reversed"]["entity"] == "10.60.1.20" and "먼저 관측됨" in kinds["reversed"]["text"]
    assert kinds["outside_window"]["entity"] == "10.60.1.30" and "시간창 600초 밖" in kinds["outside_window"]["text"]
    below = [n["text"] for n in p["near"] if n["kind"] == "below"]
    assert any(t.startswith("10.60.1.30: 조건 미달") and "5 (기준 6)" in t for t in below)
    assert any(t.startswith("10.60.1.40: 조건 미달") and " 1 (기준 6)" in t for t in below)  # a batch on one member
    assert not any("10.60.1.50" in str(m) for m in p["matches"])  # the other service is not this scenario
    assert any("NAT" in note for note in p["notes"]) and p["examined"]["records_read"] > 0

    # A required field that the logs do not have, and a link criterion that is not registered, are said — not an empty result.
    by_session = senior.post(f"/investigations/{inv['id']}/scenarios/preview", json={"content": {**definition, "entity": "session"}}).json()
    assert by_session["status"] == "insufficient_data" and "세션 식별 쿠키" in by_session["missing"][0]
    no_alerts = senior.post(f"/investigations/{inv['id']}/scenarios/preview", json={"content": {
        "name": "x", "kind": "alert_then_traffic", "min_count": 1, "window_seconds": 300}}).json()
    assert no_alerts["status"] == "insufficient_data" and no_alerts["status_label"] == "자료 부족"
    missing = senior.post("/scenarios/describe", json={"content": {**definition, "count_param": ""}})
    assert missing.status_code in (400, 422)

    # Saved as a draft: tried only. Activated: the next hunt uses it, and its version is recorded with the run.
    saved = senior.post("/knowledge/flow-items", json={"kind": "scenario", "org_unit_id": org["id"], "content": definition}).json()
    assert saved["version"] == 1
    draft_run = senior.post(f"/investigations/{inv['id']}/hunt/run", json={}).json()
    assert not [m for m in draft_run["methods"] if m["id"].startswith("scenario.")]
    active = senior.put(f"/knowledge/flow-items/{saved['id']}", json={"expected_version": 1, "content": {**definition, "state": "active"}}).json()
    run = senior.post(f"/investigations/{inv['id']}/hunt/run", json={}).json()
    method = next(m for m in run["methods"] if m["id"] == f"scenario.{saved['id']}")
    assert method["status"] == "found" and method["scenario_version"] == active["version"] == 2
    activity = next(a for a in run["activities"] if a["method"] == f"scenario.{saved['id']}")
    assert "10.60.1.10" in activity["title"] and any("v2의 조건을 만족" in line for line in activity["why"])
    assert run["versions"]["knowledge"][saved["id"]] == 2
    # Editing afterwards makes a new version; the earlier run keeps the version it used.
    senior.put(f"/knowledge/flow-items/{saved['id']}", json={"expected_version": 2, "content": {**definition, "state": "active", "min_count": 99}})
    listed = senior.get("/scenarios", params={"org_unit_id": org["id"]}).json()["scenarios"][0]
    assert listed["version"] == 3 and listed["run_state"] == "다음 헌팅부터 사용"
    later = senior.post(f"/investigations/{inv['id']}/hunt/run", json={}).json()
    assert next(m for m in later["methods"] if m["id"] == f"scenario.{saved['id']}")["status"] == "no_match"
    assert run["versions"]["knowledge"][saved["id"]] == 2


def test_templates_say_which_are_executable_and_device_scenarios_report_what_they_saw(senior):
    templates = {t["id"]: t for t in senior.get("/scenarios").json()["templates"]}
    assert len(templates) == 19 and sum(1 for t in templates.values() if t["executable"]) == 15
    assert all(t.get("reason") for t in templates.values() if not t["executable"])  # never an empty success
    inv = _inv(senior, _org(senior), "devices")
    sample = flow_samples.build(background_sessions=3)
    for name in ("ndr.csv", "waf.csv", "ips.csv", "fw.csv", "ddos.csv"):
        _process(senior, inv["id"], name, sample[name].encode())
    alert = senior.post(f"/investigations/{inv['id']}/scenarios/preview", json={"content": {
        "name": "경보 뒤 통신", "kind": "alert_then_traffic", "min_count": 1, "window_seconds": 300}}).json()
    assert alert["status"] == "found" and alert["examined"]["alerts"] == 2
    assert any("공격 성공이나 같은 요청이라는 근거가 아닙니다" in n for n in alert["notes"])
    assert all("통신" in m["title"] and "장비 조치" in m["title"] for m in alert["matches"])
    ddos = senior.post(f"/investigations/{inv['id']}/scenarios/preview", json={"content": {"name": "d", "kind": "ddos_window_access"}}).json()
    assert ddos["status"] == "found" and "같은 공격자의 행위로 묶지 않습니다" in ddos["notes"][0]


def test_a_scenario_written_from_scratch_runs_three_steps_and_a_text_condition(senior, manager, admin):
    """No template: the analyst picks how to look, writes the steps and an optional text the request must contain."""
    from saw.core.security.authz import ALL_PERMISSIONS

    catalog = senior.get("/scenarios").json()
    assert {k["kind"] for k in catalog["kinds"]} == {"threshold", "sequence", "then_variation", "periodic_external", "spread_internal",
                                                    "alert_then_traffic", "ddos_window_access"}
    assert all(k["name"] and k["hint"] and k["needs"] for k in catalog["kinds"])
    org = _org(senior)
    inv = _inv(senior, org, "own scenario")
    rows = [
        # A: the three steps in order, the last one with mode=all.
        _row("09:00:00", "10.61.1.10", "POST", "/login", "-"), _row("09:01:00", "10.61.1.10", "GET", "/report/list", "-"),
        _row("09:02:00", "10.61.1.10", "GET", "/report/export", "mode=all"),
        # B: the same paths, but the export is for one page only.
        _row("10:00:00", "10.61.1.20", "POST", "/login", "-"), _row("10:01:00", "10.61.1.20", "GET", "/report/list", "-"),
        _row("10:02:00", "10.61.1.20", "GET", "/report/export", "mode=page"),
    ]
    _process(senior, inv["id"], "ndr.csv", (H + "".join(rows)).encode())
    own = {"name": "보고서 전체 내려받기", "kind": "sequence", "host": "svc.example.test", "window_seconds": 600, "min_count": 1, "template": "",
           "steps": [{"label": "로그인", "method": "POST", "path": "/login"}, {"label": "보고서 화면", "path": "/report/", "match": "prefix"},
                     {"label": "전체 내려받기", "method": "GET", "path": "/report/export", "contains": "mode=all"}]}
    said = senior.post("/scenarios/describe", json={"content": own}).json()
    assert "'전체 내려받기'(GET /report/export, 'mode=all' 포함)" in said["description"]
    p = senior.post(f"/investigations/{inv['id']}/scenarios/preview", json={"content": own}).json()
    assert p["status"] == "found" and [m["entity"] for m in p["matches"]] == ["10.61.1.10"]
    # Without the text condition both actors complete the order.
    loose = {**own, "steps": [*own["steps"][:2], {**own["steps"][2], "contains": ""}]}
    both = senior.post(f"/investigations/{inv['id']}/scenarios/preview", json={"content": loose}).json()
    assert sorted(m["entity"] for m in both["matches"]) == ["10.61.1.10", "10.61.1.20"]

    # The manager and the administrator hold every permission: both can save it, try it on any hunt and open the hunt.
    for lead in (manager, admin):
        assert set(lead.get("/auth/me").json()["permissions"]) == set(ALL_PERMISSIONS)
        saved = lead.post("/knowledge/flow-items", json={"kind": "scenario", "org_unit_id": org["id"], "content": {**own, "name": own["name"] + lead.get("/auth/me").json()["username"]}})
        assert saved.status_code == 201, saved.text
        assert lead.post(f"/investigations/{inv['id']}/scenarios/preview", json={"content": own}).json()["status"] == "found"
        assert lead.get(f"/investigations/{inv['id']}/hunt").status_code == 200


FW = flow_samples.FW_HEADER + "\n"


def _fw(t, src, dst, port, action="allow", sent=600, rcvd=1800):
    return f"2026-10-20 {t},192.0.2.1,fw-syn-01,{action},{src},50000,{dst},{port},TCP,SA,30,{sent},{rcvd}\n"


def test_a_threshold_scenario_finds_volume_counts_and_distinct_values_on_device_records(senior):
    """The analyst's own hunt: which records, grouped by what, how much within how long - for FW, web, IPS, WAF, DDoS."""
    catalog = senior.get("/scenarios").json()
    assert "threshold" in {k["kind"] for k in catalog["kinds"]}
    options = catalog["threshold_options"]
    assert {x["id"] for x in options["sources"]} == {"fw", "web", "waf", "ips", "ddos", "app"}
    assert all(x["name"] for part in ("fields", "ops", "group_by", "measures") for x in options[part])
    org = _org(senior)
    inv = _inv(senior, org, "threshold")
    mb = 1024 * 1024
    rows = [
        # A: 60 MB to one destination inside ten minutes (three records), then quiet.
        _fw("09:00:00", "10.70.1.10", "198.51.100.7", 443, sent=20 * mb, rcvd=0), _fw("09:04:00", "10.70.1.10", "198.51.100.7", 443, sent=20 * mb, rcvd=0),
        _fw("09:08:00", "10.70.1.10", "198.51.100.7", 443, sent=20 * mb, rcvd=0),
        # B: the same 60 MB spread over an hour: never 50 MB inside ten minutes.
        *[_fw(f"10:{m:02d}:00", "10.70.1.20", "198.51.100.8", 443, sent=20 * mb, rcvd=0) for m in (0, 25, 50)],
        # C: twelve blocked attempts on twelve ports inside one minute.
        *[_fw(f"11:00:{k:02d}", "10.70.1.30", "10.70.9.9", 1000 + k, action="deny", sent=60, rcvd=0) for k in range(12)],
        # D: allowed ordinary traffic.
        *[_fw(f"12:0{k}:00", "10.70.1.40", "10.70.9.9", 443) for k in range(5)],
    ]
    _process(senior, inv["id"], "fw.csv", (FW + "".join(rows)).encode())
    url = f"/investigations/{inv['id']}/scenarios/preview"

    volume = {"name": "10분에 50MB 이상", "kind": "threshold", "sources": ["fw"], "group_by": "pair", "measure": "bytes_total", "threshold": 50,
              "byte_unit": "MB", "window_seconds": 600}
    said = senior.post("/scenarios/describe", json={"content": volume}).json()
    assert said["description"] == "방화벽·연결 기록을 같은 출발지 → 목적지(으)로 묶어, 10분 안에 전송량 합계(보낸 양+받은 양)이(가) 50MB 이상인 경우"
    p = senior.post(url, json={"content": volume}).json()
    assert p["status"] == "found" and [m["entity"] for m in p["matches"]] == ["10.70.1.10 → 198.51.100.7"]
    m = p["matches"][0]
    assert m["count"] == 60.0 and m["records"] == 3 and len(m["event_ids"]) == 3 and "기준 50MB" in m["title"]
    assert any(n["kind"] == "below" and "10.70.1.20" in n["text"] and "20.0MB" in n["text"] for n in p["near"])  # spread over an hour
    assert any("움직이는 구간" in n for n in p["notes"]) and any("방향은 장비가 기록한 열" in n for n in p["notes"])

    blocked = {"name": "차단 반복", "kind": "threshold", "sources": ["fw"], "conditions": [{"field": "enforcement_action", "value": "차단"}],
               "group_by": "src_ip", "measure": "records", "threshold": 10, "window_seconds": 60}
    p = senior.post(url, json={"content": blocked}).json()
    assert [(m["entity"], m["count"]) for m in p["matches"]] == [("10.70.1.30", 12)]
    assert p["examined"]["records_matching_conditions"] == 12
    ports = {**blocked, "name": "포트 여러 개", "conditions": [{"field": "dst_ip", "value": "10.70.0.0/16"}], "measure": "distinct_dst_port"}
    p = senior.post(url, json={"content": ports}).json()
    assert [(m["entity"], m["count"]) for m in p["matches"]] == [("10.70.1.30", 12)]  # D reaches one port only
    none = senior.post(url, json={"content": {**blocked, "threshold": 500}}).json()
    assert none["status"] == "no_match" and any("10.70.1.30" in n["text"] and "12" in n["text"] for n in none["near"])
    # And / or: (blocked and port 1000..1005) or (the 60 MB destination). Groups are joined by "or", the first is "all".
    mixed = {"name": "섞은 조건", "kind": "threshold", "sources": ["fw"], "group_by": "src_ip", "measure": "records", "threshold": 3, "window_seconds": 600,
             "groups_mode": "any", "condition_groups": [
                 {"mode": "all", "conditions": [{"field": "enforcement_action", "value": "차단"}, {"field": "dst_port", "op": "lte", "value": "1005"}]},
                 {"mode": "any", "conditions": [{"field": "dst_ip", "value": "198.51.100.7"}, {"field": "dst_port", "value": "9999"}]}]}
    said = senior.post("/scenarios/describe", json={"content": mixed}).json()["description"]
    assert "[(조치 = 차단 그리고 목적지 포트 ≤ 1005) 또는 (목적지 IP = 198.51.100.7 또는 목적지 포트 = 9999)]인 것" in said
    p = senior.post(url, json={"content": mixed}).json()
    assert sorted((m["entity"], m["count"]) for m in p["matches"]) == [("10.70.1.10", 3), ("10.70.1.30", 6)]
    assert p["examined"]["records_matching_conditions"] == 9
    both = senior.post(url, json={"content": {**mixed, "groups_mode": "all"}}).json()  # no record is in both groups
    assert both["status"] == "no_match" and both["examined"]["records_matching_conditions"] == 0
    # The plain list of older definitions is one more "all" group.
    legacy = senior.post(url, json={"content": {**mixed, "groups_mode": "all", "conditions": [{"field": "src_ip", "value": "10.70.1.30"}],
                                               "condition_groups": mixed["condition_groups"][:1]}}).json()
    assert [(m["entity"], m["count"]) for m in legacy["matches"]] == [("10.70.1.30", 6)]
    # A source this hunt does not have is "not checked", never an empty result.
    absent = senior.post(url, json={"content": {**blocked, "sources": ["ips"], "conditions": []}}).json()
    assert absent["status"] == "insufficient_data" and absent["missing"] == ["IPS 기록"]

    # Saved as active, the next hunt runs it and the activity shows its records.
    saved = senior.post("/knowledge/flow-items", json={"kind": "scenario", "org_unit_id": org["id"], "content": {**volume, "state": "active"}})
    assert saved.status_code == 201, saved.text
    run = senior.post(f"/investigations/{inv['id']}/hunt/run").json()
    method = next(x for x in run["methods"] if x["id"] == f"scenario.{saved.json()['id']}")
    assert method["status"] == "found" and method["found"] == 1
    activity = next(a for a in run["activities"] if a["method"] == method["id"])
    assert "60.0MB" in activity["title"]
    ev = senior.get(f"/investigations/{inv['id']}/hunt/activities/{activity['id']}/evidence").json()
    assert len(ev["rows"]) == 3 and all(r["src"] == "10.70.1.10" for r in ev["rows"])
    mine = next(x for x in senior.get("/scenarios").json()["scenarios"] if x["id"] == saved.json()["id"])
    assert mine["needs"] == ["방화벽·연결 기록"] and "50MB 이상" in mine["description"]


def test_threshold_scenarios_run_on_web_ips_waf_and_ddos_records_and_errors_are_in_plain_words(senior):
    inv = _inv(senior, _org(senior), "threshold devices")
    sample = flow_samples.build(background_sessions=3)
    for name in ("ndr.csv", "waf.csv", "ips.csv", "fw.csv", "ddos.csv"):
        _process(senior, inv["id"], name, sample[name].encode())
    url = f"/investigations/{inv['id']}/scenarios/preview"
    templates = {t["id"]: t for t in senior.get("/scenarios").json()["templates"] if t.get("kind") == "threshold"}
    assert set(templates) == {"fw_volume", "fw_blocked_burst", "fw_port_sweep", "ips_alert_burst", "alert_many_names", "waf_block_burst",
                              "web_error_burst", "web_large_response", "ddos_repeat"}
    for t in templates.values():  # every shipped example is a valid definition and runs on the data it names
        body = {"name": t["name"], "kind": "threshold", **t["defaults"], "threshold": 1, "byte_unit": "KB", "conditions": []}
        out = senior.post(url, json={"content": body})
        assert out.status_code == 200, (t["id"], out.text)
        assert out.json()["status"] == "found", (t["id"], out.json()["status"], out.json()["missing"], out.json()["notes"])
        assert senior.post("/scenarios/describe", json={"content": {"name": "", "kind": "threshold", **t["defaults"]}}).status_code == 200
    ips = senior.post(url, json={"content": {"name": "i", "kind": "threshold", "sources": ["ips", "waf"], "group_by": "alert_name",
                                             "measure": "records", "threshold": 1, "window_seconds": 3600}}).json()
    assert ips["status"] == "found" and all(m["entity"] for m in ips["matches"])

    # What the analyst typed wrong comes back in plain Korean, not as the library's message.
    bad = senior.post("/knowledge/flow-items", json={"kind": "scenario", "content": {"name": "", "kind": "threshold", "sources": ["fw"], "threshold": 5}})
    assert bad.status_code == 400 and "'이름'을(를) 적어 주세요." in bad.json()["detail"] and "validation error" not in bad.json()["detail"]
    for body, words in (({"name": "x", "kind": "threshold", "threshold": 5}, "어떤 자료에서 찾을지"),
                        ({"name": "x", "kind": "threshold", "sources": ["fw"]}, "기준 값을 0보다 크게"),
                        ({"name": "x", "kind": "threshold", "sources": ["fw"], "threshold": 2.5}, "정수로 적어 주세요"),
                        ({"name": "x", "kind": "sequence", "steps": [{"label": "a", "path": "nope"}, {"label": "b", "path": "/b"}]}, "/로 시작해야 합니다")):
        r = senior.post(url, json={"content": body})
        assert r.status_code == 400 and words in r.json()["detail"], r.text
