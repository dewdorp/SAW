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
    assert len(templates) == 10 and sum(1 for t in templates.values() if t["executable"]) == 6
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
