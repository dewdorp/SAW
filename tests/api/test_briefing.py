"""Report summary for people who do not read logs, and the manager's board."""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy import select

from saw.devtools.sample_data import gz_bytes, scenario_weblog
from saw.storage.db import session_scope, utcnow
from saw.storage.models import AuditEvent, Investigation
from tests.api.test_phase5_bulk import upload
from tests.conftest import Api, make_user


def _inv(api, title="고객 API 대량 조회", **kw):
    inv = api.post("/investigations", json={"title": title}).json()
    up = upload(api, inv["id"], "a.log.gz", gz_bytes(scenario_weblog(**(kw or {"normal": 300, "enum_count": 400}))))
    api.post(f"/evidence/{up['evidence_id']}/process")
    return inv


def test_open_investigation_summary_is_generated_in_plain_words(analyst):
    inv = _inv(analyst)
    b = analyst.get(f"/investigations/{inv['id']}/briefing").json()
    assert b["investigation"]["status_ko"] and b["investigation"]["verdict_ko"] is None
    assert b["facts"]["events"] > 0 and b["facts"]["files"] == 1 and b["facts"]["findings_total"] > 0
    assert b["facts"]["sources"][0]["label"] == "웹 서버·NDR 요청 기록"
    assert "판정 전" in b["text"]["headline"]
    assert b["top_findings"] and all(t["what"] and t["fact"] and t["risk_ko"] for t in b["top_findings"])
    assert b["text"]["what"] and b["text"]["todo"]                      # advice of the detections becomes "what is left"
    assert any("종결되지 않은" in c for c in b["caveats"])
    assert b["masked"] is True and b["can_edit"] is True and b["edit"] is None
    # addresses are shortened unless the full view is asked for
    assert ".***" in b["text"]["what"] or ".***" in b["text"]["impact"]
    full = analyst.get(f"/investigations/{inv['id']}/briefing?mask=false").json()
    assert ".***" not in full["text"]["what"] + full["text"]["impact"]


def test_closed_investigation_uses_the_analysts_verdict_and_response(analyst):
    inv = _inv(analyst)
    analyst.post(f"/investigations/{inv['id']}/close", json={
        "verdict": "attack", "reason": "동일 UA·분산 IP로 고객 번호 순차 조회 확인\n추가 설명", "checks": ["배치 스케줄 확인"],
        "response": "WAF 속도 제한 적용 요청", "detection_idea": "경로별 10분 500회 이상"})
    b = analyst.get(f"/investigations/{inv['id']}/briefing").json()
    assert b["text"]["headline"] == "공격으로 판정. 동일 UA·분산 IP로 고객 번호 순차 조회 확인"
    assert "WAF 속도 제한 적용 요청" in b["text"]["done"] and "확인함: 배치 스케줄 확인" in b["text"]["done"]
    assert "재발 탐지 방안" in b["text"]["todo"]
    assert not any("종결되지 않은" in c for c in b["caveats"])


def test_rewritten_sections_win_and_empty_ones_fall_back(analyst, manager, app):
    inv = _inv(analyst)
    url = f"/investigations/{inv['id']}/briefing"
    auto = analyst.get(url).json()["auto"]
    r = manager.put(url, json={"fields": {"headline": "고객 정보 대량 조회 시도, 차단 완료", "impact": "유출 확인되지 않음",
                                          "unknown": "x"}})   # a manager may edit any investigation
    assert r.status_code == 200, r.text
    b = r.json()
    assert b["text"]["headline"] == "고객 정보 대량 조회 시도, 차단 완료" and b["text"]["what"] == auto["what"]
    assert b["edited"] == {"headline": "고객 정보 대량 조회 시도, 차단 완료", "impact": "유출 확인되지 않음"}
    assert b["edit"]["by"] == "manager1" and b["edit"]["rev"] == 1
    b = manager.put(url, json={"fields": {"headline": "  ", "impact": "유출 확인되지 않음"}}).json()
    assert b["text"]["headline"] == auto["headline"] and b["edit"]["rev"] == 2
    make_user("v1", ["viewer"])
    viewer = Api(app, "v1")
    assert viewer.put(url, json={"fields": {"headline": "x"}}).status_code in (403, 404)
    with session_scope() as s:
        acts = s.execute(select(AuditEvent.detail).where(AuditEvent.action == "briefing.update")).scalars().all()
    assert [a["sections"] for a in acts] == [["headline", "impact"], ["impact"]]


def test_printable_page_is_self_contained_escaped_and_audited(analyst):
    inv = _inv(analyst, title="<script>alert(1)</script> 조사")
    analyst.put(f"/investigations/{inv['id']}/briefing", json={"fields": {"done": "<b>차단</b> 완료\n담당자 통보"}})
    r = analyst.get(f"/investigations/{inv['id']}/briefing.html")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/html")
    assert "style-src 'unsafe-inline'" in r.headers["content-security-policy"] and "attachment" in r.headers["content-disposition"]
    page = r.text
    assert "<script" not in page and "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert "&lt;b&gt;차단&lt;/b&gt; 완료" in page and "<li>담당자 통보</li>" in page
    for heading in ("무슨 일이 있었나", "영향", "조치한 내용", "남은 일", "근거", "분석한 자료", "유의할 점"):
        assert heading in page
    assert "http://" not in page and "https://" not in page          # nothing is loaded from elsewhere
    with session_scope() as s:
        assert s.execute(select(AuditEvent).where(AuditEvent.action == "briefing.export")).scalars().first() is not None


def test_board_shows_everything_to_the_manager_and_only_own_work_to_analysts(app, analyst, manager):
    mine = _inv(analyst, title="A 조사")
    make_user("a2", ["analyst"])
    other = Api(app, "a2")
    theirs = other.post("/investigations", json={"title": "B 조사"}).json()
    analyst.post(f"/investigations/{mine['id']}/close", json={"verdict": "false_positive", "reason": "배치 작업"})
    with session_scope() as s:                     # B has been untouched for ten days
        b = s.get(Investigation, theirs["id"])
        b.created_at = utcnow() - timedelta(days=10)
        for a in s.execute(select(AuditEvent).where(AuditEvent.investigation_id == theirs["id"])).scalars():
            a.at = utcnow() - timedelta(days=10)   # test-only: the chain is not checked here
    m = manager.get("/board?days=30").json()
    assert m["scope"] == "all" and {r["display_id"] for r in m["rows"]} >= {mine["display_id"], theirs["display_id"]}
    row = {r["display_id"]: r for r in m["rows"]}
    assert row[theirs["display_id"]]["stale"] is True and row[theirs["display_id"]]["idle_days"] >= 10
    assert row[mine["display_id"]]["verdict_ko"] == "오탐으로 판정" and row[mine["display_id"]]["stale"] is False
    assert m["tiles"]["open"] == 1 and m["tiles"]["stale"] == 1 and m["tiles"]["closed"] == 1
    assert next(v for v in m["by_verdict"] if v["key"] == "false_positive")["count"] == 1
    assert m["by_owner"][0]["open"] == 1 and sum(w["closed"] for w in m["weeks"]) == 1
    assert m["rows"][0]["status"] != "closed"                       # what needs attention comes first
    a = analyst.get("/board").json()
    assert a["scope"] == "mine" and [r["display_id"] for r in a["rows"]] == [mine["display_id"]]
    make_user("adm", ["admin"])
    adm = Api(app, "adm").get("/board").json()                      # the administrator can use every function
    assert adm["scope"] == "all" and {r["display_id"] for r in adm["rows"]} >= {mine["display_id"], theirs["display_id"]}
    make_user("vw", ["viewer"])
    assert Api(app, "vw").get("/board").json()["rows"] == []         # a viewer who is on no investigation sees none


def test_wording_helpers():
    from datetime import UTC, datetime

    from saw.core.application.briefing import _is_internal, _listed, _period, hide

    a = datetime(2026, 10, 6, 1, 10, 5, tzinfo=UTC)
    assert _period(a, a.replace(second=50)) == "10-06 10:10"                       # same minute: one time
    assert _period(a, a.replace(minute=25)) == "10-06 10:10 ~ 10:25"
    assert _period(a, a.replace(day=7)) == "10-06 10:10 ~ 10-07 10:10"
    assert _is_internal("10.20.1.15") and _is_internal("192.168.0.9") and not _is_internal("203.0.113.66")
    assert _listed(["10.20.1.15", "10.20.1.21", "10.20.5.33"], True, 6) == "10.20.1.***, 10.20.5.***"
    assert _listed(["10.20.1.15", "10.20.1.21"], False, 1) == "10.20.1.15 등"
    assert hide("198.51.100.7 → 10.0.0.1, v1.2.3.4.5", True) == "198.51.100.*** → 10.0.0.***, v1.2.3.4.5"
