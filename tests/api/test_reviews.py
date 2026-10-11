"""Peer review of important conclusions: when it is owed, who may answer, and what an approval is worth later."""
from __future__ import annotations

from sqlalchemy import select

from saw.devtools.sample_data import gz_bytes, scenario_weblog
from saw.storage.db import session_scope
from saw.storage.models import AuditEvent
from tests.api.test_phase5_bulk import upload
from tests.conftest import Api, make_user


def _inv(api, title="조사"):
    inv = api.post("/investigations", json={"title": title}).json()
    up = upload(api, inv["id"], "a.log.gz", gz_bytes(scenario_weblog(normal=300, enum_count=400)))
    api.post(f"/evidence/{up['evidence_id']}/process")
    return inv


def _high(api, inv_id: str) -> dict:
    fs = api.get(f"/investigations/{inv_id}/findings").json()
    return next(f for f in fs if f["risk_level"] in ("critical", "high"))


def _low(api, inv_id: str) -> dict | None:
    fs = api.get(f"/investigations/{inv_id}/findings").json()
    return next((f for f in fs if f["risk_level"] in ("low", "info", "medium")), None)


def _reviews(api, inv_id: str) -> list[dict]:
    return api.get(f"/investigations/{inv_id}/reviews").json()["reviews"]


def test_only_important_calls_create_a_review_need(analyst):
    inv = _inv(analyst)
    hi, lo = _high(analyst, inv["id"]), _low(analyst, inv["id"])
    fb = lambda f, v: analyst.post(f"/investigations/{inv['id']}/findings/{f['id']}/feedback", json={"verdict": v}).json()  # noqa: E731
    assert fb(hi, "valid")["review_needed"] is None                       # confirming a detection needs nobody else
    if lo:
        assert fb(lo, "false_positive")["review_needed"] is None          # low risk: no ceremony
    assert _reviews(analyst, inv["id"]) == []
    need = fb(hi, "false_positive")["review_needed"]                      # lowering a high-risk detection does
    assert need and fb(hi, "benign")["review_needed"] == need             # one open need per subject, not one per click
    r = _reviews(analyst, inv["id"])
    assert len(r) == 1 and r[0]["status"] == "needed" and r[0]["required"] and r[0]["open"] and r[0]["reviewer"] == ""
    assert "정상" in r[0]["conclusion"]
    # the analyst takes the call back: nothing is owed any more
    fb(hi, "valid")
    assert _reviews(analyst, inv["id"])[0]["open"] is False


def test_request_answer_and_what_an_approval_covers(app, analyst, senior):
    inv = _inv(analyst)
    hi = _high(analyst, inv["id"])
    base = f"/investigations/{inv['id']}"
    analyst.post(f"{base}/findings/{hi['id']}/feedback", json={"verdict": "false_positive", "comment": "배치로 보임"})
    people = analyst.get("/reviews/reviewers").json()
    me, sr = "analyst1", next(p for p in people if p["username"] == "senior1")
    assert all(p["username"] != me for p in people) and sr["senior"] is True
    assert senior.get(f"{base}").status_code in (403, 404)                # the reviewer had no access before being asked
    bad = analyst.post(f"{base}/reviews", json={"subject_type": "finding", "subject_id": hi["id"], "conclusion": " ", "reviewer_id": sr["id"]})
    assert bad.status_code == 400
    r = analyst.post(f"{base}/reviews", json={"subject_type": "finding", "subject_id": hi["id"], "reviewer_id": sr["id"],
                                             "conclusion": "정산 배치의 정상 조회로 판단", "scope_note": "02~03시 요청만 확인"}).json()
    assert r["status"] == "requested" and r["required"] is True and r["reviewer"] == "senior1" and r["limits"]
    assert len(_reviews(analyst, inv["id"])) == 1                         # the open need was filled in, not duplicated
    assert senior.get(f"{base}").status_code == 200                       # can now open what they review (read only)
    assert senior.post(f"{base}/findings/{hi['id']}/feedback", json={"verdict": "valid"}).status_code == 403
    box = senior.get("/reviews/inbox").json()["to_review"]
    assert [x["id"] for x in box] == [r["id"]] and box[0]["investigation"]["display_id"] == inv["display_id"]
    # only the person asked answers, and they have to say how far they agree
    assert analyst.post(f"/reviews/{r['id']}/decide", json={"outcome": "approved", "note": "스스로 승인"}).status_code == 404
    assert senior.post(f"/reviews/{r['id']}/decide", json={"outcome": "approved", "note": "ok"}).status_code == 400
    assert senior.post(f"/reviews/{r['id']}/decide", json={"outcome": "agree", "note": "충분히 긴 의견"}).status_code == 400
    back = senior.post(f"/reviews/{r['id']}/decide", json={"outcome": "too_broad", "note": "03시 이후 요청은 확인되지 않음"}).json()
    assert back["status"] == "too_broad" and back["open"] is True and back["status_ko"] == "결론 범위가 너무 넓음"
    assert analyst.get("/reviews/inbox").json()["returned"][0]["id"] == r["id"]
    assert senior.post(f"/reviews/{r['id']}/decide", json={"outcome": "approved", "note": "다시 답변 시도"}).status_code == 400
    # asked again with a narrower conclusion: the earlier answer becomes history
    r2 = analyst.post(f"{base}/reviews", json={"subject_type": "finding", "subject_id": hi["id"], "reviewer_id": sr["id"],
                                              "conclusion": "02~03시 요청에 한해 정상 조회로 판단"}).json()
    ok = senior.post(f"/reviews/{r2['id']}/decide", json={"outcome": "approved", "note": "02~03시 원본 30건 확인, 그 범위에 동의"}).json()
    assert ok["status"] == "approved" and ok["open"] is False and ok["stale"] is False
    rows = {x["id"]: x for x in _reviews(analyst, inv["id"])}
    assert rows[r["id"]]["latest"] is False and rows[r["id"]]["open"] is False and rows[r2["id"]]["latest"] is True
    # the conclusion changes after the approval: the approval no longer covers it
    analyst.post(f"{base}/findings/{hi['id']}/feedback", json={"verdict": "benign"})
    rows = _reviews(analyst, inv["id"])
    assert any(x["status"] == "needed" and x["open"] for x in rows)       # a new need, the old approval is not reused
    old = next(x for x in rows if x["id"] == r2["id"])
    assert old["stale"] is True
    with session_scope() as s:
        acts = [a for (a,) in s.execute(select(AuditEvent.action).where(AuditEvent.action.like("review.%")))]
    assert acts.count("review.request") == 2 and acts.count("review.decide") == 2


def test_closing_as_attack_owes_a_review_without_blocking_the_close(app, analyst, manager):
    inv = _inv(analyst)
    base = f"/investigations/{inv['id']}"
    out = analyst.post(f"{base}/close", json={"verdict": "attack", "reason": "고객 번호 순차 조회 확인", "response": "차단 요청"}).json()
    assert out["status"] == "closed" and out["review_needed"]             # closing is never held up
    r = _reviews(analyst, inv["id"])[0]
    assert r["subject_type"] == "conclusion" and r["status"] == "needed" and r["open"] and "공격으로 판정" in r["conclusion"]
    b = analyst.get(f"{base}/briefing").json()
    assert any("동료 검토" in c for c in b["caveats"])                     # ...but the report says it is unreviewed
    mgr = next(p for p in analyst.get("/reviews/reviewers").json() if p["username"] == "manager1")
    req = analyst.post(f"{base}/reviews", json={"subject_type": "conclusion", "reviewer_id": mgr["id"],
                                               "conclusion": "공격으로 판정: 고객 번호 순차 조회"}).json()
    # a need created by the rules cannot be withdrawn away, only un-assigned
    w = analyst.post(f"{base}/reviews/{req['id']}/withdraw").json()
    assert w["status"] == "needed" and w["open"] is True
    req = analyst.post(f"{base}/reviews", json={"subject_type": "conclusion", "reviewer_id": mgr["id"],
                                               "conclusion": "공격으로 판정: 고객 번호 순차 조회"}).json()
    manager.post(f"/reviews/{req['id']}/decide", json={"outcome": "approved", "note": "순차 조회 근거와 성공 응답 확인"}).raise_for_status()
    b = analyst.get(f"{base}/briefing").json()
    assert not any("동료 검토" in c for c in b["caveats"])
    row = next(x for x in manager.get("/board").json()["rows"] if x["id"] == inv["id"])
    assert row["reviews_open"] == 0
    # a false-positive close owes nothing
    inv2 = _inv(analyst, "오탐 조사")
    assert analyst.post(f"/investigations/{inv2['id']}/close", json={"verdict": "false_positive", "reason": "배치"}).json()["review_needed"] is None


def test_nobody_reviews_their_own_call(app, analyst):
    inv = _inv(analyst)
    with session_scope() as s:
        from saw.storage.models import User

        me = s.execute(select(User.id).where(User.username == "analyst1")).scalar_one()
    r = analyst.post(f"/investigations/{inv['id']}/reviews", json={"conclusion": "내 판단", "reviewer_id": me})
    assert r.status_code == 400
    make_user("adm", ["admin"])
    adm = Api(app, "adm")
    assert all(p["username"] != "adm" for p in analyst.get("/reviews/reviewers").json())   # administrators do not judge cases
    assert adm.get("/reviews/inbox").json() == {"to_review": [], "returned": []}
