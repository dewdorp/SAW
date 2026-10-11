"""Support requests (one separate question to a colleague) and the five-point check before closing."""
from __future__ import annotations

from saw.devtools.sample_data import gz_bytes, scenario_weblog
from tests.api.test_phase5_bulk import upload
from tests.conftest import Api, make_user


def _inv(api, title="조사"):
    inv = api.post("/investigations", json={"title": title}).json()
    up = upload(api, inv["id"], "a.log.gz", gz_bytes(scenario_weblog(normal=300, enum_count=400)))
    api.post(f"/evidence/{up['evidence_id']}/process")
    return inv


def _person(api, username: str) -> dict:
    return next(p for p in api.get("/reviews/reviewers").json() if p["username"] == username)


def test_support_is_one_question_to_a_colleague_and_the_owner_stays_the_owner(app, analyst, senior, manager):
    inv = _inv(analyst)
    base = f"/investigations/{inv['id']}"
    sr, mg = _person(analyst, "senior1"), _person(analyst, "manager1")
    assert senior.get(base).status_code in (403, 404)
    assert analyst.post(f"{base}/support", json={"question": "봐줘", "helper_id": sr["id"]}).status_code == 400   # not a question
    r = analyst.post(f"{base}/support", json={"question": "응답과 패킷에서 실행 성공 여부 확인", "scope_note": "03시 이후 요청",
                                             "helper_id": sr["id"]}).json()
    assert r["status"] == "requested" and r["helper"] == "senior1" and r["open"] is True
    box = senior.get("/support/inbox").json()["items"]
    assert [x["id"] for x in box] == [r["id"]] and box[0]["investigation"]["display_id"] == inv["display_id"]
    # the helper can now work in the investigation: record what they checked
    ev = senior.post(f"{base}/query/events", json={"filters": [], "limit": 1}).json()["events"][0]
    c = senior.post(f"{base}/checks", json={"target_type": "event", "target_key": ev["event_id"], "questions": ["success"],
                                            "judgement": "undetermined", "note": "응답 본문 없음"})
    assert c.status_code == 201 and c.json()["author"] == "senior1"
    # only the helper reports on it; "done" needs a result
    assert analyst.post(f"/support/{r['id']}", json={"status": "done", "result_note": "대신 완료"}).status_code == 404
    assert senior.post(f"/support/{r['id']}", json={"status": "working"}).json()["status_ko"] == "진행 중"
    assert senior.post(f"/support/{r['id']}", json={"status": "done", "result_note": ""}).status_code == 400
    done = senior.post(f"/support/{r['id']}", json={"status": "done", "result_note": "성공 응답 12건 확인",
                                                    "remaining": "응답 본문은 캡처에 없음"}).json()
    assert done["status"] == "done" and done["open"] is False and done["remaining"] == "응답 본문은 캡처에 없음"
    assert senior.get("/support/inbox").json()["items"] == []
    # the helper's answer does not close anything, and a helper is not an independent reviewer of the conclusion
    out = analyst.post(f"{base}/close", json={"verdict": "attack", "reason": "순차 조회 확인", "limits": "응답 본문 미확보"}).json()
    assert out["status"] == "closed"
    bad = analyst.post(f"{base}/reviews", json={"subject_type": "conclusion", "conclusion": "공격으로 판정", "reviewer_id": sr["id"]})
    assert bad.status_code == 400 and "지원한 사람" in bad.text
    assert analyst.post(f"{base}/reviews", json={"subject_type": "conclusion", "conclusion": "공격으로 판정",
                                                "reviewer_id": mg["id"]}).status_code == 201
    b = analyst.get(f"{base}/briefing").json()
    assert any("범위 제한: 응답 본문 미확보" in x for x in b["caveats"])    # closed with limits, and it says so
    # others cannot hand out work in someone else's investigation; the manager can
    make_user("a2", ["analyst"])
    other = Api(app, "a2")
    assert other.post(f"{base}/support", json={"question": "다른 자산 영향 확인", "helper_id": sr["id"]}).status_code in (400, 403, 404)
    m = manager.post(f"{base}/support", json={"question": "다른 자산 영향 확인", "helper_id": sr["id"]}).json()
    assert manager.post(f"{base}/support/{m['id']}/cancel").json()["status"] == "cancelled"
    row = next(x for x in manager.get("/board").json()["rows"] if x["id"] == inv["id"])
    assert row["support_open"] == 0


def test_closing_check_has_five_points_and_names_what_is_open(analyst, senior):
    inv = _inv(analyst)
    base = f"/investigations/{inv['id']}"
    items = analyst.get(f"{base}/closing-check").json()["items"]
    assert [x["key"] for x in items] == ["scope", "questions", "attack", "todo", "review"]
    by = {x["key"]: x for x in items}
    assert not by["scope"]["ok"] and any("직접 확인해 남긴 기록이 없습니다" in ln for ln in by["scope"]["lines"])
    assert not by["questions"]["ok"] and "평가하지 않았습니다" in by["questions"]["lines"][0]
    assert not by["attack"]["ok"] and len(by["attack"]["lines"]) == 2    # neither success nor damage was looked at
    assert by["todo"]["ok"] and by["review"]["ok"]
    # work through it: rate the detections, record success and impact, on the same target with opposite judgements
    for f in analyst.get(f"{base}/findings").json():
        if f["risk_level"] in ("critical", "high"):
            analyst.post(f"{base}/findings/{f['id']}/feedback", json={"verdict": "valid"})
    ip = analyst.post(f"{base}/query/aggregate", json={"filters": [], "agg": {"type": "terms", "field": "src_ip", "size": 1}}).json()["buckets"][0]["key"]
    mk = lambda q, j: analyst.post(f"{base}/checks", json={"target_type": "entity", "target_key": f"ip:{ip}", "target_label": ip,  # noqa: E731
                                                           "questions": [q], "judgement": j, "note": "근거"}).raise_for_status()
    mk("success", "malicious")
    mk("impact", "normal")
    mk("success", "normal")                                              # contradicts the first record on the same question
    sr = _person(analyst, "senior1")
    analyst.post(f"{base}/support", json={"question": "다른 자산 영향 확인", "helper_id": sr["id"]}).raise_for_status()
    by = {x["key"]: x for x in analyst.get(f"{base}/closing-check").json()["items"]}
    assert by["attack"]["ok"]
    assert any("'정상'과 '악성'" in ln and ip in ln for ln in by["questions"]["lines"])
    assert not any("평가하지 않았습니다" in ln for ln in by["questions"]["lines"])
    assert not by["todo"]["ok"] and "senior1" in by["todo"]["lines"][0]
    # nothing of this blocks closing
    assert analyst.post(f"{base}/close", json={"verdict": "attack", "reason": "확인"}).json()["status"] == "closed"
    by = {x["key"]: x for x in analyst.get(f"{base}/closing-check").json()["items"]}
    assert not by["review"]["ok"] and "조사 결론" in by["review"]["lines"][0] or "검토자 지정 필요" in by["review"]["lines"][0]
