"""Hunts: activities are found from the data alone, statuses are kept apart, reviews survive re-runs."""
import uuid

from saw.devtools import flow_samples
from saw.devtools.en_security_samples import fw_csv
from tests.api.test_flow_knowledge import _inv, _org, _register
from tests.api.test_text_uploads import _process

NDR_HEADER = flow_samples.NDR_HEADER + "\n"


def _row(t, ip, path, query, session="-", status=200):
    cookie = f"JSESSIONID={session}" if session != "-" else "-"
    return (f"2026-10-20 {t},site,http,http,TCP,{ip},50000,KR,10.40.1.10,443,KR,10.40.0.2,ndr-syn-01,GET,crm.example.test,"
            f"{path},{query},UA,-,{cookie},u-{uuid.uuid4().hex[:8]},{status},900,300\n")


def _walk():
    """Twelve sources read their own customer record; one source walks sixty different customers, late in the file."""
    rows = []
    for n in range(12):
        for k in range(6):
            rows.append(_row(f"09:{n:02d}:{k:02d}", f"10.50.1.{n + 10}", "/customer/view.do", f"custNo=C{n:04d}"))
    for k in range(700):  # filler so the walker lies beyond the first page and the first groups
        rows.append(_row(f"10:{k // 60:02d}:{k % 60:02d}", f"10.51.{k // 250}.{k % 250 + 2}", "/notice/list.do", "page=1"))
    for k in range(60):
        rows.append(_row(f"15:{k // 60:02d}:{k % 60:02d}", "10.50.9.77", "/customer/view.do", f"custNo=C{9000 + k}"))
    return NDR_HEADER + "".join(rows)


def test_activities_are_found_without_a_suspect_hypothesis_scenario_or_asset(senior):
    """Acceptance 1, 2, 4: affiliate + period + logs only; the planted clue is past the first pages; statuses differ."""
    inv = _inv(senior, _org(senior), "auto hunt")
    _process(senior, inv["id"], "ndr.csv", _walk().encode())
    body = senior.get(f"/investigations/{inv['id']}/hunt").json()
    run = body["run"]
    assert run["mode_label"] == "기본 분석 · AI 미연결" and run["reason"] == "ingest"
    assert body["progress"]["state"] in ("complete", "running") and body["stale"] == []
    methods = {m["id"]: m for m in run["methods"]}
    walker = next(a for a in run["activities"] if a["method"] == "target_variation")
    assert "10.50.9.77" in walker["title"] and "60가지" in walker["title"]
    assert walker["counts"] == {"records": 60, "distinct_targets": 60, "peers": 13, "peer_median": 1}
    assert any("상담" in line for line in walker["normal"]) and any("파라미터 의미 미확인" in line for line in walker["unknown"])
    assert walker["review"]["state"] == "unreviewed"
    # Every record was read, not a sample: the method says how many it examined.
    assert methods["target_variation"]["examined"]["records_read"] == 12 * 6 + 700 + 60
    assert methods["target_variation"]["status"] == "found" and methods["target_variation"]["status_label"] == "후보 있음"
    # No knowledge registered: the flow method says so instead of returning an empty success.
    assert methods["flows"]["status"] == "insufficient_data" and "등록된 업무 의미" in methods["flows"]["needs"][0]
    # A question that needs connection records it does not have is "insufficient data", one that ran and matched nothing is "no match".
    statuses = {m["status"] for m in run["methods"]}
    assert "insufficient_data" in statuses and statuses <= {"found", "no_match", "insufficient_data", "partial"}
    assert run["scope"]["selected_records"] == 832 and run["scope"]["by_source"] == {"web": 832}
    # The evidence of the activity is reachable as a filter on the same data.
    assert {"field": "src_ip", "op": "is", "value": "10.50.9.77"} in walker["evidence"]["filters"]
    # ...and the records themselves are shown with the activity: which rows, how many of how many, chosen how.
    basis = senior.get(f"/investigations/{inv['id']}/hunt/activities/{walker['id']}/evidence").json()
    assert basis["total"] == 60 and basis["shown"] == 20 and basis["basis"]
    assert all(r["src"] == "10.50.9.77" and r["event_id"] and r["time"] and "custNo=" in r["what"] for r in basis["rows"])
    assert senior.get(f"/investigations/{inv['id']}/hunt/activities/nope/evidence").status_code == 404
    listing = senior.get("/hunts").json()
    mine = next(i for i in listing["items"] if i["id"] == inv["id"])
    assert mine["bucket"] == "review" and mine["unreviewed"] == mine["activities"] >= 1


def test_review_states_are_separate_from_results_and_survive_a_rerun(senior):
    """Acceptance 4, 20, 23: a judgement is the analyst's; a re-run keeps it; nothing closes itself as 'normal'."""
    inv = _inv(senior, _org(senior), "review")
    _process(senior, inv["id"], "ndr.csv", _walk().encode())
    run = senior.get(f"/investigations/{inv['id']}/hunt").json()["run"]
    walker = next(a for a in run["activities"] if a["method"] == "target_variation")
    r = senior.post(f"/investigations/{inv['id']}/hunt/reviews", json={"activity_id": walker["id"], "state": "needs_check",
                                                                     "note": "CRM 담당에게 배치 여부 문의"})
    assert r.status_code == 201 and r.json()["state"] == "needs_check"
    assert senior.post(f"/investigations/{inv['id']}/hunt/reviews", json={"activity_id": "nope", "state": "normal_work"}).status_code == 404
    again = senior.post(f"/investigations/{inv['id']}/hunt/run", json={}).json()
    assert again["version"] == run["version"] + 1
    same = next(a for a in again["activities"] if a["id"] == walker["id"])
    assert same["review"]["state"] == "needs_check" and same["review"]["history"][0]["run_version"] == run["version"]
    assert again["summary"]["review"]["needs_check"] == 1
    # New data arrives: the stored run says it is out of date instead of silently standing for the new records.
    _process(senior, inv["id"], "fw.csv", fw_csv("spread"))
    latest = senior.get(f"/investigations/{inv['id']}/hunt").json()
    assert latest["run"]["version"] == again["version"] + 1 and latest["stale"] == []
    assert next(a for a in latest["run"]["activities"] if a["id"] == walker["id"])["review"]["state"] == "needs_check"
    assert any(a["method"] == "q.spread" for a in latest["run"]["activities"])
    senior.post(f"/investigations/{inv['id']}/hunt/reviews", json={"activity_id": walker["id"], "state": "normal_work", "note": "정산 배치로 확인"})
    item = next(i for i in senior.get("/hunts").json()["items"] if i["id"] == inv["id"])
    assert item["status"] != "closed" and item["bucket"] in ("review", "review_done")  # reviewing does not close the hunt


def test_registered_knowledge_turns_flows_into_activities_and_marks_the_run_stale(senior):
    org = _org(senior)
    inv = _inv(senior, org, "flows in hunt")
    sample = flow_samples.build(background_sessions=6)
    for name in ("app.csv", "waf.csv", "ndr.csv"):
        _process(senior, inv["id"], name, sample[name].encode())
    before = senior.get(f"/investigations/{inv['id']}/hunt").json()
    assert not [a for a in before["run"]["activities"] if a["method"] == "flows"]
    _register(senior)
    stale = senior.get(f"/investigations/{inv['id']}/hunt").json()
    assert stale["stale"] == ["등록한 업무 지식이 바뀌었습니다."]
    senior.post(f"/investigations/{inv['id']}/flows/run", json={})
    after = senior.post(f"/investigations/{inv['id']}/hunt/run", json={"reason": "knowledge_changed"}).json()
    flows = [a for a in after["activities"] if a["method"] == "flows"]
    assert any("인증은 실패로 확인됐고" in a["title"] for a in flows)
    failed = next(a for a in flows if "인증은 실패로 확인됐고" in a["title"])
    assert any("실패로 확인된 뒤" in line for line in failed["why"]) and failed["evidence"]["tab"] == "flows"
    assert after["versions"]["knowledge"] and senior.get(f"/investigations/{inv['id']}/hunt").json()["stale"] == []
    # The flow activity shows the records of its steps, in time order, without leaving the activity.
    basis = senior.get(f"/investigations/{inv['id']}/hunt/activities/{failed['id']}/evidence").json()
    assert basis["shown"] >= 2 and "단계로 묶인 기록" in basis["basis"]
    assert [r["time"] for r in basis["rows"]] == sorted(r["time"] for r in basis["rows"])
    assert any("/memberinfo" in r["what"] for r in basis["rows"])


def test_another_analyst_without_access_cannot_read_or_review_a_hunt(senior, app):
    from tests.api.test_golden_candidates import _reader

    inv = _inv(senior, _org(senior), "private")
    _process(senior, inv["id"], "ndr.csv", _walk().encode())
    other = _reader(app)
    assert other.get(f"/investigations/{inv['id']}/hunt").status_code == 403
    assert other.post(f"/investigations/{inv['id']}/hunt/reviews", json={"activity_id": "x", "state": "normal_work"}).status_code == 403
    assert other.get(f"/investigations/{inv['id']}/hunt/activities/x/evidence").status_code == 403
    assert all(i["id"] != inv["id"] for i in other.get("/hunts").json()["items"])
