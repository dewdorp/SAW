"""A question's card, its evidence and its saved condition all point at one scope, and the counts say what was
computed: unique records, what was examined, what is shown. Editing the condition changes the real result."""
import uuid

import pytest

from saw.core.application import question_bundles as qb
from saw.devtools.en_security_samples import fw_csv, ndr_csv
from tests.api.test_text_uploads import _process


def _org(api):
    r = api.post("/source-context/org-units", json={"display_name": f"가상 관계사 {uuid.uuid4().hex[:6]}"})
    assert r.status_code == 201, r.text
    return r.json()


def _inv(api, org=None, start="2026-10-13T00:00:00+09:00", end="2026-10-13T23:59:59+09:00"):
    body = {"title": f"question scope {uuid.uuid4().hex[:6]}", "period_start": start, "period_end": end}
    if org:
        body["org_unit_id"] = org["id"]
    r = api.post("/investigations", json=body)
    assert r.status_code == 201, r.text
    return r.json()


def _bundles(api, inv):
    out = api.get(f"/investigations/{inv['id']}/question-bundles")
    assert out.status_code == 200, out.text
    return out.json()


def _events(api, inv, filters, time):
    found, cursor = [], None
    while True:
        page = api.post(f"/investigations/{inv['id']}/query/events",
                        json={"filters": filters, "time": time, "limit": 500, "cursor": cursor}).json()
        found += page["events"]
        cursor = page.get("next_cursor")
        if not cursor:
            return found


def _preview(api, inv, bundle, **parameters):
    r = api.post(f"/investigations/{inv['id']}/question-bundles/{bundle}/preview", json={"parameters": parameters})
    assert r.status_code == 200, r.text
    return r.json()


def test_a_card_keeps_its_period_and_log_kind_so_its_evidence_is_exactly_its_records(senior):
    inv = _inv(senior, _org(senior))
    _process(senior, inv["id"], "ndr.csv", ndr_csv("large_response_out"))
    _process(senior, inv["id"], "fw.csv", fw_csv("pair_large"))
    out = _bundles(senior, inv)
    assert out["scope"]["investigation_id"] == inv["id"] and out["scope"]["time"]["end_exclusive"] is True
    transfer = next(b for b in out["bundles"] if b["id"] == "transfer")
    # The same src/dst pair from NDR and FW are two layers: two items, never one summed pair.
    kinds = {next(f["value"] for f in i["filters"] if f["field"] == "data_source" and f["op"] == "is"): i for i in transfer["items"]}
    assert set(kinds) == {"web", "connection"}
    for kind, item in kinds.items():
        rows = _events(senior, inv, item["filters"], out["scope"]["time"])
        assert len(rows) == item["records"] and {r["data_source"] for r in rows} == {kind}
    # Rows that carry both directions are one record each: 12 NDR rows + 3 FW rows, not 30.
    assert transfer["records"] == 15


def test_records_outside_the_period_or_in_another_affiliate_never_enter_a_card(senior):
    org_a, org_b = _org(senior), _org(senior)
    inside = _inv(senior, org_a)
    _process(senior, inside["id"], "spread.csv", fw_csv("spread"))
    later = _inv(senior, org_a, start="2026-10-14T00:00:00+09:00", end="2026-10-14T23:59:59+09:00")
    _process(senior, later["id"], "spread.csv", fw_csv("spread"))
    other = _inv(senior, org_b)
    _process(senior, other["id"], "spread.csv", fw_csv("few_targets"))
    spread = next(b for b in _bundles(senior, inside)["bundles"] if b["id"] == "spread")
    assert spread["status"] == "found" and spread["items"][0]["records"] == 60
    # The same private source in another investigation (another affiliate) is not merged into this one.
    assert next(b for b in _bundles(senior, other)["bundles"] if b["id"] == "spread")["status"] == "looked_none"
    # All records lie before the period: nothing is looked at, which is not "nothing found".
    assert next(b for b in _bundles(senior, later)["bundles"] if b["id"] == "spread")["status"] == "insufficient_data"


def test_editing_the_condition_changes_what_is_computed(senior):
    inv = _inv(senior)
    _process(senior, inv["id"], "spread.csv", fw_csv("spread"))
    _process(senior, inv["id"], "slow.csv", fw_csv("spread_slow"))
    whole = _preview(senior, inv, "spread", min_targets=10, min_ports=99, match="any")
    assert {i["entities"][0] for i in whole["items"]} == {"ip:10.20.5.99", "ip:10.20.5.98"}
    assert "조사 기간 전체에서 서로 다른 목적지 10개 이상" in whole["description"]
    # A 10-minute window keeps the fast sweep (15 hosts in two minutes) and drops the six-hour one.
    windowed = _preview(senior, inv, "spread", min_targets=10, min_ports=99, window_minutes=10)
    assert [i["entities"][0] for i in windowed["items"]] == ["ip:10.20.5.99"]
    assert "10분 동안" in windowed["description"] and "10분 안에 목적지 15개" in windowed["items"][0]["title"]
    # All 60 fast records happen to fall in the representative matching interval.
    fast = windowed["items"][0]
    assert fast["records"] == 60 and fast["time"]["start"].startswith("2026-10-13T00:00:00")
    assert fast["time"]["end"].startswith("2026-10-13T00:01:58") and "조건을 충족한 대표 구간 10-13 09:00:00 ~" in fast["observed"]
    # By ports: the fast sweep used four admin ports, the slow one only 445. Limiting to port 445 leaves each
    # source one port, so the port criterion no longer matches anyone and only 445 records are counted.
    by_ports = _preview(senior, inv, "spread", min_targets=99, min_ports=4)
    assert [i["entities"][0] for i in by_ports["items"]] == ["ip:10.20.5.99"]
    on_445 = _preview(senior, inv, "spread", min_targets=99, min_ports=4, dst_ports=[445])
    assert on_445["status"] == "looked_none" and on_445["records"] == 15 + 12
    assert "목적지 포트 445" in on_445["description"]
    excluded = _preview(senior, inv, "spread", min_targets=10, min_ports=99, exclude_src=["10.20.5.98", "10.20.5.99"])
    assert excluded["status"] == "no_match" and excluded["items"] == [] and excluded["records"] == 0
    stricter = _preview(senior, inv, "spread", min_targets=16, min_ports=99)
    assert stricter["status"] == "looked_none"
    # Each item's evidence query reproduces its records under the same scope.
    item = whole["items"][0]
    assert len(_events(senior, inv, item["filters"], whole["scope"]["time"])) == item["records"]


def test_bad_conditions_are_refused_in_korean(senior):
    inv = _inv(senior)
    url = f"/investigations/{inv['id']}/question-bundles/spread/preview"
    cidr = senior.post(url, json={"parameters": {"exclude_src": ["10.0.0.0/8"]}})
    assert cidr.status_code == 400 and "CIDR" in cidr.json()["detail"]
    assert senior.post(url, json={"parameters": {"min_targets": 0}}).status_code == 400
    assert "없는 조건" in senior.post(url, json={"parameters": {"rule": "x"}}).json()["detail"]


def test_a_limit_hit_is_reported_as_partial_not_as_complete(senior, monkeypatch):
    inv = _inv(senior)
    _process(senior, inv["id"], "spread.csv", fw_csv("spread"))
    _process(senior, inv["id"], "slow.csv", fw_csv("spread_slow"))
    monkeypatch.setattr(qb, "GROUP_LIMIT", 1)
    out = _preview(senior, inv, "spread", min_targets=10, min_ports=99)
    assert out["completeness"] == "partial" and "상위 1개만 계산" in out["partial_reasons"][0]
    assert out["examined"] == {"groups": 1, "groups_total": 2, "group_limit": 1, "timelines": 0, "timeline_limit": qb.TIMELINE_LIMIT}
    monkeypatch.setattr(qb, "GROUP_LIMIT", 1000)
    monkeypatch.setattr(qb, "MAX_ITEMS", 1)
    shown = _preview(senior, inv, "spread", min_targets=10, min_ports=99)
    # Display cap, not a computation cap: two found, one shown, the computation complete.
    assert (shown["found"], shown["shown"], shown["completeness"]) == (2, 1, "complete")


def test_a_saved_condition_runs_exactly_as_its_preview_and_keeps_versions(senior, analyst):
    org = _org(senior)
    inv = _inv(senior, org)
    _process(senior, inv["id"], "spread.csv", fw_csv("spread"))
    params = {"min_targets": 12, "min_ports": 99, "window_minutes": 10, "dst_ports": [22, 445, 3389]}
    unsaved = _preview(senior, inv, "spread", **params)
    created = senior.post(f"/investigations/{inv['id']}/question-presets", json={
        "bundle": "spread", "scope_kind": "affiliate", "name": "관리 포트 빠른 접촉", "parameters": params})
    assert created.status_code == 201, created.text
    preset = created.json()
    assert preset["version"] == 1 and preset["scope_kind"] == "affiliate" and preset["condition"] == unsaved["description"]
    saved = senior.post(f"/investigations/{inv['id']}/question-bundles/spread/preview", json={"preset_id": preset["id"]}).json()
    keep = ("status", "records", "items", "parameters", "description", "completeness")
    assert {k: saved[k] for k in keep} == {k: unsaved[k] for k in keep}
    assert saved["preset"] == {"preset_id": preset["id"], "version": 1, "name": "관리 포트 빠른 접촉", "scope_kind": "affiliate"}
    # Another investigation of the same affiliate sees it; one of another affiliate does not.
    sibling, stranger = _inv(senior, org), _inv(senior, _org(senior))
    assert [p["id"] for p in senior.get(f"/investigations/{sibling['id']}/question-presets").json()["items"]] == [preset["id"]]
    assert senior.get(f"/investigations/{stranger['id']}/question-presets").json()["items"] == []
    # An edit made from a stale screen is refused; the current one adds version 2 with a visible change.
    url = f"/investigations/{inv['id']}/question-presets/{preset['id']}"
    body = {"bundle": "spread", "scope_kind": "affiliate", "name": "관리 포트 빠른 접촉", "parameters": {**params, "min_targets": 14}}
    assert senior.put(url, json={**body, "expected_version": 1}).json()["version"] == 2
    stale = senior.put(url, json={**body, "expected_version": 1})
    assert stale.status_code == 409 and "먼저" in stale.json()["detail"]
    detail = senior.get(url).json()
    assert [v["version"] for v in detail["versions"]] == [1, 2]
    assert detail["last_change"] == [{"name": "min_targets", "before": 12, "after": 14}]
    old = senior.post(f"/investigations/{inv['id']}/question-bundles/spread/preview",
                      json={"preset_id": preset["id"], "preset_version": 1}).json()
    assert old["parameters"]["min_targets"] == 12 and old["items"] == unsaved["items"]
    # A shared template is kept by senior roles; an analyst saves for this investigation instead.
    mine = _inv(analyst)
    common = analyst.post(f"/investigations/{mine['id']}/question-presets", json={
        "bundle": "spread", "scope_kind": "common", "name": "공통", "parameters": {}})
    assert common.status_code == 403
    assert analyst.post(f"/investigations/{mine['id']}/question-presets", json={
        "bundle": "spread", "scope_kind": "investigation", "name": "내 조건", "parameters": {}}).status_code == 201


@pytest.mark.parametrize("bundle", ["web_attack", "transfer", "periodic"])
def test_every_question_runs_from_the_same_definition(senior, bundle):
    inv = _inv(senior)
    _process(senior, inv["id"], "ndr.csv", ndr_csv("large_response_out"))
    _process(senior, inv["id"], "fw.csv", fw_csv("periodic"))
    loose = _preview(senior, inv, bundle)
    assert loose["parameters"] == qb.validate(bundle, {}) and loose["description"] == qb.describe(bundle, loose["parameters"])
    strict = {"web_attack": {"min_paths": 100000, "use_patterns": False}, "transfer": {"min_mb": 10_000_000},
              "periodic": {"min_records": 100000}}[bundle]
    assert _preview(senior, inv, bundle, **strict)["items"] == []


def test_a_question_result_recorded_as_a_check_keeps_its_whole_question_into_the_request_and_golden(senior):
    inv = _inv(senior, _org(senior))
    _process(senior, inv["id"], "spread.csv", fw_csv("spread"))
    run = _preview(senior, inv, "spread", min_targets=10, min_ports=99, window_minutes=10)
    item = run["items"][0]
    page = senior.post(f"/investigations/{inv['id']}/query/events",
                       json={"filters": item["filters"], "time": item["evidence_time"], "limit": 500}).json()
    origin = {"kind": "question", "bundle": "spread", "title": run["title"], "description": run["description"],
              "parameters": run["parameters"], "scope": run["scope"], "completeness": run["completeness"],
              "partial_reasons": run["partial_reasons"], "item": item}
    check = senior.post(f"/investigations/{inv['id']}/checks", json={
        "target_type": "set", "target_label": item["title"], "questions": ["nature"], "note": item["observed"],
        "evidence": [e["event_id"] for e in page["events"][:20]],
        "scope": {"coverage": "all", "query": {"filters": item["filters"], "time": item["evidence_time"]},
                  "loaded": len(page["events"]), "event_ids": [e["event_id"] for e in page["events"][:20]], "origin": origin}})
    assert check.status_code == 201, check.text
    stored = check.json()["scope"]
    assert stored["total"] == item["records"] == 60 and stored["query"]["time"] == item["evidence_time"]
    assert stored["origin"]["scope"]["time"] == run["scope"]["time"]
    assert stored["origin"]["parameters"]["window_minutes"] == 10 and stored["origin"]["item"]["next_questions"] == item["next_questions"]
    draft = senior.get(f"/investigations/{inv['id']}/follow-ups/draft", params={"check_id": check.json()["id"]}).json()
    assert [f"확인: {q}" for q in item["next_questions"]] == draft["needed_data"][:len(item["next_questions"])]
    assert "계산 조건: " + run["description"] in draft["reason"] and draft["affiliate"] and draft["affiliate"] in draft["question"]
    # The request covers the whole group, not only the 20 records kept as references.
    assert draft["period"] == {"start": item["time"]["start"], "end": item["time"]["end"]} and "09:00 ~ 09:01 (KST)" in draft["question"]
    golden = senior.get(f"/investigations/{inv['id']}/internal-golden/draft").json()["content"]
    assert any(run["description"] in f and qb.VERSION in f and "전체 계산 · 저장 안 한 조건" in f for f in golden["observed_facts"])
    # A question result from another investigation cannot be filed here.
    other = _inv(senior)
    foreign = senior.post(f"/investigations/{other['id']}/checks", json={
        "target_type": "entity", "target_key": "ip:10.20.5.99", "questions": ["nature"], "scope": {"origin": origin}})
    assert foreign.status_code == 400


def test_the_whole_search_exports_on_the_server_beyond_what_a_screen_loads(senior):
    inv = _inv(senior)
    _process(senior, inv["id"], "spread.csv", fw_csv("spread"))
    _process(senior, inv["id"], "slow.csv", fw_csv("spread_slow"))
    body = {"filters": [{"field": "src_ip", "op": "is", "value": "10.20.5.99"}],
            "time": {"start": "2026-10-13T00:00:00+09:00", "end": "2026-10-14T00:00:00+09:00", "end_exclusive": True},
            "columns": ["timestamp", "src_ip", "dst_ip", "dst_port", "enforcement_action"]}
    r = senior.post(f"/investigations/{inv['id']}/query/events/export", json=body)
    assert r.status_code == 200, r.text
    assert (r.headers["x-saw-total"], r.headers["x-saw-rows"], r.headers["x-saw-truncated"]) == ("60", "60", "false")
    lines = r.content.decode("utf-8-sig").strip().splitlines()
    assert lines[0] == "timestamp,src_ip,dst_ip,dst_port,enforcement_action" and len(lines) == 61
    assert all(",10.20.5.99," in line for line in lines[1:])
    assert senior.post(f"/investigations/{inv['id']}/query/events/export", json={**body, "columns": ["bad field"]}).status_code == 400


def test_cookie_values_stay_out_of_normal_views_but_an_authorized_unmask_reads_the_original_line(senior, analyst):
    inv = _inv(senior)
    job = _process(senior, inv["id"], "ndr.csv", ndr_csv("web_probe"))
    event = senior.post(f"/investigations/{inv['id']}/query/events", json={"filters": [], "limit": 1}).json()["events"][0]
    detail = senior.get(f"/investigations/{inv['id']}/events/{event['event_id']}").json()
    assert "sid=s0" not in str(detail["event"]) and detail["event"]["ext"]["security_csv"]["req_cookie_names"] == ["sid"]
    assert "sid=[가림]" in detail["event"]["raw_event"]
    # Neighbouring lines of the original file and the upload preview keep the names, never the values.
    context = senior.get(f"/investigations/{inv['id']}/events/{event['event_id']}/context", params={"lines": 5}).json()
    assert len(context["lines"]) > 1 and not any("sid=s" in x and "sid=[" not in x for x in context["lines"])
    assert any("sid=[가림]" in x for x in context["lines"])
    sample = senior.get(f"/evidence/{job['evidence_id']}/files/{job['files'][0]['id']}/sample", params={"lines": 10}).json()["lines"]
    assert "req_cookie" in sample[0] and all("sid=s" not in x for x in sample[1:] if x) and "sid=[가림]" in sample[1]
    url = f"/investigations/{inv['id']}/events/{event['event_id']}/unmask"
    opened = senior.post(url, json={"reason": "쿠키 값 원문 비교(합성 시험)"})
    assert opened.status_code == 200, opened.text
    assert "sid=s0" in opened.json()["event"]["raw_event"]
    assert analyst.post(url, json={"reason": "권한 없는 열람 시도"}).status_code == 403


def test_example_specifications_keep_execution_data_and_calculation_apart(senior):
    inv = _inv(senior)
    _process(senior, inv["id"], "spread.csv", fw_csv("spread"))
    out = senior.get(f"/investigations/{inv['id']}/question-examples").json()
    assert out["catalog_total"] == 120 and out["total"] == 120
    by = {x["id"]: x for x in out["items"]}
    assert {x["kind"] for x in out["items"]} == {"detection", "hunt", "scenario"}
    d027 = by["D027"]
    assert d027["execution"] == {"state": "nearby_question", "label": "자체 실행기 없음 · 가까운 계산 Q06 연결됨",
                                 "question": "Q06", "bundle": "spread"}
    assert d027["calculation"]["state"] == "not_run" and "장비 설정" in d027["data_readiness"]["label"]
    # A spec whose question has no computation is kept as knowledge, never shown as runnable.
    assert all(x["execution"]["state"] == "spec_only" for x in out["items"] if not x["basic_questions"])
    # NDR examples in an FW-only investigation say the NDR data is missing here.
    ndr_only = next(x for x in out["items"] if x["inputs"] == ["NDR"])
    assert "NDR 자료 없음" in ndr_only["data_readiness"]["label"]
    found = senior.get(f"/investigations/{inv['id']}/question-examples", params={"q": "Q06", "kind": "hunt"}).json()
    assert found["total"] >= 1 and all(x["kind"] == "hunt" and "Q06" in x["basic_questions"] for x in found["items"])
