"""The whole-picture view states its basis, keeps empty days and out-of-period records visible."""
import csv
import io
import uuid

from saw.devtools.security_csv_samples import FW_COLUMNS
from tests.api.test_text_uploads import _process


def _fw(rows):
    out = io.StringIO(newline="")
    w = csv.writer(out, lineterminator="\r\n")
    w.writerow(FW_COLUMNS)
    for when, action, dst in rows:
        w.writerow([when, "가상 관계사", "192.0.2.1", action, "10.20.5.11", 50000, dst, 443, "TCP", "SYN", 3, 100, 200, 3, 1, 2])
    return out.getvalue().encode("cp949")


def test_scope_summary_counts_basis_actions_gaps_and_outside_period(senior):
    org = senior.post("/source-context/org-units", json={"display_name": f"Summary {uuid.uuid4().hex[:6]}"}).json()
    inv = senior.post("/investigations", json={"title": "summary", "org_unit_id": org["id"],
                                              "period_start": "2026-10-01T00:00:00+09:00",
                                              "period_end": "2026-10-05T23:59:59+09:00"}).json()
    _process(senior, inv["id"], "fw.csv", _fw([
        ("2026-10-01 10:00:00", "허용", "198.51.100.1"), ("2026-10-01 11:00:00", "차단", "198.51.100.1"),
        ("2026-10-02 10:00:00", "허용", "198.51.100.2"),
        ("2026-10-04 23:30:00", "허용", "198.51.100.2"),  # 10-03 has no records at all
        ("2026-10-09 10:00:00", "허용", "198.51.100.3"),  # outside the declared period
        ("not-a-date", "허용", "198.51.100.3"),
    ]))
    out = senior.post(f"/investigations/{inv['id']}/scope-summary", json={"filters": []})
    assert out.status_code == 200, out.text
    data = out.json()
    assert data["scope"]["org_unit_id"] == org["id"] and data["scope"]["period_declared"] is True
    assert data["basis"] == {**data["basis"], "kind": "all", "all_events": 6, "events": 6}
    actions = {b["key"]: b["count"] for b in data["breakdown"]["enforcement_action"]["buckets"]}
    assert actions == {"allowed": 5, "blocked": 1}
    assert {b["key"] for b in data["breakdown"]["enforcement_action"]["buckets"]} and \
        data["breakdown"]["enforcement_action"]["buckets"][0]["label"] in {"허용", "차단"}
    days = {d["date"]: d["count"] for d in data["time"]["daily"]}
    assert days["2026-10-01"] == 2 and days["2026-10-03"] == 0 and days["2026-10-04"] == 1
    assert "2026-10-03" in data["time"]["empty_days"]
    assert data["time"]["outside_period"] == {"before": 0, "after": 1, "inside": 4}
    assert data["time"]["without_timestamp"] == 1
    assert data["inputs"]["files"] == 1 and data["inputs"]["timestamp_invalid"] + data["inputs"]["timestamp_missing"] == 1
    assert any("시간" in f["message"] for f in data["inputs"]["by_file"])
    assert "장기 정상 기준선" in data["method_note"]
    # Device observation without a registered device was not run; the view says why instead of "nothing found".
    fw = [x for x in data["analysis"]["incomplete"] if x["detector_id"] == "fw.observation"]
    assert fw and fw[0]["reason"] == "unresolved_context" and "등록" in fw[0]["reason_label"]

    # A filter changes only the stated basis, never the whole-investigation denominator.
    filtered = senior.post(f"/investigations/{inv['id']}/scope-summary",
                           json={"filters": [{"field": "enforcement_action", "op": "is", "value": "blocked"}]}).json()
    assert filtered["basis"]["kind"] == "filter" and filtered["basis"]["events"] == 1
    assert filtered["basis"]["all_events"] == 6


def test_fine_histograms_over_long_ranges_are_bounded(tmp_path):
    from saw.core.schemas.query import AggRequest
    from saw.storage.eventstore import MAX_HISTOGRAM_BUCKETS, SQLiteEventStore

    store = SQLiteEventStore(str(tmp_path / "h.db"))
    store.index([{"event_id": "a", "investigation_id": "i", "timestamp": "2026-07-01T00:00:00+00:00", "data_source": "x"},
                 {"event_id": "b", "investigation_id": "i", "timestamp": "2026-09-29T00:00:00+00:00", "data_source": "x"}])
    out = store.aggregate("i", [], AggRequest(type="date_histogram", field="timestamp", interval_sec=1))
    span = 90 * 86400
    assert span / out["interval_sec"] <= MAX_HISTOGRAM_BUCKETS and sum(b["count"] for b in out["buckets"]) == 2
    pct = store.aggregate("i", [], AggRequest(type="percentiles", field="ts_epoch", percents=[50]))
    assert "values" in pct


def test_partial_search_results_cannot_be_recorded_as_fully_checked(analyst):
    inv = analyst.post("/investigations", json={"title": "coverage"}).json()
    _process(analyst, inv["id"], "fw.csv", _fw([(f"2026-10-01 10:0{i}:00", "허용", "198.51.100.1") for i in range(5)]))
    body = {"target_type": "set", "target_key": "", "questions": ["nature"], "note": "",
            "scope": {"coverage": "all", "query": {"filters": []}, "total": 5, "checked": 5, "loaded": 3}}
    refused = analyst.post(f"/investigations/{inv['id']}/checks", json=body)
    assert refused.status_code == 400 and "표본" in refused.text
    body["scope"].update(loaded=5)
    assert analyst.post(f"/investigations/{inv['id']}/checks", json=body).status_code in (200, 201)


def _inv_with(senior, start, end, rows):
    org = senior.post("/source-context/org-units", json={"display_name": f"Days {uuid.uuid4().hex[:6]}"}).json()
    inv = senior.post("/investigations", json={"title": "days", "org_unit_id": org["id"],
                                              "period_start": start, "period_end": end}).json()
    _process(senior, inv["id"], "fw.csv", _fw(rows))
    return inv


def test_an_old_outlier_outside_the_period_does_not_empty_the_daily_chart(senior):
    """UX-02: one 2020 record made the hourly histogram widen past a day and every 2026 day showed 0."""
    inv = _inv_with(senior, "2026-10-01T00:00:00+09:00", "2026-10-05T23:59:59+09:00", [
        ("2026-10-01 10:00:00", "허용", "198.51.100.1"), ("2026-10-03 00:00:00", "허용", "198.51.100.1"),
        ("2026-10-05 23:59:59", "허용", "198.51.100.2"), ("2020-01-01 10:00:00", "허용", "198.51.100.3")])
    data = senior.post(f"/investigations/{inv['id']}/scope-summary", json={"filters": []}).json()
    days = {d["date"]: d["count"] for d in data["time"]["daily"]}
    assert days == {"2026-10-01": 1, "2026-10-02": 0, "2026-10-03": 1, "2026-10-04": 0, "2026-10-05": 1}
    assert data["time"]["outside_period"]["before"] == 1 and data["time"]["outside_period"]["inside"] == 3


def test_the_last_day_includes_its_final_second_and_kst_midnight_belongs_to_the_next_day(senior):
    """UX-07: [start, day after end 00:00) — 23:59:59.500 of the last day is inside, 00:00 after it is not."""
    inv = _inv_with(senior, "2026-10-01T00:00:00+09:00", "2026-10-02T23:59:59+09:00", [
        ("2026-10-01 00:00:00", "허용", "198.51.100.1"), ("2026-10-02 23:59:59.500", "허용", "198.51.100.1"),
        ("2026-10-03 00:00:00", "허용", "198.51.100.1")])
    data = senior.post(f"/investigations/{inv['id']}/scope-summary", json={"filters": []}).json()
    days = {d["date"]: d["count"] for d in data["time"]["daily"]}
    assert days == {"2026-10-01": 1, "2026-10-02": 1}
    assert data["time"]["outside_period"] == {"before": 0, "after": 1, "inside": 2}


def test_days_a_search_excludes_are_not_reported_as_collection_gaps(senior):
    """UX-09: searching one day must not call the other days' data 'not collected'."""
    inv = _inv_with(senior, "2026-10-01T00:00:00+09:00", "2026-10-03T23:59:59+09:00", [
        ("2026-10-01 10:00:00", "허용", "198.51.100.1"), ("2026-10-02 10:00:00", "차단", "198.51.100.1")])
    one_day = senior.post(f"/investigations/{inv['id']}/scope-summary", json={
        "filters": [], "time": {"start": "2026-10-01T00:00:00+09:00", "end": "2026-10-01T23:59:59+09:00"}}).json()
    assert one_day["time"]["empty_days"] == ["2026-10-03"]  # nothing was collected that day at all
    assert one_day["time"]["no_result_days"] == ["2026-10-02"]  # data exists, the search just excludes it
