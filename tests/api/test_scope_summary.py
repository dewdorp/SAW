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
    assert data["time"]["outside_period"] == {"before": 0, "after": 1}
    assert data["time"]["without_timestamp"] == 1
    assert data["inputs"]["files"] == 1 and data["inputs"]["timestamp_invalid"] + data["inputs"]["timestamp_missing"] == 1
    assert any("시간" in f["message"] for f in data["inputs"]["by_file"])
    assert "장기 정상 기준선" in data["method_note"]

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
    body = {"target_type": "set", "target_key": "", "questions": ["nature"], "note": "",
            "scope": {"coverage": "all", "query": {"filters": []}, "total": 100000, "checked": 100000, "loaded": 20000}}
    refused = analyst.post(f"/investigations/{inv['id']}/checks", json=body)
    assert refused.status_code == 400 and "표본" in refused.text
    body["scope"].update(loaded=100000)
    assert analyst.post(f"/investigations/{inv['id']}/checks", json=body).status_code in (200, 201)
