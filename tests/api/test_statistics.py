from __future__ import annotations

from saw import container
from saw.core.application.analysis import history_baseline
from saw.storage.db import session_scope
from tests.conftest import Api, make_user


def seed(api):
    inv = api.post("/investigations", json={"title": "Synthetic statistics"}).json()["id"]
    rows = [
        ("a", "ea", "same.log", "web", "192.0.2.1", "2026-10-14T01:00:00Z", 100),
        ("b", "ea", "same.log", "web", "192.0.2.1", "2026-10-14T01:01:00Z", 200),
        ("c", "eb", "same.log", "web", "192.0.2.2", "2026-10-14T01:02:00Z", 300),
        ("d", "eb", "same.log", "web", None, "2026-10-14T01:03:00Z", 400),
        ("e", "ec", "other.log", "zeek_conn", "192.0.2.3", "2026-10-14T03:00:00Z", 500),
        ("f", None, None, "web", None, None, 0),
    ]
    container.get().events.index([dict(event_id=e, investigation_id=inv, evidence_id=ev, source_file=f,
        data_source=ds, src_ip=ip, timestamp=ts, bytes_out=b, raw_event="never-export-this-raw")
        for e, ev, f, ds, ip, ts, b in rows])
    return inv


def test_statistics_scope_top_missing_and_drilldown(analyst):
    inv = seed(analyst)
    body = {"group_by": "src_ip", "size": 1, "filters": [{"field": "data_source", "value": "web"}],
            "time": {"start": "2026-10-14T01:00:00Z", "end": "2026-10-14T01:03:00Z"}}
    r = analyst.post(f"/investigations/{inv}/statistics", json=body)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["summary"] == {"matched_events": 4, "time_start": "2026-10-14T01:00:00Z",
                            "time_end": "2026-10-14T01:03:00Z", "timestamp_missing": 0}
    t = d["table"]
    assert (t["shown_events"], t["other_events"], t["missing_events"], t["limit"]) == (2, 1, 1, 1)
    row, = t["rows"]
    assert row["key"] == {"src_ip": "192.0.2.1"} and row["bytes_out_sum"] == 300
    q = analyst.post(f"/investigations/{inv}/query/events", json={
        "filters": body["filters"] + row["filter"], "time": body["time"]}).json()
    assert {e["event_id"] for e in q["events"]} == {"a", "b"}
    assert sum(b["count"] for b in d["timeline"]["buckets"]) == 4
    assert "never-export-this-raw" not in r.text


def test_statistics_same_filename_stays_separate_across_evidence(analyst):
    inv = seed(analyst)
    d = analyst.post(f"/investigations/{inv}/statistics", json={"group_by": "source_file"}).json()
    t = d["table"]
    assert len(t["rows"]) == 3
    assert {r["key"]["evidence_id"] for r in t["rows"] if r["key"]["source_file"] == "same.log"} == {"ea", "eb"}
    assert t["missing_events"] == 1 and d["summary"]["timestamp_missing"] == 1
    assert sum(r["count"] for r in t["rows"]) == 5


def test_statistics_permission_and_field_allowlist(analyst, app):
    inv = seed(analyst)
    make_user("outsider-statistics", ["analyst"])
    other = Api(app, "outsider-statistics")
    assert other.post(f"/investigations/{inv}/statistics", json={}).status_code == 403
    assert analyst.post(f"/investigations/{inv}/statistics", json={"group_by": "raw_event"}).status_code == 422
    assert analyst.post(f"/investigations/{inv}/statistics", json={"size": 51}).status_code == 422
    assert analyst.post(f"/investigations/{inv}/statistics", json={"time": {"start": "yesterday"}}).status_code == 422
    assert analyst.post(f"/investigations/{inv}/statistics", json={"time": {
        "start": "2026-10-15T00:00:00Z", "end": "2026-10-14T00:00:00Z"}}).status_code == 422


def test_statistics_empty_selection_is_not_whole_investigation(analyst):
    inv = seed(analyst)
    d = analyst.post(f"/investigations/{inv}/statistics", json={"filters": [
        {"field": "src_ip", "value": "198.51.100.240"}]}).json()
    assert d["summary"]["matched_events"] == 0
    assert d["summary"]["time_start"] is None and not d["table"]["rows"]


def test_private_closed_normal_investigation_is_not_shared_baseline(analyst, app):
    inv = seed(analyst)
    container.get().events.index([{"event_id": "private", "investigation_id": inv,
                                  "data_source": "web", "user_agent": "PrivateInternalClient"}])
    analyst.post(f"/investigations/{inv}/close", json={"verdict": "normal", "reason": "Synthetic normal"})
    with session_scope() as s:
        baseline = history_baseline(s, "a-different-investigation")
    assert baseline == {"user_agent": [], "ja4": [], "edges": [], "investigations": 0}


def test_statistics_uses_instant_order_for_mixed_time_offsets(analyst):
    inv = analyst.post("/investigations", json={"title": "Synthetic offsets"}).json()["id"]
    container.get().events.index([
        {"event_id": "offset-a", "investigation_id": inv, "data_source": "web", "timestamp": "2026-10-14T09:00:00+09:00"},
        {"event_id": "offset-b", "investigation_id": inv, "data_source": "web", "timestamp": "2026-10-14T00:30:00Z"},
        {"event_id": "offset-c", "investigation_id": inv, "data_source": "web", "timestamp": "2026-10-14T02:00:00Z"},
    ])
    d = analyst.post(f"/investigations/{inv}/statistics", json={"time": {
        "start": "2026-10-14T00:00:00Z", "end": "2026-10-14T01:00:00Z"}}).json()
    assert d["summary"]["matched_events"] == 2
    assert d["summary"]["time_start"] == "2026-10-14T09:00:00+09:00"
    assert d["summary"]["time_end"] == "2026-10-14T00:30:00Z"
    assert d["table"]["rows"][0]["first_ts"] == d["summary"]["time_start"]


def test_missing_bytes_are_not_zero_and_counts_have_coverage(analyst):
    inv = analyst.post("/investigations", json={"title": "Synthetic missing bytes"}).json()["id"]
    container.get().events.index([
        {"event_id": "no-bytes", "investigation_id": inv, "data_source": "web", "src_ip": "192.0.2.1"},
        {"event_id": "zero-bytes", "investigation_id": inv, "data_source": "web", "src_ip": "192.0.2.2", "bytes_out": 0},
    ])
    d = analyst.post(f"/investigations/{inv}/statistics", json={"group_by": "src_ip"}).json()
    by_source = {r["key"]["src_ip"]: r for r in d["table"]["rows"]}
    assert by_source["192.0.2.1"]["bytes_out_sum"] is None
    assert by_source["192.0.2.1"]["bytes_out_known_events"] == 0
    assert by_source["192.0.2.2"]["bytes_out_sum"] == 0
    assert by_source["192.0.2.2"]["bytes_out_known_events"] == 1
