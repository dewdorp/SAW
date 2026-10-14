from datetime import datetime, timedelta, timezone

from saw import container
from tests.unit.test_temporal_behavior import rows


def test_reanalysis_temporal_candidate_exact_drilldown_and_cleanup(analyst):
    inv = analyst.post("/investigations", json={"title": "Synthetic temporal analysis"}).json()["id"]
    other = analyst.post("/investigations", json={"title": "Synthetic separate investigation"}).json()["id"]
    events = [{**e, "investigation_id": inv} for e in rows()]
    for i, event in enumerate(events):
        event["timestamp"] = datetime.fromisoformat(event["timestamp"]).astimezone(
            timezone(timedelta(hours=9 if i % 2 else -5))).isoformat()
    container.get().events.index(events + [{**e, "event_id": "other-" + e["event_id"], "investigation_id": other}
                                         for e in rows()])
    analyst.post(f"/investigations/{inv}/reanalyze").raise_for_status()
    findings = analyst.get(f"/investigations/{inv}/findings").json()
    finding, = [f for f in findings if f["category"] == "anomaly.temporal"]
    assert not finding["attack"]
    result = analyst.post(f"/investigations/{inv}/findings/{finding['id']}/events", json={"limit": 50}).json()
    assert result["total"] == 40
    assert {e["event_id"] for e in result["events"]} == {f"e-7-{i}" for i in range(40)}
    narrower = analyst.post(f"/investigations/{inv}/findings/{finding['id']}/events", json={
        "limit": 50, "time": {"start": "2026-10-14T01:45:10Z", "end": "2026-10-14T03:00:00Z"}}).json()
    assert narrower["total"] == 30 and len(narrower["events"]) == 30
    assert analyst.get(f"/investigations/{other}/findings").json() == []
    container.get().events.index([{**e, "status_code": 200, "bytes_out": 200} for e in events])
    analyst.post(f"/investigations/{inv}/reanalyze").raise_for_status()
    assert not [f for f in analyst.get(f"/investigations/{inv}/findings").json() if f["category"] == "anomaly.temporal"]
