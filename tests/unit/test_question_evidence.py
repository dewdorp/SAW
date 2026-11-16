"""Exercise the same structured filters, time boundaries and SQLite queries as the raw-log link."""
from datetime import datetime, timedelta, timezone

import pytest

from saw.core.application import question_bundles as qb
from saw.core.schemas.query import Filter, TimeRange
from saw.storage.eventstore import SQLiteEventStore


START = datetime(2026, 10, 1, tzinfo=timezone.utc)
MIB = 1024 ** 2


def event(i, second, dst, port, **fields):
    return {"investigation_id": "inv", "event_id": f"e{i:03}", "timestamp": (START + timedelta(seconds=second)).isoformat(),
            "data_source": "firewall", "src_ip": "10.0.0.5", "dst_ip": dst, "dst_port": port, **fields}


@pytest.mark.parametrize("direction,req_bytes,resp_bytes,shown,not_shown", [
    ("any", 120 * MIB, 1024, ["요청 120.0 MiB"], ["응답", "다운로드"]),
    ("any", 1024, 51 * MIB, ["응답 51.0 MiB"], ["요청", "반출"]),
    ("any", 50 * MIB, 75 * MIB, ["요청 50.0 MiB", "응답 75.0 MiB"], ["반출"]),
    ("out", 120 * MIB, 75 * MIB, ["응답 75.0 MiB"], ["요청", "반출"]),
    ("in", 120 * MIB, 75 * MIB, ["요청 120.0 MiB"], ["응답", "반출"]),
])
def test_transfer_names_the_direction_that_actually_matched(direction, req_bytes, resp_bytes, shown, not_shown):
    es = SQLiteEventStore(":memory:")
    es.index([event(0, 0, "198.51.100.7", 443, data_source="web", bytes_in=req_bytes, bytes_out=resp_bytes)])
    result = qb._transfer(es, "inv", None, qb.validate("transfer", {"direction": direction}))
    item = result["items"][0]
    assert all(s in item["title"] for s in shown)
    assert not any(s in item["title"] for s in not_shown)
    assert result["records"] == 1


@pytest.mark.parametrize("match,first_size,port_targets", [("any", 9, 1), ("all", 11, 10)])
def test_qualifying_window_survives_an_unrelated_window_with_more_destinations(match, first_size, port_targets):
    es = SQLiteEventStore(":memory:")
    early = [event(i, i, f"192.0.2.{i+1}", 80, enforcement_action="blocked") for i in range(first_size)]
    late = [event(i+20, 600+i, f"198.51.100.{1+i%port_targets}", 4000+i, enforcement_action="allowed") for i in range(10)]
    es.index(early + late)
    result = qb._spread(es, "inv", None, qb.validate("spread", {"window_minutes": 1, "match": match}))
    assert result["found"] == 1 and result["completeness"] == "complete"
    (item,) = result["items"]
    assert item["time"] == {k: item["evidence_time"][k] for k in ("start", "end")}
    exact = TimeRange(**item["evidence_time"])
    found = es.search("inv", [Filter(**f) for f in item["filters"]], exact)["events"]
    assert not exact.end_exclusive and [e["event_id"] for e in found] == [e["event_id"] for e in late]
    assert len(found) == item["records"] == 10
    assert item["basis"]["source_records"] == result["records"] == first_size + 10
    assert "허용 10건" in item["observed"] and "차단 0건" in item["observed"]


def test_truncated_search_cannot_report_complete_and_tied_boundary_preserves_full_evidence(monkeypatch):
    es = SQLiteEventStore(":memory:")
    es.index([event(i, 0, "198.51.100.7", 444+i, enforcement_action="allowed") for i in range(6)])
    monkeypatch.setattr(qb, "TIMELINE_LIMIT", 3)
    for minimum, expected in [(3, 1), (5, 0)]:
        run = qb._spread(es, "inv", None, qb.validate("spread", {"window_minutes": 1, "min_targets": 50, "min_ports": minimum}))
        assert run["completeness"] == "partial" and run["partial_reasons"]
        assert run["found"] == expected
        if expected:
            item = run["items"][0]
            assert len(es.search("inv", [Filter(**f) for f in item["filters"]], TimeRange(**item["evidence_time"]))["events"]) == item["records"] == 6


def test_missing_port_does_not_make_an_additional_distinct_port():
    es = SQLiteEventStore(":memory:")
    es.index([event(i, i, "198.51.100.7", None if i == 0 else i) for i in range(10)]
             + [event(20, 600, "198.51.100.7", 999)])
    run = qb._spread(es, "inv", None, qb.validate("spread", {"window_minutes": 1, "min_targets": 100, "min_ports": 10}))
    assert run["found"] == 0 and run["completeness"] == "complete"


@pytest.mark.parametrize("seconds,label", [(86400, "약 1일"), (3600, "약 1시간"), (90, "약 1분 30초"), (.25, "약 250밀리초"), (.0001, "1밀리초 미만")])
def test_periodic_uses_readable_duration_but_keeps_the_numeric_mean(seconds, label):
    es = SQLiteEventStore(":memory:")
    es.index([event(i, i * seconds, "198.51.100.7", 443) for i in range(8)])
    item, = qb._periodic(es, "inv", None, qb.validate("periodic", {}))["items"]
    assert f"{label} 간격" in item["title"]
    assert item["basis"]["mean_interval_seconds"] == pytest.approx(seconds, abs=1e-6)
    assert "평균" in item["observed"] and "초" in item["observed"]
