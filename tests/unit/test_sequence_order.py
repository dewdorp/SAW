"""Sequence scores must not depend on generated event identifiers or invented tie order."""
from copy import deepcopy

import pytest

from saw.detectors.anomaly import SequenceAnomaly
from saw.detectors.base import DetectorContext
from saw.storage.eventstore import SQLiteEventStore

NORMAL = ["/login", "/search", "/detail", "/logout"]
UNUSUAL = ["/z-start", "/export", "/admin/users", "/export", "/admin/delete", "/export"]


@pytest.fixture
def store():
    result = SQLiteEventStore(":memory:")
    yield result
    result._conn().close()


def rows(*, tied=True, metadata="offset", suspect_count=1, normal_count=3):
    out = []
    for session in range(normal_count):
        for index, path in enumerate(NORMAL):
            out.append({"event_id": f"normal-{session}-{index}", "investigation_id": "synthetic",
                        "data_source": "web", "session_id": f"normal-{session}",
                        "timestamp": f"2026-10-11T00:00:0{index}Z", "url_path": path})
    for session in range(suspect_count):
        for index, path in enumerate(UNUSUAL):
            position = {"object_key": "synthetic/source.log"}
            position[metadata] = index * 100 if metadata == "offset" else index + 1
            out.append({"event_id": f"suspect-{session}-{index}", "investigation_id": "synthetic",
                        "data_source": "web", "session_id": f"suspect-{session}",
                        "timestamp": f"2026-10-11T00:00:{10 if tied else 10 + index:02d}Z",
                        "url_path": path, "raw_ref": position})
    return out


def run(store, events):
    store.index(events)
    return SequenceAnomaly().run(DetectorContext("synthetic", store, params={"min_sessions": 3}))


def changed_ids(events):
    # Reverse database tie ordering without changing content, source order or timestamps.
    return [dict(event, event_id=f"changed-{len(events) - index:04d}") for index, event in enumerate(events)]


def matching(findings):
    return [finding for finding in findings if finding.category == "anomaly.sequence"]


@pytest.mark.parametrize("position", ["offset", "line_no"])
def test_same_source_ties_keep_record_order_and_score_when_event_ids_change(store, position):
    events = rows(metadata=position)
    first, = matching(run(store, events))
    first_path = next(m["observed_path"] for m in first.metrics if m["name"] == "sequence")
    assert first_path == UNUSUAL
    store._conn().execute("DELETE FROM events")
    second, = matching(run(store, changed_ids(events)))
    assert next(m["observed_path"] for m in second.metrics if m["name"] == "sequence") == UNUSUAL
    assert second.metrics == first.metrics
    assert second.dedup_key == first.dedup_key


def test_distinct_timestamps_keep_the_original_sequence_without_source_metadata(store):
    events = rows(tied=False)
    for event in events:
        event.pop("raw_ref", None)
    finding, = matching(run(store, changed_ids(events)))
    assert next(m["observed_path"] for m in finding.metrics if m["name"] == "sequence") == UNUSUAL
    assert next(m["normal_path"] for m in finding.metrics if m["name"] == "sequence") == NORMAL[:3]


@pytest.mark.parametrize("problem", ["missing", "different_sources", "offset_collision", "line_collision"])
def test_unordered_ties_are_excluded_with_visible_coverage(store, problem):
    events = rows()
    for index, event in enumerate(events[12:]):
        if problem == "missing":
            event.pop("raw_ref")
        elif problem == "different_sources":
            event["raw_ref"]["object_key"] = f"synthetic/source-{index % 2}.log"
        elif problem == "offset_collision":
            event["raw_ref"].update(offset=0, line_no=index + 1)
        else:
            event["raw_ref"] = {"object_key": "synthetic/source.log", "line_no": 1}
    result = run(store, events)
    assert matching(result) == []
    coverage, = [f for f in result if f.category == "anomaly.sequence.coverage"]
    assert next(m["observed"] for m in coverage.metrics if m["name"] == "excluded_sessions") == 1
    assert coverage.success_signal is False
    assert any(c["passed"] is False for c in coverage.checks)


def test_repeated_identical_actions_need_no_invented_tie_order(store):
    events = rows(tied=False)
    extra = dict(events[13], event_id="same-action")
    events.append(extra)
    for event in events:
        event.pop("raw_ref", None)
    finding, = matching(run(store, events))
    assert next(m["observed_path"] for m in finding.metrics if m["name"] == "sequence") == UNUSUAL
    assert not any(f.category == "anomaly.sequence.coverage" for f in run(store, events))


def test_equal_scores_choose_the_same_sessions_after_identifier_changes(store):
    events = rows(tied=False, suspect_count=4, normal_count=30)
    first = matching(run(store, events))
    store._conn().execute("DELETE FROM events")
    second = matching(run(store, changed_ids(events)))
    assert [f.dedup_key for f in first] == [f.dedup_key for f in second]
    assert [f.metrics for f in first] == [f.metrics for f in second]
    assert {f.dedup_key for f in second} == {"anomaly.sequence:suspect-0", "anomaly.sequence:suspect-1",
                                            "anomaly.sequence:suspect-2"}


def test_unknown_time_cannot_be_used_as_an_observed_sequence(store):
    events = deepcopy(rows(tied=False))
    for event in events[12:]:
        event["timestamp"] = None
    result = run(store, events)
    assert matching(result) == []
    coverage, = [f for f in result if f.category == "anomaly.sequence.coverage"]
    assert next(m["observed"] for m in coverage.metrics if m["name"] == "excluded_sessions") == 1
