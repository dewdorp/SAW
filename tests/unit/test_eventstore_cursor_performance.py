"""Stable SQLite iterator cursors must seek rather than rescan earlier pages."""
from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

from saw.core.schemas.query import Filter, TimeRange
from saw.storage.eventstore import SQLiteEventStore, encode_cursor


@pytest.fixture
def store(tmp_path):
    backend = SQLiteEventStore(tmp_path / "events.sqlite")
    yield backend
    backend._conn().close()


def event(ident, timestamp=None, **values):
    return {"event_id": ident, "investigation_id": "inv", "data_source": "connection",
            "timestamp": timestamp, **values}


def measured(connection, action):
    steps = 0

    def tick():
        nonlocal steps
        steps += 100
        return 0

    connection.set_progress_handler(tick, 100)
    try:
        result = action()
    finally:
        connection.set_progress_handler(None, 0)
    return result, steps


def bulk_events(size, same_time):
    start = datetime(2026, 10, 20, tzinfo=UTC)
    return [event(f"e{number:06d}",
                  (start + timedelta(seconds=0 if same_time else number // 330)).isoformat())
            for number in range(size)]


@pytest.mark.parametrize("same_time", [False, True], ids=["many-times", "same-time"])
@pytest.mark.parametrize("size", [1000, 10000])
def test_late_cursor_page_seeks_without_rescanning_prefix(store, size, same_time):
    rows = bulk_events(size, same_time)
    store.index(rows)
    previous = size - 51
    timestamp = datetime.fromisoformat(rows[previous]["timestamp"]).timestamp()
    page, steps = measured(store._conn(), lambda: store._page(
        "inv", [Filter(field="data_source", op="in", value=["connection", "ips"])],
        None, 25, encode_cursor([timestamp, f"e{previous:06d}"]), ["event_id"]))
    assert [row["event_id"] for row in page["events"]] == [
        f"e{number:06d}" for number in range(previous + 1, previous + 26)]
    # This budget allows thousands of instructions for 25 rows, but not a
    # traversal of the 1k/10k prefix. Wall-clock speed is deliberately untested.
    assert steps < 5000, f"late 25-row page executed at least {steps} SQLite VM instructions"


@pytest.mark.parametrize("same_time", [False, True], ids=["many-times", "same-time"])
def test_full_iteration_keeps_linear_work_and_exact_order(store, same_time):
    store.index(bulk_events(10000, same_time))
    rows, steps = measured(store._conn(), lambda: list(store.iterate(
        "inv", [Filter(field="data_source", value="connection")], fields=["event_id"], batch=500)))
    assert [row["event_id"] for row in rows] == [f"e{number:06d}" for number in range(10000)]
    assert steps < 2_000_000, f"10k iterator executed at least {steps} SQLite VM instructions"


def ordered_fixture():
    return [
        event("positive", "1970-01-01T00:00:01Z"),
        event("e-zero", "1970-01-01T00:00:00Z"),
        {"event_id": "d-missing", "investigation_id": "inv", "data_source": "connection"},
        event("c-invalid", "invalid"),
        event("b-zero", "1970-01-01T00:00:00Z"),
        event("a-null", None),
        event("negative", "1969-12-31T23:59:59Z"),
    ]


@pytest.mark.parametrize("batch", [1, 2, 3, 7, 20])
def test_iteration_preserves_null_zero_negative_and_id_ties(store, batch):
    store.index(ordered_fixture())
    result = list(store.iterate("inv", [], batch=batch))
    assert [row["event_id"] for row in result] == [
        "negative", "a-null", "b-zero", "c-invalid", "d-missing", "e-zero", "positive"]


@pytest.mark.parametrize("cursor_id", ["negative", "a-null", "b-zero", "c-invalid", "d-missing", "e-zero", "positive"])
def test_cursor_boundaries_keep_equal_time_tail_then_later_rows(store, cursor_id):
    store.index(ordered_fixture())
    order = ["negative", "a-null", "b-zero", "c-invalid", "d-missing", "e-zero", "positive"]
    timestamp = -1 if cursor_id == "negative" else 1 if cursor_id == "positive" else 0
    page = store._page("inv", [], None, 2, encode_cursor([timestamp, cursor_id]))
    position = order.index(cursor_id)
    assert [row["event_id"] for row in page["events"]] == order[position + 1:position + 3]


def test_iterator_reuses_scope_time_filters_and_json_projection_in_both_ranges(store):
    rows = [
        event("a", "1970-01-01T00:00:00Z", tags=["keep"], ext={"value": 7}, payload="excluded"),
        event("b", "1970-01-01T00:00:00Z", tags=["keep"], ext={"value": 8}, payload="excluded"),
        event("c", "1970-01-01T00:00:01Z", tags=["keep"], ext={"value": None}, payload="excluded"),
        event("d", "1970-01-01T00:00:02Z", tags=["keep"]),
        event("x-other", "1970-01-01T00:00:00Z", investigation_id="other", tags=["keep"]),
        event("x-source", "1970-01-01T00:00:01Z", data_source="web", tags=["keep"]),
        event("x-tag", "1970-01-01T00:00:01Z", tags=["drop"]),
        event("x-before", "1969-12-31T23:59:59Z", tags=["keep"]),
        event("x-null", None, tags=["keep"]),
    ]
    store.index(rows)
    filters = [Filter(field="data_source", value="connection"), Filter(field="tags", value="keep")]
    time = TimeRange(start="1970-01-01T00:00:00Z", end="1970-01-01T00:00:01Z")
    assert list(store.iterate("inv", filters, time, ["event_id", "ext.value", "missing"], batch=1)) == [
        {"event_id": "a", "ext.value": 7, "missing": None},
        {"event_id": "b", "ext.value": 8, "missing": None},
        {"event_id": "c", "ext.value": None, "missing": None}]
    page = store._page("inv", filters, time, 10, encode_cursor([0, "a"]), ["event_id", "ext.value"])
    assert page["events"] == [{"event_id": "b", "ext.value": 8}, {"event_id": "c", "ext.value": None}]
    assert page["next_cursor"] is None
    with pytest.raises(ValueError, match="investigation_id"):
        list(store.iterate("", filters, time, batch=1))


@pytest.mark.parametrize("sort,expected", [
    ("asc", ["negative", "a-null", "b-zero", "c-invalid", "d-missing", "e-zero", "positive"]),
    ("desc", ["positive", "e-zero", "d-missing", "c-invalid", "b-zero", "a-null", "negative"]),
])
def test_search_cursor_contract_stays_unchanged(store, sort, expected):
    store.index(ordered_fixture())
    found, cursor = [], None
    while True:
        page = store.search("inv", [], sort=sort, limit=2, cursor=cursor)
        found.extend(row["event_id"] for row in page["events"])
        cursor = page["next_cursor"]
        if cursor is None:
            break
    assert found == expected


def test_old_database_opens_idempotently_without_rewriting_events(tmp_path):
    path = tmp_path / "legacy.sqlite"
    connection = sqlite3.connect(path)
    connection.executescript("""
        CREATE TABLE events(event_id TEXT PRIMARY KEY, investigation_id TEXT NOT NULL,
                            evidence_id TEXT, data_source TEXT, ts TEXT, ts_epoch REAL, doc TEXT NOT NULL);
        CREATE INDEX ix_ev_inv_ts ON events(investigation_id, ts_epoch, event_id);
    """)
    docs = [event("a-null"), event("b-zero", "1970-01-01T00:00:00Z"),
            event("negative", "1969-12-31T23:59:59Z")]
    for doc, timestamp in zip(docs, [None, 0, -1], strict=True):
        connection.execute("INSERT INTO events VALUES (?,?,?,?,?,?,?)",
                           (doc["event_id"], "inv", None, "connection", doc["timestamp"], timestamp, json.dumps(doc)))
    connection.commit()
    original = connection.execute("SELECT event_id,doc FROM events ORDER BY event_id").fetchall()
    connection.close()
    from saw.storage.sqlite_generations import _Reader
    reader = _Reader(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True), path)
    try:
        assert list(reader.iterate("inv", [], fields=["event_id"], batch=1)) == [
            {"event_id": "negative"}, {"event_id": "a-null"}, {"event_id": "b-zero"}]
    finally:
        reader.close()
    for _ in range(2):
        backend = SQLiteEventStore(path)
        try:
            assert [row["event_id"] for row in backend.iterate("inv", [], batch=1)] == [
                "negative", "a-null", "b-zero"]
            assert backend._conn().execute("SELECT event_id,doc FROM events ORDER BY event_id").fetchall() == original
        finally:
            backend._conn().close()

def test_projection_without_event_id_keeps_internal_cursor_private(store):
    store.index([event("a", "1970-01-01T00:00:00Z", answer=1),
                 event("b", "1970-01-01T00:00:00Z", answer=2),
                 event("c", "1970-01-01T00:00:01Z", answer=3)])
    assert list(store.iterate("inv", [], fields=["answer"], batch=1)) == [
        {"answer": 1}, {"answer": 2}, {"answer": 3}]


@pytest.mark.parametrize("value_count", [40, 60])
def test_resumed_cursor_preserves_legacy_variable_budget(store, value_count):
    store.index([event("a", "1970-01-01T00:00:00Z"),
                 event("b", "1970-01-01T00:00:00Z"),
                 event("c", "1970-01-01T00:00:01Z")])
    values = ["connection"] + [f"unmatched?{number}" for number in range(value_count - 1)]
    connection = store._conn()
    previous_limit = connection.setlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, 64)
    try:
        found = list(store.iterate("inv", [Filter(field="data_source", op="in", value=values)],
                                  fields=["event_id"], batch=1))
    finally:
        connection.setlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, previous_limit)
    assert found == [{"event_id": "a"}, {"event_id": "b"}, {"event_id": "c"}]


def test_shared_cursor_bindings_keep_json_array_time_and_literal_question_marks(store):
    literal = "?') OR 1=1 --"
    matching = {"data_source": literal, "tags": [literal], "ext": {"marker": literal}}
    store.index([
        event("a", "1970-01-01T00:00:00Z", **matching),
        event("b", "1970-01-01T00:00:00Z", **matching),
        event("c", "1970-01-01T00:00:01Z", **matching),
        event("x-investigation", "1970-01-01T00:00:00Z", investigation_id="other", **matching),
        event("x-time", "1970-01-01T00:00:02Z", **matching),
        event("x-json", "1970-01-01T00:00:00Z", data_source=literal, tags=[literal], ext={"marker": "wrong"}),
        event("x-tags", "1970-01-01T00:00:00Z", data_source=literal, tags=["wrong"], ext={"marker": literal}),
        event("x-source", "1970-01-01T00:00:00Z", tags=[literal], ext={"marker": literal}),
    ])
    # Investigation + time(2) + IN(54) + JSON(path,value) + array(path,value)
    # use 61 bindings; cursor time, ID and batch must fit the old total of 64.
    values = [literal] + [f"other?{number}" for number in range(53)]
    filters = [Filter(field="data_source", op="in", value=values),
               Filter(field="ext.marker", value=literal), Filter(field="tags", value=literal)]
    time = TimeRange(start="1970-01-01T00:00:00Z", end="1970-01-01T00:00:01Z")
    connection = store._conn()
    previous_limit = connection.setlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, 64)
    try:
        found = list(store.iterate("inv", filters, time, ["event_id", "ext.marker"], batch=1))
    finally:
        connection.setlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, previous_limit)
    assert found == [{"event_id": "a", "ext.marker": literal},
                     {"event_id": "b", "ext.marker": literal},
                     {"event_id": "c", "ext.marker": literal}]