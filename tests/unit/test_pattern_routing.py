"""Synthetic routing regressions: only complete producer-owned connection views skip Drain."""
from copy import deepcopy

import pytest

from saw.analyzers.pattern.cluster import text_patterns
from saw.parsers.base import Parsed, RawLine
from saw.parsers.registry import to_ces
from saw.parsers.structured import CsvParser
from saw.storage.eventstore import SQLiteEventStore
from tests.api.test_affiliate_firewall_flow import CSV


def verified_context():
    # Same complete field/time/counter semantics as the P5 synthetic FW profile.
    return {
        "subject": {"org_unit_id": "A", "status": "verified"},
        "observer": {"device_id": "FW-1", "device_profile_version_id": "profile-1", "network": "test-lab"},
        "profile": {
            "functions": ["FW"],
            "source_fields": {"record_kind": "record_type", "session_id": "session_id", "timestamp": "timestamp",
                              "action": "action", "src_bytes": "sent_bytes", "dst_bytes": "received_bytes"},
            "record_kind_map": {"start": "session_start", "interim": "session_interim", "end": "session_end"},
            "action_map": {"allow": "allowed", "deny": "blocked"}, "action_verified": True,
            "action_basis": "synthetic fixture explicitly defines these words",
            "measurement_profile": {"counter_semantics": "cumulative", "direction": "src_to_dst",
                                    "unit": "bytes", "verified": True, "basis": "synthetic cumulative fixture"},
            "time": {"role": "occurred", "timezone": "UTC", "precision": "second",
                     "verified": True, "basis": "synthetic UTC fixture"}},
        "collection": {"scope": "full", "loss": "known"}}


def connection_rows(context=None, text=None):
    parser = CsvParser()
    return [to_ces(parser, raw, result, investigation_id="i", evidence_id="e", file_id="f",
                   source_file="synthetic.csv", object_key="synthetic", assumed_tz="UTC", context_snapshot=context)
            for raw, result in parser.parse(iter(RawLine(line, n * 100, n + 1)
                                                for n, line in enumerate((text or CSV.decode()).splitlines())))
            if isinstance(result, Parsed)]


@pytest.fixture
def store(tmp_path):
    backend = SQLiteEventStore(tmp_path / "patterns.db")
    try:
        yield backend
    finally:
        backend._conn().close()


@pytest.fixture
def mined(monkeypatch):
    from drain3 import TemplateMiner
    messages = []
    add = TemplateMiner.add_log_message

    def record(self, message):
        messages.append(message)
        return add(self, message)

    monkeypatch.setattr(TemplateMiner, "add_log_message", record)
    return messages


@pytest.mark.parametrize("mode", ["cumulative", "delta", "total"])
@pytest.mark.parametrize("functions", [["FW"], []])
def test_complete_constructor_connection_observations_do_not_enter_mining(store, mined, mode, functions):
    context = verified_context()
    context["profile"]["functions"] = functions
    context["profile"]["measurement_profile"]["counter_semantics"] = mode
    rows = connection_rows(context)
    assert {row["data_source"] for row in rows} == {"connection"}
    assert rows[0]["ext"]["observation"]["counters"]["src_to_dst_bytes"]["value"] == 0
    store.index(rows)
    assert text_patterns(store, "i") == []
    assert mined == []


def test_unverified_connection_and_custom_syslog_still_mined_in_mixed_input(store, mined):
    trusted = connection_rows(verified_context())
    unknown = connection_rows()[0]
    unknown["event_id"] = "unknown"
    texts = [{"event_id": source, "investigation_id": "i", "data_source": source, "timestamp": unknown["timestamp"],
              "raw_event": source + " useful log", "src_ip": "10.0.0.2"} for source in ("custom", "syslog", "firewall")]
    store.index(trusted + [unknown] + texts)
    patterns = text_patterns(store, "i")
    assert sum(pattern["count"] for pattern in patterns) == 4
    assert sorted(mined) == sorted([unknown["raw_event"]] + [row["raw_event"] for row in texts])


@pytest.mark.parametrize(("path", "value"), [
    (("ext",), None), (("ext",), []), (("ext", "observation"), None),
    (("ext", "observation"), []), (("ext", "observation", "producer"), "uploaded"),
    (("ext", "observation", "version"), "connection-observation/0"),
    (("ext", "observation", "context"), []),
    (("ext", "observation", "context", "resolved"), 1),
    (("ext", "observation", "context", "device_id"), None),
    (("ext", "observation", "context", "org_unit_id"), ""),
    (("ext", "observation", "context", "network"), None),
    (("ext", "observation", "profile_version"), "different-profile"),
    (("ext", "observation", "quality"), ["timestamp_context_conflict"]),
    (("ext", "observation", "quality"), None),
    (("ext", "observation", "record_kind"), "unknown"),
    (("ext", "observation", "action"), "unknown"),
    (("ext", "observation", "action"), "conflicting"),
    (("ext", "observation", "session_id"), None),
    (("ext", "observation", "counters"), []),
    (("ext", "observation", "counters", "src_to_dst_bytes", "state"), "unknown_semantics"),
    (("ext", "observation", "counters", "dst_to_src_bytes", "state"), "recorded_empty"),
    (("ext", "observation", "counters", "src_to_dst_bytes", "value"), True),
    (("ext", "observation", "counters", "src_to_dst_bytes", "value"), -1),
    (("ext", "observation", "counters", "src_to_dst_bytes", "value"), 0.5),
    (("ext", "observation", "counters", "src_to_dst_bytes", "source_field"), None),
    (("ext", "observation", "counters", "src_to_dst_bytes", "unit"), "packets"),
    (("ext", "observation", "counters", "src_to_dst_bytes", "counter_mode"), "unknown"),
    (("ext", "observation", "counters", "dst_to_src_bytes", "counter_mode"), "delta"),
    (("ext", "observation", "time_profile"), []),
    (("ext", "observation", "time_profile", "verified"), False),
    (("ext", "observation", "time_profile", "role"), "collected"),
    (("ext", "observation", "timestamp_precision"), "unknown"),
    (("ext", "observation", "timestamp_basis"), "parser_or_upload_default"),
    (("ext", "observation", "timestamp"), "invalid"),
    (("dst_ip",), None), (("data_source",), "custom"), (("data_source",), "firewall"),
])
def test_incomplete_legacy_or_conflicting_metadata_cannot_suppress_text(store, mined, path, value):
    row = connection_rows(verified_context())[0]
    target = row
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    store.index([row])
    assert sum(pattern["count"] for pattern in text_patterns(store, "i")) == 1
    assert mined == [row["raw_event"]]


@pytest.mark.parametrize("source", ["connection", "firewall"])
def test_source_label_or_resolved_context_alone_never_skips_text(store, mined, source):
    row = connection_rows()[0]
    row["data_source"] = source
    row["ext"]["observation"]["context"]["resolved"] = True
    store.index([row])
    assert sum(pattern["count"] for pattern in text_patterns(store, "i")) == 1
    assert mined == [row["raw_event"]]


def test_normal_parser_overwrites_forged_uploaded_observation(store, mined):
    import json

    from saw.parsers.structured import JsonLinesParser

    supplied = connection_rows(verified_context())[0]
    parser = JsonLinesParser()
    raw = RawLine(json.dumps(supplied), 0, 1)
    parsed = parser.parse_line(raw.text)
    assert isinstance(parsed, Parsed)
    row = to_ces(parser, raw, parsed, investigation_id="i", evidence_id="e", file_id="forged",
                 source_file="synthetic.jsonl", object_key="synthetic", assumed_tz="UTC")
    assert row["ext"]["observation"]["context"]["resolved"] is False
    assert row["ext"]["observation"]["action"] == "unknown"
    store.index([row])
    assert sum(pattern["count"] for pattern in text_patterns(store, "i")) == 1
    assert mined == [row["raw_event"][:2000]]


def test_missing_raw_stays_mined_without_hydration(store, mined):
    row = connection_rows()[0]
    row.pop("raw_event")
    before = deepcopy(row)
    store.index([row])
    text_patterns(store, "i")
    assert mined == [""]
    assert store.get("i", row["event_id"]) == before


@pytest.mark.parametrize(("limit", "expected_count"), [(0, 0), (1, 0), (2, 1), (3, 1)])
def test_examined_bound_includes_skips_without_reading_next_row(mined, limit, expected_count):
    trusted = connection_rows(verified_context())[0]
    text = connection_rows()[0]
    consumed = []

    class Bounded:
        def iterate(self, inv, filters, fields=None):
            for number, row in enumerate([trusted, text, trusted], 1):
                assert number <= limit, "read past the examined-row cap"
                consumed.append(number)
                yield {field: row.get(field) for field in fields}
            if limit == 3:
                raise AssertionError("read after the exact bound")

    result = text_patterns(Bounded(), "i", max_lines=limit)
    assert len(consumed) == limit
    assert sum(pattern["count"] for pattern in result) == expected_count
    assert len(mined) == expected_count
    assert all(pattern["sampled"] is True for pattern in result)


def test_empty_input_and_short_input_sampling(store):
    assert text_patterns(store, "i") == []
    store.index(connection_rows()[:1])
    result = text_patterns(store, "i", max_lines=2)
    assert len(result) == 1 and result[0]["sampled"] is False


def test_retained_legacy_observations_and_raw_references_are_unchanged(store):
    from saw.storage.generations import GenerationStore

    rows = connection_rows(verified_context())
    store.index(rows)
    generations = GenerationStore(store, resolve=lambda inv, **kw: None, check_read=lambda ref: None,
                                 open_raw=lambda *args: pytest.fail("unexpected raw hydration"), cursor_key=b"p" * 32)
    with generations.open_view("i") as retained:
        replaced = deepcopy(rows)
        for row in replaced:
            row["ext"]["observation"]["quality"] = ["unverified_action"]
        store.index(replaced)
        assert text_patterns(retained, "i") == []
        assert sum(pattern["count"] for pattern in text_patterns(store, "i")) == 3
        assert retained.get("i", rows[0]["event_id"]) == rows[0]

@pytest.mark.parametrize("defect", ["unverified_action", "unverified_counters", "unverified_time", "conflicting_org"])
def test_constructor_rejects_untrusted_profile_and_conflicting_row_attribution(store, mined, defect):
    context = verified_context()
    text = CSV.decode()
    if defect == "unverified_action":
        context["profile"]["action_verified"] = False
    elif defect == "unverified_counters":
        context["profile"]["measurement_profile"]["verified"] = False
    elif defect == "unverified_time":
        context["profile"]["time"]["verified"] = False
    else:
        context["profile"]["source_fields"]["org_unit_id"] = "record_org"
        text = "\n".join(line + (",record_org" if n == 0 else ",B")
                         for n, line in enumerate(text.splitlines()))
    rows = connection_rows(context, text)
    store.index(rows)
    assert sum(pattern["count"] for pattern in text_patterns(store, "i")) == 3
    assert len(mined) == 3
    if defect == "conflicting_org":
        assert all("conflicting_row_attribution" in row["ext"]["observation"]["quality"] for row in rows)


def test_default_examined_limit_stops_at_50000_even_when_rows_are_skipped(mined):
    trusted = connection_rows(verified_context())[0]
    text = connection_rows()[0]
    consumed = 0

    class Bounded:
        def iterate(self, inv, filters, fields=None):
            nonlocal consumed
            for number in range(50_000):
                consumed += 1
                row = text if number == 0 else trusted
                yield {field: row.get(field) for field in fields}
            pytest.fail("read beyond the default examined cap")

    patterns = text_patterns(Bounded(), "i")
    assert consumed == 50_000
    assert mined == [text["raw_event"]]
    assert len(patterns) == 1 and patterns[0]["count"] == 1 and patterns[0]["sampled"] is True
