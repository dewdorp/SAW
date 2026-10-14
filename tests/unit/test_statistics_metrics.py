from unittest.mock import Mock

import pytest
from pydantic import ValidationError
from saw.core.schemas.query import Filter, GroupMetric, GroupByRequest
from saw.storage.eventstore import SQLiteEventStore
from saw.storage.opensearch_store import OpenSearchEventStore


def test_group_metrics_filter_order_and_instant_bounds(tmp_path):
    es = SQLiteEventStore(tmp_path / "synthetic.db")
    es.index([
        {"event_id": "a", "investigation_id": "i", "src_ip": "a", "timestamp": "2026-10-14T09:00:00+09:00", "status_code": 404, "bytes_out": 0},
        {"event_id": "b", "investigation_id": "i", "src_ip": "a", "timestamp": "2026-10-14T00:30:00Z"},
        {"event_id": "c", "investigation_id": "i", "src_ip": "b", "status_code": 500, "bytes_out": 100},
        {"event_id": "d", "investigation_id": "foreign", "src_ip": "a", "status_code": 500, "bytes_out": 999},
    ])
    metrics = [
        GroupMetric(type="value_count", field="bytes_out", name="known"),
        GroupMetric(type="count", name="errors", filters=[Filter(field="status_code", op="range", value={"gte": 400, "lte": 599})]),
        GroupMetric(type="sum", field="bytes_out", name="volume"),
        GroupMetric(type="min_ts", name="first"),
        GroupMetric(type="max_ts", name="last"),
    ]
    assert len(es.group_by("i", [], ["src_ip"], metrics, size=20000)) == 2
    rows = es.group_by("i", [], ["src_ip"], metrics, size=1, order_by="volume")
    assert rows[0]["key"] == {"src_ip": "b"}
    row = es.group_by("i", [], ["src_ip"], metrics)[0]
    assert (row["known"], row["errors"], row["volume"]) == (1, 1, 0)
    assert row["first"] == "2026-10-14T09:00:00+09:00"
    assert row["last"] == "2026-10-14T00:30:00Z"


def test_group_metric_aliases_and_order_are_validated():
    for name in ("a; DROP TABLE events", "a.b", "_count", ""):
        with pytest.raises(ValidationError):
            GroupMetric(type="sum", field="bytes_out", name=name)
    with pytest.raises(ValidationError):
        GroupMetric(type="sum", field="bytes_out);DROP", name="safe")
    with pytest.raises(ValidationError):
        GroupByRequest(fields=["src_ip"], order_by="volume;DROP", metrics=[])
    with pytest.raises(ValueError):
        SQLiteEventStore(":memory:").group_by("i", [], ["src_ip"], [], order_by="missing")


def test_opensearch_group_filter_metrics_use_single_request():
    es = OpenSearchEventStore.__new__(OpenSearchEventStore)
    es._fresh = Mock()
    es.alias = "synthetic-events"
    es.client = Mock()
    es.client.search.return_value = {"aggregations": {"g": {"buckets": [
        {"key": "a", "doc_count": 3, "known": {"value": 2}, "errors": {"doc_count": 1}}
    ]}}}
    metrics = [GroupMetric(type="value_count", field="bytes_out", name="known"),
               GroupMetric(type="count", name="errors", filters=[Filter(field="status_code", op="range", value={"gte": 400, "lte": 599})])]
    row, = es.group_by("i", [], ["src_ip"], metrics, order_by="errors")
    assert (row["known"], row["errors"]) == (2, 1)
    assert es.client.search.call_count == 1
    body = es.client.search.call_args.kwargs["body"]
    assert body["aggs"]["g"]["terms"]["order"] == {"errors": "desc"}
    assert body["aggs"]["g"]["aggs"]["known"] == {"value_count": {"field": "bytes_out"}}
    assert "filter" in body["aggs"]["g"]["aggs"]["errors"]
    assert "i" in str(body["query"])


def test_opensearch_statistics_timestamp_keeps_source_offset():
    es = OpenSearchEventStore.__new__(OpenSearchEventStore)
    es._fresh = Mock()
    es.alias = "synthetic-events"
    es.client = Mock()
    original = "2026-10-14T09:00:00+09:00"
    es.client.search.return_value = {"aggregations": {"g": {"buckets": [
        {"key": "a", "doc_count": 1, "first": {"hits": {"hits": [{"_source": {"timestamp": original}}]}}}
    ]}}}
    row, = es.group_by("i", [], ["src_ip"], [GroupMetric(type="min_ts", name="first", preserve_timestamp=True)])
    assert row["first"] == original
    bounds = es.client.search.call_args.kwargs["body"]["aggs"]["g"]["aggs"]["first"]
    assert bounds["top_hits"]["size"] == 1 and bounds["top_hits"]["_source"] == ["timestamp"]


def test_group_filtered_sums_and_safe_filter_values(tmp_path):
    es = SQLiteEventStore(tmp_path / "synthetic-filters.db")
    es.index([
        {"event_id": "a", "investigation_id": "i", "src_ip": "a", "status_code": 200, "bytes_out": 10},
        {"event_id": "b", "investigation_id": "i", "src_ip": "a", "status_code": 500, "bytes_out": 90},
    ])
    metrics = [GroupMetric(type="sum", field="bytes_out", name="filtered",
                           filters=[Filter(field="status_code", value=500)]),
               GroupMetric(type="count", name="hostile", filters=[Filter(field="src_ip", value="a' OR 1=1 --")])]
    row, = es.group_by("i", [], ["src_ip"], metrics, order_by="filtered")
    assert row["filtered"] == 90 and row["hostile"] == 0
    with pytest.raises(ValidationError):
        GroupMetric(type="count", name="bad", filters=[{"field": "src_ip); DROP", "value": "a"}])
    with pytest.raises(ValidationError):
        GroupByRequest(fields=["src_ip"], metrics=[GroupMetric(type="min_ts", name="first", preserve_timestamp=True)], order_by="first")
    with pytest.raises(ValidationError):
        GroupByRequest(fields=["src_ip"], metrics=[GroupMetric(type="sum", field="bytes_out", name="same")] * 2)


def test_opensearch_unfiltered_count_alias_orders_by_bucket_count():
    es = OpenSearchEventStore.__new__(OpenSearchEventStore)
    es._fresh = Mock()
    es.alias = "synthetic-events"
    es.client = Mock()
    es.client.search.return_value = {"aggregations": {"g": {"buckets": [
        {"key": "a", "doc_count": 3}
    ]}}}
    row, = es.group_by("i", [], ["src_ip"], [GroupMetric(type="count", name="n")], order_by="n")
    assert row["n"] == 3
    body = es.client.search.call_args.kwargs["body"]
    assert body["aggs"]["g"]["terms"]["order"] == {"_count": "desc"}


@pytest.mark.parametrize("kind", ["min_ts", "max_ts"])
def test_timestamp_group_order_is_rejected_on_both_stores(kind):
    metric = GroupMetric(type=kind, name="bound")
    with pytest.raises(ValidationError, match="timestamp"):
        SQLiteEventStore(":memory:").group_by("i", [], ["src_ip"], [metric], order_by="bound")
    es = OpenSearchEventStore.__new__(OpenSearchEventStore)
    es._fresh = Mock()
    with pytest.raises(ValidationError, match="timestamp"):
        es.group_by("i", [], ["src_ip"], [metric], order_by="bound")
    es._fresh.assert_not_called()
