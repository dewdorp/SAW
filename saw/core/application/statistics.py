"""Bounded investigation statistics; every aggregate shares the same query scope."""
from __future__ import annotations

import math
from datetime import datetime

from saw.core.schemas.query import Filter, GroupMetric
from saw.storage.eventstore import SQLiteEventStore

GROUP_FIELDS = {"data_source": ["data_source"], "source_file": ["evidence_id", "source_file"],
                "src_ip": ["src_ip"], "dst_ip": ["dst_ip"], "dst_port": ["dst_port"]}


def bounds(store, inv_id, filters, time):
    scoped = filters + [Filter(field="timestamp", op="exists")]
    first = store.search(inv_id, scoped, time, sort="asc", limit=1)["events"]
    last = store.search(inv_id, scoped, time, sort="desc", limit=1)["events"]
    return (first[0].get("timestamp") if first else None, last[0].get("timestamp") if last else None)


def interval(start, end):
    if not start or not end:
        return 60
    span = max(1, (datetime.fromisoformat(end.replace("Z", "+00:00"))
                   - datetime.fromisoformat(start.replace("Z", "+00:00"))).total_seconds())
    for step in (1, 5, 10, 30, 60, 300, 600, 1800, 3600, 10800, 21600, 43200, 86400):
        if span / step <= 199:
            return step
    return math.ceil(span / 199)


def summarize(store, inv_id, filters, time, group_by, size):
    fields = GROUP_FIELDS[group_by]
    total = store.count(inv_id, filters, time)
    valid = filters + [Filter(field=f, op="exists") for f in fields]
    with_group = store.count(inv_id, valid, time)
    start, end = bounds(store, inv_id, filters, time)
    groups = store.group_by(inv_id, valid, fields,
                           [GroupMetric(type="sum", field="bytes_out", name="bytes_out_sum")], size=size, time=time)
    rows = []
    for group in groups:
        row_filters = [Filter(field=f, value=group["key"][f]) for f in fields]
        first, last = bounds(store, inv_id, filters + row_filters, time)
        known_bytes = store.count(inv_id, filters + row_filters + [Filter(field="bytes_out", op="exists")], time)
        rows.append({"key": group["key"], "count": group["count"],
                     "bytes_out_sum": group.get("bytes_out_sum") if known_bytes else None,
                     "bytes_out_known_events": known_bytes, "first_ts": first, "last_ts": last,
                     "filter": [f.model_dump() for f in row_filters]})
    shown = sum(r["count"] for r in rows)
    return {"scope": {"investigation_id": inv_id, "filters": [f.model_dump() for f in filters],
                      "time": time.model_dump() if time else None},
            "summary": {"matched_events": total, "time_start": start, "time_end": end,
                        "timestamp_missing": store.count(inv_id, filters + [Filter(field="timestamp", op="not_exists")], time)},
            "table": {"group_by": group_by, "rows": rows, "shown_events": shown,
                      "other_events": max(0, with_group - shown), "missing_events": total - with_group,
                      "limit": size, "approximate": not isinstance(store, SQLiteEventStore)},
            "timeline": store.histogram_metrics(inv_id, filters, interval(start, end), [], time)}
