"""Bounded investigation statistics; every aggregate shares the same query scope."""
from __future__ import annotations

import math
from datetime import datetime

from saw.core.schemas.query import Filter, GroupMetric
from saw.storage.eventstore import SQLiteEventStore

GROUP_FIELDS = {"data_source": ["data_source"], "source_file": ["evidence_id", "source_file"],
                "src_ip": ["src_ip"], "dst_ip": ["dst_ip"], "dst_port": ["dst_port"],
                "src_dst": ["src_ip", "dst_ip"], "status_code": ["status_code"], "method": ["method"],
                "enforcement_action": ["enforcement_action"], "alert_name": ["alert_name"], "protocol": ["protocol"]}


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


def summarize(store, inv_id, filters, time, group_by, size, order_by="count"):
    fields = GROUP_FIELDS[group_by]
    total = store.count(inv_id, filters, time)
    valid = filters + [Filter(field=f, op="exists") for f in fields]
    with_group = store.count(inv_id, valid, time)
    start, end = bounds(store, inv_id, filters, time)
    metrics = [GroupMetric(type=kind, field=field, name=name, preserve_timestamp=kind in ("min_ts", "max_ts")) for kind, field, name in [
        ("sum", "bytes_in", "bytes_in_sum"), ("sum", "bytes_out", "bytes_out_sum"),
        ("value_count", "bytes_in", "bytes_in_known_events"), ("value_count", "bytes_out", "bytes_out_known_events"),
        ("min_ts", None, "first_ts"), ("max_ts", None, "last_ts")]]
    for name, lo, hi in [("http_status_known_events", 100, 599), ("http_4xx_count", 400, 499),
                         ("http_5xx_count", 500, 599), ("http_error_count", 400, 599)]:
        metrics.append(GroupMetric(type="count", name=name, filters=[
            Filter(field="status_code", op="range", value={"gte": lo, "lte": hi})]))
    groups = store.group_by(inv_id, valid, fields, metrics, size=size, time=time, order_by=order_by)
    rows = []
    for group in groups:
        row = dict(group)
        for direction in ("in", "out"):
            if not row[f"bytes_{direction}_known_events"]:
                row[f"bytes_{direction}_sum"] = None
        known = row["http_status_known_events"]
        row["http_error_rate"] = row["http_error_count"] * 100 / known if known else None
        row["http_4xx_rate"] = row["http_4xx_count"] * 100 / known if known else None
        row["http_5xx_rate"] = row["http_5xx_count"] * 100 / known if known else None
        row["filter"] = [Filter(field=f, value=group["key"][f]).model_dump() for f in fields]
        rows.append(row)
    shown = sum(r["count"] for r in rows)
    return {"scope": {"investigation_id": inv_id, "filters": [f.model_dump() for f in filters],
                      "time": time.model_dump() if time else None},
            "summary": {"matched_events": total, "time_start": start, "time_end": end,
                        "timestamp_missing": store.count(inv_id, filters + [Filter(field="timestamp", op="not_exists")], time)},
            "table": {"group_by": group_by, "order_by": order_by, "rows": rows, "shown_events": shown,
                      "other_events": max(0, with_group - shown), "missing_events": total - with_group,
                      "limit": size, "approximate": not isinstance(store, SQLiteEventStore)},
            "timeline": store.histogram_metrics(inv_id, filters, interval(start, end), [], time)}
