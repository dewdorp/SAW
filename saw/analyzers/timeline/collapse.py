"""Timeline collapse of repetitive events (docs/23 §3)."""
from __future__ import annotations

import statistics
from datetime import datetime


def _ep(ts: str | None) -> float | None:
    return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp() if ts else None


def collapse_key(e: dict) -> tuple:
    ds = e.get("data_source")
    if ds in ("web", "waf"):
        return (ds, e.get("method"), e.get("uri_template"), e.get("status_code"))
    if ds and ds.startswith("zeek"):
        return (ds, e.get("src_ip"), e.get("dst_ip"), e.get("dst_port"), e.get("domain"))
    return (ds, e.get("event_type"), e.get("process"), e.get("src_ip"))


def collapse(events: list[dict], min_run: int = 5) -> list[dict]:
    """events must be time ordered. Returns items: {'kind':'event',...} | {'kind':'group',...}."""
    items: list[dict] = []
    i = 0
    prev_ts: float | None = None
    while i < len(events):
        k = collapse_key(events[i])
        j = i
        while j + 1 < len(events) and collapse_key(events[j + 1]) == k:
            j += 1
        run = events[i:j + 1]
        if len(run) >= min_run:
            ts = [x for x in (_ep(e.get("timestamp")) for e in run) if x is not None]
            d = [b - a for a, b in zip(ts, ts[1:], strict=False)]
            med = statistics.median(d) if d else None
            mean = statistics.fmean(d) if d else None
            cv = (statistics.pstdev(d) / mean) if d and mean else None
            # show first two as samples, collapse the rest
            for e in run[:2]:
                t = _ep(e.get("timestamp"))
                items.append({"kind": "event", "event": e, "delta_sec": (t - prev_ts) if t and prev_ts else None})
                prev_ts = t or prev_ts
            items.append({"kind": "group", "count": len(run) - 2, "key": [str(x) if x is not None else None for x in k],
                          "src_count": len({e.get("src_ip") for e in run}), "dt_median": med,
                          "dt_cv": round(cv, 3) if cv is not None else None,
                          "first": run[2].get("timestamp"), "last": run[-1].get("timestamp"),
                          "sample_ids": [e["event_id"] for e in run[2:4]]})
            prev_ts = ts[-1] if ts else prev_ts
        else:
            for e in run:
                t = _ep(e.get("timestamp"))
                items.append({"kind": "event", "event": e, "delta_sec": (t - prev_ts) if t and prev_ts else None})
                prev_ts = t or prev_ts
        i = j + 1
    return items
