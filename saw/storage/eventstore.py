"""EventStorePort + SQLite adapter (local, verified). OpenSearch adapter lives in opensearch_store.py (ENV-03).

Every query is scoped to one investigation_id — callers cannot omit it (docs/08 §6 safety).
"""
from __future__ import annotations

import base64
import json
import sqlite3
import threading
from collections.abc import Iterable, Iterator
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol

import orjson

from saw.core.schemas.query import FIELD_RE, AggRequest, Filter, GroupMetric, GroupByRequest, TimeRange

INDEXED_COLUMNS = {"event_id", "investigation_id", "evidence_id", "data_source"}
ARRAY_FIELDS = {"tags", "param_names", "finding_ids"}
MAX_HISTOGRAM_BUCKETS = 5000
_INTERVALS = (1, 5, 10, 30, 60, 300, 600, 1800, 3600, 10800, 21600, 43200, 86400, 604800)


def widened_interval(iv: int, span: float | None) -> int:
    """The requested interval, or the smallest standard one keeping the bucket count bounded."""
    if span is None or span / max(1, iv) <= MAX_HISTOGRAM_BUCKETS:
        return iv
    return next((x for x in _INTERVALS if x >= iv and span / x <= MAX_HISTOGRAM_BUCKETS), _INTERVALS[-1])


class EventStorePort(Protocol):
    def index(self, events: Iterable[dict[str, Any]]) -> int: ...
    def get(self, investigation_id: str, event_id: str) -> dict | None: ...
    def search(self, investigation_id: str, filters: list[Filter], time: TimeRange | None = None,
               sort: str = "asc", limit: int = 100, cursor: str | None = None) -> dict: ...
    def iterate(self, investigation_id: str, filters: list[Filter], time: TimeRange | None = None,
                fields: list[str] | None = None, batch: int = 5000) -> Iterator[dict]: ...
    def count(self, investigation_id: str, filters: list[Filter] | None = None,
              time: TimeRange | None = None) -> int: ...
    def aggregate(self, investigation_id: str, filters: list[Filter], agg: AggRequest,
                  time: TimeRange | None = None) -> dict: ...
    def group_by(self, investigation_id: str, filters: list[Filter], fields: list[str],
                 metrics: list[GroupMetric], size: int = 100, time: TimeRange | None = None,
                 order_by: str | None = None) -> list[dict]: ...
    def delete_by_evidence(self, investigation_id: str, evidence_id: str) -> int: ...
    def delete_by_investigation(self, investigation_id: str) -> int: ...
    def time_bounds(self, investigation_id: str,
                    filters: list[Filter] | None = None) -> tuple[str | None, str | None]: ...


def ts_epoch(ts: str | None) -> float | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def encode_cursor(values: list[Any]) -> str:
    return base64.urlsafe_b64encode(json.dumps(values).encode()).decode()


def decode_cursor(c: str) -> list[Any]:
    return json.loads(base64.urlsafe_b64decode(c.encode()))


def _jpath(field: str) -> str:
    if not FIELD_RE.match(field):
        raise ValueError(f"invalid field {field!r}")
    return "$." + ".".join(f'"{p}"' for p in field.split("."))


def _col(field: str) -> tuple[str, list[Any]]:
    if field in INDEXED_COLUMNS:
        return field, []
    if field == "timestamp":
        return "ts", []
    return "json_extract(doc, ?)", [_jpath(field)]


def _like_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


class _FirstTimestamp:
    reverse = False

    def __init__(self):
        self.epoch = None
        self.value = None

    def step(self, value, epoch):
        if epoch is not None and (self.epoch is None or (epoch > self.epoch if self.reverse else epoch < self.epoch)):
            self.epoch, self.value = epoch, value

    def finalize(self):
        return self.value


class _LastTimestamp(_FirstTimestamp):
    reverse = True


class SQLiteEventStore:
    def __init__(self, path: str | Path):
        self.path = str(path)
        self._uri = self.path.startswith("file:")
        if self.path != ":memory:" and not self._uri:
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._write_lock = threading.Lock()
        # shared-cache in-memory DBs vanish when their last connection closes: keep an anchor for the store's lifetime
        self._anchor = sqlite3.connect(self.path, check_same_thread=False, uri=True) if self._uri else None
        c = self._conn()
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS events(
              event_id TEXT PRIMARY KEY, investigation_id TEXT NOT NULL, evidence_id TEXT,
              data_source TEXT, ts TEXT, ts_epoch REAL, doc TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS ix_ev_inv_ts ON events(investigation_id, ts_epoch, event_id);
            CREATE INDEX IF NOT EXISTS ix_ev_inv_cursor ON events(investigation_id, COALESCE(ts_epoch,0), event_id);
            CREATE INDEX IF NOT EXISTS ix_ev_inv_src ON events(investigation_id, json_extract(doc,'$."src_ip"'));
            CREATE INDEX IF NOT EXISTS ix_ev_inv_tpl ON events(investigation_id, json_extract(doc,'$."uri_template"'));
            CREATE INDEX IF NOT EXISTS ix_ev_inv_evd ON events(investigation_id, evidence_id);
            """
        )
        c.commit()

    def _conn(self) -> sqlite3.Connection:
        c = getattr(self._local, "c", None)
        if c is None:
            c = sqlite3.connect(self.path, check_same_thread=False, timeout=60, uri=self._uri)
            if not self._uri:
                c.execute("PRAGMA journal_mode=WAL")
            c.execute("PRAGMA synchronous=NORMAL")
            c.execute("PRAGMA cache_size=-65536")  # 64 MB page cache: bounded for small PCs, avoids re-reading pages
            c.execute("PRAGMA temp_store=MEMORY")
            c.create_aggregate("first_timestamp", 2, _FirstTimestamp)
            c.create_aggregate("last_timestamp", 2, _LastTimestamp)
            self._local.c = c
        return c

    # ------------------------------------------------------------------ write
    def index(self, events: Iterable[dict[str, Any]]) -> int:
        rows = []
        for e in events:
            if not e.get("investigation_id") or not e.get("event_id"):
                raise ValueError("event requires investigation_id and event_id")
            rows.append((
                e["event_id"], e["investigation_id"], e.get("evidence_id"), e.get("data_source"),
                e.get("timestamp"), ts_epoch(e.get("timestamp")), orjson.dumps(e).decode(),
            ))
        if not rows:
            return 0
        with self._write_lock:
            c = self._conn()
            c.executemany("INSERT OR REPLACE INTO events VALUES (?,?,?,?,?,?,?)", rows)
            c.commit()
        return len(rows)

    def delete_by_evidence(self, investigation_id: str, evidence_id: str) -> int:
        with self._write_lock:
            c = self._conn()
            cur = c.execute("DELETE FROM events WHERE investigation_id=? AND evidence_id=?",
                            (investigation_id, evidence_id))
            c.commit()
            return cur.rowcount

    def delete_by_investigation(self, investigation_id: str) -> int:
        if not investigation_id:
            raise ValueError("investigation_id is mandatory")
        with self._write_lock:
            c = self._conn()
            result = c.execute("DELETE FROM events WHERE investigation_id=?", (investigation_id,))
            c.commit()
            return result.rowcount

    # ------------------------------------------------------------------ where
    def _where(self, inv: str, filters: list[Filter] | None, time: TimeRange | None) -> tuple[str, list]:
        if not inv:
            raise ValueError("investigation_id is mandatory")
        clauses, params = ["investigation_id = ?"], [inv]
        if time and time.start:
            clauses.append("ts_epoch >= ?")
            params.append(ts_epoch(time.start))
        if time and time.end:
            clauses.append("ts_epoch <= ?")
            params.append(ts_epoch(time.end))
        for f in filters or []:
            if f.field in ARRAY_FIELDS and f.op in ("is", "is_not", "in", "not_in"):
                vals = list(f.value) if f.op in ("in", "not_in") else [f.value]
                ph = ",".join("?" * len(vals)) or "NULL"
                sub = f"EXISTS(SELECT 1 FROM json_each(doc, ?) WHERE value IN ({ph}))"
                clauses.append(sub if f.op in ("is", "in") else f"NOT {sub}")
                params += [_jpath(f.field)] + vals
                continue
            col, cp = _col(f.field)
            if f.op == "is":
                clauses.append(f"{col} = ?")
                params += cp + [f.value]
            elif f.op == "is_not":
                clauses.append(f"({col} IS NULL OR {col} != ?)")
                params += cp + cp + [f.value]
            elif f.op in ("in", "not_in"):
                vals = list(f.value or [])
                if not vals:
                    clauses.append("1=0" if f.op == "in" else "1=1")
                    continue
                ph = ",".join("?" * len(vals))
                if f.op == "in":
                    clauses.append(f"{col} IN ({ph})")
                    params += cp + vals
                else:
                    clauses.append(f"({col} IS NULL OR {col} NOT IN ({ph}))")
                    params += cp + cp + vals
            elif f.op == "range":
                v = f.value or {}
                for k, sym in (("gte", ">="), ("gt", ">"), ("lte", "<="), ("lt", "<")):
                    if k in v:
                        clauses.append(f"{col} {sym} ?")
                        params += cp + [v[k]]
            elif f.op == "exists":
                clauses.append(f"{col} IS NOT NULL")
                params += cp
            elif f.op == "not_exists":
                clauses.append(f"{col} IS NULL")
                params += cp
            elif f.op == "prefix":
                clauses.append(f"{col} LIKE ? ESCAPE '\\'")
                params += cp + [_like_escape(str(f.value)) + "%"]
            elif f.op == "contains":
                clauses.append(f"{col} LIKE ? ESCAPE '\\'")
                params += cp + ["%" + _like_escape(str(f.value)) + "%"]
        return " AND ".join(clauses), params

    # ------------------------------------------------------------------ read
    def get(self, investigation_id: str, event_id: str) -> dict | None:
        r = self._conn().execute(
            "SELECT doc FROM events WHERE investigation_id=? AND event_id=?", (investigation_id, event_id)
        ).fetchone()
        return orjson.loads(r[0]) if r else None

    def count(self, investigation_id: str, filters: list[Filter] | None = None,
              time: TimeRange | None = None) -> int:
        w, p = self._where(investigation_id, filters, time)
        return self._conn().execute(f"SELECT COUNT(*) FROM events WHERE {w}", p).fetchone()[0]

    def search(self, investigation_id: str, filters: list[Filter], time: TimeRange | None = None,
               sort: str = "asc", limit: int = 100, cursor: str | None = None) -> dict:
        w, p = self._where(investigation_id, filters, time)
        order = "ASC" if sort == "asc" else "DESC"
        if cursor:
            cts, cid = decode_cursor(cursor)
            cmp = ">" if sort == "asc" else "<"
            w += f" AND (COALESCE(ts_epoch,0), event_id) {cmp} (?, ?)"
            p += [cts, cid]
        rows = self._conn().execute(
            f"SELECT doc, COALESCE(ts_epoch,0), event_id FROM events WHERE {w} "
            f"ORDER BY COALESCE(ts_epoch,0) {order}, event_id {order} LIMIT ?",
            p + [limit + 1],
        ).fetchall()
        more = len(rows) > limit
        rows = rows[:limit]
        nxt = encode_cursor([rows[-1][1], rows[-1][2]]) if more and rows else None
        return {"events": [orjson.loads(r[0]) for r in rows], "next_cursor": nxt}

    def iterate(self, investigation_id: str, filters: list[Filter], time: TimeRange | None = None,
                fields: list[str] | None = None, batch: int = 5000) -> Iterator[dict]:
        cursor = None
        while True:
            page = self._page(investigation_id, filters, time, batch, cursor, fields)
            for e in page["events"]:
                yield {k: e.get(k) for k in fields} if fields else e
            cursor = page["next_cursor"]
            if not cursor:
                return

    def _page(self, inv: str, filters: list[Filter], time: TimeRange | None, batch: int, cursor: str | None,
              fields: list[str] | None = None):
        w, p = self._where(inv, filters, time)
        # projection inside SQLite: detectors ask for a few fields, parsing whole documents in Python dominated
        sel = "doc"
        if fields and all(FIELD_RE.match(f) for f in fields):
            sel = "json_object(" + ", ".join(f"'{f}', json(doc -> '{_jpath(f)}')" for f in fields) + ")"
        if cursor:
            # _where emits trusted SQL; paths and values are bound, never literals.
            # Number only its placeholders so both ranges share the old P+3 budget.
            parts = w.split("?")
            if len(parts) != len(p) + 1:
                raise ValueError("unexpected SQL placeholder count")
            w = "".join(f"{part}?{number}" for number, part in enumerate(parts[:-1], 1)) + parts[-1]
        query = f"SELECT {sel} AS document, COALESCE(ts_epoch,0) AS cursor_ts, event_id FROM events WHERE {w}"
        if cursor:
            cts, cid = decode_cursor(cursor)
            ts_arg, id_arg, batch_arg = (f"?{len(p) + offset}" for offset in (1, 2, 3))
            # A tuple over an expression cannot seek both index keys. Split its
            # disjoint ranges, bound each before merging, and keep one snapshot.
            rows = self._conn().execute(
                f"SELECT * FROM ({query} AND COALESCE(ts_epoch,0)={ts_arg} AND event_id>{id_arg} "
                f"ORDER BY event_id LIMIT {batch_arg}) "
                f"UNION ALL SELECT * FROM ({query} AND COALESCE(ts_epoch,0)>{ts_arg} "
                f"ORDER BY COALESCE(ts_epoch,0), event_id LIMIT {batch_arg}) "
                f"ORDER BY cursor_ts, event_id LIMIT {batch_arg}",
                p + [cts, cid, batch],
            ).fetchall()
        else:
            rows = self._conn().execute(
                query + " ORDER BY COALESCE(ts_epoch,0), event_id LIMIT ?", p + [batch]
            ).fetchall()
        nxt = encode_cursor([rows[-1][1], rows[-1][2]]) if len(rows) == batch else None
        return {"events": [orjson.loads(r[0]) for r in rows], "next_cursor": nxt}

    def aggregate(self, investigation_id: str, filters: list[Filter], agg: AggRequest,
                  time: TimeRange | None = None) -> dict:
        w, p = self._where(investigation_id, filters, time)
        c = self._conn()
        if agg.type == "count":
            return {"value": c.execute(f"SELECT COUNT(*) FROM events WHERE {w}", p).fetchone()[0]}
        if agg.field is None:
            raise ValueError("field required")
        col, cp = _col(agg.field)
        if agg.type == "terms":
            rows = c.execute(
                f"SELECT {col} AS k, COUNT(*) AS n FROM events WHERE {w} AND {col} IS NOT NULL "
                f"GROUP BY k ORDER BY n DESC, k LIMIT ?", cp + p + cp + [agg.size]
            ).fetchall()
            total = c.execute(f"SELECT COUNT(*) FROM events WHERE {w} AND {col} IS NOT NULL",
                              p + cp).fetchone()[0]
            shown = sum(r[1] for r in rows)
            return {"buckets": [{"key": r[0], "count": r[1]} for r in rows], "other": total - shown,
                    "total": total}
        if agg.type == "cardinality":
            v = c.execute(f"SELECT COUNT(DISTINCT {col}) FROM events WHERE {w}", cp + p).fetchone()[0]
            return {"value": v, "approximate": False}
        if agg.type == "stats":
            r = c.execute(f"SELECT MIN({col}),MAX({col}),AVG({col}),SUM({col}),COUNT({col}) FROM events "
                          f"WHERE {w}", cp * 5 + p).fetchone()
            return {"min": r[0], "max": r[1], "avg": r[2], "sum": r[3], "count": r[4]}
        if agg.type == "percentiles":
            # One indexed position lookup per percentile instead of loading the whole column into memory.
            n = c.execute(f"SELECT COUNT({col}) FROM events WHERE {w}", cp + p).fetchone()[0]
            out = {}
            for pc in agg.percents:
                if not n:
                    out[str(pc)] = None
                    continue
                row = c.execute(f"SELECT {col} AS v FROM events WHERE {w} AND {col} IS NOT NULL ORDER BY v "
                                "LIMIT 1 OFFSET ?", cp + p + cp + [min(n - 1, int(n * pc / 100))]).fetchone()
                out[str(pc)] = row[0] if row else None
            return {"values": out}
        if agg.type == "date_histogram":
            iv = self._bounded_interval(w, p, agg.interval_sec or self._auto_interval(investigation_id, w, p))
            rows = c.execute(
                f"SELECT CAST(ts_epoch / ? AS INTEGER) * ? AS b, COUNT(*) FROM events WHERE {w} "
                f"AND ts_epoch IS NOT NULL GROUP BY b ORDER BY b", [iv, iv] + p
            ).fetchall()
            return {"interval_sec": iv, "buckets": [{"key": r[0], "count": r[1]} for r in rows]}
        raise ValueError(f"unsupported agg {agg.type}")

    def _bounded_interval(self, w: str, p: list, iv: int) -> int:
        """Never return more than MAX_HISTOGRAM_BUCKETS buckets: widen a too fine interval instead."""
        lo, hi = self._conn().execute(f"SELECT MIN(ts_epoch), MAX(ts_epoch) FROM events WHERE {w}", p).fetchone()
        return widened_interval(iv, None if lo is None else hi - lo)

    def _auto_interval(self, inv: str, w: str, p: list) -> int:
        lo, hi = self._conn().execute(f"SELECT MIN(ts_epoch), MAX(ts_epoch) FROM events WHERE {w}", p).fetchone()
        if lo is None:
            return 60
        span = max(1.0, hi - lo)
        for iv in (1, 5, 10, 30, 60, 300, 600, 1800, 3600, 10800, 21600, 43200, 86400):
            if span / iv <= 200:
                return iv
        return 86400

    def group_by(self, investigation_id: str, filters: list[Filter], fields: list[str],
                 metrics: list[GroupMetric], size: int = 100, time: TimeRange | None = None,
                 order_by: str | None = None) -> list[dict]:
        request = GroupByRequest(fields=fields, metrics=metrics, order_by=order_by)
        w, p = self._where(investigation_id, filters, time)
        sel, sel_p = [], []
        for i, f in enumerate(fields):
            col, cp = _col(f)
            sel.append(f"{col} AS g{i}")
            sel_p += cp
        msel = ["COUNT(*) AS __count"]
        for i, m in enumerate(metrics):
            condition, condition_p = self._where(investigation_id, m.filters, None) if m.filters else ("1", [])
            if m.type in ("min_ts", "max_ts"):
                fn = "first_timestamp" if m.type == "min_ts" else "last_timestamp"
                expression = f"{fn}(ts, CASE WHEN {condition} THEN ts_epoch END)"
                expression_p = condition_p
            elif m.type == "count":
                expression = f"SUM(CASE WHEN {condition} THEN 1 ELSE 0 END)"
                expression_p = condition_p
            else:
                col, cp = _col(m.field or "")
                value = f"CASE WHEN {condition} THEN {col} END" if m.filters else col
                expression_p = condition_p + cp if m.filters else cp
                fn = {"value_count": "COUNT({})", "cardinality": "COUNT(DISTINCT {})",
                      "min": "MIN({})", "max": "MAX({})", "sum": "SUM({})", "avg": "AVG({})"}[m.type]
                expression = fn.format(value)
            msel.append(f"{expression} AS m{i}")
            sel_p += expression_p
        group_cols = ", ".join(f"g{i}" for i in range(len(fields)))
        order = "__count" if request.order_by in (None, "count") else f"m{next(i for i,m in enumerate(metrics) if m.name == request.order_by)}"
        rows = self._conn().execute(
            f"SELECT {', '.join(sel + msel)} FROM events WHERE {w} GROUP BY {group_cols} "
            f"ORDER BY {order} DESC, __count DESC LIMIT ?", sel_p + p + [size]
        ).fetchall()
        return [{"key": {f: r[i] for i, f in enumerate(fields)}, "count": r[len(fields)],
                 **{m.name: r[len(fields) + 1 + j] for j, m in enumerate(metrics)}} for r in rows]

    def histogram_metrics(self, investigation_id: str, filters: list[Filter], interval_sec: int | None,
                          metrics: list[GroupMetric], time: TimeRange | None = None,
                          split_field: str | None = None) -> dict:
        """Date histogram with per-bucket metrics (avg/max/sum/cardinality) and optional split series."""
        w, p = self._where(investigation_id, filters, time)
        iv = self._bounded_interval(w, p, interval_sec or self._auto_interval(investigation_id, w, p))
        sel, sp = ["CAST(ts_epoch / ? AS INTEGER) * ? AS b"], [iv, iv]
        grp = "b"
        if split_field:
            col, cp = _col(split_field)
            sel.append(f"{col} AS s")
            sp += cp
            grp = "b, s"
        sel.append("COUNT(*)")
        for m in metrics:
            if m.type == "count":
                continue
            col, cp = _col(m.field or "")
            fn = {"cardinality": "COUNT(DISTINCT {})", "min": "MIN({})", "max": "MAX({})", "sum": "SUM({})",
                  "avg": "AVG({})"}[m.type]
            sel.append(fn.format(col))
            sp += cp
        rows = self._conn().execute(
            f"SELECT {', '.join(sel)} FROM events WHERE {w} AND ts_epoch IS NOT NULL GROUP BY {grp} ORDER BY b",
            sp + p).fetchall()
        ms = [m for m in metrics if m.type != "count"]
        off = 2 if split_field else 1
        out = []
        for r in rows:
            d = {"key": r[0], "count": r[off]}
            if split_field:
                d["series"] = r[1]
            for j, m in enumerate(ms):
                d[m.name] = r[off + 1 + j]
            out.append(d)
        return {"interval_sec": iv, "buckets": out}

    def time_bounds(self, investigation_id: str, filters: list[Filter] | None = None) -> tuple[str | None, str | None]:
        w, p = self._where(investigation_id, filters, None)
        r = self._conn().execute(
            f"SELECT ts FROM events WHERE {w} AND ts_epoch IS NOT NULL ORDER BY ts_epoch LIMIT 1", p).fetchone()
        r2 = self._conn().execute(
            f"SELECT ts FROM events WHERE {w} AND ts_epoch IS NOT NULL ORDER BY ts_epoch DESC LIMIT 1", p).fetchone()
        return (r[0] if r else None, r2[0] if r2 else None)
