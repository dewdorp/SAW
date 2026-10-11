"""OpenSearch EventStore adapter (docs/08, ADR-0016). Verified against OpenSearch 2.19 (tests/contract).

Translates the structured SAW Query Model to OpenSearch DSL; investigation_id filter always injected.
An index template maps strings to keyword (exact match/aggregation like the SQLite store), raw_event to a
`wildcard` field (substring search) with a nori-analysed subfield, and puts every saw-* index behind ALIAS.
Writes mark the store dirty; the next read refreshes first, so detectors see events indexed just before.
"""
from __future__ import annotations

import logging
from collections.abc import Iterable, Iterator
from datetime import datetime
from typing import Any

from saw.core.schemas.query import AggRequest, Filter, GroupMetric, TimeRange
from saw.storage.eventstore import decode_cursor, encode_cursor

INDEX_BY_SOURCE = {
    "web": "saw-web", "waf": "saw-waf", "zeek_conn": "saw-netflow", "firewall": "saw-netflow",
    "zeek_dns": "saw-dns", "zeek_http": "saw-http-net", "zeek_ssl": "saw-tls", "suricata": "saw-ids",
    "zeek_files": "saw-files",
}
log = logging.getLogger("saw.opensearch")


def translog(durability: str) -> dict:
    """request: fsync before every bulk request is acknowledged. async: fsync every 10 s (see Settings)."""
    return {"durability": "async", "sync_interval": "10s"} if durability == "async" else {"durability": "request"}


def index_template(prefix: str = "saw", shards: int = 1, replicas: int = 0, durability: str = "request") -> dict:
    kw = {"type": "keyword", "ignore_above": 4096}
    return {
        "index_patterns": [f"{prefix}-*"],
        "priority": 100 if prefix == "saw" else 101,
        "template": {
            "aliases": {f"{prefix}-events": {}},
            "settings": {
                "number_of_shards": shards, "number_of_replicas": replicas, "refresh_interval": "30s",
                "translog": translog(durability),
                "codec": "best_compression",
                "mapping": {"total_fields": {"limit": 10000}, "ignore_malformed": True},
                "analysis": {"analyzer": {"saw_nori": {"type": "custom", "tokenizer": "nori_tokenizer",
                                                        "filter": ["lowercase"]}}},
            },
            "mappings": {
                "date_detection": False,
                "numeric_detection": False,
                "dynamic_templates": [{"strings": {"match_mapping_type": "string", "mapping": kw}}],
                "properties": {
                    "timestamp": {"type": "date", "format": "strict_date_optional_time||epoch_millis"},
                    "event_id": {"type": "keyword"}, "investigation_id": {"type": "keyword"},
                    "evidence_id": {"type": "keyword"}, "data_source": {"type": "keyword"},
                    "event_type": {"type": "keyword"},
                    "raw_event": {"type": "wildcard", "fields": {"text": {"type": "text", "analyzer": "saw_nori"}}},
                    "src_port": {"type": "integer"}, "dst_port": {"type": "integer"},
                    "status_code": {"type": "integer"}, "bytes_in": {"type": "long"}, "bytes_out": {"type": "long"},
                    "params": {"type": "flat_object"},  # arbitrary parameter names must not grow the mapping
                    "raw_ref": {"type": "object", "enabled": False},
                },
            },
        },
    }


def index_for(event: dict, prefix: str = "saw") -> str:
    base = INDEX_BY_SOURCE.get(event.get("data_source", ""), "saw-sec")
    if prefix != "saw":
        base = prefix + base[3:]
    return f"{base}-{(event.get('timestamp') or '0000-00')[:7].replace('-', '.')}"


def filters_to_dsl(inv: str, filters: list[Filter], time: TimeRange | None) -> dict:
    must: list[dict] = [{"term": {"investigation_id": inv}}]
    must_not: list[dict] = []
    if time and (time.start or time.end):
        r: dict[str, Any] = {}
        if time.start:
            r["gte"] = time.start
        if time.end:
            r["lte"] = time.end
        must.append({"range": {"timestamp": r}})
    for f in filters:
        if f.op == "is":
            must.append({"term": {f.field: f.value}})
        elif f.op == "is_not":
            must_not.append({"term": {f.field: f.value}})
        elif f.op == "in":
            must.append({"terms": {f.field: list(f.value or [])}})
        elif f.op == "not_in":
            must_not.append({"terms": {f.field: list(f.value or [])}})
        elif f.op == "range":
            must.append({"range": {f.field: dict(f.value or {})}})
        elif f.op == "exists":
            must.append({"exists": {"field": f.field}})
        elif f.op == "not_exists":
            must_not.append({"exists": {"field": f.field}})
        elif f.op == "prefix":
            must.append({"prefix": {f.field: f.value}})
        elif f.op == "contains":
            # wildcard on keyword; leading wildcard is expensive -> limited to sync input sizes by API
            must.append({"wildcard": {f.field: {"value": f"*{f.value}*", "case_insensitive": True}}})
    return {"bool": {"filter": must, "must_not": must_not}}


TRANSIENT = {408, 429, 502, 503, 504}


class IndexUnavailable(RuntimeError):
    """The batch was not stored for a reason that passes; event ids are deterministic, so it is safe to send again."""


class OpenSearchEventStore:
    def __init__(self, url: str, ensure: bool = True, prefix: str = "saw", durability: str = "request", **kw: Any):
        """`prefix` separates SAW instances/test runs sharing one cluster (indices `<prefix>-*`, alias `<prefix>-events`)."""
        from opensearchpy import OpenSearch

        kw.setdefault("timeout", 60)
        self.client = OpenSearch(url, **kw)
        self.prefix = prefix
        self.durability = "async" if durability == "async" else "request"
        self.alias = f"{prefix}-events"
        self._dirty = False
        self.rejected = 0
        self.last_errors: list[dict] = []  # events the last index() call could not store: [{event_id, reason}]
        if ensure:
            self._wait_ready()
            self.ensure_template()

    def _wait_ready(self, timeout_s: float = 120.0) -> None:
        """At boot the SAW service can start before OpenSearch accepts requests; wait instead of crash-looping."""
        import time

        from opensearchpy.exceptions import ConnectionError as OSConnectionError
        from opensearchpy.exceptions import TransportError

        deadline = time.monotonic() + timeout_s
        while True:
            try:
                self.client.cluster.health(wait_for_status="yellow", params={"timeout": "10s"}, request_timeout=15)
                return
            except (OSConnectionError, TransportError) as e:
                if time.monotonic() > deadline:
                    raise RuntimeError(f"OpenSearch not reachable after {timeout_s:.0f}s: {e}") from e
                log.info("waiting for OpenSearch ...")
                time.sleep(3)

    def ensure_template(self) -> None:
        self.client.indices.put_index_template(name=f"{self.prefix}-events",
                                               body=index_template(self.prefix, durability=self.durability))
        # the template only reaches new indices: existing ones get the configured durability as well
        self.client.indices.put_settings(index=f"{self.prefix}-*", body={"index": {"translog": translog(self.durability)}},
                                         ignore_unavailable=True, allow_no_indices=True)
        boot = f"{self.prefix}-bootstrap"  # empty index so the alias exists before the first event (reads never 404)
        if not self.client.indices.exists(index=boot):
            self.client.indices.create(index=boot, ignore=400)

    def _fresh(self) -> None:
        if self._dirty:
            self.client.indices.refresh(index=self.alias, ignore_unavailable=True, allow_no_indices=True)
            self._dirty = False

    def index(self, events: Iterable[dict[str, Any]]) -> int:
        from opensearchpy import helpers

        actions = ({"_op_type": "index", "_index": index_for(e, self.prefix), "_id": e["event_id"], "_source": e}
                   for e in events)
        ok, errors = helpers.bulk(self.client, actions, chunk_size=5000, max_chunk_bytes=10 * 1024 * 1024,
                                  max_retries=5, raise_on_error=False, raise_on_exception=True)
        self._dirty = True
        self.last_errors = []
        if errors:
            items = [next(iter(e.values()), {}) if isinstance(e, dict) else {} for e in errors]
            busy = [i for i in items if i.get("status") in TRANSIENT or i.get("status") is None]
            if busy:  # the node had no room (queue full, restarting): nothing is wrong with the events themselves
                raise IndexUnavailable(
                    f"검색엔진이 잠시 저장을 받지 못했습니다 (HTTP {busy[0].get('status')}, {len(busy)}건). "
                    "'다시 시도'를 누르면 멈춘 곳부터 이어서 처리합니다.")
            # e.g. object/scalar mapping conflicts from heterogeneous logs: keep the batch, report the rest
            self.rejected += len(items)
            self.last_errors = [{"event_id": i.get("_id"), "reason": str((i.get("error") or {}).get("type") or "rejected")}
                                for i in items]
            log.warning("opensearch rejected %d events (first: %s)", len(items), str(errors[0])[:300])
        return ok

    def get(self, investigation_id: str, event_id: str) -> dict | None:
        self._fresh()
        r = self.client.search(index=self.alias, body={"query": filters_to_dsl(
            investigation_id, [Filter(field="event_id", value=event_id)], None), "size": 1})
        hits = r["hits"]["hits"]
        return hits[0]["_source"] if hits else None

    def count(self, investigation_id: str, filters: list[Filter] | None = None,
              time: TimeRange | None = None) -> int:
        self._fresh()
        return self.client.count(index=self.alias, body={"query": filters_to_dsl(investigation_id, filters or [], time)})["count"]

    def search(self, investigation_id: str, filters: list[Filter], time: TimeRange | None = None,
               sort: str = "asc", limit: int = 100, cursor: str | None = None,
               fields: list[str] | None = None) -> dict:
        self._fresh()
        body: dict[str, Any] = {
            "query": filters_to_dsl(investigation_id, filters, time), "size": limit,
            "sort": [{"timestamp": sort}, {"event_id": sort}],
        }
        if fields:  # detectors read a few fields: do not ship whole documents over HTTP
            body["_source"] = {"includes": list(fields)}
        if cursor:
            body["search_after"] = decode_cursor(cursor)
        hits = self.client.search(index=self.alias, body=body)["hits"]["hits"]
        nxt = encode_cursor(hits[-1]["sort"]) if len(hits) == limit else None
        return {"events": [h["_source"] for h in hits], "next_cursor": nxt}

    def iterate(self, investigation_id: str, filters: list[Filter], time: TimeRange | None = None,
                fields: list[str] | None = None, batch: int = 5000) -> Iterator[dict]:
        cursor = None
        while True:
            page = self.search(investigation_id, filters, time, "asc", batch, cursor, fields)
            for e in page["events"]:
                yield {k: e.get(k) for k in fields} if fields else e
            cursor = page["next_cursor"]
            if not cursor:
                return

    def aggregate(self, investigation_id: str, filters: list[Filter], agg: AggRequest,
                  time: TimeRange | None = None) -> dict:
        self._fresh()
        q = filters_to_dsl(investigation_id, filters, time)
        if agg.type == "count":
            return {"value": self.count(investigation_id, filters, time)}
        aggs: dict[str, Any]
        if agg.type == "terms":
            aggs = {"a": {"terms": {"field": agg.field, "size": agg.size}},
                    "n": {"filter": {"exists": {"field": agg.field}}}}
        elif agg.type == "cardinality":
            aggs = {"a": {"cardinality": {"field": agg.field, "precision_threshold": 40000}}}
        elif agg.type == "stats":
            aggs = {"a": {"stats": {"field": agg.field}}}
        elif agg.type == "percentiles":
            aggs = {"a": {"percentiles": {"field": agg.field, "percents": agg.percents}}}
        else:
            aggs = {"a": {"date_histogram": {"field": "timestamp",
                                             "fixed_interval": f"{agg.interval_sec or 60}s"}}}
        if agg.type == "date_histogram" and not agg.interval_sec:
            aggs = {"a": {"date_histogram": {"field": "timestamp",
                                             "fixed_interval": f"{self._auto_interval(investigation_id, filters, time)}s"}}}
        res = self.client.search(index=self.alias, body={"query": q, "size": 0, "aggs": aggs})["aggregations"]
        r = res["a"]
        if agg.type == "terms":
            b = [{"key": x["key"], "count": x["doc_count"]} for x in r["buckets"]]
            total = res["n"]["doc_count"]
            return {"buckets": b, "other": max(0, total - sum(x["count"] for x in b)), "total": total}
        if agg.type == "cardinality":
            return {"value": r["value"], "approximate": True}
        if agg.type == "stats":
            return {k: r.get(k) for k in ("min", "max", "avg", "sum", "count")}
        if agg.type == "percentiles":
            return {"values": r["values"]}
        iv = int(aggs["a"]["date_histogram"]["fixed_interval"][:-1])
        return {"interval_sec": iv,
                "buckets": [{"key": int(x["key"] / 1000), "count": x["doc_count"]} for x in r["buckets"] if x["doc_count"]]}

    def _auto_interval(self, investigation_id: str, filters: list[Filter], time: TimeRange | None) -> int:
        """Same bucket choice as the SQLite store: smallest step giving <= 200 buckets."""
        lo, hi = self.time_bounds(investigation_id, filters)
        if not lo or not hi:
            return 60
        span = max(1.0, (datetime.fromisoformat(hi.replace("Z", "+00:00"))
                         - datetime.fromisoformat(lo.replace("Z", "+00:00"))).total_seconds())
        for iv in (1, 5, 10, 30, 60, 300, 600, 1800, 3600, 10800, 21600, 43200, 86400):
            if span / iv <= 200:
                return iv
        return 86400

    def group_by(self, investigation_id: str, filters: list[Filter], fields: list[str],
                 metrics: list[GroupMetric], size: int = 100, time: TimeRange | None = None) -> list[dict]:
        self._fresh()
        sub: dict[str, Any] = {}
        for m in metrics:
            if m.type == "cardinality":
                sub[m.name] = {"cardinality": {"field": m.field}}
            elif m.type in ("min", "max", "sum", "avg"):
                sub[m.name] = {m.type: {"field": m.field}}
            elif m.type in ("min_ts", "max_ts"):
                sub[m.name] = {m.type[:3]: {"field": "timestamp"}}
        body = {"query": filters_to_dsl(investigation_id, filters, time), "size": 0, "aggs": {"g": {
            "multi_terms" if len(fields) > 1 else "terms":
                ({"terms": [{"field": f} for f in fields], "size": size} if len(fields) > 1
                 else {"field": fields[0], "size": size}),
            "aggs": sub}}}
        out = []
        for b in self.client.search(index=self.alias, body=body)["aggregations"]["g"]["buckets"]:
            keys = b["key"] if isinstance(b["key"], list) else [b["key"]]
            d = {"key": dict(zip(fields, keys, strict=False)), "count": b["doc_count"]}
            for m in metrics:
                d[m.name] = b["doc_count"] if m.type == "count" else b.get(m.name, {}).get(
                    "value_as_string", b.get(m.name, {}).get("value"))
            out.append(d)
        return out

    def delete_by_evidence(self, investigation_id: str, evidence_id: str) -> int:
        self._fresh()
        r = self.client.delete_by_query(index=self.alias, body={"query": filters_to_dsl(
            investigation_id, [Filter(field="evidence_id", value=evidence_id)], None)})
        self._dirty = True  # deleted documents stay searchable until the next refresh: the next read must not see them
        return r.get("deleted", 0)

    def histogram_metrics(self, investigation_id: str, filters: list[Filter], interval_sec: int | None,
                          metrics: list[GroupMetric], time: TimeRange | None = None,
                          split_field: str | None = None) -> dict:
        self._fresh()
        iv = interval_sec or self._auto_interval(investigation_id, filters, time)
        sub = {m.name: ({"cardinality": {"field": m.field}} if m.type == "cardinality" else {m.type: {"field": m.field}})
               for m in metrics if m.type != "count"}
        h: dict[str, Any] = {"date_histogram": {"field": "timestamp", "fixed_interval": f"{iv}s", "min_doc_count": 1},
                             "aggs": sub}
        if split_field:
            h["aggs"] = {"s": {"terms": {"field": split_field, "size": 10}, "aggs": sub}}
        r = self.client.search(index=self.alias, body={"query": filters_to_dsl(investigation_id, filters, time), "size": 0,
                                                  "aggs": {"h": h}})["aggregations"]["h"]["buckets"]
        out = []
        for b in r:
            groups = b["s"]["buckets"] if split_field else [b]
            for g in groups:
                d = {"key": int(b["key"] / 1000), "count": g["doc_count"]}
                if split_field:
                    d["series"] = g["key"]
                for m in metrics:
                    if m.type != "count":
                        d[m.name] = g.get(m.name, {}).get("value")
                out.append(d)
        return {"interval_sec": iv, "buckets": out}

    def time_bounds(self, investigation_id: str, filters: list[Filter] | None = None):
        self._fresh()
        r = self.client.search(index=self.alias, body={"query": filters_to_dsl(investigation_id, filters or [], None),
                                                  "size": 0, "aggs": {"lo": {"min": {"field": "timestamp"}},
                                                                      "hi": {"max": {"field": "timestamp"}}}})
        a = r["aggregations"]
        return a["lo"].get("value_as_string"), a["hi"].get("value_as_string")
