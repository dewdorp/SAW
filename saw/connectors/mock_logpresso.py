"""MockLogpressoConnector: fixture-backed SIEM stand-in (ADR-0012) so connector-driven features can be built/tested.

Data is synthetic and deterministic (firewall / IPS / WAF / VPN events around the demo scenario).
"""
from __future__ import annotations

import random
import time
import uuid
from datetime import datetime, timedelta, timezone

from saw.analyzers.log.normalize import finalize
from saw.connectors.base import Health
from saw.core.schemas.query import AggRequest, Filter, TimeRange
from saw.storage.eventstore import SQLiteEventStore

SCOPE = "_connector"
FIELDS_BY_TYPE = {"ipv4": ["src_ip", "dst_ip"], "ipv6": ["src_ip", "dst_ip"], "ip": ["src_ip", "dst_ip"],
                  "domain": ["domain", "hostname"], "user": ["user"], "ja4": ["ja4"]}


def _fixture(seed: int = 11) -> list[dict]:
    rnd = random.Random(seed)
    t0 = datetime(2026, 9, 20, tzinfo=timezone.utc)
    evs: list[dict] = []

    def add(ds: str, product: str, et: str, ts: datetime, **f) -> None:
        e = {"event_id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"mock:{len(evs)}")), "investigation_id": SCOPE,
             "data_source": ds, "product": product, "event_type": et, "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
             "parser": "mock_logpresso", "parser_version": "1.0.0", "raw_event": f"[mock-siem] {ds} {f}", **f}
        evs.append(finalize(e))
    scanners = ["104.248.11.20", "185.220.100.240"]
    cloud = [f"43.201.{rnd.randint(0, 255)}.{rnd.randint(1, 254)}" for _ in range(20)]
    for d in range(16):
        day = t0 + timedelta(days=d)
        for _ in range(40):
            ts = day + timedelta(seconds=rnd.randint(0, 86399))
            add("firewall", "fw-mock", "session", ts, src_ip=rnd.choice(scanners + cloud), dst_ip="10.10.1.21",
                dst_port=rnd.choice([443, 443, 443, 22, 8080]), protocol="tcp", bytes_out=rnd.randint(200, 9000),
                ext={"fw": {"action": rnd.choice(["allow", "allow", "deny"])}})
        for _ in range(5):
            ts = day + timedelta(seconds=rnd.randint(0, 86399))
            add("ips", "ips-mock", "ids_alert", ts, src_ip=rnd.choice(scanners), dst_ip="10.10.1.21", dst_port=443,
                severity="medium", ext={"ips": {"signature": "Web Application Scan (mock)", "action": "detect"}})
        for _ in range(8):
            ts = day + timedelta(seconds=rnd.randint(0, 86399))
            add("waf", "waf-mock", "waf_event", ts, src_ip=rnd.choice(scanners + cloud[:5]), method="GET",
                uri=f"/api/customer?id={rnd.randint(10000, 30000)}", status_code=rnd.choice([200, 403]),
                hostname="service.example.com", user_agent="python-httpx/0.27")
    for d in range(16):
        ts = t0 + timedelta(days=d, hours=9)
        add("vpn", "vpn-mock", "auth", ts, src_ip="121.130.10.5", user="kim.analyst", ext={"vpn": {"outcome": "success"}})
    return evs


class MockLogpressoConnector:
    kind = "mock_logpresso"
    read_only = True

    def __init__(self, cid: str, settings: dict | None = None, secret: str | None = None):
        self.id = cid
        # shared-cache in-memory DB so every request thread sees the same fixture
        self.store = SQLiteEventStore(f"file:mockconn_{cid}?mode=memory&cache=shared")
        self.store.index(_fixture(int((settings or {}).get("seed", 11))))
        self.requires_secret = False

    def search(self, filters: list[Filter], time: TimeRange | None = None, limit: int = 100, cursor: str | None = None) -> dict:
        return self.store.search(SCOPE, filters, time, "asc", min(limit, 500), cursor)

    def get_event(self, event_id: str) -> dict | None:
        return self.store.get(SCOPE, event_id)

    def get_events(self, event_ids: list[str]) -> list[dict]:
        return [e for e in (self.get_event(i) for i in event_ids) if e]

    def aggregate(self, filters: list[Filter], agg: AggRequest, time: TimeRange | None = None) -> dict:
        return self.store.aggregate(SCOPE, filters, agg, time)

    def get_context(self, observable_type: str, value: str) -> dict:
        by_source: dict[str, int] = {}
        first = last = None
        for f in FIELDS_BY_TYPE.get(observable_type, []):
            flt = [Filter(field=f, value=value)]
            for b in self.store.aggregate(SCOPE, flt, AggRequest(type="terms", field="data_source", size=20))["buckets"]:
                by_source[b["key"]] = by_source.get(b["key"], 0) + b["count"]
            lo, hi = self.store.time_bounds(SCOPE, flt)
            first = min(filter(None, [first, lo]), default=None)
            last = max(filter(None, [last, hi]), default=None)
        return {"connector": self.id, "kind": self.kind, "events_by_source": by_source, "first_seen": first,
                "last_seen": last, "note": "mock data (fixture) — not a real SIEM"}

    def health_check(self) -> Health:
        t = time.perf_counter()
        n = self.store.count(SCOPE)
        return Health(n > 0, f"mock fixture with {n} events", round((time.perf_counter() - t) * 1000, 2))
