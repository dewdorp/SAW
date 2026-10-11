"""Entity/Relation materialization via grouped aggregation (docs/22 §3). No graph DB."""
from __future__ import annotations

from saw.core.schemas.query import Filter, GroupMetric
from saw.storage.eventstore import EventStorePort

# data_source class -> [(from_field, to_field, edge_type, from_type, to_type)]
EDGE_RULES: dict[str, list[tuple[str, str, str, str, str]]] = {
    "web": [
        ("src_ip", "ja4", "USED", "ip", "ja4"),
        ("src_ip", "user_agent", "USED", "ip", "user_agent"),
        ("src_ip", "uri_template", "ACCESSED", "ip", "uri"),
        ("src_ip", "session_id", "USED", "ip", "session"),
        ("session_id", "user", "AUTHENTICATED_AS", "session", "user"),
        ("src_ip", "user", "AUTHENTICATED_AS", "ip", "user"),
        ("src_ip", "dst_asset_id", "ACCESSED", "ip", "asset"),
        ("uri_template", "dst_asset_id", "OBSERVED_WITH", "uri", "asset"),
    ],
    "zeek_conn": [("src_ip", "dst_ip", "CONNECTED_TO", "ip", "ip")],
    "zeek_dns": [("src_ip", "domain", "RESOLVED_TO", "ip", "domain")],
    "zeek_ssl": [("src_ip", "ja4", "USED", "ip", "ja4"), ("src_ip", "domain", "CONNECTED_TO", "ip", "domain")],
    "suricata": [("src_ip", "dst_ip", "CONNECTED_TO", "ip", "ip")],
    "auth": [("src_ip", "user", "AUTHENTICATED_AS", "ip", "user")],
}
SOURCE_CLASS = {"web": "web", "waf": "web", "zeek_conn": "zeek_conn", "firewall": "zeek_conn",
                "zeek_dns": "zeek_dns", "zeek_ssl": "zeek_ssl", "suricata": "suricata", "linux": "auth",
                "windows": "auth", "vpn": "auth"}


def build(events: EventStorePort, inv: str, data_sources: list[str], size: int = 5000) -> tuple[dict, list[dict]]:
    """Returns (entities{key: info}, edges[]). Entity key = type:value."""
    entities: dict[str, dict] = {}
    edges: list[dict] = []

    def ent(t: str, v, first, last, n) -> str:
        k = f"{t}:{v}"
        e = entities.setdefault(k, {"type": t, "value": str(v), "first": first, "last": last, "count": 0})
        e["count"] += n
        if first and (not e["first"] or first < e["first"]):
            e["first"] = first
        if last and (not e["last"] or last > e["last"]):
            e["last"] = last
        return k

    for ds in data_sources:
        cls = SOURCE_CLASS.get(ds)
        for a, b, et, ta, tb in EDGE_RULES.get(cls or "", []):
            rows = events.group_by(inv, [Filter(field="data_source", value=ds), Filter(field=a, op="exists"),
                                         Filter(field=b, op="exists")], [a, b],
                                   [GroupMetric(type="min_ts", name="first"), GroupMetric(type="max_ts", name="last")],
                                   size=size)
            for r in rows:
                va, vb = r["key"][a], r["key"][b]
                if va in (None, "") or vb in (None, ""):
                    continue
                ka = ent(ta, va, r["first"], r["last"], r["count"])
                kb = ent(tb, vb, r["first"], r["last"], 0)
                edges.append({"src": ka, "dst": kb, "type": et, "count": r["count"], "first": r["first"],
                              "last": r["last"], "source": ds})
    return entities, edges
