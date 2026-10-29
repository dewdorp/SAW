"""Behavioral pattern clustering (docs/19 §4): deterministic grouping first, Drain3 for free-text sources."""
from __future__ import annotations

import re
from datetime import datetime
from itertools import islice

from saw.core.schemas.query import Filter, GroupMetric
from saw.observation.connection import VERSION as CONNECTION_OBSERVATION_VERSION
from saw.storage.eventstore import EventStorePort

TAG_RULES = [
    ("sensitive-file-probe", re.compile(r"(?i)(/\.env|/\.git|/config|/backup|\.bak|\.sql|/wp-config|/\.aws|phpinfo)")),
    ("cms-probe", re.compile(r"(?i)(/wp-admin|/wp-login|/xmlrpc\.php|/wp-content|/joomla|/drupal)")),
    ("static-assets", re.compile(r"(?i)\.(css|js|png|jpe?g|gif|svg|ico|woff2?|map)(\?|$)")),
    ("login", re.compile(r"(?i)(login|signin|auth|session|token)")),
]


# sources with their own structured views (web patterns, network tabs): free-text mining adds nothing and is slow
STRUCTURED_SOURCES = ["web", "waf", "zeek_conn", "zeek_dns", "zeek_ssl", "zeek_http", "zeek_files", "suricata",
                      "pcap_auth", "pcap_arp", "ndr_http"]


def web_patterns(events: EventStorePort, inv: str, limit: int = 200) -> list[dict]:
    rows = events.group_by(inv, [Filter(field="data_source", op="in", value=["web", "waf"])],
                           ["method", "uri_template", "status_class", "ua_class"],
                           [GroupMetric(type="cardinality", field="src_ip", name="srcs"),
                            GroupMetric(type="min_ts", name="first"), GroupMetric(type="max_ts", name="last")],
                           size=limit)
    out = []
    for r in rows:
        k = r["key"]
        tpl = k.get("uri_template") or ""
        tags = [name for name, rx in TAG_RULES if rx.search(tpl)]
        if "<NUM>" in tpl:
            tags.append("numeric-id")
        if k.get("ua_class") in ("script", "scanner", "empty"):
            tags.append(f"ua:{k['ua_class']}")
        out.append({"template": f"{k.get('method') or '*'} {tpl}", "key": k, "count": r["count"], "srcs": r["srcs"],
                    "first": r["first"], "last": r["last"], "success": 1.0 if k.get("status_class") == "2xx" else 0.0,
                    "tags": tags})
    # injection-like cluster (tag based)
    for tag in ("pattern:sqli", "pattern:xss", "pattern:traversal", "pattern:cmdi", "pattern:ssti"):
        n = events.count(inv, [Filter(field="tags", value=tag)])
        if n:
            lo, hi = events.time_bounds(inv, [Filter(field="tags", value=tag)])
            out.append({"template": f"* {tag.split(':')[1].upper()}-like mutation", "key": {"tags": tag}, "count": n,
                        "srcs": 0, "first": lo, "last": hi, "success": 0.0, "tags": ["injection-like"]})
    out.sort(key=lambda x: -x["count"])
    return out


def _has_complete_connection_view(event: dict) -> bool:
    """Only persisted, producer-owned, fully verified connection semantics replace text."""
    if event.get("data_source") != "connection":
        return False
    if not all(isinstance(event.get(key), str) and event[key].strip() for key in ("src_ip", "dst_ip")):
        return False
    ext = event.get("ext")
    obs = ext.get("observation") if isinstance(ext, dict) else None
    if not isinstance(obs, dict) or obs.get("producer") != "saw" or obs.get("version") != CONNECTION_OBSERVATION_VERSION:
        return False
    context = obs.get("context")
    if (not isinstance(context, dict) or context.get("resolved") is not True or obs.get("quality") != []
            or context.get("status") not in (None, "resolved")):
        return False
    if not all(isinstance(context.get(key), str) and context[key].strip()
               for key in ("org_unit_id", "device_id", "device_profile_version_id", "network")):
        return False
    if obs.get("profile_version") != context["device_profile_version_id"]:
        return False
    if (obs.get("record_kind") not in ("session_start", "session_interim", "session_end")
            or obs.get("action") not in ("allowed", "blocked", "reset", "detected", "challenged")
            or not isinstance(obs.get("session_id"), str) or not obs["session_id"].strip()):
        return False
    counters = obs.get("counters")
    if not isinstance(counters, dict):
        return False
    modes = []
    for key in ("src_to_dst_bytes", "dst_to_src_bytes"):
        counter = counters.get(key)
        if (not isinstance(counter, dict) or counter.get("state") != "observed" or counter.get("unit") != "bytes"
                or counter.get("counter_mode") not in ("cumulative", "delta", "total")
                or type(counter.get("value")) is not int or counter["value"] < 0
                or not isinstance(counter.get("source_field"), str) or not counter["source_field"].strip()):
            return False
        modes.append(counter["counter_mode"])
    if modes[0] != modes[1]:
        return False
    time_profile = obs.get("time_profile")
    timestamp = obs.get("timestamp")
    if (not isinstance(time_profile, dict) or time_profile.get("verified") is not True
            or time_profile.get("role") not in ("occurred", "start", "end")
            or obs.get("timestamp_precision") not in ("seconds", "subseconds")
            or obs.get("timestamp_basis") != "verified_device_profile"
            or not isinstance(timestamp, str) or timestamp != event.get("timestamp")):
        return False
    try:
        return datetime.fromisoformat(timestamp).utcoffset() is not None
    except ValueError:
        return False


def text_patterns(events: EventStorePort, inv: str, max_lines: int = 50_000) -> list[dict]:
    """Mine text outside complete structured views, bounded by examined rows."""
    if max_lines <= 0:
        return []
    from drain3 import TemplateMiner
    from drain3.template_miner_config import TemplateMinerConfig

    cfg = TemplateMinerConfig()
    cfg.profiling_enabled = False
    cfg.drain_sim_th = 0.5
    cfg.mask_prefix, cfg.mask_suffix = "<", ">"
    from drain3.masking import MaskingInstruction

    cfg.masking_instructions = [
        MaskingInstruction(r"(\d{1,3}\.){3}\d{1,3}", "IP"),
        MaskingInstruction(r"\b[0-9a-fA-F]{16,}\b", "HEX"),
        MaskingInstruction(r"\b\d+\b", "NUM"),
    ]
    tm = TemplateMiner(config=cfg)
    flt = [Filter(field="data_source", op="not_in", value=STRUCTURED_SOURCES)]
    ids: dict[int, dict] = {}
    n = 0
    # Top-level ext is compatible with both retained SQLite and native projections.
    rows = events.iterate(inv, flt, fields=["raw_event", "timestamp", "src_ip", "dst_ip", "data_source", "ext"])
    for e in islice(rows, max_lines):
        n += 1
        if _has_complete_connection_view(e):
            continue
        msg = (e.get("raw_event") or "")[:2000]
        r = tm.add_log_message(msg)
        cid = r["cluster_id"]
        d = ids.setdefault(cid, {"count": 0, "first": e.get("timestamp"), "last": e.get("timestamp"), "srcs": set()})
        d["count"] += 1
        d["last"] = e.get("timestamp") or d["last"]
        if e.get("src_ip"):
            d["srcs"].add(e["src_ip"])
    out = []
    for c in tm.drain.clusters:
        d = ids.get(c.cluster_id)
        if d:
            out.append({"template": c.get_template(), "key": {"drain_cluster": c.cluster_id}, "count": d["count"],
                        "srcs": len(d["srcs"]), "first": d["first"], "last": d["last"], "success": 0.0,
                        "tags": ["drain3"], "sampled": n >= max_lines})
    out.sort(key=lambda x: -x["count"])
    return out
