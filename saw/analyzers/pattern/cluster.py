"""Behavioral pattern clustering (docs/19 §4): deterministic grouping first, Drain3 for free-text sources."""
from __future__ import annotations

import re

from saw.core.schemas.query import Filter, GroupMetric
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


def text_patterns(events: EventStorePort, inv: str, max_lines: int = 50_000) -> list[dict]:
    """Drain3 template mining for non-web sources (syslog/auth/custom)."""
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
    for e in events.iterate(inv, flt, fields=["raw_event", "timestamp", "src_ip"]):
        msg = (e.get("raw_event") or "")[:2000]
        r = tm.add_log_message(msg)
        cid = r["cluster_id"]
        d = ids.setdefault(cid, {"count": 0, "first": e.get("timestamp"), "last": e.get("timestamp"), "srcs": set()})
        d["count"] += 1
        d["last"] = e.get("timestamp") or d["last"]
        if e.get("src_ip"):
            d["srcs"].add(e["src_ip"])
        n += 1
        if n >= max_lines:
            break
    out = []
    for c in tm.drain.clusters:
        d = ids.get(c.cluster_id)
        if d:
            out.append({"template": c.get_template(), "key": {"drain_cluster": c.cluster_id}, "count": d["count"],
                        "srcs": len(d["srcs"]), "first": d["first"], "last": d["last"], "success": 0.0,
                        "tags": ["drain3"], "sampled": n >= max_lines})
    out.sort(key=lambda x: -x["count"])
    return out
