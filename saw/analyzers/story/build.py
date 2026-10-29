"""Attack Story generation (docs/21 §3). Deterministic; numbers come from Finding metrics only."""
from __future__ import annotations

from datetime import datetime
from ipaddress import ip_address

ALGO_VERSION = "story/1.0.1"
STAGE_ORDER = ["INFRASTRUCTURE", "RECON", "DISCOVERY", "AUTHENTICATION", "EXPLOITATION", "DELIVERY", "DATA_ACCESS",
               "EXECUTION", "PERSISTENCE", "LATERAL", "OUTBOUND", "UNCLASSIFIED"]
LINK_WINDOW_SEC = 2 * 3600
RISK_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _ep(ts) -> float | None:
    if not ts:
        return None
    if isinstance(ts, datetime):
        return ts.timestamp()
    return datetime.fromisoformat(str(ts).replace("Z", "+00:00")).timestamp()


def _key_entities(f: dict) -> set[str]:
    result = set()
    for entity in f.get("entities", []):
        if entity.startswith("url_path:"):
            continue
        if entity.startswith("ip:"):
            try:
                ip_address(entity[3:])
            except ValueError:
                continue
        result.add(entity)
    return result


def build_story(findings: list[dict], correlations: list[dict] | None = None) -> dict:
    """findings: dicts with id, display_id, title, stage, risk_level, metrics, entities, time_start, time_end,
    attack (list)."""
    # 1) group findings per stage sharing entities into nodes
    nodes: list[dict] = []
    for f in sorted(findings, key=lambda x: (_ep(x.get("time_start")) or 0)):
        stage = f.get("stage") or "UNCLASSIFIED"
        ents = _key_entities(f)
        target = None
        for n in nodes:
            if n["stage"] == stage and (n["_ents"] & ents):
                target = n
                break
        if target is None:
            target = {"id": f"n{len(nodes) + 1}", "stage": stage, "title": f["title"].replace("Possible ", "")
                      .replace("Potential ", ""), "risk": f["risk_level"], "finding_ids": [], "metrics": [],
                      "time": {"start": f.get("time_start"), "end": f.get("time_end")}, "_ents": set(),
                      "attack": [], "origin": "auto", "pinned": False}
            nodes.append(target)
        target["finding_ids"].append(f["id"])
        target["_ents"] |= ents
        if RISK_RANK.get(f["risk_level"], 0) > RISK_RANK.get(target["risk"], 0):
            target["risk"] = f["risk_level"]
        ms = [m for m in f.get("metrics", []) if m.get("observed") is not None][:3]
        if not target["metrics"]:
            target["metrics"] = [{"name": m["name"], "label": m.get("label", m["name"]), "value": m["observed"],
                                  "unit": m.get("unit", "")} for m in ms]
        for a in f.get("attack", []):
            if a.get("technique_id") not in {x["technique_id"] for x in target["attack"]}:
                target["attack"].append({"technique_id": a["technique_id"], "name": a.get("name"),
                                         "confidence": a.get("confidence"), "tactic": a.get("tactic")})
        ts, te = _ep(f.get("time_start")), _ep(f.get("time_end"))
        if ts and (not _ep(target["time"]["start"]) or ts < _ep(target["time"]["start"])):
            target["time"]["start"] = f.get("time_start")
        if te and (not _ep(target["time"]["end"]) or te > _ep(target["time"]["end"])):
            target["time"]["end"] = f.get("time_end")
    # 2) order by stage then time
    nodes.sort(key=lambda n: (STAGE_ORDER.index(n["stage"]) if n["stage"] in STAGE_ORDER else 99,
                              _ep(n["time"]["start"]) or 0))
    # 3) edges: consecutive-stage nodes linked by shared entities (strong) or time proximity on same asset (weak)
    edges = []
    for i, a in enumerate(nodes):
        for b in nodes[i + 1:]:
            if a["stage"] == b["stage"]:
                continue
            shared = sorted(a["_ents"] & b["_ents"])
            ta, tb = _ep(a["time"]["start"]), _ep(b["time"]["start"])
            dt = (tb - ta) if (ta and tb) else None
            if dt is not None and (dt < -300 or dt > LINK_WINDOW_SEC):
                continue
            if shared:
                edges.append({"from": a["id"], "to": b["id"], "confidence": "high" if len(shared) >= 2 else "medium",
                              "link_reason": shared[:5], "delta_sec": dt})
            elif dt is not None and 0 <= dt <= 1800:
                edges.append({"from": a["id"], "to": b["id"], "confidence": "low",
                              "link_reason": ["time proximity (weak link)"], "delta_sec": dt})
    # keep only the best outgoing edge per (node, next stage) to avoid spaghetti
    best: dict[tuple[str, str], dict] = {}
    rank = {"high": 3, "medium": 2, "low": 1}
    stage_of = {n["id"]: n["stage"] for n in nodes}
    for e in edges:
        k = (e["from"], stage_of[e["to"]])
        if k not in best or rank[e["confidence"]] > rank[best[k]["confidence"]]:
            best[k] = e
    for n in nodes:
        n["entities"] = sorted(n.pop("_ents"))[:10]
    return {"algo_version": ALGO_VERSION, "nodes": nodes, "edges": list(best.values()),
            "correlations": correlations or []}
