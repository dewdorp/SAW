"""ATT&CK views over Investigation findings (docs/34 §4 V1/V3/V4) + Navigator layer export."""
from __future__ import annotations

from collections import defaultdict

from saw.attack.catalog import (
    ATTACK_VERSION, COMPONENT_SOURCES, COOCCURRENCE, DATA_NEEDS, TACTICS, TECHNIQUES, technique,
)

CONF_RANK = {"high": 3, "medium": 2, "low": 1, "candidate": 0}


def matrix(findings: list[dict], mode: str = "compact") -> dict:
    cells: dict[str, dict] = {}
    for f in findings:
        for a in f.get("attack") or []:
            tid = a["technique_id"]
            c = cells.setdefault(tid, {"technique_id": tid, "name": a.get("name") or technique(tid)["name"],
                                       "tactics": technique(tid)["tactics"], "findings": [], "best_confidence": "candidate",
                                       "sources": set(), "observed": False, "primary_tactics": set()})
            c["primary_tactics"].add(a.get("tactic") or (technique(tid)["tactics"] or [None])[0])
            c["findings"].append({"id": f["id"], "display_id": f.get("display_id"), "title": f["title"],
                                  "confidence": a.get("confidence"), "condition_met": a.get("condition_met", True)})
            c["sources"].add(a.get("source", "detector_map"))
            if CONF_RANK.get(a.get("confidence"), 0) > CONF_RANK.get(c["best_confidence"], 0):
                c["best_confidence"] = a.get("confidence")
            if a.get("confidence") != "candidate":
                c["observed"] = True
    columns = []
    for tac_id, short, name in TACTICS:
        # compact: a technique appears only under the tactic recorded on its mapping (no column duplication)
        techs = [c for c in cells.values() if (short in c["primary_tactics"] if mode == "compact" else short in c["tactics"])]
        if mode == "full":
            for tid, t in TECHNIQUES.items():  # full matrix: parent techniques (sub-techniques only when observed)
                if short in t["tactics"] and tid not in cells and not t.get("sub"):
                    techs.append({"technique_id": tid, "name": t["name"], "tactics": t["tactics"], "findings": [],
                                  "best_confidence": None, "sources": set(), "observed": False})
        if mode == "compact" and not techs:
            continue
        columns.append({"tactic_id": tac_id, "tactic": short, "name": name,
                        "techniques": sorted(({**c, "sources": sorted(c["sources"]),
                                               "primary_tactics": sorted(x for x in c.get("primary_tactics", set()) if x)}
                                              for c in techs),
                                             key=lambda c: (-len(c["findings"]), c["technique_id"]))})
    unmapped = [{"id": f["id"], "display_id": f.get("display_id"), "title": f["title"],
                 "reason": f.get("attack_unmapped_reason")}
                for f in findings if f.get("attack_unmapped_reason") or not f.get("attack")]
    return {"attack_version": ATTACK_VERSION, "mode": mode, "columns": columns, "unmapped": unmapped}


def technique_timeline(findings: list[dict]) -> list[dict]:
    out = []
    for f in findings:
        for a in f.get("attack") or []:
            t = technique(a["technique_id"])
            out.append({"ts": f.get("time_start"), "technique_id": a["technique_id"], "name": t["name"],
                        "tactic": (t["tactics"] or ["unknown"])[0], "observed": a.get("confidence") != "candidate",
                        "finding_id": f["id"], "display_id": f.get("display_id")})
    out.sort(key=lambda x: str(x["ts"] or ""))
    return out


def inferred(findings: list[dict], data_sources: set[str], top: int = 5) -> dict:
    """Local co-occurrence fallback for TIE (ENV-17). Clearly labeled as inferred, never observed."""
    observed = {a["technique_id"] for f in findings for a in f.get("attack") or [] if a.get("confidence") != "candidate"}
    scores: dict[str, float] = defaultdict(float)
    basis: dict[str, list[str]] = defaultdict(list)
    for o in observed:
        for t, w in COOCCURRENCE.get(o, []):
            if t in observed:
                continue
            scores[t] = 1 - (1 - scores[t]) * (1 - w)
            basis[t].append(o)
    recs = []
    for t, sc in sorted(scores.items(), key=lambda x: -x[1])[:top]:
        needs = DATA_NEEDS.get(t, [])
        have = [{"component": n, "available": bool(COMPONENT_SOURCES.get(n, set()) & data_sources)} for n in needs]
        recs.append({**technique(t), "score": round(sc, 2), "based_on": basis[t], "data_needed": have})
    return {"engine": "local-cooccurrence (TIE fallback)", "observed": sorted(observed), "recommendations": recs,
            "label": "Inferred · not observed"}


def navigator_layer(findings: list[dict], name: str) -> dict:
    """ATT&CK Navigator layer (format 4.5) for 'Open in Navigator' on an internally hosted Navigator."""
    m = matrix(findings)
    score = {"high": 100, "medium": 66, "low": 33, "candidate": 10}
    techniques = []
    for col in m["columns"]:
        for c in col["techniques"]:
            techniques.append({"techniqueID": c["technique_id"], "tactic": col["tactic"],
                               "score": score.get(c["best_confidence"] or "candidate", 10),
                               "comment": "; ".join(f"{x['display_id']} {x['title']}" for x in c["findings"])[:500],
                               "enabled": True})
    return {"name": name, "versions": {"layer": "4.5", "navigator": "5.1.0", "attack": ATTACK_VERSION.split("-")[0]},
            "domain": "enterprise-attack", "description": "Exported from SAW (evidence-backed mappings)",
            "techniques": techniques,
            "gradient": {"colors": ["#d9e6f2", "#3b82f6"], "minValue": 0, "maxValue": 100},
            "legendItems": [{"label": "candidate", "color": "#d9e6f2"}, {"label": "high", "color": "#3b82f6"}]}
