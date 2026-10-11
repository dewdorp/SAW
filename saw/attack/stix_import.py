"""Build the compact offline ATT&CK catalog SAW ships from an official MITRE STIX 2.1 bundle (adopted, ADR-0015).

The 54 MB bundle is not shipped; only what the product needs (ids, names, tactics, matrix order, platforms, a
one-paragraph description and the ATT&CK URL) plus provenance: source commit, source SHA-256, ATT&CK version.
Usage: python -m saw.cli attack-import enterprise-attack-19.2.json --sha256 <expected>
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

DATA = Path(__file__).resolve().parents[2] / "data" / "mitre"
COMPACT = DATA / "enterprise-attack.compact.json"
_CITE = re.compile(r"\(Citation:[^)]*\)")
_LINK = re.compile(r"\[([^\]]+)\]\([^)]*\)")


def _ext_id(obj: dict) -> tuple[str | None, str | None]:
    for r in obj.get("external_references") or []:
        if r.get("source_name") == "mitre-attack":
            return r.get("external_id"), r.get("url")
    return None, None


def _summary(text: str, limit: int = 400) -> str:
    t = _LINK.sub(r"\1", _CITE.sub("", text or "")).replace("<code>", "").replace("</code>", "")
    t = " ".join(t.split())
    first = t.split("\n")[0]
    return first if len(first) <= limit else first[: limit - 1].rsplit(" ", 1)[0] + "…"


def build_compact(bundle_path: Path, expected_sha256: str | None = None, source: str = "") -> dict:
    raw = Path(bundle_path).read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if expected_sha256 and digest != expected_sha256.lower():
        raise ValueError(f"SHA-256 mismatch: expected {expected_sha256}, got {digest}")
    objs = json.loads(raw)["objects"]
    live = [o for o in objs if not o.get("revoked") and not o.get("x_mitre_deprecated")]
    collection = next((o for o in objs if o.get("type") == "x-mitre-collection"), {})
    version = collection.get("x_mitre_version") or ""
    tactics_by_ref = {o["id"]: o for o in live if o.get("type") == "x-mitre-tactic"}
    matrix = next((o for o in live if o.get("type") == "x-mitre-matrix"), {})
    tactics = []
    for ref in matrix.get("tactic_refs") or tactics_by_ref:
        o = tactics_by_ref.get(ref)
        if o:
            tid, _ = _ext_id(o)
            tactics.append([tid, o["x_mitre_shortname"], o["name"]])
    techniques = {}
    for o in live:
        if o.get("type") != "attack-pattern":
            continue
        tid, url = _ext_id(o)
        if not tid:
            continue
        techniques[tid] = {
            "name": o["name"],
            "tactics": [p["phase_name"] for p in o.get("kill_chain_phases") or [] if p.get("kill_chain_name") == "mitre-attack"],
            "sub": bool(o.get("x_mitre_is_subtechnique")),
            "platforms": o.get("x_mitre_platforms") or [],
            "summary": _summary(o.get("description", "")),
            "url": url,
        }
    # sub-technique names are shown as "Parent: Sub" like the ATT&CK website
    for tid, t in techniques.items():
        if t["sub"] and "." in tid and tid.split(".")[0] in techniques and ":" not in t["name"]:
            t["name"] = f"{techniques[tid.split('.')[0]]['name']}: {t['name']}"
    return {"attack_version": version, "domain": "enterprise-attack", "source": source, "source_sha256": digest,
            "tactics": tactics, "techniques": dict(sorted(techniques.items()))}


def write_compact(catalog: dict, out: Path = COMPACT) -> Path:
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(catalog, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    return out
