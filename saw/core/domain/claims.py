"""Claim types (adopted from the Codex comparison): every statement SAW shows says what kind of knowledge it is.

OBSERVED  — present in evidence as-is (raw log line, packet, field value)
DERIVED   — deterministic computation over observations (counts, ratios, baselines, entropy, hashes)
INFERRED  — hypothesis or interpretation (a "Potential …" finding, ATT&CK mapping, story link, AI text)
VERDICT   — a human analyst's decision (feedback, investigation close)
"""
from __future__ import annotations

OBSERVED, DERIVED, INFERRED, VERDICT = "OBSERVED", "DERIVED", "INFERRED", "VERDICT"
LABELS_KO = {OBSERVED: "관측", DERIVED: "계산", INFERRED: "추론", VERDICT: "판정"}


def annotate_finding(d: dict) -> dict:
    """Add claim types to a serialized finding (does not change stored data)."""
    d["claim"] = INFERRED
    d["metrics"] = [{**m, "claim": DERIVED} for m in d.get("metrics") or []]
    d["checks"] = [{**c, "claim": DERIVED} for c in d.get("checks") or []]
    d["counter_evidence"] = [{**c, "claim": DERIVED} if isinstance(c, dict) else c for c in d.get("counter_evidence") or []]
    d["attack"] = [{**a, "claim": INFERRED} for a in d.get("attack") or []]
    refs = dict(d.get("evidence_refs") or {})
    refs["claim"] = OBSERVED  # sample events / query point at evidence as-is
    d["evidence_refs"] = refs
    return d
