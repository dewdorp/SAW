"""Detector plugin contract and Finding construction (docs/24)."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from saw.attack.catalog import ATTACK_VERSION, technique
from saw.core.domain.enums import risk_level_for
from saw.storage.eventstore import EventStorePort

CONF_FACTOR = {"low": 0.5, "medium": 0.75, "high": 1.0}
ASSET_FACTOR = {"critical": 1.2, "high": 1.0, "medium": 0.8, "low": 0.6, None: 0.9}


@dataclass
class DetectorContext:
    investigation_id: str
    events: EventStorePort
    assets: Any = None  # AssetPort (Phase 8); None -> relative comparison only
    params: dict[str, Any] = field(default_factory=dict)
    data_sources: set[str] = field(default_factory=set)


@dataclass
class AttackMap:
    technique_id: str
    confidence: str
    condition: str
    condition_met: bool = True
    rationale: str = ""
    source: str = "detector_map"

    def to_dict(self) -> dict:
        t = technique(self.technique_id)
        return {"technique_id": self.technique_id, "name": t["name"], "tactic": (t["tactics"] or [None])[0],
                "source": self.source, "confidence": self.confidence if self.condition_met else "candidate",
                "condition": self.condition, "condition_met": self.condition_met, "rationale": self.rationale,
                "attack_version": ATTACK_VERSION}


@dataclass
class FindingDraft:
    detector_id: str
    detector_version: str
    title: str
    category: str
    stage: str
    severity: float  # behavior severity 0..1
    confidence: str  # low|medium|high
    metrics: list[dict]
    checks: list[dict]
    entities: list[str]
    evidence_query: dict  # {"filters": [...], "time": {...}}
    time_start: str | None
    time_end: str | None
    dedup_key: str
    counter_evidence: list[dict] = field(default_factory=list)
    attack: list[AttackMap] = field(default_factory=list)
    attack_unmapped_reason: str | None = None
    asset_criticality: str | None = None
    success_signal: bool = True
    explanation: str = ""
    sample_event_ids: list[str] = field(default_factory=list)
    total_events: int = 0

    def risk(self) -> tuple[float, str, list[dict]]:
        cf = CONF_FACTOR[self.confidence]
        af = ASSET_FACTOR.get(self.asset_criticality, 0.9)
        of = 1.0 if self.success_signal else 0.6
        score = max(0.0, min(100.0, 100 * self.severity * cf * af * of))
        factors = [
            {"name": "behavior_severity", "value": self.severity},
            {"name": "confidence", "value": self.confidence, "factor": cf},
            {"name": "asset_criticality", "value": self.asset_criticality or "unknown", "factor": af},
            {"name": "outcome", "value": "success signal" if self.success_signal else "success not verified",
             "factor": of},
        ]
        return round(score, 1), str(risk_level_for(score)), factors


class Detector(Protocol):
    id: str
    version: str
    category: str
    stage: str
    data_sources: set[str]

    def run(self, ctx: DetectorContext) -> list[FindingDraft]: ...


def check(label: str, passed: bool | None, value: Any, detail: str = "") -> dict:
    return {"label": label, "passed": passed, "value": value, "detail": detail}


def metric(name: str, observed: Any, baseline: dict | None = None, unit: str = "", approx: bool = False,
           label: str | None = None) -> dict:
    m = {"name": name, "label": label or name, "observed": observed, "unit": unit}
    if baseline:
        m["baseline"] = baseline
        if baseline.get("max"):
            try:
                m["ratio"] = round(float(observed) / float(baseline["max"]), 1)
            except (TypeError, ValueError, ZeroDivisionError):
                pass
    if approx:
        m["approx"] = True
    return m
