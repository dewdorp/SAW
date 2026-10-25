"""Attack flows: findings of one investigation that follow each other for the same address (packs/scenarios.yaml).

A flow does not replace its findings. It says "these belong together, in this order", which is what a reader of a
long finding list cannot see at a glance. Matching is deliberately simple: findings that share an IP entity, ordered
by start time, have to cover the steps of a scenario one after the other.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from functools import lru_cache
from ipaddress import ip_address
from itertools import groupby
from pathlib import Path
from typing import Any

import yaml

from saw.detectors.base import AttackMap, FindingDraft, check, metric

PACK = Path(__file__).parent / "packs" / "scenarios.yaml"
DETECTOR_ID, VERSION = "scenario.flow", "1.2.0"
RISK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
ADVICE = "\n\n### 확인·대응 권고 (분석가 판단 후 수행)\n"


@dataclass(frozen=True)
class Step:
    name: str
    stages: tuple[str, ...] = ()
    categories: tuple[str, ...] = ()
    success: bool = False

    def fits(self, f: dict) -> bool:
        if self.success and not f["success"]:
            return False
        return f["stage"] in self.stages or any(str(f["category"]).startswith(c) for c in self.categories)


@dataclass(frozen=True)
class Scenario:
    id: str
    title: str
    severity: float
    attack: tuple[str, ...]
    min_risk: str
    steps: tuple[Step, ...]
    explain: str
    checks: tuple[str, ...]
    max_span_seconds: int = 14400
    entity_role: str = "any"
    strict_order: bool = False


@lru_cache(maxsize=1)
def load() -> tuple[Scenario, ...]:
    doc = yaml.safe_load(PACK.read_text(encoding="utf-8")) or {}
    out = []
    for s in doc.get("scenarios") or []:
        steps = tuple(Step(str(x["name"]), tuple(x.get("stages") or ()), tuple(x.get("categories") or ()), bool(x.get("success")))
                      for x in s["steps"])
        if not 2 <= len(steps) <= 5 or any(not (st.stages or st.categories) for st in steps):
            raise ValueError(f"scenario {s['id']}: needs two or more steps, each with stages or categories")
        span, role, strict = s.get("max_span_seconds", 14400), s.get("entity_role", "any"), s.get("strict_order", False)
        if type(span) is not int or not 1 <= span <= 604800 or role not in ("any", "source", "destination") or type(strict) is not bool:
            raise ValueError(f"scenario {s['id']}: invalid time window/entity role")
        out.append(Scenario(str(s["id"]), str(s["title"]), float(s.get("severity", 0.8)), tuple(s.get("attack") or ()),
                            str(s.get("min_risk", "medium")), steps, str(s.get("explain", "")), tuple(s.get("checks") or ()), span, role, strict))
    return tuple(out)


def _ts(v: Any) -> float | None:
    try:
        dt = v if isinstance(v, datetime) else datetime.fromisoformat(str(v).replace("Z", "+00:00"))
        return dt.timestamp() if dt.tzinfo is not None else None
    except (ValueError, OverflowError, OSError):
        return None


def _iso(v: Any) -> str | None:
    return v.isoformat() if isinstance(v, datetime) else (str(v) if v else None)


MAX_PER_SCENARIO = 5  # a busy server may show the same flow for many addresses: the riskiest few are enough to act on


def _walk(sc: Scenario, rows: list[dict], ip: str) -> list[dict] | None:
    """Keep viable prefixes; strict steps read a snapshot before each equal-time batch."""
    prefixes: list[list[dict] | None] = [None] * len(sc.steps)

    def prefer(candidate, existing):
        return existing is None or (candidate[0]["t0"], -max(f["t1"] for f in candidate)) > (
            existing[0]["t0"], -max(f["t1"] for f in existing))

    for _stamp, batch in groupby(rows, key=lambda row: row["t0"]):
        before = prefixes[:]
        for row in batch:
            if sc.entity_role != "any" and ip not in (row.get("entity_roles") or {}).get(sc.entity_role, []):
                continue
            for index in range(len(sc.steps) - 1, -1, -1):
                if not sc.steps[index].fits(row):
                    continue
                if index == 0:
                    if row["t1"] - row["t0"] <= sc.max_span_seconds and prefer([row], prefixes[0]):
                        prefixes[0] = [row]
                    continue
                prefix = (before if sc.strict_order else prefixes)[index - 1]
                if not prefix or row in prefix:
                    continue
                if sc.strict_order and row["t0"] <= prefix[-1]["t0"]:
                    continue
                if max(row["t1"], *(f["t1"] for f in prefix)) - prefix[0]["t0"] > sc.max_span_seconds:
                    continue
                chain = prefix + [row]
                if index == len(sc.steps) - 1:
                    return chain
                if prefer(chain, prefixes[index]):
                    prefixes[index] = chain
    return None


def _valid_ip_entity(value):
    if not str(value).startswith("ip:"):
        return False
    try:
        ip_address(str(value)[3:])
        return True
    except ValueError:
        return False


def _eligible(f):
    t0 = _ts(f.get("time_start"))
    t1 = _ts(f.get("time_end") or f.get("time_start"))
    return (t0 is not None and t1 is not None and t1 >= t0
            and any(_valid_ip_entity(value) for value in f.get("entities") or []))


def match(findings: list[dict]) -> list[FindingDraft]:
    """findings: dicts with id, display_id, title, category, stage, risk_level, success, entities, time_start, time_end
    (flows themselves and anything rated false positive / duplicate / benign are left out by the caller)."""
    by_ip: dict[str, list[dict]] = {}
    for f in findings:
        if not _eligible(f):
            continue
        t0 = _ts(f["time_start"])
        t1 = _ts(f.get("time_end") or f["time_start"])
        if t0 is None or t1 is None or t1 < t0:
            continue
        f = {**f, "t0": t0, "t1": t1}
        for e in f.get("entities") or []:
            if _valid_ip_entity(e):
                by_ip.setdefault(str(e)[3:], []).append(f)
    out: dict[tuple[str, tuple[str, ...]], FindingDraft] = {}
    for ip, rows in by_ip.items():
        rows.sort(key=lambda f: f["t0"])
        for sc in load():
            chain = _walk(sc, rows, ip)
            if not chain or max(RISK.get(f["risk_level"], 0) for f in chain) < RISK.get(sc.min_risk, 2):
                continue
            key = (sc.id, tuple(sorted(f["id"] for f in chain)))  # the same chain reached through two addresses: once
            if key in out:
                out[key].entities.append(f"ip:{ip}")
                continue
            lines = [f"{'①②③④⑤'[i]} {st.name}: {f['display_id']} {f['title']}" for i, (st, f) in enumerate(zip(sc.steps, chain, strict=True))]
            won = any(f["success"] for f in chain)
            out[key] = FindingDraft(
                DETECTOR_ID, VERSION, sc.title, f"scenario.{sc.id}", chain[-1]["stage"], sc.severity,
                "high" if won else "medium",
                [metric("steps", len(chain), label="이어진 단계"), metric("findings", len(chain), label="묶인 탐지")],
                [check(f"{st.name} 단계의 탐지", True, f"{f['display_id']} ({f['risk_level']})") for st, f in zip(sc.steps, chain, strict=True)]
                + [check("성공 정황이 있는 단계", won, "있음" if won else "없음")],
                [f"ip:{ip}"], {"filters": [], "time": {"start": _iso(chain[0]["time_start"]), "end": _iso(max(chain, key=lambda f: f["t1"]).get("time_end") or chain[-1]["time_start"])}, "finding_ids": [f["id"] for f in chain]},
                _iso(chain[0]["time_start"]), _iso(max(chain, key=lambda f: f["t1"]).get("time_end") or chain[-1]["time_start"]),
                f"scenario:{sc.id}:{ip}",
                attack=[AttackMap(t, "medium", "탐지들이 순서대로 이어짐", condition_met=won) for t in sc.attack],
                success_signal=won,
                explanation=(f"{ip} 과(와) 관련된 탐지 {len(chain)}건이 차례로 이어집니다. " + " → ".join(lines) + f". {sc.explain}"
                             + f" 시작 시각 기준 {sc.max_span_seconds}초 이내의 연관 후보이며 인과관계나 공격 성공을 확정하지 않습니다."
                             + (ADVICE + "\n".join(f"- {c}" for c in sc.checks) if sc.checks else "")),
                sample_event_ids=[], total_events=0)
    kept: list[FindingDraft] = []
    per: dict[str, int] = {}
    for (sid, _ids), d in sorted(out.items(), key=lambda kv: -kv[1].risk()[0]):
        if per.get(sid, 0) < MAX_PER_SCENARIO:
            per[sid] = per.get(sid, 0) + 1
            kept.append(d)
    return kept


def catalog() -> list[dict[str, Any]]:
    return [{"id": s.id, "title": s.title, "severity": s.severity, "attack": list(s.attack), "explain": s.explain,
             "steps": [{"name": st.name, "stages": list(st.stages), "categories": list(st.categories), "success": st.success}
                       for st in s.steps], "checks": list(s.checks), "max_span_seconds": s.max_span_seconds,
             "entity_role": s.entity_role, "strict_order": s.strict_order} for s in load()]


def execution_report(findings: list[dict], drafts: list[FindingDraft]) -> dict:
    """Describe this exact matcher input/output; no-chain never means normal."""
    from saw.core.application.provenance import digest

    pack = load()
    eligible = [row for row in findings if _eligible(row)]
    results = []
    for sc in pack:
        steps = []
        for step in sc.steps:
            count = sum(step.fits(row) and (sc.entity_role == "any" or any(
                _valid_ip_entity("ip:" + str(value))
                and "ip:" + str(value) in (row.get("entities") or [])
                for value in (row.get("entity_roles") or {}).get(sc.entity_role, [])))
                for row in eligible)
            steps.append({"name": step.name, "eligible_findings": count})
        matched = sum(d.category == "scenario." + sc.id for d in drafts)
        status = ("matched_candidate" if matched else "insufficient_evidence"
                  if any(not step["eligible_findings"] for step in steps) else "no_chain")
        results.append({"id": sc.id, "title": sc.title, "status": status, "match_count": matched,
                        "steps": steps, "max_span_seconds": sc.max_span_seconds,
                        "entity_role": sc.entity_role, "strict_order": sc.strict_order})
    return {"schema": "scenario-execution/1", "match_unit": "flow", "engine_version": VERSION,
            "pack_sha256": digest([asdict(sc) for sc in pack]),
            "counts": {"input_findings": len(findings), "eligible_findings": len(eligible),
                       "excluded_findings": len(findings) - len(eligible)},
            "max_results_per_scenario": MAX_PER_SCENARIO,
            "scenarios": results,
            "limitations": ["탐지 결과 사이의 시간·주소 연관 후보이며 인과관계나 침해 성공을 확정하지 않습니다.",
                           "단계 근거 없음·무적중은 정상 또는 오탐 정답이 아닙니다. 상위 탐지기의 실패·자료 부족·비활성 상태를 함께 확인하세요.",
                           "수집 범위·장비 시각·주소 익명화 대응이 검증되지 않으면 장비 간 동일 자산이나 공격 순서를 확정할 수 없습니다."]}
