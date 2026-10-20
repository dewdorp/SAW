"""Bounded, investigation-scoped execution of the exact reviewed Sigma version."""
from __future__ import annotations

import json
import logging
from collections import Counter
from types import SimpleNamespace
from copy import deepcopy
from time import monotonic

from sqlalchemy import select
from sqlalchemy.orm import Session

from saw.attack.catalog import TECHNIQUES
from saw.content_packages.service import has_package_validation
from saw.core.application.identity import principal_of
from saw.core.application.investigations import access_of
from saw.core.schemas.query import Filter
from saw.core.security.authz import can
from saw.detection.service import Detection, DetectionVersion
from saw.detection.sigma_eval import (
    SigmaError,
    _get,
    apply_threshold,
    attack_tags,
    compile_rule,
    evaluate,
    local_field,
    validate_threshold,
)
from saw.detectors.base import AttackMap, DetectorContext, FindingDraft, check, metric
from saw.storage.models import Finding, User

PREFIX = "sigma.approved:"
COVERAGE_ID = "sigma.coverage"
MAX_RULES = 50
MAX_EVENTS = 500000
MAX_HITS = 100000
MAX_METADATA_BYTES = 8 * 1024 * 1024
MAX_EVENT_METADATA_BYTES = 65536
MAX_EVALUATIONS = 2000000
MAX_SECONDS = 30
EVIDENCE_LIMIT = 1000
logger = logging.getLogger("saw.detectors")


def _authorized(s: Session, det: Detection, version: DetectionVersion, inv_id: str) -> bool:
    creator = s.get(User, det.created_by)
    author = s.execute(select(User).where(User.username == version.created_by)).scalar_one_or_none()
    reviewer = s.execute(select(User).where(User.username == version.reviewed_by)).scalar_one_or_none()
    if any(user is None or user.status != "active" for user in (creator, author, reviewer)):
        return False
    if reviewer.id in (creator.id, author.id) or not can(principal_of(reviewer), "detection.approve"):
        return False
    source_inv = (det.source or {}).get("investigation_id")
    if source_inv and source_inv != inv_id:
        return False
    # Reviewed synthetic package definitions are shared content without private source investigations.
    if not source_inv and has_package_validation(s, det.id, version.version):
        return True
    for user in (creator, author):
        principal = principal_of(user)
        for ident in {inv_id, source_inv} - {None}:
            if not can(principal, "investigation.read", access_of(s, principal, ident)):
                return False
    return True


def _project_metadata(event: dict, fields: set[str]) -> tuple[dict, int]:
    """Retain only requested nested leaves, with a serialized size budget."""
    kept = {}
    for field in sorted(fields):
        value = _get(event, field)
        if value is None:
            continue
        target = kept
        parts = field.split(".")
        for part in parts[:-1]:
            target = target.setdefault(part, {})
        target[parts[-1]] = value
    size = len(json.dumps(kept, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
    if size > MAX_EVENT_METADATA_BYTES:
        raise SigmaError("matching metadata exceeds the per-event size limit")
    return kept, size


def _finding(det: Detection, version: DetectionVersion, rule, hits: list[dict], scanned: int,
             validation_kind: str = "historical_replay") -> FindingDraft:
    ids = [event["event_id"] for event in hits]
    timestamps = sorted(event["timestamp"] for event in hits if event.get("timestamp"))
    ips = sorted({str(event[key]) for event in hits for key in ("src_ip", "dst_ip") if event.get(key)})[:20]
    techniques = sorted(set(attack_tags(rule)) | {str(t).removeprefix("attack.").upper() for t in version.attack or []})
    return FindingDraft(
        detector_id=PREFIX + det.id, detector_version=str(version.version), title="승인 규칙 일치: " + version.title,
        category="sigma.approved", stage="DETECTION", severity={"critical": .9, "high": .75, "medium": .55, "low": .3, "info": .1}.get(version.severity, .55),
        confidence=version.confidence if version.confidence in {"low", "medium", "high"} else "medium",
        metrics=[metric("matched_events", len(hits), label="일치한 기록"), metric("scanned_events", scanned, label="검사한 기록"),
                 metric("rule_version", version.version, label="승인된 규칙 버전")],
        checks=[check("승인된 현재 버전", True, f"{det.display_id} v{version.version}"),
                check("승인 시험 종류", True, validation_kind,
                      "합성 양성·정상 예제 시험이며 과거 조사 재생 시험은 아닙니다" if validation_kind == "package_fixture" else "과거 조사 재생 시험"),
                check("전체 검사 완료", True, f"{scanned:,}건"),
                check("근거 조회 범위", True, f"{min(len(ids), EVIDENCE_LIMIT):,}/{len(ids):,}건",
                      "일치한 기록이 많으면 근거 조회는 표본으로 제한합니다")],
        entities=["ip:" + ip for ip in ips],
        evidence_query={"filters": [{"field": "event_id", "op": "in", "value": ids[:EVIDENCE_LIMIT]}], "time": None,
                        "detection_id": det.id, "version": version.version, "sampled": len(ids) > EVIDENCE_LIMIT},
        time_start=timestamps[0] if timestamps else None, time_end=timestamps[-1] if timestamps else None,
        dedup_key=PREFIX + det.id,
        attack=[AttackMap(t, "medium", "승인된 Sigma 규칙의 ATT&CK 태그", condition_met=False,
                          rationale="규칙 일치는 공격 성공의 확정이 아닙니다", source="approved_sigma")
                for t in techniques if t in TECHNIQUES],
        success_signal=False, explanation=f"승인된 {det.display_id} v{version.version} 규칙에 {len(hits):,}건이 일치했습니다. "
                                            "예외와 시간창 조건을 적용한 결과이며 공격 성공 여부는 별도로 확인해야 합니다.",
        sample_event_ids=ids[:20], total_events=len(hits))


def _coverage(reasons: Counter, scanned: int) -> FindingDraft:
    labels = {"budget": "처리 한도 도달", "unsupported": "지원하지 않는 규칙", "failed": "평가 실패"}
    return FindingDraft(
        COVERAGE_ID, "1", "승인 규칙 일부를 검사하지 못함", COVERAGE_ID, "DETECTION", 0, "low",
        [metric("incomplete_rules", sum(reasons.values()), label="미완료 규칙(최소)"), metric("scanned_events", scanned, label="검사한 기록")],
        [check(labels[key], False, count, "이 규칙의 이전 탐지 결과는 이번 실행으로 갱신되지 않았습니다" if key != "unsupported" else "규칙을 지원 범위에 맞게 고쳐야 합니다")
         for key, count in sorted(reasons.items())], [], {"filters": [{"field": "event_id", "op": "in", "value": []}]},
        None, None, COVERAGE_ID, success_signal=False,
        explanation="승인 규칙 검사에 미완료 항목이 있습니다. 탐지가 없다는 뜻이 아닙니다. 처리 한도와 규칙의 지원 조건을 확인하세요.")


def run_approved(s: Session, ctx: DetectorContext) -> tuple[list[FindingDraft], set[str]]:
    """A rule is settled only after complete evaluation or an intentional eligibility change.

    Ineligible/private rules are silently skipped; their titles, sources and rejection reasons do not cross scopes.
    Runtime failures keep prior results and emit a separate execution report. No source values are logged.
    """
    budget = ctx.params.setdefault("sigma_runtime_budget", {"deadline": monotonic() + MAX_SECONDS,
                                                          "evaluations": 0, "rules": 0})
    deadline = min(monotonic() + MAX_SECONDS, budget["deadline"])
    from saw.detection import governance as gov
    from saw.core.application.investigations import Forbidden, NotFound
    from saw.storage.models import Investigation
    runtime = ctx.params.get("runtime_pin")
    explicitly_inactive = set()
    reports = ctx.params.setdefault("execution_reports", [])
    if runtime is None:
        # Internal compatibility entry point: pin once before event iteration.
        # HTTP execution supplies its authenticated actor and already-frozen runtime set.
        inv = s.get(Investigation, ctx.investigation_id)
        actor = s.get(User, ctx.params.get("actor_id") or (inv.owner_id if inv else None))
        pins = []
        if actor and actor.status == "active":
            p = principal_of(actor)
            # Compatibility callers can prove a live inactive state explicitly.
            # A missing bounded/runtime pin alone never authorizes retirement.
            prior_finding = select(Finding.id).where(
                Finding.detector_id == PREFIX + Detection.id,
                Finding.investigation_id == ctx.investigation_id).exists()
            inactive = s.scalars(select(Detection).where(
                Detection.active_version_id.is_(None), prior_finding).order_by(Detection.id).limit(MAX_RULES))
            for det in inactive:
                try:
                    source_inv = (det.source or {}).get("investigation_id")
                    if source_inv and source_inv != ctx.investigation_id:
                        continue
                    gov._read_sources(s, p, [ctx.investigation_id, *gov._source_ids(s, "rule", det)])
                    explicitly_inactive.add(PREFIX + det.id)
                except (Forbidden, NotFound, ValueError):
                    continue
            for det in s.scalars(select(Detection).where(Detection.active_version_id.is_not(None))
                                 .order_by(Detection.id).limit(MAX_RULES + 1)):
                try:
                    version = gov._version(s, "rule", det, det.active_version_id)
                    approval = gov.validate_approval(s, p, "rule", det, version, det.active_approval_id)
                    if not _authorized(s, det, version, ctx.investigation_id):
                        continue
                    pin = gov.pin_rule(s, p, det.id, version.id, {"kind": "group"})
                    pin.update(approval_id=approval.id, validation_kind=approval.proof["method"])
                    pin["source_investigation_ids"] = sorted(set(pin["source_investigation_ids"] + approval.source_investigation_ids))
                    pins.append(pin)
                except (Forbidden, NotFound, ValueError):
                    continue
    elif runtime.get("schema") == "det-runtime-set/1":
        pins = deepcopy(runtime.get("rules", []))
    elif runtime.get("schema") == "det-runtime-pin/1" and runtime.get("rule"):
        pins = [deepcopy(runtime)]
    else:
        raise ValueError("trusted exact runtime pin required")
    # An absent captured rule may be inaccessible or outside the capture budget.
    # Absence is not a completed zero-match evaluation or a retirement instruction.
    settled = {COVERAGE_ID} | explicitly_inactive
    out, reasons = [], Counter()
    if len(pins) > MAX_RULES:
        reasons["budget"] += 1
    scanned_total = 0
    max_events = max(1, min(MAX_EVENTS, int(ctx.params.get("sigma_max_events", MAX_EVENTS))))
    for pin in pins[:MAX_RULES]:
        if budget["rules"] >= 500 or budget["evaluations"] >= MAX_EVALUATIONS:
            reasons["budget"] += 1
            break
        budget["rules"] += 1
        item = pin["rule"]
        det = SimpleNamespace(id=item["id"], display_id=item["display_id"])
        version = SimpleNamespace(id=item["version_id"], version=item["version"], **item["payload"])
        ident = PREFIX + det.id
        if monotonic() >= deadline:
            reasons["budget"] += 1
            continue
        if pin.get("context_scope", {"kind": "group"}) != {"kind": "group"} and ctx.params.get("runtime_scope") != pin["context_scope"]:
            reports.append({"detector_id": ident, "status": "insufficient_data", "reason": "scoped_runtime_required",
                            "effective_config": pin})
            continue
        settled.add(ident)
        if not pin["policy"]["values"].get("enabled", True):
            reports.append({"detector_id": ident, "status": "disabled", "effective_config": pin, "match_count": 0})
            continue
        validation_kind = pin.get("validation_kind", "selected_truth_v1")
        if budget["evaluations"] >= MAX_EVALUATIONS or monotonic() >= deadline:
            settled.discard(ident)
            reasons["budget"] += 1
            continue
        try:
            rule = compile_rule(version.logic)
            threshold = validate_threshold(version.threshold)
            exception_groups = [[Filter(**item) for item in version.exceptions or []],
                                [Filter(**item) for item in pin["policy"].get("exclusions", [])]]
            exceptions = [item for group in exception_groups for item in group]
            if len(exceptions) > 32:
                raise SigmaError("too many exceptions")
            for exception in exceptions:
                local_field(exception.field)
        except (ValueError, TypeError):
            settled.discard(ident)
            reasons["unsupported"] += 1
            continue
        sources = set(rule.data_sources) & ctx.data_sources
        if not sources:
            continue
        if budget["evaluations"] >= MAX_EVALUATIONS or monotonic() >= deadline:
            settled.discard(ident)
            reasons["budget"] += 1
            continue
        pre = [Filter(field="data_source", op="in", value=sorted(sources))]
        scanned, excluded, hits = 0, set(), []
        metadata_bytes = 0
        try:
            # Each exception list is a conjunction; rule and policy groups are excluded by union.
            for group in exception_groups:
                if group:
                    for event in ctx.events.iterate(ctx.investigation_id, pre + group, fields=["event_id"]):
                        if len(excluded) >= max_events or monotonic() >= deadline:
                            raise TimeoutError
                        excluded.add(event["event_id"])
            for event in ctx.events.iterate(ctx.investigation_id, pre):
                if scanned >= max_events or budget["evaluations"] >= MAX_EVALUATIONS or monotonic() >= deadline or len(hits) >= MAX_HITS:
                    raise TimeoutError
                scanned += 1
                scanned_total += 1
                budget["evaluations"] += 1
                if event.get("event_id") not in excluded and evaluate(rule, event):
                    fields = {"event_id", "timestamp", "src_ip", "dst_ip", *threshold.get("group_by", [])}
                    if threshold.get("distinct_field"):
                        fields.add(threshold["distinct_field"])
                    # Keep bounded matching metadata, not request bodies, while collecting threshold windows.
                    kept, size = _project_metadata(event, fields)
                    metadata_bytes += size
                    if metadata_bytes > MAX_METADATA_BYTES:
                        raise TimeoutError
                    hits.append(kept)
            hits = apply_threshold(hits, threshold)
            if hits:
                out.append(_finding(det, version, rule, hits, scanned, validation_kind))
            reports.append({"detector_id": ident, "status": "complete", "input_count": scanned, "match_count": len(hits),
                            "effective_config": pin, "match_unit": "event"})
        except TimeoutError:
            settled.discard(ident)
            reasons["budget"] += 1
        except Exception:  # noqa: BLE001 - preserve prior findings on event/store failure
            settled.discard(ident)
            reasons["failed"] += 1
            logger.warning("approved Sigma evaluation failed for rule %s", det.id)
    if reasons:
        reports.append({"detector_id": "sigma.approved", "status": "partial", "input_count": scanned_total,
                        "detail": dict(reasons), "match_count": None})
    return out, settled
