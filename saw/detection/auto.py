"""Bounded, investigation-scoped execution of the exact reviewed Sigma version."""
from __future__ import annotations

import json
import logging
from collections import Counter
from time import monotonic

from sqlalchemy import select
from sqlalchemy.orm import Session

from saw.attack.catalog import TECHNIQUES
from saw.core.application.identity import principal_of
from saw.core.application.investigations import access_of
from saw.core.schemas.query import Filter
from saw.core.security.authz import can
from saw.detection.service import Detection, DetectionVersion, has_passing_test
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


def _finding(det: Detection, version: DetectionVersion, rule, hits: list[dict], scanned: int) -> FindingDraft:
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
    Runtime failures keep prior results and emit one visible coverage finding. No source values are logged.
    """
    deadline = monotonic() + MAX_SECONDS
    existing = set(s.execute(select(Finding.detector_id).where(Finding.investigation_id == ctx.investigation_id,
                                                               Finding.detector_id.startswith(PREFIX))).scalars())
    existing_ids = {ident[len(PREFIX):] for ident in existing}
    still_active = set(s.execute(select(Detection.id).where(Detection.id.in_(existing_ids),
                                                          Detection.status.in_(["approved", "deployed"]))).scalars()) if existing_ids else set()
    settled = (existing - {PREFIX + ident for ident in still_active}) | {COVERAGE_ID}
    detections = list(s.execute(select(Detection).where(Detection.status.in_(["approved", "deployed"]))
                               .order_by(Detection.id).limit(MAX_RULES + 1)).scalars())
    out, reasons = [], Counter()
    if len(detections) > MAX_RULES:
        reasons["budget"] += 1
    scanned_total = 0
    max_events = max(1, min(MAX_EVENTS, int(ctx.params.get("sigma_max_events", MAX_EVENTS))))
    for det in detections[:MAX_RULES]:
        ident = PREFIX + det.id
        if monotonic() >= deadline:
            reasons["budget"] += 1
            continue
        settled.add(ident)
        version = s.execute(select(DetectionVersion).where(DetectionVersion.detection_id == det.id)
                            .order_by(DetectionVersion.version.desc()).limit(1)).scalars().first()
        if (version is None or version.version != det.current_version or version.format != "sigma"
                or version.status_at_version not in {"approved", "deployed"} or not _authorized(s, det, version, ctx.investigation_id)):
            continue
        if not has_passing_test(s, det.id, version.version):
            continue
        if scanned_total >= MAX_EVALUATIONS or monotonic() >= deadline:
            settled.discard(ident)
            reasons["budget"] += 1
            continue
        try:
            rule = compile_rule(version.logic)
            threshold = validate_threshold(version.threshold)
            exceptions = [Filter(**item) for item in version.exceptions or []]
            if len(exceptions) > 32:
                raise SigmaError("too many exceptions")
            for exception in exceptions:
                local_field(exception.field)
        except (ValueError, TypeError):
            reasons["unsupported"] += 1
            continue
        sources = set(rule.data_sources) & ctx.data_sources
        if not sources:
            continue
        if scanned_total >= MAX_EVALUATIONS or monotonic() >= deadline:
            settled.discard(ident)
            reasons["budget"] += 1
            continue
        pre = [Filter(field="data_source", op="in", value=sorted(sources))]
        scanned, excluded, hits = 0, set(), []
        metadata_bytes = 0
        try:
            if exceptions:
                for event in ctx.events.iterate(ctx.investigation_id, pre + exceptions, fields=["event_id"]):
                    if len(excluded) >= max_events or monotonic() >= deadline:
                        raise TimeoutError
                    excluded.add(event["event_id"])
            for event in ctx.events.iterate(ctx.investigation_id, pre):
                if scanned >= max_events or scanned_total >= MAX_EVALUATIONS or monotonic() >= deadline or len(hits) >= MAX_HITS:
                    raise TimeoutError
                scanned += 1
                scanned_total += 1
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
                out.append(_finding(det, version, rule, hits, scanned))
        except TimeoutError:
            settled.discard(ident)
            reasons["budget"] += 1
        except Exception:  # noqa: BLE001 - preserve prior findings on event/store failure
            settled.discard(ident)
            reasons["failed"] += 1
            logger.warning("approved Sigma evaluation failed for rule %s", det.id)
    if reasons:
        out.append(_coverage(reasons, scanned_total))
    return out, settled
