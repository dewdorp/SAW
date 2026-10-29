from __future__ import annotations

from enum import StrEnum


class Role(StrEnum):
    ADMIN = "admin"
    SOC_MANAGER = "soc_manager"
    SENIOR_ANALYST = "senior_analyst"
    ANALYST = "analyst"
    VIEWER = "viewer"


class JobState(StrEnum):
    QUEUED = "QUEUED"
    UPLOADING = "UPLOADING"
    PARSING = "PARSING"
    INDEXING = "INDEXING"
    ANALYZING = "ANALYZING"
    WAITING_INPUT = "WAITING_INPUT"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


TERMINAL_JOB_STATES = {JobState.COMPLETED, JobState.FAILED, JobState.CANCELLED}


class InvestigationStatus(StrEnum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    PENDING_REVIEW = "pending_review"
    CLOSED = "closed"


class Verdict(StrEnum):
    # Analyst conclusions. A device alert name, severity, HTTP 200 or a firewall "allow" never sets one of these.
    NORMAL = "normal"  # 정상 업무로 확인
    ATTACK_ATTEMPT = "attack_attempt"  # 공격 시도 확인 (성공·영향은 확인되지 않음)
    COMPROMISE_CONFIRMED = "compromise_confirmed"  # 침해 또는 실제 영향 확인
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"  # 증거 부족으로 추가 확인 필요
    DATA_QUALITY_LIMITED = "data_quality_limited"  # 데이터 품질 문제로 판단 제한
    # Earlier values, still accepted and shown for existing records.
    ATTACK = "attack"
    FALSE_POSITIVE = "false_positive"
    UNKNOWN = "unknown"


ATTACK_VERDICTS = frozenset({Verdict.ATTACK, Verdict.ATTACK_ATTEMPT, Verdict.COMPROMISE_CONFIRMED})
BENIGN_VERDICTS = frozenset({Verdict.NORMAL, Verdict.FALSE_POSITIVE})


class RiskLevel(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(StrEnum):
    NEW = "new"
    TRIAGED = "triaged"
    VALID = "valid"
    BENIGN = "benign"
    FALSE_POSITIVE = "false_positive"
    DUPLICATE = "duplicate"


class CaseStatus(StrEnum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    CLOSED = "closed"


class KnowledgeStatus(StrEnum):
    DRAFT = "draft"
    REVIEW = "review"
    APPROVED = "approved"
    DEPRECATED = "deprecated"


class DetectionStatus(StrEnum):
    DRAFT = "draft"
    TEST = "test"
    APPROVED = "approved"
    DEPLOYED = "deployed"
    DEPRECATED = "deprecated"


def risk_level_for(score: float) -> RiskLevel:
    if score >= 85:
        return RiskLevel.CRITICAL
    if score >= 65:
        return RiskLevel.HIGH
    if score >= 40:
        return RiskLevel.MEDIUM
    if score >= 20:
        return RiskLevel.LOW
    return RiskLevel.INFO
