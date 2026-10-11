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
    ATTACK = "attack"
    NORMAL = "normal"
    FALSE_POSITIVE = "false_positive"
    UNKNOWN = "unknown"


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
