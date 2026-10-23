"""Immutable release records and private holdout use ledgers."""
from __future__ import annotations

from datetime import datetime
from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, event, inspect
from sqlalchemy.orm import Mapped, mapped_column
from saw.storage.db import Base, new_id, utcnow


class GoldenProfileVersion(Base):
    __tablename__ = "kn_golden_profile_version"
    __table_args__ = (UniqueConstraint("kind", "profile_key", "version"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    kind: Mapped[str] = mapped_column(String(32), index=True)
    profile_key: Mapped[str] = mapped_column(String(100))
    version: Mapped[int] = mapped_column(Integer)
    implementation: Mapped[str] = mapped_column(String(100))
    payload: Mapped[dict] = mapped_column(JSON)
    payload_sha256: Mapped[str] = mapped_column(String(64))
    contributor_ids: Mapped[list] = mapped_column(JSON, default=list)
    created_by: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class GoldenValidation(Base):
    __tablename__ = "kn_golden_validation"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    golden_version_id: Mapped[str] = mapped_column(ForeignKey("kn_golden_version.id"), index=True)
    subject_sha256: Mapped[str] = mapped_column(String(64))
    payload: Mapped[dict] = mapped_column(JSON)
    payload_sha256: Mapped[str] = mapped_column(String(64))
    source_investigation_ids: Mapped[list] = mapped_column(JSON)
    validator_version: Mapped[str] = mapped_column(String(100))
    created_by: Mapped[str] = mapped_column(String(36))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class GoldenRelease(Base):
    __tablename__ = "kn_golden_release"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    current_version_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    current_revision: Mapped[int] = mapped_column(Integer, default=0)
    pending_job_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    created_by: Mapped[str] = mapped_column(String(36), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class GoldenReleaseVersion(Base):
    __tablename__ = "kn_golden_release_version"
    __table_args__ = (UniqueConstraint("release_id", "revision"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    release_id: Mapped[str] = mapped_column(ForeignKey("kn_golden_release.id"), index=True)
    revision: Mapped[int] = mapped_column(Integer)
    request: Mapped[dict] = mapped_column(JSON)
    request_sha256: Mapped[str] = mapped_column(String(64))
    payload: Mapped[dict] = mapped_column(JSON)
    payload_sha256: Mapped[str] = mapped_column(String(64))
    source_investigation_ids: Mapped[list] = mapped_column(JSON)
    contributor_ids: Mapped[list] = mapped_column(JSON)
    private_objects: Mapped[dict] = mapped_column(JSON)
    validation_refs: Mapped[list] = mapped_column(JSON, default=list)
    artifact_sha256: Mapped[str] = mapped_column(String(64))
    size_bytes: Mapped[int] = mapped_column(Integer)
    family_snapshot_sha256: Mapped[str] = mapped_column(String(64))
    created_by: Mapped[str] = mapped_column(String(36))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class GoldenReleaseDecision(Base):
    __tablename__ = "kn_golden_release_decision"
    __table_args__ = (UniqueConstraint("release_version_id", "sequence"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    release_version_id: Mapped[str] = mapped_column(ForeignKey("kn_golden_release_version.id"), index=True)
    sequence: Mapped[int] = mapped_column(Integer)
    previous_decision_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    decision: Mapped[str] = mapped_column(String(16))
    payload_sha256: Mapped[str] = mapped_column(String(64))
    artifact_sha256: Mapped[str] = mapped_column(String(64))
    reviewer_id: Mapped[str] = mapped_column(String(36))
    reason: Mapped[str] = mapped_column(Text)
    confirmations: Mapped[dict] = mapped_column(JSON)
    request_sha256: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class GoldenReleasePreview(Base):
    __tablename__ = "kn_golden_release_preview"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    release_version_id: Mapped[str] = mapped_column(ForeignKey("kn_golden_release_version.id"), index=True)
    reviewer_id: Mapped[str] = mapped_column(String(36), index=True)
    artifact_sha256: Mapped[str] = mapped_column(String(64))
    preview_sha256: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class GoldenReleaseSource(Base):
    __tablename__ = "kn_golden_release_source"
    release_version_id: Mapped[str] = mapped_column(ForeignKey("kn_golden_release_version.id"), primary_key=True)
    investigation_id: Mapped[str] = mapped_column(String(36), primary_key=True, index=True)


class GoldenHoldoutAttempt(Base):
    __tablename__ = "kn_golden_holdout_attempt"
    __table_args__ = (UniqueConstraint("created_by", "idempotency_key"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    release_version_id: Mapped[str] = mapped_column(ForeignKey("kn_golden_release_version.id"), index=True)
    target: Mapped[dict] = mapped_column(JSON)
    target_sha256: Mapped[str] = mapped_column(String(64), index=True)
    request_sha256: Mapped[str] = mapped_column(String(64))
    idempotency_key: Mapped[str] = mapped_column(String(128))
    purpose_text: Mapped[str] = mapped_column(Text)
    family_ids: Mapped[list] = mapped_column(JSON)
    family_investigation_ids: Mapped[list] = mapped_column(JSON)
    family_snapshot_sha256: Mapped[str] = mapped_column(String(64))
    source_investigation_ids: Mapped[list] = mapped_column(JSON)
    state: Mapped[str] = mapped_column(String(32), default="reserved")
    input_count: Mapped[int] = mapped_column(Integer, default=0)
    input_first_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    input_last_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    answers_count: Mapped[int] = mapped_column(Integer, default=0)
    answers_first_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    answers_last_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    result_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_by: Mapped[str] = mapped_column(String(36), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class GoldenHoldoutUse(Base):
    __tablename__ = "kn_golden_holdout_use"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    attempt_id: Mapped[str] = mapped_column(ForeignKey("kn_golden_holdout_attempt.id"), index=True)
    action: Mapped[str] = mapped_column(String(24))
    payload: Mapped[dict] = mapped_column(JSON)
    payload_sha256: Mapped[str] = mapped_column(String(64))
    actor_id: Mapped[str] = mapped_column(String(36))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


def _immutable(_mapper, _connection, target):
    if any(a.history.has_changes() for a in inspect(target).attrs):
        raise ValueError("golden_governance_record_immutable")


def _no_delete(_mapper, _connection, _target):
    raise ValueError("golden_governance_record_immutable")


for _model in (GoldenProfileVersion, GoldenValidation, GoldenReleaseVersion, GoldenReleaseDecision,
               GoldenReleasePreview, GoldenReleaseSource, GoldenHoldoutUse):
    event.listen(_model, "before_update", _immutable)
    event.listen(_model, "before_delete", _no_delete)


@event.listens_for(GoldenHoldoutAttempt, "before_update")
def _attempt_identity(_mapper, _connection, target):
    mutable = {"state", "input_count", "input_first_at", "input_last_at", "answers_count",
               "answers_first_at", "answers_last_at", "result", "result_sha256"}
    if any(a.history.has_changes() for a in inspect(target).attrs if a.key not in mutable):
        raise ValueError("golden_holdout_identity_immutable")
