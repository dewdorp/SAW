"""Portable SQL records. Deletion is an explicit authorized closure, never cascading."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from saw.storage.db import Base, new_id, utcnow


class EventGeneration(Base):
    __tablename__ = "eg_generation"
    __table_args__ = (UniqueConstraint("job_id", "attempt", "purpose", name="uq_eg_job_attempt_purpose"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("inv_investigation.id"), index=True)
    job_id: Mapped[str] = mapped_column(String(36), index=True)
    attempt: Mapped[int] = mapped_column(Integer)
    purpose: Mapped[str] = mapped_column(String(16), default="replacement")
    requester_id: Mapped[str] = mapped_column(String(36))
    parent_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    parent_revision: Mapped[int] = mapped_column(Integer, default=0)
    data_epoch: Mapped[int] = mapped_column(Integer)
    revision: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(16), default="allocated", index=True)
    input_manifest: Mapped[dict] = mapped_column(JSON)
    input_sha256: Mapped[str] = mapped_column(String(64))
    request_sha256: Mapped[str] = mapped_column(String(64), default="")
    storage_targets: Mapped[list] = mapped_column(JSON)
    raw_objects: Mapped[list] = mapped_column(JSON, default=list)
    output_manifest: Mapped[dict] = mapped_column(JSON, default=dict)
    output_sha256: Mapped[str] = mapped_column(String(64), default="")
    file_results: Mapped[list] = mapped_column(JSON, default=list)
    reason: Mapped[str] = mapped_column(String(48), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    ready_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    abandoned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class InvestigationHead(Base):
    __tablename__ = "eg_head"
    investigation_id: Mapped[str] = mapped_column(ForeignKey("inv_investigation.id"), primary_key=True)
    generation_id: Mapped[str] = mapped_column(ForeignKey("eg_generation.id"))
    revision: Mapped[int] = mapped_column(Integer)


class WriterReservation(Base):
    __tablename__ = "eg_writer"
    investigation_id: Mapped[str] = mapped_column(ForeignKey("inv_investigation.id"), primary_key=True)
    generation_id: Mapped[str] = mapped_column(ForeignKey("eg_generation.id"))
    job_id: Mapped[str] = mapped_column(String(36))
    attempt: Mapped[int] = mapped_column(Integer)


class AnalysisRunGeneration(Base):
    __tablename__ = "eg_analysis_run"
    run_id: Mapped[str] = mapped_column(ForeignKey("an_analysis_run.id"), primary_key=True)
    generation_id: Mapped[str] = mapped_column(ForeignKey("eg_generation.id"), index=True)
    input_sha256: Mapped[str] = mapped_column(String(64))
    source_sha256: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


def generation_tables():
    return [
        EventGeneration.__table__,
        InvestigationHead.__table__,
        WriterReservation.__table__,
        AnalysisRunGeneration.__table__,
    ]


# ORM guardrails complement the service's persisted SQL comparisons. Direct SQL used by
# authorized retention/deletion remains explicit; no cascading deletion erases history.
from sqlalchemy import event, inspect

from saw.storage.models import Job


def _generation_immutable(_mapper, _connection, target):
    state = inspect(target)
    immutable = {
        "id",
        "investigation_id",
        "job_id",
        "attempt",
        "purpose",
        "requester_id",
        "parent_id",
        "parent_revision",
        "data_epoch",
        "input_manifest",
        "input_sha256",
        "request_sha256",
        "storage_targets",
        "created_at",
    }
    prior = state.attrs.status.history.deleted
    before = prior[0] if prior else target.status
    if before in {"ready", "published", "retained", "abandoned"}:
        immutable |= {"output_manifest", "output_sha256", "file_results", "raw_objects", "ready_at"}
    if before in {"published", "retained"}:
        immutable |= {"revision", "published_at", "reason", "abandoned_at"}
        if target.status not in {"published", "retained"}:
            raise ValueError("generation published state is immutable")
    if any(state.attrs[name].history.has_changes() for name in immutable):
        raise ValueError("generation metadata is immutable")


def _request_immutable(_mapper, _connection, target):
    changes = inspect(target).attrs.stages.history
    if changes.has_changes() and changes.deleted:
        old = (changes.deleted[0] or {}).get("generation_request")
        if old is not None and old != (target.stages or {}).get("generation_request"):
            raise ValueError("generation request is immutable")


def _association_immutable(_mapper, _connection, _target):
    raise ValueError("generation historical association is immutable")


event.listen(EventGeneration, "before_update", _generation_immutable)
event.listen(Job, "before_update", _request_immutable)
event.listen(AnalysisRunGeneration, "before_update", _association_immutable)
