"""Append-only interpretation snapshots; mutable Findings remain the analyst work list."""
from __future__ import annotations
from datetime import datetime
from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column
from saw.storage.db import Base, new_id, utcnow


class AnalysisRun(Base):
    __tablename__ = "an_analysis_run"
    __table_args__ = (UniqueConstraint("investigation_id", "version"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("inv_investigation.id"), index=True)
    version: Mapped[int] = mapped_column(Integer)
    job_id: Mapped[str | None] = mapped_column(String(36), index=True)
    created_by: Mapped[str] = mapped_column(String(36), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(24), default="running")
    input_manifest: Mapped[dict] = mapped_column(JSON)
    input_sha256: Mapped[str] = mapped_column(String(64))
    scope: Mapped[dict] = mapped_column(JSON, default=dict)
    engine_version: Mapped[str] = mapped_column(String(32), default="saw.analysis/3")
    summary: Mapped[dict] = mapped_column(JSON, default=dict)


class DetectorExecution(Base):
    __tablename__ = "an_detector_execution"
    __table_args__ = (UniqueConstraint("run_id", "detector_id"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    run_id: Mapped[str] = mapped_column(ForeignKey("an_analysis_run.id"), index=True)
    detector_id: Mapped[str] = mapped_column(String(128))
    detector_version: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(24))
    input_count: Mapped[int | None] = mapped_column(Integer)
    match_count: Mapped[int | None] = mapped_column(Integer)
    elapsed_ms: Mapped[int] = mapped_column(Integer, default=0)
    effective_config: Mapped[dict] = mapped_column(JSON, default=dict)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)


class FindingSnapshot(Base):
    __tablename__ = "an_finding_snapshot"
    __table_args__ = (UniqueConstraint("run_id", "finding_id"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    run_id: Mapped[str] = mapped_column(ForeignKey("an_analysis_run.id"), index=True)
    # Deliberately not a foreign key: retiring current findings cannot delete historical evidence.
    finding_id: Mapped[str] = mapped_column(String(36), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    payload: Mapped[dict] = mapped_column(JSON)
    payload_sha256: Mapped[str] = mapped_column(String(64))
