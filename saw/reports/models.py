"""A report freezes observations and analyst revisions at explicit creation time."""
from __future__ import annotations
from datetime import datetime
from sqlalchemy import event, JSON, DateTime, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column
from saw.storage.db import Base, new_id, utcnow


class ReportVersion(Base):
    __tablename__ = "an_report_version"
    __table_args__ = (UniqueConstraint("investigation_id", "version"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("inv_investigation.id"), index=True)
    version: Mapped[int] = mapped_column(Integer)
    created_by: Mapped[str] = mapped_column(String(36))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    source_investigation_ids: Mapped[list] = mapped_column(JSON)
    content: Mapped[dict] = mapped_column(JSON)
    content_sha256: Mapped[str] = mapped_column(String(64))


class ReportSourceInvestigation(Base):
    """Queryable source ledger for deletion fencing; frozen JSON remains authoritative."""
    __tablename__ = "an_report_source_investigation"
    report_id: Mapped[str] = mapped_column(
        ForeignKey("an_report_version.id", ondelete="CASCADE"), primary_key=True)
    investigation_id: Mapped[str] = mapped_column(String(36), primary_key=True, index=True)


class JobSourceInvestigation(Base):
    __tablename__ = "an_job_source_investigation"
    job_id: Mapped[str] = mapped_column(
        ForeignKey("an_job.id", ondelete="CASCADE"), primary_key=True)
    investigation_id: Mapped[str] = mapped_column(String(36), primary_key=True, index=True)


@event.listens_for(ReportVersion, "before_update")
def _immutable_report(_mapper, _connection, _target):
    raise ValueError("report_version_is_immutable")
