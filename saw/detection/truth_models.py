"""Immutable selected truth versions; source content remains investigation-scoped."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, UniqueConstraint, event, inspect
from sqlalchemy.orm import Mapped, mapped_column

from saw.storage.db import Base, new_id, utcnow


class DetectionCase(Base):
    __tablename__ = "det_case"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("inv_investigation.id"), index=True)
    current_version: Mapped[int] = mapped_column(Integer, default=0)
    created_by: Mapped[str] = mapped_column(String(36))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class DetectionCaseVersion(Base):
    __tablename__ = "det_case_version"
    __table_args__ = (UniqueConstraint("case_id", "version"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    case_id: Mapped[str] = mapped_column(ForeignKey("det_case.id"), index=True)
    version: Mapped[int] = mapped_column(Integer)
    investigation_id: Mapped[str] = mapped_column(String(36), index=True)
    payload: Mapped[dict] = mapped_column(JSON)
    sha256: Mapped[str] = mapped_column(String(64))
    source_manifest: Mapped[dict] = mapped_column(JSON)
    input_sha256: Mapped[str] = mapped_column(String(64))
    input_count: Mapped[int] = mapped_column(Integer)
    contributor_ids: Mapped[list] = mapped_column(JSON, default=list)
    created_by: Mapped[str] = mapped_column(String(36))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


@event.listens_for(DetectionCaseVersion, "before_update")
def _immutable(_mapper, _connection, target):
    if any(a.history.has_changes() for a in inspect(target).attrs):
        raise ValueError("detection_case_version_immutable")
