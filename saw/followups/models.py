"""Append-only follow-up and Check snapshots; cancellation never erases history."""
from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, UniqueConstraint, event
from sqlalchemy.orm import Mapped, mapped_column

from saw.storage.db import Base, new_id, utcnow


class CheckRevision(Base):
    __tablename__ = "inv_check_revision"
    __table_args__ = (UniqueConstraint("check_id", "revision"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    check_id: Mapped[str] = mapped_column(ForeignKey("inv_check.id"), index=True)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("inv_investigation.id"), index=True)
    revision: Mapped[int] = mapped_column(Integer)
    payload: Mapped[dict] = mapped_column(JSON)
    payload_sha256: Mapped[str] = mapped_column(String(64))
    source_investigation_ids: Mapped[list] = mapped_column(JSON)
    created_by: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    capture_reason: Mapped[str] = mapped_column(String(64))
    origin: Mapped[str] = mapped_column(String(32))


class FollowUp(Base):
    __tablename__ = "inv_followup"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("inv_investigation.id"), index=True)
    current_version_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    current_revision: Mapped[int] = mapped_column(Integer, default=0)
    created_by: Mapped[str] = mapped_column(String(36))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class FollowUpVersion(Base):
    __tablename__ = "inv_followup_version"
    __table_args__ = (UniqueConstraint("followup_id", "revision"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    followup_id: Mapped[str] = mapped_column(ForeignKey("inv_followup.id"), index=True)
    revision: Mapped[int] = mapped_column(Integer)
    payload: Mapped[dict] = mapped_column(JSON)
    payload_sha256: Mapped[str] = mapped_column(String(64))
    source_investigation_ids: Mapped[list] = mapped_column(JSON)
    created_by: Mapped[str] = mapped_column(String(36))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    action: Mapped[str] = mapped_column(String(32))


def _immutable(_mapper, _connection, _target):
    raise ValueError("followup_revision_immutable")


for _model in (CheckRevision, FollowUpVersion):
    event.listen(_model, "before_update", _immutable)
    event.listen(_model, "before_delete", _immutable)
