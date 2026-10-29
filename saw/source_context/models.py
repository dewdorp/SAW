"""Stable registry identities and append-only profile and evidence context records."""
from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, UniqueConstraint, event
from sqlalchemy.orm import Mapped, mapped_column

from saw.storage.db import Base, new_id, utcnow


class OrgUnit(Base):
    __tablename__ = "sc_org_unit"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    display_name: Mapped[str] = mapped_column(String(64))
    state: Mapped[str] = mapped_column(String(16), default="active")
    created_by: Mapped[str] = mapped_column(String(36))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class OrgUnitAssignment(Base):
    __tablename__ = "sc_org_assignment"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    investigation_id: Mapped[str] = mapped_column(String(36), index=True)
    legacy_value: Mapped[str] = mapped_column(String(64))
    org_unit_id: Mapped[str | None] = mapped_column(ForeignKey("sc_org_unit.id"), nullable=True)
    state: Mapped[str] = mapped_column(String(16))
    created_by: Mapped[str] = mapped_column(String(36))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Device(Base):
    __tablename__ = "sc_device"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    investigation_id: Mapped[str] = mapped_column(String(36), index=True)
    display_name: Mapped[str] = mapped_column(String(128))
    created_by: Mapped[str] = mapped_column(String(36))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class DeviceProfileVersion(Base):
    __tablename__ = "sc_device_profile"
    __table_args__ = (UniqueConstraint("device_id", "version"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    device_id: Mapped[str] = mapped_column(ForeignKey("sc_device.id"), index=True)
    version: Mapped[int] = mapped_column(Integer)
    payload: Mapped[dict] = mapped_column(JSON)
    sha256: Mapped[str] = mapped_column(String(64))
    created_by: Mapped[str] = mapped_column(String(36))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class EvidenceContextSnapshot(Base):
    __tablename__ = "sc_evidence_context"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    # No FK back to mutable evidence: snapshots are retained if approved deletion removes the source.
    evidence_id: Mapped[str] = mapped_column(String(36), unique=True)
    investigation_id: Mapped[str] = mapped_column(String(36), index=True)
    device_profile_version_id: Mapped[str | None] = mapped_column(ForeignKey("sc_device_profile.id"), nullable=True)
    snapshot: Mapped[dict] = mapped_column(JSON)
    sha256: Mapped[str] = mapped_column(String(64))
    created_by: Mapped[str] = mapped_column(String(36))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


def _immutable(_mapper, _connection, _target):
    raise ValueError("source context versions are immutable")


for _model in (OrgUnitAssignment, DeviceProfileVersion, EvidenceContextSnapshot):
    event.listen(_model, "before_update", _immutable)
    event.listen(_model, "before_delete", _immutable)

# Pin the mutable evidence row to its first immutable context version.
from sqlalchemy import inspect

from saw.storage.models import Evidence


def _pin_context(_mapper, _connection, target):
    changes = inspect(target).attrs.context_snapshot_id.history
    if changes.has_changes() and changes.deleted and changes.deleted[0] is not None:
        raise ValueError("evidence context reference is immutable")


event.listen(Evidence, "before_update", _pin_context)