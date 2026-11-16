"""Internal knowledge kept by analysts: golden investigation records and device alert-name meanings.

Both are current rows plus append-only versions, so every change stays visible. Neither needs an approver.
"""
from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from saw.storage.db import Base, new_id, utcnow


class InternalGolden(Base):
    """One investigation's analysis as an internal golden record (scope, facts, questions, replies, judgement)."""
    __tablename__ = "kn_internal_golden"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    investigation_id: Mapped[str] = mapped_column(String(36), index=True, unique=True)
    org_unit_id: Mapped[str | None] = mapped_column(String(36), index=True, nullable=True)
    title: Mapped[str] = mapped_column(String(256))
    final_status: Mapped[str] = mapped_column(String(32), default="")
    current_version: Mapped[int] = mapped_column(Integer, default=0)
    created_by: Mapped[str] = mapped_column(String(36))
    updated_by: Mapped[str] = mapped_column(String(36))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class InternalGoldenVersion(Base):
    __tablename__ = "kn_internal_golden_version"
    __table_args__ = (UniqueConstraint("record_id", "version"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    record_id: Mapped[str] = mapped_column(ForeignKey("kn_internal_golden.id"), index=True)
    version: Mapped[int] = mapped_column(Integer)
    content: Mapped[dict] = mapped_column(JSON)
    change_note: Mapped[str] = mapped_column(Text, default="")
    changed_by: Mapped[str] = mapped_column(String(36))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class DeviceSignature(Base):
    """What a device's own alert name / signature ID means, as confirmed by an analyst.

    The original name is matched exactly; a similar name is never treated as the same signature.
    """
    __tablename__ = "kn_device_signature"
    __table_args__ = (UniqueConstraint("match_key"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    match_key: Mapped[str] = mapped_column(String(700))
    vendor: Mapped[str] = mapped_column(String(128), default="")
    product: Mapped[str] = mapped_column(String(128), default="")
    original_name: Mapped[str] = mapped_column(String(512))
    signature_id: Mapped[str] = mapped_column(String(128), default="")
    status: Mapped[str] = mapped_column(String(32), default="confirmed")
    current_version: Mapped[int] = mapped_column(Integer, default=0)
    content: Mapped[dict] = mapped_column(JSON, default=dict)
    created_by: Mapped[str] = mapped_column(String(36))
    updated_by: Mapped[str] = mapped_column(String(36))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class DeviceSignatureVersion(Base):
    __tablename__ = "kn_device_signature_version"
    __table_args__ = (UniqueConstraint("signature_id_ref", "version"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    signature_id_ref: Mapped[str] = mapped_column(ForeignKey("kn_device_signature.id"), index=True)
    version: Mapped[int] = mapped_column(Integer)
    content: Mapped[dict] = mapped_column(JSON)
    changed_by: Mapped[str] = mapped_column(String(36))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class GoldenCandidate(Base):
    """A case an analyst set aside for the golden set: a pointer to a reproducible source, never a copy of its logs.

    The source is a synthetic casebook case (its case file's SHA-256) or an investigation (its evidence files'
    SHA-256). The same source at the same version is one candidate however often it is added. Removing a
    candidate deletes only this pointer; the source and any golden versions saved from it stay.
    """
    __tablename__ = "kn_golden_candidate"
    __table_args__ = (UniqueConstraint("source_key"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    source_key: Mapped[str] = mapped_column(String(160))
    source_kind: Mapped[str] = mapped_column(String(16), index=True)  # casebook | investigation
    source_id: Mapped[str] = mapped_column(String(64), index=True)
    source_version: Mapped[str] = mapped_column(String(64))
    source_refs: Mapped[dict] = mapped_column(JSON, default=dict)
    title: Mapped[str] = mapped_column(String(256))
    org_unit_id: Mapped[str | None] = mapped_column(String(36), index=True, nullable=True)
    org_label: Mapped[str] = mapped_column(String(256), default="")
    note: Mapped[str] = mapped_column(Text, default="")
    split: Mapped[str] = mapped_column(String(16), default="unassigned")
    golden_record_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    golden_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_by: Mapped[str] = mapped_column(String(36))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
