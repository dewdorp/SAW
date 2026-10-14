"""Separate golden review data; never embedded into public Experience knowledge."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from saw.storage.db import Base, new_id, utcnow


class GoldenFamily(Base):
    __tablename__ = "kn_golden_family"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    split: Mapped[str] = mapped_column(String(16))
    created_by: Mapped[str] = mapped_column(String(36))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class GoldenFamilyMember(Base):
    __tablename__ = "kn_golden_family_member"
    investigation_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    family_id: Mapped[str] = mapped_column(ForeignKey("kn_golden_family.id"), index=True)


class GoldenBlob(Base):
    __tablename__ = "kn_golden_blob"
    sha256: Mapped[str] = mapped_column(String(64), primary_key=True)
    content: Mapped[dict] = mapped_column(JSON)
    size_bytes: Mapped[int] = mapped_column(Integer)
    masking_version: Mapped[str] = mapped_column(String(32), default="golden-mask-v1")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class GoldenVersion(Base):
    __tablename__ = "kn_golden_version"
    __table_args__ = (UniqueConstraint("experience_id", "version"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    experience_id: Mapped[str] = mapped_column(ForeignKey("kn_experience.id"), index=True)
    experience_rev: Mapped[int] = mapped_column(Integer)
    version: Mapped[int] = mapped_column(Integer)
    source_investigation_id: Mapped[str] = mapped_column(String(36), index=True)
    family_id: Mapped[str | None] = mapped_column(ForeignKey("kn_golden_family.id"), nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="draft")
    methodology_version: Mapped[str] = mapped_column(String(64))
    as_of: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    input: Mapped[dict] = mapped_column(JSON)
    answers: Mapped[dict] = mapped_column(JSON)
    manifest: Mapped[list] = mapped_column(JSON)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict)
    content_sha256: Mapped[str] = mapped_column(String(64))
    author_id: Mapped[str] = mapped_column(String(36))
    contributor_ids: Mapped[list] = mapped_column(JSON, default=list)
    reviewer_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    reviewer_name: Mapped[str | None] = mapped_column(String(64), nullable=True)
    confirmations: Mapped[dict] = mapped_column(JSON, default=dict)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
