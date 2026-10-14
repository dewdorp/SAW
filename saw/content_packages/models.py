"""Package records are separate from live definitions until explicit review and apply."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from saw.storage.db import Base, new_id, utcnow


class ContentPackage(Base):
    __tablename__ = "cp_package"
    __table_args__ = (UniqueConstraint("package_id", "revision", name="uq_cp_package_revision"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    package_id: Mapped[str] = mapped_column(String(64))
    revision: Mapped[int] = mapped_column(Integer)
    digest: Mapped[str] = mapped_column(String(64))
    document: Mapped[dict] = mapped_column(JSON)
    imported_by: Mapped[str] = mapped_column(String(36))
    imported_by_name: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    status: Mapped[str] = mapped_column(String(16), default="staged")
    baseline: Mapped[list] = mapped_column(JSON, default=list)
    test_result: Mapped[dict] = mapped_column(JSON, default=dict)
    receipt: Mapped[dict] = mapped_column(JSON, default=dict)


class ContentBinding(Base):
    __tablename__ = "cp_binding"
    kind: Mapped[str] = mapped_column(String(16), primary_key=True)
    source_id: Mapped[str] = mapped_column(String(47), primary_key=True)
    target_id: Mapped[str] = mapped_column(String(64))
    source_version: Mapped[int] = mapped_column(Integer)
    max_source_version: Mapped[int] = mapped_column(Integer)
    payload_digest: Mapped[str] = mapped_column(String(64))


class ContentValidation(Base):
    __tablename__ = "cp_validation"
    __table_args__ = (UniqueConstraint("detection_id", "version", name="uq_cp_validation_version"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    detection_id: Mapped[str] = mapped_column(String(36), index=True)
    version: Mapped[int] = mapped_column(Integer)
    package_record_id: Mapped[str] = mapped_column(String(36))
    source_id: Mapped[str] = mapped_column(String(47))
    payload_digest: Mapped[str] = mapped_column(String(64))
    kind: Mapped[str] = mapped_column(String(32), default="package_fixture")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
