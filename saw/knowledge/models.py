"""Knowledge tables (docs/07 knowledge, docs/25, docs/27)."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from saw.storage.db import Base, new_id, utcnow


class Experience(Base):
    __tablename__ = "kn_experience"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    display_id: Mapped[str] = mapped_column(String(32), unique=True)
    status: Mapped[str] = mapped_column(String(16), default="draft")  # status of the working copy
    data: Mapped[dict] = mapped_column(JSON, default=dict)  # working copy (draft/review)
    approved_data: Mapped[dict | None] = mapped_column(JSON, nullable=True)  # production knowledge (immutable copy)
    analyst_id: Mapped[str] = mapped_column(String(36))
    analyst_name: Mapped[str] = mapped_column(String(64), default="")
    reviewer_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    reviewer_name: Mapped[str | None] = mapped_column(String(64), nullable=True)
    review_comment: Mapped[str] = mapped_column(Text, default="")
    rev: Mapped[int] = mapped_column(Integer, default=1)
    approved_rev: Mapped[int | None] = mapped_column(Integer, nullable=True)
    source_investigation_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    deprecated: Mapped[bool] = mapped_column(Boolean, default=False)
    views: Mapped[int] = mapped_column(Integer, default=0)
    helpful: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class KnowledgeRevision(Base):
    """Append-only snapshots for every knowledge object change (experience/asset/fp_rule/playbook)."""

    __tablename__ = "kn_revision"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    kind: Mapped[str] = mapped_column(String(16), index=True)
    ref_id: Mapped[str] = mapped_column(String(36), index=True)
    rev: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(16))
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    actor: Mapped[str] = mapped_column(String(64))
    note: Mapped[str] = mapped_column(Text, default="")
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Asset(Base):
    __tablename__ = "kn_asset"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    asset_id: Mapped[str] = mapped_column(String(64), unique=True)
    service: Mapped[str] = mapped_column(String(256))
    data: Mapped[dict] = mapped_column(JSON, default=dict)  # all other docs/27 fields
    criticality: Mapped[str] = mapped_column(String(16), default="medium")
    source: Mapped[str] = mapped_column(String(16), default="manual")
    rev: Mapped[int] = mapped_column(Integer, default=1)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class FalsePositiveRule(Base):
    __tablename__ = "kn_fp_rule"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    display_id: Mapped[str] = mapped_column(String(32), unique=True)
    title: Mapped[str] = mapped_column(String(256))
    detector_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    conditions: Mapped[list] = mapped_column(JSON, default=list)  # SAW Query Model filters
    reason: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(16), default="draft")
    conflicts: Mapped[dict] = mapped_column(JSON, default=dict)
    created_by: Mapped[str] = mapped_column(String(36))
    approved_by: Mapped[str | None] = mapped_column(String(36), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rev: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Playbook(Base):
    __tablename__ = "kn_playbook"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    title: Mapped[str] = mapped_column(String(256))
    applies_to: Mapped[list] = mapped_column(JSON, default=list)  # finding categories
    steps: Mapped[list] = mapped_column(JSON, default=list)  # [{check, why, how}]
    status: Mapped[str] = mapped_column(String(16), default="approved")
    rev: Mapped[int] = mapped_column(Integer, default=1)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SimilarFeedback(Base):
    __tablename__ = "kn_similar_feedback"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    query_ref: Mapped[str] = mapped_column(String(64))
    result_ref: Mapped[str] = mapped_column(String(64))
    useful: Mapped[bool] = mapped_column(Boolean)
    user_id: Mapped[str] = mapped_column(String(36))
    score: Mapped[float] = mapped_column(Float, default=0)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
