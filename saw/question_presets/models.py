"""Saved question conditions: a current row plus append-only versions, so every edit stays visible.

A preset is a saved search condition for one investigation question. It is not an active detection policy:
saving one never changes what automatic analysis runs or raises.
"""
from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from saw.storage.db import Base, new_id, utcnow


class QuestionPreset(Base):
    __tablename__ = "kn_question_preset"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    bundle: Mapped[str] = mapped_column(String(32), index=True)
    # investigation: this investigation only · affiliate: investigations of one affiliate · common: everyone
    scope_kind: Mapped[str] = mapped_column(String(16), index=True)
    scope_id: Mapped[str | None] = mapped_column(String(36), index=True, nullable=True)
    name: Mapped[str] = mapped_column(String(128))
    current_version: Mapped[int] = mapped_column(Integer, default=0)
    created_by: Mapped[str] = mapped_column(String(36))
    updated_by: Mapped[str] = mapped_column(String(36))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class QuestionPresetVersion(Base):
    __tablename__ = "kn_question_preset_version"
    __table_args__ = (UniqueConstraint("preset_id", "version"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    preset_id: Mapped[str] = mapped_column(ForeignKey("kn_question_preset.id"), index=True)
    version: Mapped[int] = mapped_column(Integer)
    name: Mapped[str] = mapped_column(String(128))
    description: Mapped[str] = mapped_column(Text, default="")
    parameters: Mapped[dict] = mapped_column(JSON)
    definition_version: Mapped[str] = mapped_column(String(64))
    change_note: Mapped[str] = mapped_column(Text, default="")
    changed_by: Mapped[str] = mapped_column(String(36))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
