"""A hunt run (what was examined, by which methods, under which versions) and the analyst's review of its activities.

A hunt is an investigation seen from the analyst's side: pick a scope, let the platform find what deserves a look,
check the evidence, leave a judgement. Three things are kept apart and never stand in for each other:
- progress of the run (queued / running / stopped / complete),
- the result of each computation (found / no match / insufficient data / partial / failed / unsupported),
- the analyst's review of an activity (unreviewed / needs a check / normal work / threat confirmed).
"""
from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from saw.storage.db import Base, new_id, utcnow


class HuntRun(Base):
    """One pass of the built-in analysis over an investigation's whole selected data. Append-only."""
    __tablename__ = "hunt_run"
    __table_args__ = (UniqueConstraint("investigation_id", "version"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("inv_investigation.id"), index=True)
    version: Mapped[int] = mapped_column(Integer)
    mode: Mapped[str] = mapped_column(String(24), default="basic")  # basic = built-in analysis, no AI model involved
    status: Mapped[str] = mapped_column(String(24), default="complete")  # complete | partial | failed
    reason: Mapped[str] = mapped_column(String(32), default="manual")
    scope: Mapped[dict] = mapped_column(JSON, default=dict)  # affiliate, period, filters, data generation, counts
    versions: Mapped[dict] = mapped_column(JSON, default=dict)  # engine, knowledge, scenarios, assets in force
    methods: Mapped[list] = mapped_column(JSON, default=list)  # per method: status, what was examined, limits hit
    activities: Mapped[list] = mapped_column(JSON, default=list)
    summary: Mapped[dict] = mapped_column(JSON, default=dict)
    created_by: Mapped[str] = mapped_column(String(36), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    elapsed_ms: Mapped[int] = mapped_column(Integer, default=0)


class HuntReview(Base):
    """An analyst's review of one activity. Every change is a new row; the latest row is the current state."""
    __tablename__ = "hunt_review"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("inv_investigation.id"), index=True)
    activity_id: Mapped[str] = mapped_column(String(64), index=True)
    state: Mapped[str] = mapped_column(String(24))  # needs_check | normal_work | threat_confirmed | unreviewed
    note: Mapped[str] = mapped_column(Text, default="")
    activity: Mapped[dict] = mapped_column(JSON, default=dict)  # title, method and evidence reference when reviewed
    run_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    versions: Mapped[dict] = mapped_column(JSON, default=dict)
    created_by: Mapped[str] = mapped_column(String(36))
    created_by_name: Mapped[str] = mapped_column(String(128), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
