"""Analyst knowledge about business meaning and flows, the runs that applied it, and per-incident judgements.

Three things are kept apart on purpose:
- reusable knowledge (what a request means, how a result is confirmed, how requests link, what a flow is),
- an analysis run (which knowledge versions were applied to which records, and what came out),
- an analyst's judgement of one incident (never widened into "this address is always normal").
Knowledge rows are current state plus append-only versions; runs are append-only.
"""
from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from saw.storage.db import Base, new_id, utcnow


class FlowKnowledge(Base):
    __tablename__ = "fk_knowledge"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    kind: Mapped[str] = mapped_column(String(16), index=True)  # activity | link | flow
    # None = common to every affiliate; otherwise the knowledge applies to that affiliate's investigations only.
    org_unit_id: Mapped[str | None] = mapped_column(String(36), index=True, nullable=True)
    host: Mapped[str] = mapped_column(String(255), index=True, default="")  # the service, lower-cased
    # What the knowledge is about (not what it says): two active rows with one scope key are conflicting definitions.
    scope_key: Mapped[str] = mapped_column(String(700), index=True)
    title: Mapped[str] = mapped_column(String(256), default="")
    status: Mapped[str] = mapped_column(String(16), default="active")  # active | stopped
    current_version: Mapped[int] = mapped_column(Integer, default=0)
    content: Mapped[dict] = mapped_column(JSON, default=dict)
    created_by: Mapped[str] = mapped_column(String(36))
    updated_by: Mapped[str] = mapped_column(String(36))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class FlowKnowledgeVersion(Base):
    __tablename__ = "fk_knowledge_version"
    __table_args__ = (UniqueConstraint("knowledge_id", "version"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    knowledge_id: Mapped[str] = mapped_column(ForeignKey("fk_knowledge.id"), index=True)
    version: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(16), default="active")
    content: Mapped[dict] = mapped_column(JSON)
    change_note: Mapped[str] = mapped_column(Text, default="")
    # Where the analyst was when this was written: the investigation and the records looked at.
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    changed_by: Mapped[str] = mapped_column(String(36))
    changed_by_name: Mapped[str] = mapped_column(String(128), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class FlowRun(Base):
    """One application of the knowledge to one investigation's records. Never rewritten."""
    __tablename__ = "fk_run"
    __table_args__ = (UniqueConstraint("investigation_id", "version"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("inv_investigation.id"), index=True)
    version: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(24), default="running")  # running|complete|partial|no_data|failed
    reason: Mapped[str] = mapped_column(String(32), default="manual")  # ingest | knowledge_changed | manual
    # Same records + same knowledge + same scope = the same run: a repeated request reuses it.
    input_sha256: Mapped[str] = mapped_column(String(64), index=True)
    knowledge: Mapped[dict] = mapped_column(JSON, default=dict)  # {knowledge_id: version} that was applied
    scope: Mapped[dict] = mapped_column(JSON, default=dict)
    summary: Mapped[dict] = mapped_column(JSON, default=dict)
    result: Mapped[dict] = mapped_column(JSON, default=dict)
    changes: Mapped[dict] = mapped_column(JSON, default=dict)  # difference from the run before, and why
    created_by: Mapped[str] = mapped_column(String(36), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    elapsed_ms: Mapped[int] = mapped_column(Integer, default=0)


class FlowJudgement(Base):
    """An analyst's judgement of one observed flow in one investigation, with the records it rests on."""
    __tablename__ = "fk_judgement"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("inv_investigation.id"), index=True)
    run_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    flow_key: Mapped[str] = mapped_column(String(128), default="", index=True)
    verdict: Mapped[str] = mapped_column(String(24))  # normal | suspicious | undetermined
    note: Mapped[str] = mapped_column(Text, default="")
    event_ids: Mapped[list] = mapped_column(JSON, default=list)
    knowledge: Mapped[dict] = mapped_column(JSON, default=dict)  # versions in force when the judgement was made
    created_by: Mapped[str] = mapped_column(String(36))
    created_by_name: Mapped[str] = mapped_column(String(128), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
