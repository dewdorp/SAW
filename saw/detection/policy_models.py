"""Immutable detection policy versions, approvals and activation history."""
from datetime import datetime
from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, UniqueConstraint, event
from sqlalchemy.orm import Mapped, mapped_column
from saw.storage.db import Base, new_id, utcnow


class PolicyBinding(Base):
    __tablename__ = "det_policy_binding"
    __table_args__ = (UniqueConstraint("detector_id", "scope_key"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    detector_id: Mapped[str] = mapped_column(String(128))
    scope_key: Mapped[str] = mapped_column(String(128))
    scope: Mapped[dict] = mapped_column(JSON)
    draft_version_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    approved_version_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    active_version_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    approved_approval_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    active_approval_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    activation_revision: Mapped[int] = mapped_column(Integer, default=0)
    created_by: Mapped[str] = mapped_column(String(36))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class PolicyVersion(Base):
    __tablename__ = "det_policy_version"
    __table_args__ = (UniqueConstraint("binding_id", "version"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    binding_id: Mapped[str] = mapped_column(ForeignKey("det_policy_binding.id"), index=True)
    version: Mapped[int] = mapped_column(Integer)
    parent_version_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    spec_id: Mapped[str] = mapped_column(String(128))
    spec_version: Mapped[str] = mapped_column(String(64))
    spec_sha256: Mapped[str] = mapped_column(String(64))
    payload: Mapped[dict] = mapped_column(JSON)
    payload_sha256: Mapped[str] = mapped_column(String(64))
    contributor_ids: Mapped[list] = mapped_column(JSON, default=list)
    legacy_contributor_names: Mapped[list] = mapped_column(JSON, default=list)
    contributor_resolution: Mapped[str] = mapped_column(String(32), default="resolved")
    created_by: Mapped[str] = mapped_column(String(36))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Approval(Base):
    __tablename__ = "det_approval"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    subject_kind: Mapped[str] = mapped_column(String(16), index=True)
    subject_id: Mapped[str] = mapped_column(String(36), index=True)
    subject_version_id: Mapped[str] = mapped_column(String(36), index=True)
    payload_sha256: Mapped[str] = mapped_column(String(64))
    reviewer_id: Mapped[str] = mapped_column(String(36))
    reviewer_name: Mapped[str] = mapped_column(String(64))
    reviewed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    proof: Mapped[dict] = mapped_column(JSON)
    proof_sha256: Mapped[str] = mapped_column(String(64))
    contributor_ids: Mapped[list] = mapped_column(JSON, default=list)
    source_investigation_ids: Mapped[list] = mapped_column(JSON, default=list)
    provenance: Mapped[str] = mapped_column(String(32), default="reviewed")


class Activation(Base):
    __tablename__ = "det_activation"
    __table_args__ = (UniqueConstraint("subject_kind", "subject_id", "revision"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    subject_kind: Mapped[str] = mapped_column(String(16), index=True)
    subject_id: Mapped[str] = mapped_column(String(36), index=True)
    revision: Mapped[int] = mapped_column(Integer)
    from_version_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    to_version_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    approval_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    action: Mapped[str] = mapped_column(String(32))
    actor_id: Mapped[str] = mapped_column(String(36))
    actor_name: Mapped[str] = mapped_column(String(64))
    reason: Mapped[str] = mapped_column(String(2000))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    snapshot: Mapped[dict] = mapped_column(JSON, default=dict)


def _immutable(_mapper, _connection, _target):
    raise ValueError("detection governance records are immutable")


for _model in (PolicyVersion, Approval, Activation):
    event.listen(_model, "before_update", _immutable)
    event.listen(_model, "before_delete", _immutable)
