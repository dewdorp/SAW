"""Relational model (docs/07). Portable types so the same model runs on SQLite (dev) and PostgreSQL."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from saw.storage.db import Base, new_id, utcnow


def _id() -> Mapped[str]:
    return mapped_column(String(36), primary_key=True, default=new_id)


def _ts() -> Mapped[datetime]:
    return mapped_column(DateTime(timezone=True), default=utcnow)


# ---------------------------------------------------------------- iam
class User(Base):
    __tablename__ = "iam_user"
    id: Mapped[str] = _id()
    username: Mapped[str] = mapped_column(String(64), unique=True)
    display_name: Mapped[str] = mapped_column(String(128), default="")
    password_hash: Mapped[str] = mapped_column(String(256))
    roles: Mapped[list] = mapped_column(JSON, default=list)
    mfa_secret: Mapped[str | None] = mapped_column(String(64), nullable=True)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(16), default="active")
    failed_count: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    mfa_failed_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    mfa_last_step: Mapped[int | None] = mapped_column(BigInteger, nullable=True)  # last accepted TOTP time step
    created_at: Mapped[datetime] = _ts()


class UserSession(Base):
    __tablename__ = "iam_session"
    id: Mapped[str] = _id()
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("iam_user.id"))
    csrf_token: Mapped[str] = mapped_column(String(64))
    mfa_passed: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = _ts()
    last_seen_at: Mapped[datetime] = _ts()
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    ip: Mapped[str] = mapped_column(String(64), default="")
    user_agent: Mapped[str] = mapped_column(String(256), default="")
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


# ---------------------------------------------------------------- audit (hash chain)
class AuditEvent(Base):
    __tablename__ = "audit_event"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    at: Mapped[datetime] = _ts()
    actor_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    actor_name: Mapped[str] = mapped_column(String(64), default="")
    actor_ip: Mapped[str] = mapped_column(String(64), default="")
    action: Mapped[str] = mapped_column(String(64), index=True)
    target_type: Mapped[str] = mapped_column(String(32), default="")
    target_id: Mapped[str] = mapped_column(String(64), default="")
    investigation_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    outcome: Mapped[str] = mapped_column(String(16), default="success")
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64), default="")
    hash: Mapped[str] = mapped_column(String(64), default="")


class AuditHead(Base):
    """Where the audit chain ends (one row). Without it, removing the newest entries leaves a valid shorter chain."""
    __tablename__ = "audit_head"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    last_id: Mapped[int] = mapped_column(Integer, default=0)
    last_hash: Mapped[str] = mapped_column(String(64), default="")
    entries: Mapped[int] = mapped_column(Integer, default=0)


# ---------------------------------------------------------------- investigation
class Investigation(Base):
    __tablename__ = "inv_investigation"
    id: Mapped[str] = _id()
    display_id: Mapped[str] = mapped_column(String(32), unique=True)
    title: Mapped[str] = mapped_column(String(256))
    status: Mapped[str] = mapped_column(String(24), default="open")
    risk_level: Mapped[str] = mapped_column(String(16), default="info")
    risk_score: Mapped[float] = mapped_column(Float, default=0)
    risk_override: Mapped[str | None] = mapped_column(String(16), nullable=True)
    time_start: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    time_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    owner_id: Mapped[str] = mapped_column(ForeignKey("iam_user.id"))
    verdict: Mapped[str | None] = mapped_column(String(24), nullable=True)
    verdict_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    close_detail: Mapped[dict] = mapped_column(JSON, default=dict)
    org_unit: Mapped[str] = mapped_column(String(64), default="")
    settings: Mapped[dict] = mapped_column(JSON, default=dict)  # clock skew etc.
    created_at: Mapped[datetime] = _ts()
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class InvestigationMember(Base):
    __tablename__ = "inv_member"
    investigation_id: Mapped[str] = mapped_column(ForeignKey("inv_investigation.id"), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("iam_user.id"), primary_key=True)
    access: Mapped[str] = mapped_column(String(16), default="editor")


class Evidence(Base):
    __tablename__ = "ev_evidence"
    id: Mapped[str] = _id()
    investigation_id: Mapped[str] = mapped_column(ForeignKey("inv_investigation.id"), index=True)
    kind: Mapped[str] = mapped_column(String(24))
    title: Mapped[str] = mapped_column(String(256), default="")
    classification: Mapped[str] = mapped_column(String(32), default="internal")
    legal_hold: Mapped[bool] = mapped_column(Boolean, default=False)
    tz_assumed: Mapped[str] = mapped_column(String(48), default="Asia/Seoul")
    status: Mapped[str] = mapped_column(String(24), default="pending")
    total_size: Mapped[int] = mapped_column(BigInteger, default=0)  # > 2 GB evidence (PostgreSQL int4)
    file_count: Mapped[int] = mapped_column(Integer, default=0)
    uploaded_by: Mapped[str] = mapped_column(ForeignKey("iam_user.id"))
    uploaded_at: Mapped[datetime] = _ts()


class EvidenceFile(Base):
    __tablename__ = "ev_file"
    id: Mapped[str] = _id()
    evidence_id: Mapped[str] = mapped_column(ForeignKey("ev_evidence.id"), index=True)
    parent_file_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    display_name: Mapped[str] = mapped_column(String(512))
    object_key: Mapped[str] = mapped_column(String(512))
    sha256: Mapped[str] = mapped_column(String(64), default="")
    size: Mapped[int] = mapped_column(BigInteger, default=0)
    type_detected: Mapped[str] = mapped_column(String(32), default="")
    parser_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    parser_version: Mapped[str | None] = mapped_column(String(16), nullable=True)
    parser_confidence: Mapped[float] = mapped_column(Float, default=0)
    parse_status: Mapped[str] = mapped_column(String(24), default="pending")
    events_parsed: Mapped[int] = mapped_column(Integer, default=0)
    events_failed: Mapped[int] = mapped_column(Integer, default=0)
    error_samples: Mapped[list] = mapped_column(JSON, default=list)
    message: Mapped[str] = mapped_column(Text, default="")
    first_ts: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_ts: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class UploadSession(Base):
    __tablename__ = "ev_upload_session"
    id: Mapped[str] = _id()
    user_id: Mapped[str] = mapped_column(ForeignKey("iam_user.id"))
    evidence_id: Mapped[str] = mapped_column(ForeignKey("ev_evidence.id"))
    filename: Mapped[str] = mapped_column(String(512))
    declared_size: Mapped[int] = mapped_column(BigInteger)
    declared_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    received_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    parts: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(16), default="open")
    created_at: Mapped[datetime] = _ts()


class CustodyLog(Base):
    __tablename__ = "ev_custody_log"
    id: Mapped[str] = _id()
    evidence_id: Mapped[str] = mapped_column(String(36), index=True)
    file_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    action: Mapped[str] = mapped_column(String(24))
    actor: Mapped[str] = mapped_column(String(64))
    at: Mapped[datetime] = _ts()
    detail: Mapped[dict] = mapped_column(JSON, default=dict)


class Job(Base):
    __tablename__ = "an_job"
    __table_args__ = (UniqueConstraint("requested_by", "idempotency_key", name="uq_an_job_idempotency"),)
    id: Mapped[str] = _id()
    investigation_id: Mapped[str] = mapped_column(String(36), index=True)
    evidence_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    kind: Mapped[str] = mapped_column(String(24))
    state: Mapped[str] = mapped_column(String(24), default="QUEUED")
    stages: Mapped[dict] = mapped_column(JSON, default=dict)
    events_total_est: Mapped[int] = mapped_column(Integer, default=0)
    events_done: Mapped[int] = mapped_column(Integer, default=0)
    current_item: Mapped[str] = mapped_column(String(512), default="")
    error: Mapped[dict] = mapped_column(JSON, default=dict)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    requested_by: Mapped[str] = mapped_column(String(36))
    # client-supplied key: retries/double clicks return the same job instead of starting another
    idempotency_key: Mapped[str | None] = mapped_column(String(128), nullable=True)
    # lease epoch: bumped whenever a worker claims the job; a worker whose epoch is stale stops writing
    attempt: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    created_at: Mapped[datetime] = _ts()
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ProcessingRun(Base):
    """Provenance of one parse of one evidence file: who ran it, the input fingerprint, the parser and settings
    fingerprints and the result fingerprint. Content-free (no log data), so it can be shown to auditors."""
    __tablename__ = "ev_processing_run"
    id: Mapped[str] = _id()
    investigation_id: Mapped[str] = mapped_column(String(36), index=True)
    evidence_id: Mapped[str] = mapped_column(String(36))
    file_id: Mapped[str] = mapped_column(String(36), index=True)
    job_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    actor_id: Mapped[str] = mapped_column(String(36), index=True)
    actor_name: Mapped[str] = mapped_column(String(64), default="")
    file_name: Mapped[str] = mapped_column(String(512), default="")
    input_sha256: Mapped[str] = mapped_column(String(64), index=True, default="")
    input_size: Mapped[int] = mapped_column(BigInteger, default=0)
    parser_id: Mapped[str] = mapped_column(String(64), default="")
    parser_version: Mapped[str] = mapped_column(String(16), default="")
    parser_digest: Mapped[str] = mapped_column(String(64), default="")
    settings: Mapped[dict] = mapped_column(JSON, default=dict)
    settings_digest: Mapped[str] = mapped_column(String(64), index=True, default="")
    events: Mapped[int] = mapped_column(Integer, default=0)
    failed: Mapped[int] = mapped_column(Integer, default=0)
    coverage: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(16), default="done")
    run_digest: Mapped[str] = mapped_column(String(64), default="")
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime] = _ts()


# ---------------------------------------------------------------- analysis results
class Finding(Base):
    __tablename__ = "an_finding"
    __table_args__ = (UniqueConstraint("investigation_id", "dedup_key"),)
    id: Mapped[str] = _id()
    display_id: Mapped[str] = mapped_column(String(24))
    investigation_id: Mapped[str] = mapped_column(String(36), index=True)
    detector_id: Mapped[str] = mapped_column(String(64))
    detector_version: Mapped[str] = mapped_column(String(16))
    title: Mapped[str] = mapped_column(String(256))
    category: Mapped[str] = mapped_column(String(64))
    stage: Mapped[str] = mapped_column(String(32), default="UNCLASSIFIED")
    risk_level: Mapped[str] = mapped_column(String(16))
    risk_score: Mapped[float] = mapped_column(Float)
    risk_factors: Mapped[list] = mapped_column(JSON, default=list)
    confidence: Mapped[str] = mapped_column(String(8))
    status: Mapped[str] = mapped_column(String(24), default="new")
    time_start: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    time_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    metrics: Mapped[list] = mapped_column(JSON, default=list)
    checks: Mapped[list] = mapped_column(JSON, default=list)
    counter_evidence: Mapped[list] = mapped_column(JSON, default=list)
    entities: Mapped[list] = mapped_column(JSON, default=list)
    evidence_refs: Mapped[dict] = mapped_column(JSON, default=dict)
    attack: Mapped[list] = mapped_column(JSON, default=list)
    attack_unmapped_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    explanation_md: Mapped[str] = mapped_column(Text, default="")
    dedup_key: Mapped[str] = mapped_column(String(256))
    created_at: Mapped[datetime] = _ts()


class FindingFeedback(Base):
    __tablename__ = "an_finding_feedback"
    id: Mapped[str] = _id()
    finding_id: Mapped[str] = mapped_column(ForeignKey("an_finding.id"), index=True)
    user_id: Mapped[str] = mapped_column(String(36))
    verdict: Mapped[str] = mapped_column(String(24))
    comment: Mapped[str] = mapped_column(Text, default="")
    at: Mapped[datetime] = _ts()


class Pattern(Base):
    __tablename__ = "an_pattern"
    id: Mapped[str] = _id()
    investigation_id: Mapped[str] = mapped_column(String(36), index=True)
    evidence_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    seq: Mapped[int] = mapped_column(Integer)
    template: Mapped[str] = mapped_column(Text)
    key: Mapped[dict] = mapped_column(JSON, default=dict)
    event_count: Mapped[int] = mapped_column(Integer)
    src_count: Mapped[int] = mapped_column(Integer, default=0)
    success_ratio: Mapped[float] = mapped_column(Float, default=0)
    first_ts: Mapped[str | None] = mapped_column(String(40), nullable=True)
    last_ts: Mapped[str | None] = mapped_column(String(40), nullable=True)
    tags: Mapped[list] = mapped_column(JSON, default=list)


class ParameterProfile(Base):
    __tablename__ = "an_parameter_profile"
    id: Mapped[str] = _id()
    investigation_id: Mapped[str] = mapped_column(String(36), index=True)
    uri_template: Mapped[str] = mapped_column(Text)
    param_name: Mapped[str] = mapped_column(String(256))
    location: Mapped[str] = mapped_column(String(16))
    profile: Mapped[dict] = mapped_column(JSON, default=dict)


class Entity(Base):
    __tablename__ = "inv_entity"
    __table_args__ = (UniqueConstraint("investigation_id", "type", "value"),)
    id: Mapped[str] = _id()
    investigation_id: Mapped[str] = mapped_column(String(36), index=True)
    type: Mapped[str] = mapped_column(String(24))
    value: Mapped[str] = mapped_column(String(1024))
    first_seen: Mapped[str | None] = mapped_column(String(40), nullable=True)
    last_seen: Mapped[str | None] = mapped_column(String(40), nullable=True)
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    attrs: Mapped[dict] = mapped_column(JSON, default=dict)


class Relation(Base):
    __tablename__ = "inv_relation"
    id: Mapped[str] = _id()
    investigation_id: Mapped[str] = mapped_column(String(36), index=True)
    src_entity_id: Mapped[str] = mapped_column(String(36))
    edge_type: Mapped[str] = mapped_column(String(24))
    dst_entity_id: Mapped[str] = mapped_column(String(36))
    count: Mapped[int] = mapped_column(Integer, default=0)
    first_seen: Mapped[str | None] = mapped_column(String(40), nullable=True)
    last_seen: Mapped[str | None] = mapped_column(String(40), nullable=True)
    sources: Mapped[list] = mapped_column(JSON, default=list)


class AttackStory(Base):
    __tablename__ = "inv_attack_story"
    id: Mapped[str] = _id()
    investigation_id: Mapped[str] = mapped_column(String(36), index=True)
    version: Mapped[int] = mapped_column(Integer)
    origin: Mapped[str] = mapped_column(String(16), default="auto")
    algo_version: Mapped[str] = mapped_column(String(16), default="")
    graph: Mapped[dict] = mapped_column(JSON, default=dict)
    edited_by: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = _ts()


class Briefing(Base):
    """What a person wrote over the generated report summary of an investigation (one row per investigation).
    Only the edited fields are stored; everything else is generated again from the analysis each time."""
    __tablename__ = "inv_briefing"
    investigation_id: Mapped[str] = mapped_column(ForeignKey("inv_investigation.id"), primary_key=True)
    fields: Mapped[dict] = mapped_column(JSON, default=dict)
    rev: Mapped[int] = mapped_column(Integer, default=1)
    updated_by: Mapped[str] = mapped_column(String(36), default="")
    updated_by_name: Mapped[str] = mapped_column(String(64), default="")
    updated_at: Mapped[datetime] = _ts()


class Check(Base):
    """What an analyst actually checked about a target, kept apart from having merely opened it and from the verdict
    of the investigation. A change never edits a row: it adds a new one that supersedes the old (history stays).
    A check marked `shared` is offered, as a reference only, to other investigations that meet the same target."""
    __tablename__ = "inv_check"
    id: Mapped[str] = _id()
    investigation_id: Mapped[str] = mapped_column(ForeignKey("inv_investigation.id"), index=True)
    target_type: Mapped[str] = mapped_column(String(16))   # event | entity | finding | set (a search result)
    target_key: Mapped[str] = mapped_column(String(512), index=True)  # event id / "ip:1.2.3.4" / finding id / "set:<digest>"
    target_label: Mapped[str] = mapped_column(String(512), default="")
    # coverage: one | selected | sample | all; checked/total counts; the query and event ids that define the range
    scope: Mapped[dict] = mapped_column(JSON, default=dict)
    questions: Mapped[list] = mapped_column(JSON, default=list)        # nature | success | impact | business
    judgement: Mapped[str | None] = mapped_column(String(16), nullable=True)  # normal | suspicious | malicious | undetermined
    note: Mapped[str] = mapped_column(Text, default="")
    evidence: Mapped[list] = mapped_column(JSON, default=list)          # event ids the analyst points to
    time_start: Mapped[str | None] = mapped_column(String(40), nullable=True)
    time_end: Mapped[str | None] = mapped_column(String(40), nullable=True)
    kind: Mapped[str] = mapped_column(String(12), default="direct")     # direct = looked at this data; cited = relies on a shared check
    source_check_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    source_state: Mapped[str] = mapped_column(String(12), default="")   # cited rows: "" | changed | retracted
    shared: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    share: Mapped[dict] = mapped_column(JSON, default=dict)             # fact / confirmed_scope / unconfirmed_scope
    share_status: Mapped[str] = mapped_column(String(16), default="")   # unreviewed | reviewed | recheck | retracted
    valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    context: Mapped[dict] = mapped_column(JSON, default=dict)           # conditions seen when shared (hours, peers, paths)
    state: Mapped[str] = mapped_column(String(12), default="active", index=True)  # active | cancelled | superseded
    state_note: Mapped[str] = mapped_column(String(512), default="")
    state_by: Mapped[str] = mapped_column(String(64), default="")
    supersedes_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    author_id: Mapped[str] = mapped_column(String(36), index=True)
    author_name: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = _ts()
    updated_at: Mapped[datetime] = _ts()


class Review(Base):
    """A request to have one important conclusion checked by someone else, and their answer."""
    __tablename__ = "inv_review"
    id: Mapped[str] = _id()
    investigation_id: Mapped[str] = mapped_column(ForeignKey("inv_investigation.id"), index=True)
    subject_type: Mapped[str] = mapped_column(String(16))               # finding | conclusion | other
    subject_id: Mapped[str] = mapped_column(String(64), default="")
    subject_label: Mapped[str] = mapped_column(String(256), default="")
    conclusion: Mapped[str] = mapped_column(Text, default="")
    scope_note: Mapped[str] = mapped_column(Text, default="")
    evidence: Mapped[list] = mapped_column(JSON, default=list)
    limits: Mapped[list] = mapped_column(JSON, default=list)             # known gaps of the data at request time
    required: Mapped[bool] = mapped_column(Boolean, default=False)       # created by the rules, not by choice
    status: Mapped[str] = mapped_column(String(20), default="needed", index=True)
    snapshot: Mapped[str] = mapped_column(String(32), default="")        # state of the subject the answer applies to
    requested_by: Mapped[str] = mapped_column(String(36), index=True)
    requested_by_name: Mapped[str] = mapped_column(String(64), default="")
    reviewer_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    reviewer_name: Mapped[str] = mapped_column(String(128), default="")
    outcome_note: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = _ts()
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Support(Base):
    """A separate question of an investigation handed to a colleague (the owner stays the owner)."""
    __tablename__ = "inv_support"
    id: Mapped[str] = _id()
    investigation_id: Mapped[str] = mapped_column(ForeignKey("inv_investigation.id"), index=True)
    question: Mapped[str] = mapped_column(String(500))
    scope_note: Mapped[str] = mapped_column(Text, default="")
    helper_id: Mapped[str] = mapped_column(String(36), index=True)
    helper_name: Mapped[str] = mapped_column(String(128), default="")
    status: Mapped[str] = mapped_column(String(16), default="requested", index=True)  # requested|working|done|declined|cancelled
    result_note: Mapped[str] = mapped_column(Text, default="")
    remaining: Mapped[str] = mapped_column(Text, default="")            # what the helper could not establish
    requested_by: Mapped[str] = mapped_column(String(36))
    requested_by_name: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = _ts()
    updated_at: Mapped[datetime] = _ts()


class SignatureSetting(Base):
    """Per-site switch for one signature of the shipped pack (a noisy rule can be turned off without code)."""
    __tablename__ = "det_signature_setting"
    sig_id: Mapped[str] = mapped_column(String(96), primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    note: Mapped[str] = mapped_column(String(512), default="")
    updated_by: Mapped[str] = mapped_column(String(64), default="")
    updated_at: Mapped[datetime] = _ts()


class Note(Base):
    __tablename__ = "inv_note"
    id: Mapped[str] = _id()
    investigation_id: Mapped[str] = mapped_column(String(36), index=True)
    author_id: Mapped[str] = mapped_column(String(36))
    author_name: Mapped[str] = mapped_column(String(64), default="")
    body_md: Mapped[str] = mapped_column(Text)
    ts: Mapped[str | None] = mapped_column(String(40), nullable=True)  # timeline anchor
    links: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = _ts()


class SavedView(Base):
    __tablename__ = "inv_saved_view"
    id: Mapped[str] = _id()
    investigation_id: Mapped[str] = mapped_column(String(36), index=True)
    owner_id: Mapped[str] = mapped_column(String(36))
    name: Mapped[str] = mapped_column(String(128))
    state: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = _ts()


class Correlation(Base):
    __tablename__ = "inv_correlation"
    id: Mapped[str] = _id()
    investigation_id: Mapped[str] = mapped_column(String(36), index=True)
    kind: Mapped[str] = mapped_column(String(32))
    strength: Mapped[str] = mapped_column(String(16))
    entity_keys: Mapped[list] = mapped_column(JSON, default=list)
    steps: Mapped[list] = mapped_column(JSON, default=list)
    explanation: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = _ts()


# ---------------------------------------------------------------- case
class Case(Base):
    __tablename__ = "inv_case"
    id: Mapped[str] = _id()
    display_id: Mapped[str] = mapped_column(String(32), unique=True)
    title: Mapped[str] = mapped_column(String(256))
    severity: Mapped[str] = mapped_column(String(16), default="medium")
    status: Mapped[str] = mapped_column(String(16), default="open")
    assignee_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    summary_md: Mapped[str] = mapped_column(Text, default="")
    response_md: Mapped[str] = mapped_column(Text, default="")
    verdict: Mapped[str | None] = mapped_column(String(24), nullable=True)
    investigation_ids: Mapped[list] = mapped_column(JSON, default=list)
    related_detection_ids: Mapped[list] = mapped_column(JSON, default=list)
    features: Mapped[dict] = mapped_column(JSON, default=dict)
    created_by: Mapped[str] = mapped_column(String(36))
    created_at: Mapped[datetime] = _ts()
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class CaseItem(Base):
    __tablename__ = "inv_case_item"
    id: Mapped[str] = _id()
    case_id: Mapped[str] = mapped_column(ForeignKey("inv_case.id"), index=True)
    item_type: Mapped[str] = mapped_column(String(24))
    ref_id: Mapped[str] = mapped_column(String(64))
    snapshot: Mapped[dict] = mapped_column(JSON, default=dict)
    added_by: Mapped[str] = mapped_column(String(36))
    added_at: Mapped[datetime] = _ts()


class CaseRevision(Base):
    __tablename__ = "inv_case_revision"
    id: Mapped[str] = _id()
    case_id: Mapped[str] = mapped_column(ForeignKey("inv_case.id"), index=True)
    rev: Mapped[int] = mapped_column(Integer)
    diff: Mapped[dict] = mapped_column(JSON, default=dict)
    actor: Mapped[str] = mapped_column(String(64))
    at: Mapped[datetime] = _ts()


class Counter(Base):
    """Display-id sequences (INV-YYYYMMDD-NNN etc.)."""

    __tablename__ = "sys_counter"
    name: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[int] = mapped_column(Integer, default=0)


class DataDeletion(Base):
    """Durable cleanup receipt. Plans are private; only content-free counts are returned by the API."""
    __tablename__ = "admin_data_deletion"
    id: Mapped[str] = _id()
    target_type: Mapped[str] = mapped_column(String(16))
    target_id: Mapped[str] = mapped_column(String(36), index=True)
    investigation_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    state: Mapped[str] = mapped_column(String(16), default="PENDING")
    step: Mapped[str] = mapped_column(String(16), default="planned")
    plan: Mapped[dict] = mapped_column(JSON, default=dict)
    reason: Mapped[str] = mapped_column(String(500))
    actor_id: Mapped[str] = mapped_column(String(36))
    actor_name: Mapped[str] = mapped_column(String(64))
    error_code: Mapped[str] = mapped_column(String(48), default="")
    created_at: Mapped[datetime] = _ts()
    updated_at: Mapped[datetime] = _ts()
