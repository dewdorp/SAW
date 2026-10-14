"""Parser library: analyst-defined parser definitions, versioned and audited (FR-LOG-11).

Saving a definition creates a new version (the previous active one becomes `superseded`); events record which
parser id + version produced them, so a file can be re-processed after a definition is improved. Definitions
travel between air-gapped analyst PCs as small JSON documents (export / import).
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from datetime import datetime

from sqlalchemy import JSON, DateTime, Integer, String, Text, UniqueConstraint, func, select
from sqlalchemy.orm import Mapped, Session, mapped_column

from saw.core.application import audit
from saw.core.application.investigations import Forbidden, NotFound
from saw.core.security.authz import Principal, can
from saw.parsers.custom import SLUG, DefinedParser, ParserSpec
from saw.storage.db import Base, new_id, session_scope, utcnow

EXPORT_KIND = "saw.parser-definition"
PINNED = re.compile(r"u:([a-z0-9_-]+)@(\d+)")


class ParserDefinition(Base):
    __tablename__ = "ps_parser"
    __table_args__ = (UniqueConstraint("slug", "version", name="uq_ps_parser_slug_version"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    slug: Mapped[str] = mapped_column(String(48), index=True)
    name: Mapped[str] = mapped_column(String(128))
    version: Mapped[int] = mapped_column(Integer)
    # draft (author only) → pending (share requested) → active (approved by someone else, used for auto-detection)
    # → superseded (a newer version was approved) | disabled
    status: Mapped[str] = mapped_column(String(16), default="draft")
    spec: Mapped[dict] = mapped_column(JSON)
    note: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str] = mapped_column(String(36))
    created_by_name: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    reviewed_by: Mapped[str | None] = mapped_column(String(36), nullable=True)
    reviewed_by_name: Mapped[str] = mapped_column(String(64), default="")
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    review_note: Mapped[str] = mapped_column(Text, default="")


def slugify(name: str) -> str:
    s = re.sub(r"[^a-z0-9_-]+", "-", name.lower()).strip("-")[:46]
    return s if SLUG.match(s) else f"parser-{int(time.time())}"


def spec_digest(spec: dict) -> str:
    return hashlib.sha256(json.dumps(spec, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()


def to_dict(d: ParserDefinition, p: Principal | None = None) -> dict:
    out = {"id": f"u:{d.slug}", "pinned_id": f"u:{d.slug}@{d.version}", "slug": d.slug, "name": d.name,
           "version": d.version, "status": d.status, "spec": d.spec, "spec_digest": spec_digest(d.spec), "note": d.note,
           "created_by": d.created_by_name, "created_at": d.created_at, "reviewed_by": d.reviewed_by_name,
           "reviewed_at": d.reviewed_at, "review_note": d.review_note}
    if p is not None:
        out["mine"] = d.created_by == p.user_id
        out["can_review"] = d.status == "pending" and d.created_by != p.user_id and can(p, "parser.approve")
    return out


def _need(p: Principal, perm: str) -> None:
    if not can(p, perm):
        raise Forbidden(f"permission {perm} required")


def _lock_mutation(s: Session) -> None:
    # Packages and the library share a transaction lock before selecting a version or active row.
    audit._head(s)
    s.expire_all()


def _visible(d: ParserDefinition, p: Principal) -> bool:
    return d.status != "draft" or d.created_by == p.user_id  # drafts are private to their author


def build(d: ParserDefinition, pinned: bool = False) -> DefinedParser:
    return DefinedParser(d.slug, d.version, ParserSpec.model_validate(d.spec), d.name,
                         pid=f"u:{d.slug}@{d.version}" if pinned else None)


def active_parsers() -> list[DefinedParser]:
    """Provider for saw.parsers.registry: approved (shared) definitions, the only ones used for auto-detection."""
    with session_scope() as s:
        rows = s.execute(select(ParserDefinition).where(ParserDefinition.status == "active")
                         .order_by(ParserDefinition.created_at.desc())).scalars().all()
        out = []
        for d in rows:
            try:
                out.append(build(d))
            except ValueError:
                continue  # a definition that no longer validates is skipped, never fatal for ingest
        return out


def _pinned(s: Session, pid: str) -> ParserDefinition | None:
    m = PINNED.fullmatch(pid)
    if not m:
        return None
    return s.execute(select(ParserDefinition).where(ParserDefinition.slug == m.group(1),
                                                    ParserDefinition.version == int(m.group(2)))).scalar_one_or_none()


def parser_by_id(pid: str) -> DefinedParser | None:
    """Provider for exact versions `u:<slug>@<n>` (drafts included: who may use them is checked on assignment)."""
    with session_scope() as s:
        d = _pinned(s, pid)
        return build(d, pinned=True) if d is not None and d.status != "disabled" else None


def check_use(s: Session, p: Principal, pid: str) -> None:
    """May this analyst process evidence with `pid`? Drafts are usable by their author only."""
    if not pid.startswith("u:"):
        return
    if "@" not in pid:
        if not s.execute(select(ParserDefinition.id).where(ParserDefinition.slug == pid[2:],
                                                           ParserDefinition.status == "active")).first():
            raise NotFound("no approved version of this parser")
        return
    d = _pinned(s, pid)
    if d is None or d.status == "disabled":
        raise NotFound("parser version not found")
    if d.status in ("draft", "pending") and d.created_by != p.user_id:
        raise Forbidden("a draft parser can only be used by its author until it is approved")


def picker(s: Session, p: Principal) -> list[dict]:
    """Parsers this analyst can choose for a file: approved ones and their own drafts."""
    out = []
    for d in s.execute(select(ParserDefinition).where(ParserDefinition.status.in_(["active", "draft", "pending"]))
                       .order_by(ParserDefinition.slug, ParserDefinition.version.desc())).scalars():
        base = {"version": str(d.version), "name": d.name, "user": True, "status": d.status,
                "data_source": d.spec.get("data_source"), "product": f"u_{d.slug}"}
        if d.status == "active":
            out.append({"id": f"u:{d.slug}", **base})
        elif d.created_by == p.user_id:
            out.append({"id": f"u:{d.slug}@{d.version}", **base})
    return out


def list_definitions(s: Session, p: Principal) -> list[dict]:
    rows = s.execute(select(ParserDefinition).where(ParserDefinition.status != "superseded")
                     .order_by(ParserDefinition.slug, ParserDefinition.version.desc())).scalars()
    return [to_dict(d, p) for d in rows if _visible(d, p)]


def history(s: Session, slug: str, p: Principal) -> list[dict]:
    rows = [d for d in s.execute(select(ParserDefinition).where(ParserDefinition.slug == slug)
                                 .order_by(ParserDefinition.version.desc())).scalars() if _visible(d, p)]
    if not rows:
        raise NotFound("parser not found")
    return [to_dict(d, p) for d in rows]


def _version(s: Session, slug: str, version: int) -> ParserDefinition:
    d = s.execute(select(ParserDefinition).where(ParserDefinition.slug == slug,
                                                 ParserDefinition.version == version)).scalar_one_or_none()
    if d is None:
        raise NotFound("parser version not found")
    return d


def save(s: Session, p: Principal, name: str, spec: dict, slug: str | None = None, note: str = "",
         action: str = "parser.save") -> dict:
    """Every save is a new private draft; it joins auto-detection only after another analyst approves it."""
    _need(p, "parser.manage")
    validated = ParserSpec.model_validate(spec).model_dump()
    slug = slug or slugify(name)
    if not SLUG.match(slug):
        raise ValueError("slug: lower-case letters, digits, - and _ (2-47 chars)")
    _lock_mutation(s)
    last = s.execute(select(func.max(ParserDefinition.version)).where(ParserDefinition.slug == slug)).scalar() or 0
    d = ParserDefinition(slug=slug, name=name[:128], version=last + 1, status="draft", spec=validated,
                         note=note[:2000], created_by=p.user_id, created_by_name=p.username)
    s.add(d)
    s.flush()
    audit.record(s, action, actor_id=p.user_id, actor_name=p.username, target_type="parser", target_id=f"u:{slug}",
                 detail={"version": d.version, "format": validated["format"], "data_source": validated["data_source"],
                         "spec_digest": spec_digest(validated)})
    return to_dict(d, p)


def request_share(s: Session, p: Principal, slug: str, version: int) -> dict:
    _need(p, "parser.manage")
    _lock_mutation(s)
    d = _version(s, slug, version)
    if d.created_by != p.user_id:
        raise Forbidden("only the author can ask to share a draft")
    if d.status != "draft":
        raise ValueError(f"version {version} is {d.status}, not a draft")
    d.status = "pending"
    audit.record(s, "parser.share_request", actor_id=p.user_id, actor_name=p.username, target_type="parser",
                 target_id=f"u:{slug}", detail={"version": version, "spec_digest": spec_digest(d.spec)})
    return to_dict(d, p)


def review(s: Session, p: Principal, slug: str, version: int, approve: bool, note: str = "") -> dict:
    """4-eyes: a reviewer other than the author approves (shared, auto-detected) or returns it to draft."""
    _need(p, "parser.approve")
    _lock_mutation(s)
    d = _version(s, slug, version)
    if d.status != "pending":
        raise ValueError(f"version {version} is {d.status}, not waiting for review")
    if d.created_by == p.user_id:
        raise Forbidden("the author cannot approve their own parser (4-eyes)")
    if approve:
        for old in s.execute(select(ParserDefinition).where(ParserDefinition.slug == slug,
                                                            ParserDefinition.status == "active")).scalars():
            old.status = "superseded"
    d.status = "active" if approve else "draft"
    d.reviewed_by, d.reviewed_by_name, d.reviewed_at, d.review_note = p.user_id, p.username, utcnow(), note[:2000]
    audit.record(s, "parser.approve" if approve else "parser.reject", actor_id=p.user_id, actor_name=p.username,
                 target_type="parser", target_id=f"u:{slug}",
                 detail={"version": version, "author": d.created_by_name, "spec_digest": spec_digest(d.spec),
                         "note": note[:200]})
    return to_dict(d, p)


def set_status(s: Session, p: Principal, slug: str, enabled: bool) -> dict:
    """Turn the shared parser off (or back on). It affects everyone, so it needs the approver permission."""
    _need(p, "parser.approve")
    _lock_mutation(s)
    want = "disabled" if enabled else "active"
    d = s.execute(select(ParserDefinition).where(ParserDefinition.slug == slug, ParserDefinition.status == want)
                  .order_by(ParserDefinition.version.desc())).scalars().first()
    if d is None:
        raise NotFound("no shared version to change")
    if enabled and s.scalar(select(ParserDefinition.id).where(ParserDefinition.slug == slug,
                                                              ParserDefinition.status == "active").limit(1)):
        raise ValueError("이미 활성 버전이 있습니다. 현재 공용 버전을 먼저 검토하세요.")
    d.status = "active" if enabled else "disabled"
    audit.record(s, "parser.enable" if enabled else "parser.disable", actor_id=p.user_id, actor_name=p.username,
                 target_type="parser", target_id=f"u:{slug}", detail={"version": d.version})
    return to_dict(d, p)


def export(s: Session, slug: str, p: Principal) -> dict:
    rows = history(s, slug, p)
    d = next((r for r in rows if r["status"] == "active"), rows[0])
    return {"kind": EXPORT_KIND, "format_version": 1, "name": d["name"], "slug": d["slug"], "version": d["version"],
            "spec": d["spec"], "spec_digest": d["spec_digest"], "note": d["note"], "exported_at": utcnow().isoformat()}


def import_definition(s: Session, p: Principal, doc: dict) -> dict:
    """Imported definitions arrive as the importer's draft and are reviewed like any other change."""
    if not isinstance(doc, dict) or doc.get("kind") != EXPORT_KIND:
        raise ValueError("not a SAW parser definition file")
    note = f"imported (source version {doc.get('version')}). {doc.get('note') or ''}".strip()
    return save(s, p, str(doc.get("name") or doc.get("slug")), doc.get("spec") or {}, str(doc.get("slug") or ""),
                note, action="parser.import")
