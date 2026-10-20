"""Current authorization and approval gates for model context."""
from __future__ import annotations
from saw.detection.derived_access import visible_snapshot

import hashlib
import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from saw.core.application.identity import principal_of
from saw.core.application.investigations import access_of
from saw.core.security.authz import Principal, can
from saw.core.security.masking import mask_text
from saw.knowledge.models import Experience
from saw.storage.db import utcnow
from saw.storage.models import Investigation, User


def allowed_experiences(s: Session, p: Principal) -> frozenset[str]:
    if not can(p, "knowledge.read"):
        return frozenset()
    now = utcnow()
    allowed = set()
    for e in s.execute(select(Experience).where(Experience.approved_data.isnot(None),
                                                Experience.deprecated.is_(False))).scalars():
        if not e.approved_data or not e.approved_rev or not e.reviewer_id or e.reviewer_id == e.analyst_id:
            continue
        if e.expires_at and e.expires_at.replace(tzinfo=e.expires_at.tzinfo or now.tzinfo) <= now:
            continue
        reviewer = s.get(User, e.reviewer_id)
        author = s.get(User, e.analyst_id)
        if reviewer is None or reviewer.status != "active" or author is None or author.status != "active":
            continue
        if not can(principal_of(reviewer), "knowledge.approve"):
            continue
        if e.source_investigation_id:
            if s.get(Investigation, e.source_investigation_id) is None:
                continue
            if not can(p, "investigation.read", access_of(s, p, e.source_investigation_id)):
                continue
        if not visible_snapshot(s, p, e.approved_data):
            continue
        allowed.add(e.id)
    return frozenset(allowed)


def mask_context(value):
    if isinstance(value, dict):
        return {key: mask_context(item) for key, item in value.items()}
    if isinstance(value, list):
        return [mask_context(item) for item in value]
    if isinstance(value, str):
        return mask_text(value).text
    return value


def knowledge_snapshot(s: Session, display_ids: list[str]) -> dict[str, tuple[int, str]]:
    if not display_ids:
        return {}
    return {e.id: (e.approved_rev, hashlib.sha256(json.dumps(e.approved_data, sort_keys=True,
            ensure_ascii=False).encode()).hexdigest()) for e in s.execute(select(Experience).where(
            Experience.display_id.in_(display_ids))).scalars()}


def knowledge_still_allowed(s: Session, p: Principal, snapshot: dict[str, tuple[int, str]]) -> bool:
    if not snapshot:
        return True
    if not set(snapshot).issubset(allowed_experiences(s, p)):
        return False
    for eid, expected in snapshot.items():
        e = s.get(Experience, eid)
        current = (e.approved_rev, hashlib.sha256(json.dumps(e.approved_data, sort_keys=True,
                   ensure_ascii=False).encode()).hexdigest())
        if current != expected:
            return False
    return True
