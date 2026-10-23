"""Finite immutable transformation profiles; no executable expressions."""
from __future__ import annotations
import base64
import json
import uuid
from fastapi import HTTPException
from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from saw.core.application.identity import principal_of
from saw.core.application.investigations import Forbidden, NotFound
from saw.core.application.provenance import canonical, digest
from saw.core.security.authz import can
from saw.knowledge.golden_governance_models import GoldenProfileVersion
from saw.knowledge.golden_schemas import ProfileIn
from saw.storage.models import User

PSEUDONYM = {"schema": "saw.pseudonymization-profile.v1", "version": 1,
    "identity_scope": "org_network", "identity_mapping": "scoped_injective/1",
    "time_transform": "none", "free_text": "drop_unapproved", "metadata": "allowlist_v2"}
CONVERSIONS = {"golden-native/1": ("golden-native", "native-input-and-answers/1", "native-files/1"),
    "input-output-jsonl/1": ("input-output", "input-output/1", "jsonl-utf8/1"),
    "messages-jsonl/1": ("messages", "messages/1", "jsonl-utf8/1")}


def actor(s, p, permission=None):
    user = s.get(User, p.user_id, populate_existing=True) if p else None
    if user is None or user.status != "active":
        raise Forbidden("active_user_required")
    current = principal_of(user)
    if permission and not can(current, permission):
        raise Forbidden(permission)
    return current


def cursor_id(cursor):
    if cursor is None:
        return None
    try:
        value = json.loads(base64.urlsafe_b64decode(cursor.encode()).decode())
        if set(value) != {"after"} or not isinstance(value["after"], str) or len(value["after"]) > 128:
            raise ValueError()
        return value["after"]
    except Exception:
        raise ValueError("golden_invalid_cursor") from None


def page(items, limit):
    return {"items": items[:limit], "next_cursor": base64.urlsafe_b64encode(
        canonical({"after": items[limit - 1]["id"]}).encode()).decode() if len(items) > limit else None}


def stock():
    yield "pseudonymization", "scoped-identities", "scoped-identities/1", PSEUDONYM
    for implementation, (target, mapping, serialization) in CONVERSIONS.items():
        yield "model_conversion", target, implementation, {
            "schema": "saw.model-conversion-profile.v1", "version": 1,
            "target": {"name": target, "version": "1"}, "field_mapping": mapping,
            "serialization_contract": serialization, "validation_suite": "saw-release-reference-leakage/1"}


def ensure_stock(s):
    for kind, key, implementation, payload in stock():
        ident = str(uuid.uuid5(uuid.NAMESPACE_URL, "saw/golden/profile/" + implementation))
        if s.get(GoldenProfileVersion, ident) is not None:
            continue
        try:
            with s.begin_nested():
                s.add(GoldenProfileVersion(id=ident, kind=kind, profile_key=key, version=1,
                    implementation=implementation, payload=payload, payload_sha256=digest(payload),
                    contributor_ids=[], created_by=None))
                s.flush()
        except IntegrityError:
            if s.get(GoldenProfileVersion, ident) is None:
                raise


def to_dict(row):
    if digest(row.payload) != row.payload_sha256:
        raise HTTPException(409, "golden_profile_corrupt")
    return {"id": row.id, "kind": row.kind, "profile_key": row.profile_key, "version": row.version,
        "payload_sha256": row.payload_sha256, "implementation": row.implementation, "payload": row.payload,
        "contributors": row.contributor_ids, "created_by": row.created_by, "created_at": row.created_at,
        "capabilities": [row.implementation], "limits": ["profile_is_not_export_authorization"]}


def get(s, p, ident):
    actor(s, p, "knowledge.read")
    row = s.get(GoldenProfileVersion, ident)
    if row is None:
        raise NotFound("profile not found")
    to_dict(row)
    return row


def list_for(s, p, kind, *, limit=50, cursor=None):
    actor(s, p, "knowledge.read")
    if kind not in {"pseudonymization", "model_conversion"} or not 1 <= limit <= 100:
        raise ValueError("golden_profile_list_invalid")
    ensure_stock(s)
    query = select(GoldenProfileVersion).where(GoldenProfileVersion.kind == kind)
    after = cursor_id(cursor)
    if after:
        query = query.where(GoldenProfileVersion.id > after)
    rows = list(s.scalars(query.order_by(GoldenProfileVersion.id).limit(limit + 1)))
    # Native is the initial default; clients still pin exact identities explicitly.
    if cursor is None and len(rows) <= limit:
        rows.sort(key=lambda r: (r.implementation != "golden-native/1", r.id))
    return page([to_dict(r) for r in rows], limit)


def create(s, p, raw):
    from saw.knowledge.golden_projection import validate_profile
    p = actor(s, p, "knowledge.write")
    body = ProfileIn.model_validate(raw)
    if len(canonical(body.payload).encode()) > 32768:
        raise HTTPException(413, "golden_profile_too_large")
    payload = validate_profile(body.kind, body.implementation, body.payload)
    ensure_stock(s)
    # A stable shipped row is a bounded cross-user registry allocator lock.
    anchor = str(uuid.uuid5(uuid.NAMESPACE_URL, "saw/golden/profile/scoped-identities/1"))
    s.execute(update(GoldenProfileVersion).where(GoldenProfileVersion.id == anchor).values(id=anchor))
    latest = s.scalar(select(GoldenProfileVersion).where(GoldenProfileVersion.kind == body.kind,
        GoldenProfileVersion.profile_key == body.profile_key).order_by(GoldenProfileVersion.version.desc()).limit(1))
    if (latest.id if latest else None) != body.expected_latest_id:
        raise HTTPException(409, "golden_profile_version_conflict")
    if latest and latest.version >= 50:
        raise HTTPException(413, "golden_profile_version_limit")
    keys = s.scalar(select(func.count(func.distinct(GoldenProfileVersion.profile_key))).where(
        GoldenProfileVersion.kind == body.kind))
    if latest is None and keys >= 100:
        raise HTTPException(413, "golden_profile_key_limit")
    row = GoldenProfileVersion(kind=body.kind, profile_key=body.profile_key,
        version=(latest.version + 1 if latest else 1), implementation=body.implementation,
        payload=payload, payload_sha256=digest(payload), contributor_ids=[p.user_id], created_by=p.user_id)
    s.add(row)
    s.flush()
    return row
