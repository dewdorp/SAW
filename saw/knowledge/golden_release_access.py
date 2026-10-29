"""Fresh source authority, independent decisions and bounded release DTOs."""
from __future__ import annotations
from copy import deepcopy
from fastapi import HTTPException
from sqlalchemy import select, update
from saw.core.application import audit
from saw.core.application.identity import principal_of
from saw.core.application.investigations import Forbidden, NotFound
from saw.core.application.provenance import digest
from saw.core.security.authz import can
from saw.knowledge import golden, golden_profiles
from saw.knowledge.golden_governance_models import (
    GoldenRelease, GoldenReleaseVersion, GoldenReleaseSource, GoldenReleaseDecision, GoldenReleasePreview)
from saw.knowledge.golden_schemas import ApprovalIn, RevokeIn
from saw.storage.db import utcnow
from saw.storage.models import Job, User


def latest(s, vid):
    return s.scalar(select(GoldenReleaseDecision).where(GoldenReleaseDecision.release_version_id == vid)
                    .order_by(GoldenReleaseDecision.sequence.desc()).limit(1))


def _verify(s, p, version):
    from saw.knowledge import golden_releases as service
    if digest(version.payload) != version.payload_sha256 or service.request_hash(version.request) != version.request_sha256:
        raise HTTPException(409, "golden_release_seal_changed")
    ledger = set(s.scalars(select(GoldenReleaseSource.investigation_id).where(
        GoldenReleaseSource.release_version_id == version.id)))
    if ledger != set(version.source_investigation_ids):
        raise HTTPException(409, "golden_release_source_ledger_changed")
    p = service.authorize_sources(s, p, ledger)
    artifact = version.private_objects.get("artifact") or {}
    if artifact.get("sha256") != version.artifact_sha256 or artifact.get("size_bytes") != version.size_bytes:
        raise HTTPException(409, "golden_release_artifact_changed")
    return p


def _valid_current(s, p, version):
    from saw.knowledge import golden_releases as service
    value = service._collect(s, p, service.normalize_request(version.request), freeze=False, require_create=False)
    if value["family_snapshot_sha256"] != version.family_snapshot_sha256:
        raise HTTPException(409, "golden_release_family_changed")
    if set(value["source_investigation_ids"]) != set(version.source_investigation_ids):
        raise HTTPException(409, "golden_release_sources_changed")
    if not set(value["contributor_ids"]) - {p.user_id} <= set(version.contributor_ids):
        raise HTTPException(409, "golden_release_contributors_changed")


def state(version, decision):
    if golden._aware(version.request["expires_at"]) <= utcnow():
        return "expired"
    return {"approve": "approved", "decline": "declined", "revoke": "revoked"}.get(
        decision.decision if decision else None, "awaiting_review")


def _eligibility(s, p, version, decision, valid):
    release = s.get(GoldenRelease, version.release_id)
    status = state(version, decision)
    revoked = s.scalar(select(GoldenReleaseDecision.id).where(
        GoldenReleaseDecision.release_version_id == version.id,
        GoldenReleaseDecision.decision == "revoke").limit(1)) is not None
    independent = p.user_id not in version.contributor_ids
    approver, create = can(p, "golden.release.approve"), can(p, "golden.release.create")
    receipt = s.scalar(select(GoldenReleasePreview.id).where(GoldenReleasePreview.release_version_id == version.id,
        GoldenReleasePreview.reviewer_id == p.user_id,
        GoldenReleasePreview.artifact_sha256 == version.artifact_sha256).limit(1))
    values = {
        "preview": (p.user_id == version.created_by or approver, "golden_preview_permission_required"),
        "approve": (approver and independent and bool(receipt) and release.current_version_id == version.id
                    and valid and not revoked and status != "expired", "golden_independent_preview_approval_required"),
        "decline": (approver and independent and release.current_version_id == version.id
                    and not revoked and status != "expired", "golden_independent_decline_required"),
        "download": ((create or approver) and valid and status == "approved", "golden_active_release_approval_required"),
        "revoke": (approver and decision is not None and decision.decision == "approve", "golden_approved_release_required"),
        "new_version": (create and release.pending_job_id is None, "golden_release_build_pending_or_permission")}
    return {k: {"enabled": bool(ok), "reasons": [] if ok else [reason]} for k, (ok, reason) in values.items()}


def authorize_version(s, p, version_id, action):
    from saw.knowledge import golden_releases as service
    version = s.get(GoldenReleaseVersion, version_id, populate_existing=True)
    if version is None:
        raise NotFound("release version not found")
    p = _verify(s, p, version)
    decision = latest(s, version.id)
    valid = True
    try:
        _valid_current(s, p, version)
        if decision and decision.decision == "approve":
            reviewer = s.get(User, decision.reviewer_id, populate_existing=True)
            if (reviewer is None or reviewer.status != "active" or
                    not can(principal_of(reviewer), "golden.release.approve") or
                    decision.reviewer_id in version.contributor_ids):
                raise HTTPException(409, "golden_release_reviewer_unavailable")
            service.authorize_sources(s, principal_of(reviewer), version.source_investigation_ids)
    except (ValueError, HTTPException, Forbidden, NotFound):
        valid = False
    eligibility = _eligibility(s, p, version, decision, valid)
    if action != "read":
        if action not in eligibility:
            raise ValueError("golden_release_action_invalid")
        if not eligibility[action]["enabled"]:
            if action in {"approve", "decline", "revoke"} and not can(p, "golden.release.approve"):
                raise Forbidden("golden.release.approve")
            if action in {"approve", "decline"} and p.user_id in version.contributor_ids:
                raise Forbidden("golden_release_independent_reviewer_required")
            if action == "preview" and not (p.user_id == version.created_by or can(p, "golden.release.approve")):
                raise Forbidden("golden_preview_permission_required")
            if action == "download" and not (can(p, "golden.release.create") or can(p, "golden.release.approve")):
                raise Forbidden("golden.release.create")
            raise HTTPException(409, eligibility[action]["reasons"][0])
    return {"version": version, "source_investigation_ids": sorted(version.source_investigation_ids),
            "eligibility": eligibility, "valid": valid}


def decision_dict(row):
    return {"id": row.id, "decision": row.decision, "reviewer_id": row.reviewer_id,
            "created_at": row.created_at, "reason": row.reason} if row else None


def to_dict(s, p, release, version_id=None):
    from saw.knowledge import golden_releases as service
    if isinstance(release, str):
        release = s.get(GoldenRelease, release)
    if release is None:
        raise NotFound("release not found")
    p = golden_profiles.actor(s, p, "knowledge.read")
    selected = version_id or release.current_version_id
    if selected:
        auth = authorize_version(s, p, selected, "read")
        version = auth["version"]
        if version.release_id != release.id:
            raise NotFound("release version not found")
        decision = latest(s, selected)
        payload = {k: deepcopy(v) for k, v in version.payload.items() if k != "validation"}
        if payload["split"] == "holdout":
            payload["applicability"]["validations"] = []
        payload.update(id=version.id, revision=version.revision, payload_sha256=version.payload_sha256,
            request_sha256=version.request_sha256, created_by=version.created_by, created_at=version.created_at)
        status = state(version, decision) if auth["valid"] else "ineligible"
        eligibility = auth["eligibility"]
    else:
        if release.created_by != p.user_id:
            raise NotFound("release not found")
        version, decision, payload, status = None, None, None, "building"
        eligibility = {k: {"enabled": False, "reasons": ["golden_build_pending"]}
                       for k in ("preview", "approve", "decline", "download", "revoke", "new_version")}
    current_id = release.current_version_id
    if current_id and current_id != selected:
        try:
            authorize_version(s, p, current_id, "read")
        except (Forbidden, NotFound, HTTPException, ValueError):
            current_id = None
    pending = s.get(Job, release.pending_job_id) if release.pending_job_id else None
    if pending:
        from saw.knowledge.golden_jobs import require_job
        try:
            require_job(s, p, pending)
            ids = set((pending.stages or {}).get("source_ids", []))
            service.authorize_sources(s, p, ids)
        except (Forbidden, NotFound, HTTPException, ValueError):
            pending = None
            if not selected:
                raise NotFound("release not found") from None
    versions = []
    for item in s.scalars(select(GoldenReleaseVersion).where(GoldenReleaseVersion.release_id == release.id)
                          .order_by(GoldenReleaseVersion.revision.desc()).limit(50)):
        try:
            auth = authorize_version(s, p, item.id, "read")
        except (Forbidden, NotFound):
            continue
        versions.append({"id": item.id, "revision": item.revision, "payload_sha256": item.payload_sha256,
            "created_at": item.created_at, "state": state(item, latest(s, item.id)) if auth["valid"] else "ineligible"})
    return {"id": release.id, "current_version_id": current_id,
        "pending_job": {"id": pending.id, "state": pending.state} if pending else None,
        "version": payload, "approval": decision_dict(decision),
        "state": "building" if pending and not version_id else status, "eligibility": eligibility, "versions": versions}


def list_for(s, p, *, limit=50, cursor=None):
    golden_profiles.actor(s, p, "knowledge.read")
    if not 1 <= limit <= 100:
        raise ValueError("golden_list_limit")
    after = golden_profiles.cursor_id(cursor)
    query = select(GoldenRelease).order_by(GoldenRelease.id)
    if after:
        query = query.where(GoldenRelease.id > after)
    items = []
    for row in s.scalars(query):
        try:
            items.append(to_dict(s, p, row))
        except (Forbidden, NotFound):
            continue
        if len(items) > limit:
            break
    return golden_profiles.page(items, limit)


def versions_for(s, p, release_id, *, limit=50, cursor=None):
    if not 1 <= limit <= 100:
        raise ValueError("golden_list_limit")
    after = golden_profiles.cursor_id(cursor)
    query = select(GoldenReleaseVersion).where(GoldenReleaseVersion.release_id == release_id).order_by(GoldenReleaseVersion.id)
    if after:
        query = query.where(GoldenReleaseVersion.id > after)
    items = []
    for row in s.scalars(query):
        try:
            envelope = to_dict(s, p, release_id, version_id=row.id)
        except (Forbidden, NotFound):
            continue
        items.append({"id": row.id, "revision": row.revision, "payload_sha256": row.payload_sha256,
                      "created_at": row.created_at, "state": envelope["state"]})
        if len(items) > limit:
            break
    return golden_profiles.page(items, limit)


def record_preview(s, p, version_id, artifact_sha256, preview_sha256):
    version = authorize_version(s, p, version_id, "preview")["version"]
    if artifact_sha256 != version.artifact_sha256:
        raise HTTPException(409, "golden_preview_artifact_changed")
    receipt = GoldenReleasePreview(release_version_id=version.id, reviewer_id=p.user_id,
        artifact_sha256=artifact_sha256, preview_sha256=preview_sha256)
    s.add(receipt)
    audit.record(s, "golden.release.preview", actor_id=p.user_id, actor_name=p.username,
        target_type="golden_release_version", target_id=version.id,
        detail={"artifact_sha256": artifact_sha256, "preview_sha256": preview_sha256})
    s.flush()
    return receipt


def _lock(s, p, version_id):
    from saw.knowledge import golden_releases as service
    auth = authorize_version(s, p, version_id, "read")
    version = auth["version"]
    service.authorize_sources(s, p, auth["source_investigation_ids"], lock=True)
    s.execute(update(GoldenRelease).where(GoldenRelease.id == version.release_id).values(id=version.release_id)
              .execution_options(synchronize_session=False))
    return s.get(GoldenRelease, version.release_id, populate_existing=True), version


def decide(s, p, version_id, raw):
    body = ApprovalIn.model_validate(raw)
    p = golden_profiles.actor(s, p, "golden.release.approve")
    release, version = _lock(s, p, version_id)
    previous = latest(s, version_id)
    if (release.current_version_id != version_id or body.expected_current_version_id != version_id
            or version.payload_sha256 != body.expected_payload_sha256 or version.artifact_sha256 != body.expected_artifact_sha256
            or (previous.id if previous else None) != body.expected_decision_id):
        raise HTTPException(409, "golden_release_decision_conflict")
    if p.user_id in version.contributor_ids:
        raise Forbidden("golden_release_independent_reviewer_required")
    if s.scalar(select(GoldenReleaseDecision.id).where(
            GoldenReleaseDecision.release_version_id == version_id,
            GoldenReleaseDecision.decision == "revoke").limit(1)):
        raise HTTPException(409, "golden_revoked_version_requires_new_candidate")
    if body.decision == "approve":
        if not all(body.confirmations.model_dump().values()):
            raise ValueError("golden_release_confirmations_required")
        authorize_version(s, p, version.id, "approve")
    else:
        authorize_version(s, p, version.id, "decline")
    row = GoldenReleaseDecision(release_version_id=version.id, sequence=previous.sequence + 1 if previous else 1,
        previous_decision_id=previous.id if previous else None, decision=body.decision,
        payload_sha256=version.payload_sha256, artifact_sha256=version.artifact_sha256, reviewer_id=p.user_id,
        reason=body.reason, confirmations=body.confirmations.model_dump(), request_sha256=digest(body.model_dump()))
    s.add(row)
    s.flush()
    audit.record(s, "golden.release." + body.decision, actor_id=p.user_id, actor_name=p.username,
        target_type="golden_release_version", target_id=version.id,
        detail={"decision_id": row.id, "artifact_sha256": version.artifact_sha256})
    return to_dict(s, p, release, version_id=version.id)


def revoke(s, p, version_id, raw):
    body = RevokeIn.model_validate(raw)
    p = golden_profiles.actor(s, p, "golden.release.approve")
    release, version = _lock(s, p, version_id)
    previous = latest(s, version_id)
    if (previous and previous.decision == "revoke" and previous.request_sha256 == digest(body.model_dump())
            and previous.reviewer_id == p.user_id):
        return to_dict(s, p, release, version_id=version.id)
    if previous is None or previous.id != body.expected_decision_id or previous.decision != "approve":
        raise HTTPException(409, "golden_release_decision_conflict")
    row = GoldenReleaseDecision(release_version_id=version.id, sequence=previous.sequence + 1,
        previous_decision_id=previous.id, decision="revoke", payload_sha256=version.payload_sha256,
        artifact_sha256=version.artifact_sha256, reviewer_id=p.user_id, reason=body.reason,
        confirmations={}, request_sha256=digest(body.model_dump()))
    s.add(row)
    s.flush()
    audit.record(s, "golden.release.revoke", actor_id=p.user_id, actor_name=p.username,
        target_type="golden_release_version", target_id=version.id, detail={"decision_id": row.id})
    return to_dict(s, p, release, version_id=version.id)
