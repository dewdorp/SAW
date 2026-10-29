"""Persisted holdout consumption; operator reports are never model execution."""
from __future__ import annotations
from fastapi import HTTPException
from sqlalchemy import select, update
from saw.core.application import audit
from saw.core.application.investigations import Forbidden, NotFound
from saw.core.application.provenance import digest
from saw.core.security.authz import can
from saw.knowledge import golden, golden_profiles, golden_releases
from saw.knowledge.golden_governance_models import GoldenHoldoutAttempt, GoldenHoldoutUse, GoldenReleaseVersion
from saw.knowledge.golden_models import GoldenVersion
from saw.knowledge.golden_schemas import AttemptIn, ResultIn
from saw.storage.db import utcnow


def _family(s, version):
    rows = [s.get(GoldenVersion, x["version_id"]) for x in version.request["examples"]]
    if any(row is None for row in rows):
        raise HTTPException(409, "golden_holdout_source_missing")
    return golden_releases.family_snapshot(s, rows, "holdout")


def get(s, p, ident, *, lock=False):
    p = golden_profiles.actor(s, p)
    row = s.get(GoldenHoldoutAttempt, ident, populate_existing=True)
    if row is None:
        raise NotFound("holdout attempt not found")
    if row.created_by != p.user_id and not can(p, "golden.evaluate.read"):
        raise NotFound("holdout attempt not found")
    golden_releases.authorize_sources(s, p, row.source_investigation_ids, lock=lock)
    if lock:
        s.execute(update(GoldenHoldoutAttempt).where(GoldenHoldoutAttempt.id == row.id).values(id=row.id)
                  .execution_options(synchronize_session=False))
        s.refresh(row)
    return row


def _related(s, row, *, consumed_only=True):
    query = select(GoldenHoldoutAttempt).where(GoldenHoldoutAttempt.id != row.id)
    if consumed_only:
        query = query.where(GoldenHoldoutAttempt.input_count > 0)
    sources = set(row.family_investigation_ids)
    families = set(row.family_ids)
    return [other for other in s.scalars(query) if
            sources & set(other.family_investigation_ids) or families & set(other.family_ids)]


def _no_repeat(s, row):
    if any(other.target_sha256 == row.target_sha256 for other in _related(s, row)):
        raise HTTPException(409, "holdout_repeat_requires_new_evaluation_policy")


def to_dict(s, p, row):
    row = get(s, p, row.id)
    p = golden_profiles.actor(s, p)
    version = s.get(GoldenReleaseVersion, row.release_version_id)
    readable = can(p, "golden.evaluate.read") and row.result is not None
    download = row.created_by == p.user_id
    try:
        golden_releases.authorize_version(s, p, version.id, "download")
        if row.input_count == 0:
            _no_repeat(s, row)
    except (Forbidden, NotFound, ValueError, HTTPException):
        download = False
    result = row.result or {"status": "not_submitted", "artifact_sha256": None, "summary": None, "recorded_at": None}
    return {"id": row.id, "release_id": version.release_id, "release_version_id": row.release_version_id,
        "target": {**row.target, "identity_status": "operator_declared"}, "purpose_text": row.purpose_text,
        "status": row.state, "family_snapshot_sha256": row.family_snapshot_sha256, "created_at": row.created_at,
        "input_access": {"first_at": row.input_first_at, "last_at": row.input_last_at, "count": row.input_count},
        "result": result,
        "answers_access": {"first_at": row.answers_first_at, "last_at": row.answers_last_at, "count": row.answers_count},
        "prior_family_use_count": len(_related(s, row)),
        "eligibility": {
            "download_input": {"enabled": download, "reasons": [] if download else ["golden_holdout_input_unavailable"]},
            "record_result": {"enabled": row.created_by == p.user_id and row.input_count > 0 and row.result is None and row.answers_count == 0,
                "reasons": [] if row.created_by == p.user_id and row.input_count > 0 and row.result is None and row.answers_count == 0
                    else ["golden_holdout_result_unavailable"]},
            "read_answers": {"enabled": readable, "reasons": [] if readable else ["golden_holdout_result_and_evaluator_required"]}},
        "limits": ["target_identity_operator_declared", "operator_report_is_not_model_execution"]}


def create(s, p, raw):
    body = AttemptIn.model_validate(raw)
    p = golden_profiles.actor(s, p)
    if not (can(p, "golden.release.create") or can(p, "golden.release.approve")):
        raise Forbidden("golden.release.create")
    auth = golden_releases.authorize_version(s, p, body.release_version_id, "download")
    version = auth["version"]
    if version.request["split"] != "holdout" or version.artifact_sha256 != body.expected_artifact_sha256:
        raise HTTPException(409, "golden_holdout_release_mismatch")
    golden_releases.authorize_sources(s, p, auth["source_investigation_ids"], lock=True)
    request_sha = digest(body.model_dump(exclude={"idempotency_key"}))
    existing = s.scalar(select(GoldenHoldoutAttempt).where(GoldenHoldoutAttempt.created_by == p.user_id,
        GoldenHoldoutAttempt.idempotency_key == body.idempotency_key))
    if existing:
        if existing.request_sha256 != request_sha:
            raise HTTPException(409, "golden_holdout_idempotency_conflict")
        return to_dict(s, p, existing)
    family, sha = _family(s, version)
    if sha != version.family_snapshot_sha256:
        raise HTTPException(409, "golden_release_family_changed")
    row = GoldenHoldoutAttempt(release_version_id=version.id, target=body.target.model_dump(),
        target_sha256=body.target.artifact_sha256, request_sha256=request_sha, idempotency_key=body.idempotency_key,
        purpose_text=body.purpose_text, family_ids=family["family_ids"], family_investigation_ids=family["investigation_ids"],
        family_snapshot_sha256=sha, source_investigation_ids=version.source_investigation_ids, created_by=p.user_id)
    s.add(row)
    s.flush()
    _no_repeat(s, row)
    return to_dict(s, p, row)


def _use(s, p, row, action, payload):
    s.add(GoldenHoldoutUse(attempt_id=row.id, action=action, payload=payload,
        payload_sha256=digest(payload), actor_id=p.user_id))
    audit.record(s, "golden.holdout." + action, actor_id=p.user_id, actor_name=p.username,
        target_type="golden_holdout_attempt", target_id=row.id, detail={"release_version_id": row.release_version_id})


def consume_input(s, p, attempt_id, version_id, artifact_sha256):
    row = get(s, p, attempt_id, lock=True)
    if row.created_by != p.user_id:
        raise Forbidden("golden_holdout_creator_required")
    version = golden_releases.authorize_version(s, p, version_id, "download")["version"]
    if row.release_version_id != version_id or version.artifact_sha256 != artifact_sha256:
        raise HTTPException(409, "golden_holdout_input_mismatch")
    family, sha = _family(s, version)
    if sha != row.family_snapshot_sha256:
        raise HTTPException(409, "golden_holdout_family_changed")
    if not row.input_count:
        _no_repeat(s, row)
    now = utcnow()
    row.input_count += 1
    row.input_first_at = row.input_first_at or now
    row.input_last_at = now
    if row.state == "reserved":
        row.state = "input_accessed"
    _use(s, p, row, "input_read", {"artifact_sha256": artifact_sha256, "target_sha256": row.target_sha256})
    s.flush()
    return row


def record_result(s, p, ident, raw):
    body = ResultIn.model_validate(raw)
    row = get(s, p, ident, lock=True)
    if row.created_by != p.user_id:
        raise Forbidden("golden_holdout_creator_required")
    content = {"artifact_sha256": body.artifact_sha256, "summary": body.summary}
    sha = digest(content)
    if row.result:
        if row.result_sha256 == sha and body.expected_result_sha256 in (None, sha):
            return to_dict(s, p, row)
        raise HTTPException(409, "golden_holdout_result_immutable")
    if body.expected_result_sha256 is not None or row.input_count == 0 or row.answers_count:
        raise HTTPException(409, "golden_holdout_input_before_result_required")
    row.result = {"status": "operator_reported", **content, "recorded_at": utcnow().isoformat()}
    row.result_sha256, row.state = sha, "result_recorded"
    _use(s, p, row, "result_recorded", {"result_sha256": sha, "status": "operator_reported"})
    s.flush()
    return to_dict(s, p, row)


def answers(s, p, ident):
    from saw.knowledge.golden_conversion import evaluator_jsonl
    p = golden_profiles.actor(s, p, "golden.evaluate.read")
    row = get(s, p, ident, lock=True)
    if row.result is None:
        raise HTTPException(409, "golden_holdout_result_required")
    version = golden_releases.authorize_version(s, p, row.release_version_id, "read")["version"]
    value = golden_releases._collect(s, p, version.request, freeze=True, require_create=False)
    if value["family_snapshot_sha256"] != row.family_snapshot_sha256:
        raise HTTPException(409, "golden_holdout_family_changed")
    data = evaluator_jsonl(value["examples"])
    if len(data) > golden.MAX_EXPORT:
        raise HTTPException(413, "golden_evaluator_export_limit")
    now = utcnow()
    row.answers_count += 1
    row.answers_first_at = row.answers_first_at or now
    row.answers_last_at, row.state = now, "answers_accessed"
    _use(s, p, row, "answers_read", {"result_sha256": row.result_sha256})
    s.flush()
    return data


def list_for(s, p, *, limit=50, cursor=None):
    p = golden_profiles.actor(s, p)
    if not 1 <= limit <= 100:
        raise ValueError("golden_list_limit")
    after = golden_profiles.cursor_id(cursor)
    query = select(GoldenHoldoutAttempt).order_by(GoldenHoldoutAttempt.id)
    if after:
        query = query.where(GoldenHoldoutAttempt.id > after)
    items = []
    for row in s.scalars(query):
        try:
            items.append(to_dict(s, p, row))
        except (Forbidden, NotFound):
            continue
        if len(items) > limit:
            break
    return golden_profiles.page(items, limit)
