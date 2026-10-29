"""Private source-bound Golden artifact jobs with bounded public progress."""
from __future__ import annotations

import hashlib
import io
import json
import secrets
import tempfile
import time
from contextlib import contextmanager
from copy import deepcopy
from datetime import UTC
from pathlib import Path

from fastapi import HTTPException
from sqlalchemy import func, select, update

from saw import container
from saw.core.application import audit
from saw.core.application.data_deletion import lock_investigation
from saw.core.application.identity import principal_of
from saw.core.application.investigations import Forbidden, NotFound, require
from saw.core.application.provenance import canonical, digest
from saw.core.security.authz import can
from saw.knowledge.golden_projection import GoldenBuildFailure, failure_message, safe_failure_reasons
from saw.reports.models import JobSourceInvestigation
from saw.storage.db import session_scope, utcnow
from saw.storage.models import Investigation, Job, User, UserSession
from saw.workers.pipeline import Cancelled, StaleLease
from saw.workers.runner import task

KIND = "golden_export"
TERMINAL = {"COMPLETED", "FAILED", "CANCELLED"}
MAX_INPUT_BYTES = 20 * 1024 * 1024
MAX_ARTIFACT_BYTES = 20 * 1024 * 1024
MAX_SECONDS = 120
MAX_PENDING_PER_USER = 8


def public_stage(job, *, can_manage=False, can_retry=False):
    """Never copy internal input references, mappings or answer data to Job DTOs."""
    stage = (job.stages or {}).get(KIND) or {}
    artifact = stage.get("artifact")
    artifact = ({key: artifact[key] for key in
                 ("filename", "bytes", "sha256", "download_url") if key in artifact}
                if isinstance(artifact, dict) else None)
    return {"release_id": stage.get("release_id"), "version_id": stage.get("version_id"),
            "state": job.state, "progress": {"done": job.events_done or 0,
                "total": job.events_total_est or 0},
            "summary": {"mode": stage.get("mode"), "example_count": stage.get("example_count", 0)},
            "actions": {
                "cancel": {"enabled": can_manage and job.state not in TERMINAL,
                           "reasons": [] if can_manage else ["golden_job_manage_required"]},
                "retry": {"enabled": can_retry and job.state in {"FAILED", "CANCELLED"} and
                          (job.stages or {}).get("input_state") == "input_ready",
                          "reasons": [] if can_manage else ["golden_job_manage_required"]}},
            "failure_reasons": safe_failure_reasons(stage.get("failure_reasons")) if job.state == "FAILED" else [],
            "artifact": artifact}


def actor(s, user_id, *, session_id=None):
    s.flush()
    s.expire_all()
    user = s.get(User, user_id, populate_existing=True)
    if user is None or user.status != "active":
        raise Forbidden("golden_actor_unavailable")
    if session_id:
        login = s.get(UserSession, session_id, populate_existing=True)
        if login is None or login.user_id != user_id or not login.mfa_passed or login.revoked_at:
            raise Forbidden("golden_session_unavailable")
        expiry = login.expires_at
        expiry = expiry.replace(tzinfo=UTC) if expiry.tzinfo is None else expiry.astimezone(UTC)
        if expiry <= utcnow():
            raise Forbidden("golden_session_unavailable")
    return principal_of(user)


def require_job(s, p, job):
    current = actor(s, p.user_id)
    if job.kind != KIND or not can(current, "knowledge.read"):
        raise Forbidden("golden_job_read_required")
    sources = set(s.scalars(select(JobSourceInvestigation.investigation_id).where(
        JobSourceInvestigation.job_id == job.id)))
    if not sources or sources != set((job.stages or {}).get("source_ids", [])):
        raise ValueError("golden_job_source_ledger_corrupt")
    for inv_id in sorted(sources):
        require(s, current, "investigation.read", inv_id)
    return current


def can_manage(p, job):
    return ((p.user_id == job.requested_by and can(p, "golden.release.create"))
            or can(p, "golden.release.approve"))


@contextmanager
def source_fence(s, sources, *, allow_deleting=False):
    previous = s.info.get("snapshot_source_ids")
    ids = set(sources)
    try:
        for inv_id in sorted(ids):
            lock_investigation(s, inv_id, allow_deleting=allow_deleting)
        s.info["snapshot_source_ids"] = ids
        yield
    finally:
        if previous is None:
            s.info.pop("snapshot_source_ids", None)
        else:
            s.info["snapshot_source_ids"] = previous


def _admit(s, p):
    s.execute(update(User).where(User.id == p.user_id).values(id=p.user_id)
              .execution_options(synchronize_session=False))
    count = s.scalar(select(func.count()).select_from(Job).where(
        Job.requested_by == p.user_id, Job.kind == KIND, Job.state.notin_(TERMINAL))) or 0
    if count >= MAX_PENDING_PER_USER:
        raise HTTPException(429, "golden_export_queue_full_wait_or_cancel")


def _request(raw):
    from saw.knowledge.golden_releases import normalize_request
    return normalize_request(raw)


def _read_ref(ref, *, limit=MAX_INPUT_BYTES):
    if (not isinstance(ref, dict) or ref.get("bucket") != "saw-exports"
            or not isinstance(ref.get("key"), str) or not ref["key"].startswith("golden/")
            or ".." in ref["key"] or "\\" in ref["key"]
            or type(ref.get("size_bytes")) is not int or not 0 <= ref["size_bytes"] <= limit):
        raise ValueError("golden_private_reference_invalid")
    data = bytearray()
    hasher = hashlib.sha256()
    with container.get().objects.open(ref["bucket"], ref["key"]) as stream:
        while block := stream.read(65536):
            data.extend(block); hasher.update(block)
            if len(data) > limit or len(data) > ref["size_bytes"]:
                raise ValueError("golden_private_size_mismatch")
    if len(data) != ref["size_bytes"] or hasher.hexdigest() != ref.get("sha256"):
        raise ValueError("golden_private_digest_mismatch")
    return bytes(data)


def _input_reference(job):
    stages = job.stages or {}
    reference = stages.get("input_ref")
    expected = stages.get("input_expected_sha256")
    key = f"golden/{job.id}/inputs/{expected}.json"
    if (not isinstance(expected, str) or len(expected) != 64
            or not isinstance(reference, dict) or stages.get("input_key") != key
            or reference.get("key") != key or reference.get("sha256") != expected):
        raise ValueError("golden_input_ownership_changed")
    return deepcopy(reference)


def _put_bytes(key, data):
    if len(data) > MAX_INPUT_BYTES:
        raise HTTPException(413, "golden_private_size_limit")
    sha = hashlib.sha256(data).hexdigest()
    size, stored_sha = container.get().objects.put_stream("saw-exports", key, io.BytesIO(data))
    if (size, stored_sha) != (len(data), sha):
        raise ValueError("golden_private_write_mismatch")
    ref = {"bucket": "saw-exports", "key": key, "size_bytes": size, "sha256": sha}
    _read_ref(ref)
    return ref


def _pending_clear(s, job):
    from saw.knowledge.golden_governance_models import GoldenRelease
    release_id = (job.stages or {}).get(KIND, {}).get("release_id")
    s.execute(update(GoldenRelease).where(GoldenRelease.id == release_id,
        GoldenRelease.pending_job_id == job.id).values(pending_job_id=None)
        .execution_options(synchronize_session=False))


def recover_input_pending(s, job):
    if job.kind == KIND and job.state not in TERMINAL and job.stages.get("input_state") != "input_ready":
        job.attempt += 1
        job.state, job.finished_at = "FAILED", utcnow()
        job.error = {"type": "InputIncomplete", "message": "비공개 입력 저장이 완료되지 않았습니다. 새 요청을 만드세요."}
        job.current_item = ""
        _pending_clear(s, job)
        return True
    return False


def _fail(job_id, observed_attempt, exc):
    with session_scope() as s:
        job = s.get(Job, job_id)
        if job is None or job.kind != KIND:
            return
        with source_fence(s, job.stages.get("source_ids", []), allow_deleting=True):
            s.refresh(job)
            if job.attempt != observed_attempt or job.state in TERMINAL:
                return
            stopped = isinstance(exc, Cancelled) or job.cancel_requested
            job.state, job.finished_at = ("CANCELLED" if stopped else "FAILED"), utcnow()
            job.current_item = ""
            reasons = safe_failure_reasons(exc.reasons) if isinstance(exc, GoldenBuildFailure) and not stopped else []
            job.error = {"type": "GoldenBuildFailure" if reasons else "BuildError",
                         "message": failure_message(reasons), "reasons": reasons}
            job.stages = {**job.stages, KIND: {**job.stages.get(KIND, {}), "failure_reasons": reasons}}
            _pending_clear(s, job)
            audit.record(s, "golden.export_" + job.state.lower(), actor_id=job.requested_by,
                         target_type="job", target_id=job.id, investigation_id=job.investigation_id,
                         detail={"error_type": type(exc).__name__})


def _new(s, p, request, preflight, release, frozen, *, retry_of=None, key=None):
    frozen = deepcopy(frozen)
    if "private_context" not in frozen:
        frozen["private_context"] = {"mapping_seed": secrets.token_hex(32),
            "release_id": release.id, "created_at": utcnow().isoformat()}
    data = canonical(frozen).encode("utf-8")
    if len(data) > MAX_INPUT_BYTES:
        raise HTTPException(413, "golden_frozen_input_limit")
    sha = hashlib.sha256(data).hexdigest()
    job = Job(investigation_id=preflight["anchor_investigation_id"], kind=KIND, state="QUEUED",
              requested_by=p.user_id, idempotency_key=key,
              stages={KIND: {"release_id": release.id, "version_id": None, "artifact": None,
                  "mode": request["applicability_request"]["mode"], "example_count": len(request["examples"])},
                  "build_request": request, "request_sha256": preflight["request_sha256"],
                  "source_ids": sorted(preflight["source_investigation_ids"]),
                  "source_epochs": frozen["source_epochs"], "input_state": "input_pending",
                  "input_expected_sha256": sha, "retry_of": retry_of})
    s.add(job); s.flush()
    job.stages = {**job.stages, "input_key": f"golden/{job.id}/inputs/{sha}.json"}
    release.pending_job_id = job.id
    s.add_all(JobSourceInvestigation(job_id=job.id, investigation_id=source)
              for source in preflight["source_investigation_ids"])
    audit.record(s, "golden.export_requested", actor_id=p.user_id, actor_name=p.username,
                 target_type="job", target_id=job.id, investigation_id=job.investigation_id,
                 detail={"release_id": release.id, "example_count": len(request["examples"]),
                         "request_sha256": preflight["request_sha256"], "retry_of": retry_of})
    return job, data


def _checkpoint(s, job_id, epoch, *, require_running=True):
    from saw.knowledge import golden_releases
    job = s.get(Job, job_id, populate_existing=True)
    if job is None or job.attempt != epoch:
        raise StaleLease("golden_worker_superseded")
    if job.cancel_requested or job.state == "CANCELLED":
        raise Cancelled("golden_export_cancelled")
    if job.state in TERMINAL or (require_running and job.state != "ANALYZING"):
        raise StaleLease("golden_worker_not_running")
    p = require_job(s, actor(s, job.requested_by), job)
    if not can(p, "golden.release.create"):
        raise Forbidden("golden_release_create_required")
    before = golden_releases.preflight_sources(s, p, job.stages["build_request"])
    if (before["request_sha256"] != job.stages["request_sha256"]
            or sorted(before["source_investigation_ids"]) != sorted(job.stages["source_ids"])):
        raise HTTPException(409, "golden_build_source_changed")
    for inv_id, expected in job.stages["source_epochs"].items():
        inv = s.get(Investigation, inv_id, populate_existing=True)
        if inv is None or int((inv.settings or {}).get("data_epoch", 0)) != expected:
            raise HTTPException(409, "golden_build_source_changed")
    return job, p


def _store_input(s, job, data):
    jid, attempt, key = job.id, job.attempt, job.stages["input_key"]
    s.commit()
    try:
        reference = _put_bytes(key, data)
        with source_fence(s, job.stages["source_ids"]):
            current, _ = _checkpoint(s, jid, attempt, require_running=False)
            from saw.knowledge.golden_governance_models import GoldenRelease
            release = s.get(GoldenRelease, current.stages[KIND]["release_id"], populate_existing=True)
            if (current.state != "QUEUED" or current.stages["input_state"] != "input_pending"
                    or release is None or release.pending_job_id != jid
                    or reference["sha256"] != current.stages["input_expected_sha256"]):
                raise HTTPException(409, "golden_input_reservation_changed")
            current.stages = {**current.stages, "input_state": "input_ready", "input_ref": reference}
        s.commit()
    except Exception as exc:  # noqa: BLE001 - persist failure while preserving the last published version
        s.rollback()
        _fail(jid, attempt, exc)
    s.expire_all()
    return s.get(Job, jid)


def _admission_sources(s, p, release_id, new_sources):
    """Old current sources fence pointer replacement, but never enter the new artifact ledger."""
    from saw.knowledge import golden_releases
    from saw.knowledge.golden_governance_models import GoldenRelease
    ids = set(new_sources)
    if release_id is not None:
        release = s.get(GoldenRelease, release_id, populate_existing=True)
        if release is None:
            raise NotFound("release not found")
        if release.current_version_id:
            current = golden_releases.authorize_version(s, p, release.current_version_id, "read")
            ids.update(current["source_investigation_ids"])
    if len(ids) > 1000:
        raise HTTPException(413, "golden_source_limit")
    return ids


def submit(s, p, raw, *, release_id=None):
    from saw.knowledge import golden_releases
    request = _request(raw)
    p = actor(s, p.user_id)
    if not can(p, "golden.release.create"):
        raise Forbidden("golden_release_create_required")
    # Serialize idempotency before the queue limit so replay never consumes another slot.
    s.execute(update(User).where(User.id == p.user_id).values(id=p.user_id)
              .execution_options(synchronize_session=False))
    wanted = golden_releases.request_hash(request)
    old = s.scalar(select(Job).where(Job.requested_by == p.user_id,
                                     Job.idempotency_key == request["idempotency_key"]))
    if old is not None:
        if (old.kind != KIND or old.stages.get("request_sha256") != wanted
                or (release_id is not None and old.stages[KIND]["release_id"] != release_id)):
            raise HTTPException(409, "golden_export_idempotency_conflict")
        require_job(s, p, old)
        return old, False
    _admit(s, p)
    preflight = golden_releases.preflight_sources(s, p, request)
    admission_sources = _admission_sources(s, p, release_id, preflight["source_investigation_ids"])
    with source_fence(s, admission_sources):
        release = golden_releases.reserve_build(s, p, request, release_id=release_id)
        frozen = golden_releases.freeze_build(s, p, request)
        job, data = _new(s, p, request, preflight, release, frozen, key=request["idempotency_key"])
    return _store_input(s, job, data), True


def retry(s, p, old):
    from saw.knowledge import golden_releases
    p = require_job(s, p, old)
    if p.user_id != old.requested_by or not can(p, "golden.release.create"):
        raise Forbidden("golden_job_retry_requires_creator")
    if old.state not in {"FAILED", "CANCELLED"} or old.stages.get("input_state") != "input_ready":
        raise HTTPException(409, "golden_retry_requires_verified_frozen_input")
    reference, old_id = _input_reference(old), old.id
    release_id = old.stages[KIND]["release_id"]
    s.commit()
    frozen = json.loads(_read_ref(reference).decode("utf-8"))
    p = actor(s, p.user_id)
    _admit(s, p)
    request = frozen["request"]
    preflight = golden_releases.preflight_sources(s, p, request)
    admission_sources = _admission_sources(s, p, release_id, preflight["source_investigation_ids"])
    with source_fence(s, admission_sources):
        latest = golden_releases.freeze_build(s, p, request)
        if digest(latest) != digest({k:v for k,v in frozen.items() if k != "private_context"}):
            raise HTTPException(409, "golden_retry_source_changed")
        release = golden_releases.reserve_build(s, p, request, release_id=release_id)
        job, data = _new(s, p, request, preflight, release, frozen, retry_of=old_id)
    return _store_input(s, job, data)


def cancel(s, p, job):
    p = require_job(s, p, job)
    if not can_manage(p, job):
        raise Forbidden("golden_job_manage_required")
    with source_fence(s, job.stages["source_ids"]):
        s.refresh(job)
        if job.state in TERMINAL:
            raise HTTPException(409, "golden_job_terminal_use_release_revocation")
        job.cancel_requested = True
        if job.state == "QUEUED":
            job.state, job.finished_at = "CANCELLED", utcnow()
            _pending_clear(s, job)
        audit.record(s, "golden.export_cancel_requested", actor_id=p.user_id,
                     target_type="job", target_id=job.id, investigation_id=job.investigation_id)
    return job


@task("golden_export.run")
def run(job_id):
    epoch = None
    started = time.monotonic()
    try:
        with session_scope() as s:
            job = s.get(Job, job_id)
            if job is None or job.kind != KIND or job.state in TERMINAL:
                return
            epoch = job.attempt
            with source_fence(s, job.stages["source_ids"]):
                s.refresh(job)
                if job.attempt != epoch or (job.state != "QUEUED" and job.current_item != "recovered after restart"):
                    return
                if recover_input_pending(s, job):
                    return
                job, p = _checkpoint(s, job_id, epoch, require_running=False)
                reference = _input_reference(job)
                claimed_attempt = job.attempt + 1
                job.attempt = claimed_attempt
                job.state, job.started_at, job.finished_at = "ANALYZING", utcnow(), None
                job.error = {}
                job.current_item = "승인 후보 골든셋 파일 생성 중"
        epoch = claimed_attempt
        frozen = json.loads(_read_ref(reference).decode("utf-8"))
        last_check = 0.0
        def cancelled():
            nonlocal last_check
            now = time.monotonic()
            if now-started > MAX_SECONDS:
                raise ValueError("golden_export_time_limit")
            if now-last_check >= 0.1:
                with session_scope() as s:
                    _checkpoint(s, job_id, epoch)
                last_check = now
            return False
        cancelled()
        from saw.knowledge.golden_artifact import build_release
        from saw.knowledge.golden_projection import prepare_release_inputs
        inputs = prepare_release_inputs(frozen["request"], frozen["examples"], frozen["profiles"],
                    cancelled=cancelled, private_context=frozen["private_context"])
        if frozen["request"]["applicability_request"]["mode"] == "full_recalculation":
            from saw.knowledge.golden_capture import capture_complete_scope
            from saw.knowledge.golden_job_source import source_state
            captured_bytes = 0
            for example in frozen["examples"]:
                scope = example["complete_scope"]
                capture = capture_complete_scope(container.get().events, scope,
                    source_state=lambda scope=scope:source_state(job_id, epoch, scope), cancelled=cancelled)
                captured_bytes += capture.size_bytes
                if captured_bytes > MAX_INPUT_BYTES:
                    raise HTTPException(413, "golden_capture_aggregate_limit")
                inputs["captures"][example["version_id"]] = capture
        scratch = Path(container.get().settings.data_dir)/"scratch"/"golden-export"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="attempt-", dir=scratch) as work:
            path = Path(work)/"release.zip"
            result = build_release(inputs, path, cancelled=cancelled)
            from saw.knowledge.golden_archive import inspect_archive
            with path.open("rb") as stream:
                inspect_archive(stream, expected_manifest=result["manifest"],
                                holdout=frozen["request"]["split"] == "holdout", cancelled=cancelled)
            data = path.read_bytes()
            if (len(data) > MAX_ARTIFACT_BYTES or len(data) != result["size_bytes"]
                    or hashlib.sha256(data).hexdigest() != result["artifact_sha256"]):
                raise ValueError("golden_builder_artifact_mismatch")
            cancelled()
            artifact = _put_bytes(f"golden/{job_id}/{epoch}/artifact/{result['artifact_sha256']}.zip", data)
            mapping = result.get("private_mapping")
            mapping_ref = None
            if mapping is not None:
                encoded = canonical(mapping["content"]).encode("utf-8")
                if len(encoded) != mapping["size_bytes"] or hashlib.sha256(encoded).hexdigest() != mapping["sha256"]:
                    raise ValueError("golden_mapping_digest_mismatch")
                cancelled()
                mapping_ref = _put_bytes(f"golden/{job_id}/{epoch}/mapping/{mapping['sha256']}.json", encoded)
            cancelled()
            with session_scope() as s:
                with source_fence(s, frozen["source_investigation_ids"]):
                    job, p = _checkpoint(s, job_id, epoch)
                    from saw.knowledge import golden_releases
                    from saw.knowledge.golden_governance_models import GoldenRelease
                    release = s.get(GoldenRelease, job.stages[KIND]["release_id"], populate_existing=True)
                    latest = golden_releases.freeze_build(s, p, frozen["request"])
                    if digest(latest) != digest({k:v for k,v in frozen.items() if k != "private_context"}):
                        raise HTTPException(409, "golden_build_snapshot_changed")
                    refs = {"artifact":artifact, "mapping":mapping_ref, "frozen_inputs":reference}
                    version = golden_releases.publish_version(s, p, release, job, {**result, "frozen_inputs": frozen}, refs)
                    stage = {**job.stages[KIND], "version_id": version.id,
                        "artifact":{"filename":f"SAW-golden-v{version.revision}-{version.id[:8]}.zip",
                            "bytes":version.size_bytes, "sha256":version.artifact_sha256,
                            "download_url":f"/api/v1/knowledge/golden/releases/{release.id}/versions/{version.id}/download"}}
                    job.stages = {**job.stages, KIND:stage}
                    job.state, job.finished_at = "COMPLETED", utcnow()
                    job.current_item = "골든셋 파일 생성 완료 · 독립 반출 승인 필요"
                    audit.record(s,"golden.export_completed",actor_id=p.user_id,
                        target_type="job",target_id=job.id,investigation_id=job.investigation_id,
                        detail={"release_id":release.id,"version_id":version.id,
                                "sha256":version.artifact_sha256,"bytes":version.size_bytes})
    except StaleLease:
        return
    except Exception as exc:  # noqa: BLE001 - persist failure while preserving the last published version
        if epoch is not None:
            _fail(job_id, epoch, exc)
