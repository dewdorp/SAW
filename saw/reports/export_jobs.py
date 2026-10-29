"""Bounded report artifacts from an exact frozen snapshot, with source ACL at every boundary."""
from __future__ import annotations

import hashlib
import tempfile
import time
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
from saw.reports import service
from saw.reports.models import JobSourceInvestigation
from saw.reports.schemas import ExportRequest
from saw.storage.db import session_scope, utcnow
from saw.storage.models import Job, User, UserSession
from saw.workers.pipeline import Cancelled, StaleLease
from saw.workers.runner import task

KIND = "report_export"
TERMINAL = {"COMPLETED", "FAILED", "CANCELLED"}
MAX_ARTIFACT_BYTES = 128 * 1024 * 1024
MAX_SECONDS = 120
MAX_PENDING_PER_USER = 8


def _actor(s, uid):
    user = s.get(User, uid, populate_existing=True)
    if user is None or user.status != "active":
        raise Forbidden("report_requester_unavailable")
    return principal_of(user)


def _admit(s, p):
    # Serialize this requester's submissions, including cross-investigation selections.
    s.execute(update(User).where(User.id == p.user_id).values(id=p.user_id)
              .execution_options(synchronize_session=False))


def _pending_limit(s, p):
    pending = s.scalar(select(func.count()).select_from(Job).where(
        Job.requested_by == p.user_id, Job.kind == KIND, Job.state.notin_(TERMINAL))) or 0
    if pending >= MAX_PENDING_PER_USER:
        raise HTTPException(429, "report_export_queue_full_wait_or_cancel")


def require_job(s, p, job):
    if job.kind != KIND:
        raise ValueError("report_job_kind_required")
    stage = (job.stages or {}).get(KIND) or {}
    report = service.get(s, p, job.investigation_id, stage.get("report_id"))
    if (stage.get("content_sha256") != report.content_sha256 or
            stage.get("scope") != report.content.get("scope")):
        raise ValueError("report_job_snapshot_corrupt")
    linked = set(s.scalars(select(JobSourceInvestigation.investigation_id).where(
        JobSourceInvestigation.job_id == job.id)))
    if linked != service.source_ids(report):
        raise ValueError("report_job_source_ledger_corrupt")
    return report


def _new(s, p, report, fmt, *, key=None, request_sha256=None, retry_of=None):
    stage = {"report_id": report.id, "anchor_investigation_id": report.investigation_id,
             "format": fmt, "scope": deepcopy(report.content["scope"]),
             "content_sha256": report.content_sha256, "artifact": None}
    job = Job(investigation_id=report.investigation_id, kind=KIND, state="QUEUED",
              requested_by=p.user_id, idempotency_key=key,
              stages={KIND: stage, "request_sha256": request_sha256, "retry_of": retry_of})
    s.add(job)
    s.flush()
    s.add_all(JobSourceInvestigation(job_id=job.id, investigation_id=x)
              for x in sorted(service.source_ids(report)))
    audit.record(s, "report.export_requested", actor_id=p.user_id, actor_name=p.username,
                 target_type="job", target_id=job.id, investigation_id=job.investigation_id,
                 detail={"report_id": report.id, "format": fmt, "retry_of": retry_of})
    return job


def submit(s, p, raw):
    request = ExportRequest.model_validate(raw)
    request_hash = digest(request.model_dump(exclude={"idempotency_key"}))
    _admit(s, p)
    old = s.scalar(select(Job).where(Job.requested_by == p.user_id,
                                     Job.idempotency_key == request.idempotency_key))
    if old is not None:
        if old.kind != KIND or (old.stages or {}).get("request_sha256") != request_hash:
            raise HTTPException(409, "report_export_idempotency_conflict")
        require_job(s, p, old)
        return old, False
    _pending_limit(s, p)
    report = service.create_scoped(s, p, request.scope.model_dump())
    return _new(s, p, report, request.format, key=request.idempotency_key,
                request_sha256=request_hash), True


def retry(s, p, old):
    _admit(s, p)
    _pending_limit(s, p)
    report = require_job(s, p, old)
    if old.state not in {"FAILED", "CANCELLED"}:
        raise HTTPException(409, "report_export_retry_requires_failed_or_cancelled")
    for item in report.content["scope"]["selections"]:
        require(s, p, "investigation.write", item["investigation_id"])
    return _new(s, p, report, old.stages[KIND]["format"],
                request_sha256=old.stages.get("request_sha256"), retry_of=old.id)


def _checkpoint(s, job_id, epoch, *, writing=False):
    job = s.get(Job, job_id)
    if job is None:
        raise StaleLease()
    # Reuse the snapshot's deterministic source-lock order, then refresh the lease.
    p = _actor(s, job.requested_by)
    report = require_job(s, p, job)
    s.refresh(job)
    if job.attempt != epoch:
        raise StaleLease()
    if job.cancel_requested or job.state == "CANCELLED":
        raise Cancelled()
    if job.state in TERMINAL:
        raise StaleLease()
    if writing:
        for item in report.content["scope"]["selections"]:
            require(s, p, "investigation.write", item["investigation_id"])
    return job, report


def render_artifact(content, path, fmt, *, cancelled):
    if cancelled():
        raise Cancelled()
    if fmt == "xlsx":
        from saw.reports.xlsx import write
        return write(content, path, cancelled=cancelled)
    if fmt != "html":
        raise ValueError("report_format_unsupported")
    from saw.reports.projection_html import render
    output = render(content, cancelled=cancelled).encode("utf-8")
    if len(output) > MAX_ARTIFACT_BYTES:
        raise ValueError("report_artifact_limit_split_selection")
    if cancelled():
        raise Cancelled()
    Path(path).write_bytes(output)
    return {"content_sha256": digest(content), "format": "html"}


def _file_digest(path):
    total, result = 0, hashlib.sha256()
    with open(path, "rb") as stream:
        while block := stream.read(1024 * 1024):
            total += len(block)
            if total > MAX_ARTIFACT_BYTES:
                raise ValueError("report_artifact_limit_split_selection")
            result.update(block)
    return total, result.hexdigest()


@task("report_export.run")
def run(job_id):
    epoch = None
    started = time.monotonic()
    try:
        with session_scope() as s:
            job = s.get(Job, job_id)
            if job is None or job.kind != KIND or job.state in TERMINAL:
                return
            # Even pre-claim failures belong to this observed attempt, never a newer worker.
            epoch = job.attempt
            p = _actor(s, job.requested_by)
            report = require_job(s, p, job)
            s.refresh(job)
            if job.state in TERMINAL:
                return
            epoch = job.attempt
            if job.cancel_requested:
                raise Cancelled()
            for item in report.content["scope"]["selections"]:
                require(s, p, "investigation.write", item["investigation_id"])
            job.attempt += 1
            epoch = job.attempt
            job.state, job.started_at, job.finished_at = "ANALYZING", utcnow(), None
            job.error = {}
            job.current_item = "저장한 보고서 버전으로 파일 작성 중"
            content = deepcopy(report.content)
            content_sha = report.content_sha256
            fmt = job.stages[KIND]["format"]
            version = report.version

        last_check = 0.0
        def cancelled():
            nonlocal last_check
            now = time.monotonic()
            if now - started > MAX_SECONDS:
                raise ValueError("report_export_time_limit_split_selection")
            if now - last_check >= 0.2:
                with session_scope() as s:
                    _checkpoint(s, job_id, epoch)
                last_check = now
            return False

        scratch = Path(container.get().settings.data_dir) / "scratch" / "report-export"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="attempt-", dir=scratch) as work:
            path = Path(work) / ("report." + fmt)
            manifest = render_artifact(content, path, fmt, cancelled=cancelled)
            if manifest.get("content_sha256") != content_sha:
                raise ValueError("report_writer_snapshot_mismatch")
            if len(canonical(manifest).encode("utf-8")) > 512 * 1024:
                raise ValueError("report_manifest_limit_split_selection")
            size, sha = _file_digest(path)
            # Before uploading, ensure this worker still owns its source-bound lease.
            with session_scope() as s:
                _checkpoint(s, job_id, epoch, writing=True)
            key = f"reports/{job_id}/{epoch}/{sha}.{fmt}"
            with path.open("rb") as stream:
                stored_size, stored_sha = container.get().objects.put_stream("saw-exports", key, stream)
            if (stored_size, stored_sha) != (size, sha):
                raise ValueError("report_object_write_mismatch")
            # Uploaded bytes are private until this transaction publishes their reference.
            with session_scope() as s:
                job, report = _checkpoint(s, job_id, epoch, writing=True)
                if report.content_sha256 != content_sha:
                    raise ValueError("report_snapshot_changed")
                artifact = {"filename": f"SAW-report-v{version}-{job_id[:8]}.{fmt}",
                            "bytes": size, "sha256": sha,
                            "download_url": f"/api/v1/report-export-jobs/{job_id}/download",
                            "manifest": manifest}
                job.stages = {**job.stages, KIND: {**job.stages[KIND], "artifact": artifact},
                              "report_object_key": key}
                job.state, job.finished_at = "COMPLETED", utcnow()
                job.current_item = "보고서 파일 생성 완료"
                audit.record(s, "report.export_completed", actor_id=job.requested_by,
                             target_type="job", target_id=job.id, investigation_id=job.investigation_id,
                             detail={"report_id": report.id, "bytes": size, "sha256": sha})
    except StaleLease:
        return
    except Exception as exc:  # noqa: BLE001 - task boundary records every failed attempt without publishing.
        with session_scope() as s:
            job = s.get(Job, job_id)
            if job is None or job.kind != KIND:
                return
            lock_investigation(s, job.investigation_id, allow_deleting=True)
            s.refresh(job)
            if epoch is not None and job.attempt != epoch:
                return
            if job.state in TERMINAL:
                return
            from saw.reports.xlsx import ReportCancelled
            stopped = isinstance(exc, (Cancelled, ReportCancelled)) or job.cancel_requested
            job.state, job.finished_at = ("CANCELLED" if stopped else "FAILED"), utcnow()
            job.error = {"type": type(exc).__name__, "message":
                         "보고서 생성을 중단했습니다. 권한·선택 범위·자료 상태를 확인한 뒤 다시 시도하세요."}
            job.current_item = ""
            job.stages = {**(job.stages or {}), KIND: {**((job.stages or {}).get(KIND) or {}),
                                                     "artifact": None}}
            audit.record(s, "report.export_" + job.state.lower(), actor_id=job.requested_by,
                         target_type="job", target_id=job.id, investigation_id=job.investigation_id,
                         detail={"error_type": type(exc).__name__})


def download_actor(s, p, *, session_id=None):
    """Refresh authority after I/O; cached roles and memberships are not evidence."""
    # Persist the ordinary auth last_seen update before expiring the identity map.
    s.flush()
    s.expire_all()
    actor = _actor(s, p.user_id)
    if session_id is not None:
        login = s.get(UserSession, session_id, populate_existing=True)
        if (login is None or login.user_id != actor.user_id or not login.mfa_passed or
                login.revoked_at is not None):
            raise Forbidden("report_download_session_unavailable")
        expiry = login.expires_at
        expiry = expiry.replace(tzinfo=UTC) if expiry.tzinfo is None else expiry.astimezone(UTC)
        if expiry <= utcnow():
            raise Forbidden("report_download_session_unavailable")
    return actor


def _download_reference(s, p, job_id):
    job = s.get(Job, job_id, populate_existing=True)
    if job is None or job.kind != KIND:
        raise NotFound("report export job not found")
    report = require_job(s, p, job)
    if job.state != "COMPLETED" or job.cancel_requested:
        raise HTTPException(409, "report_artifact_unavailable")
    stage = job.stages[KIND]
    artifact = stage.get("artifact")
    key = job.stages.get("report_object_key")
    if not artifact or not key:
        raise ValueError("report_artifact_missing")
    expected = f"reports/{job.id}/{job.attempt}/{artifact['sha256']}.{stage['format']}"
    if key != expected:
        raise ValueError("report_artifact_reference_corrupt")
    return {"artifact": deepcopy(artifact), "key": key, "format": stage["format"],
            "attempt": job.attempt, "report_id": report.id,
            "content_sha256": report.content_sha256}


def open_download(s, p, job_id, *, session_id=None):
    p = download_actor(s, p, session_id=session_id)
    frozen = _download_reference(s, p, job_id)
    artifact, key = frozen["artifact"], frozen["key"]
    # Object verification may be slow. It must not hold source/auth writer locks
    # that prevent another transaction from revoking access or cancelling a job.
    s.commit()
    output = tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024, mode="w+b")  # noqa: SIM115 - caller closes the streamed download.
    size, sha = 0, hashlib.sha256()
    try:
        with container.get().objects.open("saw-exports", key) as stream:
            while block := stream.read(1024 * 1024):
                size += len(block)
                if size > MAX_ARTIFACT_BYTES or size > artifact["bytes"]:
                    raise ValueError("report_artifact_size_mismatch")
                sha.update(block)
                output.write(block)
        if size != artifact["bytes"] or sha.hexdigest() != artifact["sha256"]:
            raise ValueError("report_artifact_digest_mismatch")
        current = download_actor(s, p, session_id=session_id)
        if _download_reference(s, current, job_id) != frozen:
            raise HTTPException(409, "report_artifact_reference_changed")
        output.seek(0)
        return output, artifact, frozen["format"]
    except Exception:
        output.close()
        raise
