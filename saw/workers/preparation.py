"""Domain-owned recovery and cancellation before bounded queue admission."""
from __future__ import annotations

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from saw.core.application import audit
from saw.core.application.data_deletion import lock_investigation
from saw.core.application.identity import principal_of
from saw.core.application.investigations import Forbidden, NotFound, require
from saw.storage.db import utcnow
from saw.storage.generations import GenerationConflict, GenerationRef
from saw.storage.models import Job, User
from saw.workers.durable_queue import RECOVERABLE_STATES, resolve_task


def _abandon_generations(s: Session, job: Job, reason: str) -> None:
    from saw.event_generations.models import EventGeneration
    from saw.event_generations.service import abandon

    rows = list(s.scalars(select(EventGeneration).where(
        EventGeneration.job_id == job.id,
        EventGeneration.status.in_(("allocated", "ready")))))
    for gen in rows:
        ref = GenerationRef(gen.investigation_id, gen.id, gen.parent_revision,
                            gen.output_sha256, tuple(gen.storage_targets), False)
        abandon(s, ref, job_id=job.id, attempt=gen.attempt, reason=reason)


def _settle(s: Session, job: Job, state: str, code: str) -> None:
    from saw.analysis_runs.models import AnalysisRun
    from saw.analysis_runs.service import finish

    _abandon_generations(s, job, "cancelled" if state == "CANCELLED" else "failed")
    job.state, job.finished_at, job.current_item = state, utcnow(), ""
    if state == "FAILED":
        job.error = {"type": "AdmissionRejected", "code": code,
                     "message": "요청자의 권한 또는 원천 자료가 변경되어 작업을 시작하지 않았습니다."}
    if job.kind == "golden_export":
        from saw.knowledge.golden_jobs import _pending_clear
        _pending_clear(s, job)
    if state == "CANCELLED" and job.kind == "device_analysis":
        from saw.analysis_runs.scoped import cancel_queued
        cancel_queued(s, job)
    for run in s.scalars(select(AnalysisRun).where(AnalysisRun.job_id == job.id,
                                                   AnalysisRun.status == "running")):
        finish(s, run, status=state.lower(), detail={"error_type": code})
    audit.record(s, "job." + state.lower(), actor_id=job.requested_by,
                 target_type="job", target_id=job.id, investigation_id=job.investigation_id,
                 detail={"reason": code})


def prepare_job(s: Session, job: Job, *, recovering: bool) -> str | None:
    """Keep source-before-Job locking and leave transaction ownership to the runner."""
    if job.state not in RECOVERABLE_STATES:
        return None
    from saw.knowledge.golden_jobs import recover_input_pending, source_fence
    from saw.reports.models import JobSourceInvestigation

    sources = {job.investigation_id}
    if job.kind in {"golden_export", "report_export"}:
        sources.update(s.scalars(select(JobSourceInvestigation.investigation_id).where(
            JobSourceInvestigation.job_id == job.id)))
    if job.kind == "golden_export":
        sources.update((job.stages or {}).get("source_ids", []))
    try:
        with source_fence(s, sorted(sources), allow_deleting=True):
            s.refresh(job)
            if job.state not in RECOVERABLE_STATES or (not recovering and job.state != "QUEUED"):
                return None
            if job.cancel_requested:
                _settle(s, job, "CANCELLED", "cancel_requested")
                return None
            if recovering and recover_input_pending(s, job):
                return None
            # A live producer may still be committing its private Golden input.
            if job.kind == "golden_export" and (job.stages or {}).get("input_state") != "input_ready":
                return None
            actor = s.get(User, job.requested_by, populate_existing=True)
            if actor is None or actor.status != "active":
                raise Forbidden("requester_unavailable")
            principal = principal_of(actor)
            for inv_id in sorted(sources):
                lock_investigation(s, inv_id)
            if job.kind == "golden_export":
                from saw.knowledge.golden_jobs import require_job
                require_job(s, principal, job)
            elif job.kind == "report_export":
                from saw.reports.export_jobs import require_job
                require_job(s, principal, job)
            else:
                require(s, principal, "investigation.write", job.investigation_id)
            route = None
            if recovering and job.kind in {"ingest", "reprocess"}:
                from saw.event_generations.service import recover
                route = recover(s, job)
            route = route or resolve_task(job)
            if route is None:
                return None
            if recovering:
                job.state = "QUEUED"
                job.current_item = "recovered after restart"
            job.stages = {**(job.stages or {}), "_queue_task": route}
            return route
    except GenerationConflict as exc:
        if str(exc) != "generation_published_superseded":
            raise
        _settle(s, job, "FAILED", "generation_published_superseded")
        return None
    except (Forbidden, NotFound, HTTPException):
        _settle(s, job, "FAILED", "source_or_actor_unavailable")
        return None
