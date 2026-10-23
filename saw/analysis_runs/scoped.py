"""Independent snapshot-only firewall jobs over pinned investigation query scopes."""
from __future__ import annotations

import time
from copy import deepcopy
from datetime import datetime
from typing import Literal

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import func, select

from saw import container
from saw.analysis_runs import service
from saw.analysis_runs.models import AnalysisRun
from saw.behavior.service import source_manifest
from saw.core.application import audit
from saw.core.application.data_deletion import lock_investigation
from saw.core.application.identity import principal_of
from saw.core.application.investigations import Forbidden, require
from saw.core.application.provenance import canonical, digest
from saw.core.schemas.query import Filter, TimeRange
from saw.detection.runtime import run_for_request
from saw.detection.runtime_capture import authorize, capture
from saw.detection.specs import get_spec
from saw.knowledge.golden import masked
from saw.storage.db import session_scope, utcnow
from saw.storage.models import Investigation, Job, User
from saw.workers.pipeline import Cancelled, StaleLease
from saw.workers.runner import task

KIND = "device_analysis"
TERMINAL = ("COMPLETED", "FAILED", "CANCELLED")
MAX_EVENTS = 1_000_000
MAX_RESULTS = 100
MAX_SECONDS = 120
MAX_RESULT_BYTES = 3 * 1024 * 1024


class ScopedRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    detector_id: Literal["fw.observation", "waf.observation", "ips.observation", "ddos.observation", "ndr.observation"] | None = None
    org_unit_id: str | None = Field(None, min_length=1, max_length=36)
    device_id: str | None = Field(None, min_length=1, max_length=36)
    filters: list[Filter] = Field(default_factory=list, max_length=30)
    time: TimeRange | None = None
    idempotency_key: str | None = Field(None, min_length=1, max_length=128)

    @model_validator(mode="after")
    def bounded(self):
        if len(canonical(self.model_dump()).encode()) > 32768:
            raise ValueError("device_analysis_request_too_large")
        if self.time:
            times = []
            for raw in (self.time.start, self.time.end):
                if raw is None:
                    times.append(None)
                    continue
                parsed = datetime.fromisoformat(raw)
                if parsed.tzinfo is None:
                    raise ValueError("device_analysis_time_timezone_required")
                times.append(parsed)
            if all(times) and times[0] >= times[1]:
                raise ValueError("device_analysis_time_range_invalid")
        return self


def _idle(s, inv_id):
    # Only read-only analysis jobs are excluded. Ingest/reprocess/reanalyze still block.
    active = s.scalar(select(Job.id).where(Job.investigation_id == inv_id,
        Job.kind.notin_(("behavior", KIND, "report_export", "golden_export")), Job.state.notin_(TERMINAL)).limit(1))
    if active:
        raise HTTPException(409, "device_analysis_source_processing_active")


def _manifest(s, inv_id):
    result = source_manifest(s, inv_id)
    readonly_ids = set(s.scalars(select(Job.id).where(Job.investigation_id == inv_id, Job.kind == KIND)))
    result["source_jobs"] = [j for j in result["source_jobs"] if j["id"] not in readonly_ids]
    inv = s.get(Investigation, inv_id)
    result.update(org_unit_id=inv.org_unit_id, org_unit=inv.org_unit,
                  normalization_version="saw.observation/1")
    return result


def _new_run(s, job, request):
    number = (s.scalar(select(func.max(AnalysisRun.version)).where(
        AnalysisRun.investigation_id == job.investigation_id)) or 0) + 1
    manifest = _manifest(s, job.investigation_id)
    actor = s.get(User, job.requested_by)
    if actor is None or actor.status != "active":
        raise Forbidden("device_analysis_requester_unavailable")
    manifest["runtime_pin"] = capture(s, principal_of(actor), job.investigation_id, request)
    run = AnalysisRun(investigation_id=job.investigation_id, job_id=job.id,
        version=number, created_by=job.requested_by, input_manifest=manifest,
        input_sha256=digest(manifest), scope=deepcopy(request))
    s.add(run)
    s.flush()
    job.stages = {**job.stages, "analysis_run_id": run.id}
    return run


def submit(s, p, inv_id, raw):
    require(s, p, "investigation.write", inv_id)
    body = ScopedRequest.model_validate(raw)
    request = body.model_dump(exclude={"idempotency_key"}, exclude_none=True)
    lock_investigation(s, inv_id)
    if body.idempotency_key:
        old = s.scalar(select(Job).where(Job.requested_by == p.user_id,
                                         Job.idempotency_key == body.idempotency_key))
        if old:
            if old.kind != KIND or old.investigation_id != inv_id or (
                    old.stages or {}).get("device_analysis_request") != request:
                raise HTTPException(409, "device_analysis_idempotency_conflict")
            return old, False
    if body.org_unit_id:
        from saw.source_context.service import org_by_id
        org_by_id(s, body.org_unit_id)
    if body.device_id:
        from saw.source_context.models import Device
        dev = s.get(Device, body.device_id)
        if dev is None or dev.investigation_id != inv_id:
            raise ValueError("device_analysis_device_outside_investigation")
    _idle(s, inv_id)
    job = Job(investigation_id=inv_id, kind=KIND, requested_by=p.user_id,
        idempotency_key=body.idempotency_key, stages={"device_analysis_request": request,
            "requested": {"by": p.user_id, "name": p.username, "action": KIND}})
    s.add(job)
    s.flush()
    run = _new_run(s, job, request)
    audit.record(s, "device_analysis.submit", actor_id=p.user_id, actor_name=p.username,
        target_type="job", target_id=job.id, investigation_id=inv_id,
        detail={"scope_sha256": digest(request), "analysis_run_id": run.id})
    return job, True


def _authorized(s, job):
    user = s.get(User, job.requested_by)
    if user is None or user.status != "active":
        raise Forbidden("device_analysis_requester_unavailable")
    require(s, principal_of(user), "investigation.write", job.investigation_id)
    return principal_of(user)


def _events(inv_id, request):
    filters = [Filter.model_validate(f) for f in request["filters"]]
    for name in ("org_unit_id", "device_id"):
        if request.get(name):
            filters.append(Filter(field="ext.observation.context." + name, value=request[name]))
    selected_time = TimeRange.model_validate(request["time"]) if request.get("time") else None
    # The adapter always applies investigation_id, regardless of user filter contents.
    return container.get().events.iterate(inv_id, filters, selected_time, batch=500)


@task("device_analysis.run")
def device_analysis_run(job_id: str):
    epoch = None
    run_id = None
    started = time.monotonic()
    try:
        with session_scope() as s:
            job = s.get(Job, job_id)
            if job is None:
                return
            lock_investigation(s, job.investigation_id)
            s.refresh(job)
            if job.kind != KIND or job.state not in ("QUEUED", "ANALYZING", "PARSING"):
                return
            # Only a queued job may claim a fresh lease; live deliveries cannot steal work.
            if job.state != "QUEUED" and job.current_item != "recovered after restart":
                return
            epoch = job.attempt = (job.attempt or 0) + 1
            request = deepcopy(job.stages["device_analysis_request"])
            detector_id = request.get("detector_id") or "fw.observation"
            engine_version = get_spec(detector_id)["engine"]["version"]
            run = s.get(AnalysisRun, job.stages.get("analysis_run_id"))
            if run is None or run.status != "running":
                run = _new_run(s, job, request)
            run_id = run.id
            before = deepcopy(run.input_manifest)
            input_sha256 = run.input_sha256
            inv_id = job.investigation_id
            job.state, job.started_at = "ANALYZING", job.started_at or utcnow()
            job.current_item = "device_analysis"
        # Commit the claim before validation can fail, so failure handling owns its lease.
        with session_scope() as s:
            job = s.get(Job, job_id)
            if job.cancel_requested:
                raise Cancelled("device_analysis_cancelled")
            actor = _authorized(s, job)
            _idle(s, inv_id)
            pin = before.get("runtime_pin")
            if pin is None:
                raise ValueError("device_analysis_runtime_pin_missing")
            authorize(s, actor, inv_id, pin, writing=True)
            if digest(before) != input_sha256 or _manifest(s, inv_id) != {k: v for k, v in before.items() if k != "runtime_pin"}:
                raise ValueError("device_analysis_source_changed")
        last_poll = 0.0
        def check(force=False):
            nonlocal last_poll
            now = time.monotonic()
            if not force and now - last_poll < 0.2:
                return False
            last_poll = now
            if now - started > MAX_SECONDS:
                raise TimeoutError("device_analysis_time_limit")
            with session_scope() as s:
                current = s.get(Job, job_id)
                if current is None or current.attempt != epoch:
                    raise StaleLease("device_analysis_lease_superseded")
                if current.cancel_requested or current.state == "CANCELLED":
                    raise Cancelled("device_analysis_cancelled")
                if current.state != "ANALYZING":
                    raise StaleLease("device_analysis_job_not_running")
            return False
        result = run_for_request(container.get().events, inv_id, request, pin, max_records=MAX_EVENTS,
                                 max_results=MAX_RESULTS, cancelled=check)
        check(force=True)
        if result["status"] == "cancelled":
            raise Cancelled("device_analysis_cancelled")
        if len(canonical(result).encode()) > MAX_RESULT_BYTES:
            raise ValueError("device_analysis_result_too_large")
        with session_scope() as s:
            lock_investigation(s, inv_id)
            job = s.get(Job, job_id)
            if job is None or job.attempt != epoch:
                raise StaleLease("device_analysis_lease_superseded")
            if job.cancel_requested:
                raise Cancelled("device_analysis_cancelled")
            if job.state != "ANALYZING":
                raise StaleLease("device_analysis_job_not_running")
            actor = _authorized(s, job)
            _idle(s, inv_id)
            authorize(s, actor, inv_id, pin, writing=True)
            if _manifest(s, inv_id) != {k: v for k, v in before.items() if k != "runtime_pin"}:
                raise ValueError("device_analysis_source_changed")
            run = s.get(AnalysisRun, run_id)
            status = {"completed_match": "complete", "completed_no_match": "complete",
                      "disabled": "not_applicable"}.get(
                result["status"], result["status"])
            service.record(s, run, detector_id, engine_version, status,
                input_count=result["counts"]["records"],
                match_count=None if status in {"insufficient_data", "not_applicable"} else result["counts"]["candidates"],
                elapsed_ms=int((time.monotonic() - started) * 1000),
                effective_config={"pins": result.get("effective_pins", []), "values": result.get("policy", {})}, detail=masked(result))
            service.finish(s, run, status=status, detail={"kind": KIND})
            job.state, job.finished_at = "COMPLETED", utcnow()
            job.events_done = result["counts"]["records"]
            audit.record(s, "device_analysis.completed", actor_id=job.requested_by,
                target_type="analysis_run", target_id=run.id, investigation_id=inv_id,
                detail={"status": status, "job_id": job.id})
    except StaleLease:
        return
    except Exception as exc:  # noqa: BLE001 - Every worker failure must seal its ledger.
        with session_scope() as s:
            job = s.get(Job, job_id)
            if job is None or epoch is None:
                return
            lock_investigation(s, job.investigation_id, allow_deleting=True)
            s.refresh(job)
            if job.attempt != epoch:
                return
            job.state = "CANCELLED" if isinstance(exc, Cancelled) or job.cancel_requested else "FAILED"
            job.finished_at = utcnow()
            job.error = {"message": masked(str(getattr(exc, "detail", exc)))[:512],
                         "type": type(exc).__name__}
            run = s.get(AnalysisRun, run_id or job.stages.get("analysis_run_id"))
            if run is not None and run.status == "running":
                status = job.state.lower()
                failed_detector = (job.stages.get("device_analysis_request") or {}).get("detector_id") or "fw.observation"
                service.record(s, run, failed_detector, get_spec(failed_detector)["engine"]["version"], status,
                    elapsed_ms=int((time.monotonic() - started) * 1000),
                    detail={"error_type": type(exc).__name__})
                service.finish(s, run, status=status, detail={"kind": KIND, "error_type": type(exc).__name__})
            audit.record(s, "device_analysis." + job.state.lower(), actor_id=job.requested_by,
                target_type="job", target_id=job.id, investigation_id=job.investigation_id,
                detail={"error_type": type(exc).__name__})


def cancel_queued(s, job):
    """Seal a never-started run in the same transaction as the API cancellation."""
    if job.kind != KIND or job.state != "CANCELLED":
        return
    run = s.get(AnalysisRun, (job.stages or {}).get("analysis_run_id"))
    if run is not None and run.status == "running":
        detector_id = (job.stages.get("device_analysis_request") or {}).get("detector_id") or "fw.observation"
        service.record(s, run, detector_id, get_spec(detector_id)["engine"]["version"], "cancelled",
                       detail={"error_type": "Cancelled"})
        service.finish(s, run, status="cancelled", detail={"kind": KIND})
    job.finished_at = job.finished_at or utcnow()
