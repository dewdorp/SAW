"""Capture the exact inputs and distinguish unexecuted, failed, partial and complete runs."""
from __future__ import annotations
import json
from copy import deepcopy
from sqlalchemy import func, select
from saw import container
from saw.analysis_runs.models import AnalysisRun, DetectorExecution, FindingSnapshot
from saw.core.application.investigations import NotFound, require
from saw.core.application.provenance import canonical, digest
from saw.core.application.data_deletion import lock_investigation
from saw.storage.db import utcnow
from saw.storage.models import Investigation, Job


def start(s, inv_id, *, job_id=None, scope=None):
    from saw.behavior.service import source_manifest
    lock_investigation(s, inv_id)
    inv = s.get(Investigation, inv_id)
    manifest = source_manifest(s, inv_id)
    manifest["org_unit_id"] = getattr(inv, "org_unit_id", None)
    manifest["org_unit"] = inv.org_unit
    manifest["normalization_version"] = "saw.observation/1"
    job = s.get(Job, job_id) if job_id else None
    number = (s.scalar(select(func.max(AnalysisRun.version)).where(
        AnalysisRun.investigation_id == inv_id)) or 0) + 1
    row = AnalysisRun(investigation_id=inv_id, version=number, job_id=job_id,
        created_by=(job.requested_by or "") if job else "", input_manifest=manifest,
        input_sha256=digest(manifest), scope=scope or {"filters": [], "time": None})
    s.add(row)
    s.flush()
    return row


def record(s, run, detector_id, version, status, *, input_count=None, match_count=None,
           elapsed_ms=0, effective_config=None, detail=None):
    row = DetectorExecution(run_id=run.id, detector_id=detector_id, detector_version=str(version),
        status=status, input_count=input_count, match_count=match_count, elapsed_ms=elapsed_ms,
        effective_config=deepcopy(effective_config or {}), detail=deepcopy(detail or {}))
    s.add(row)
    return row


def capture_findings(s, run, findings):
    from saw.core.application.analysis import finding_dict
    s.flush()
    existing = set(s.scalars(select(FindingSnapshot.finding_id).where(FindingSnapshot.run_id == run.id)))
    for finding in findings:
        if finding.id in existing:
            continue
        payload = json.loads(canonical(finding_dict(finding)))
        s.add(FindingSnapshot(run_id=run.id, finding_id=finding.id, payload=payload,
                              payload_sha256=digest(payload)))
        existing.add(finding.id)


def finish(s, run, *, status=None, detail=None):
    s.flush()
    executions = list(s.scalars(select(DetectorExecution).where(DetectorExecution.run_id == run.id)))
    inv = s.get(Investigation, run.investigation_id)
    changed = int((inv.settings or {}).get("data_epoch", 0)) != run.input_manifest["data_epoch"]
    failed = sum(e.status == "failed" for e in executions)
    partial = sum(e.status in {"partial", "limited", "insufficient_data"} for e in executions)
    run.status = status or ("failed" if changed else "partial" if failed or partial else "complete")
    run.finished_at = utcnow()
    run.summary = {"executed": sum(e.status in {"complete", "partial", "failed", "limited"} for e in executions),
        "failed": failed, "partial": partial,
        "insufficient_data": sum(e.status == "insufficient_data" for e in executions),
        "not_applicable": sum(e.status == "not_applicable" for e in executions),
        "source_changed": changed, **(detail or {})}
    return run


def get(s, p, inv_id, run_id):
    require(s, p, "investigation.read", inv_id)
    row = s.get(AnalysisRun, run_id)
    if row is None or row.investigation_id != inv_id:
        raise NotFound("analysis run not found")
    if digest(row.input_manifest) != row.input_sha256:
        raise ValueError("analysis_input_manifest_corrupt")
    return row


def run_dict(s, row, *, full=True):
    out = {"id": row.id, "version": row.version, "status": row.status, "created_at": row.created_at,
        "finished_at": row.finished_at, "job_id": row.job_id, "scope": row.scope,
        "summary": row.summary, "engine_version": row.engine_version, "input_sha256": row.input_sha256}
    if full:
        out["input_manifest"] = deepcopy(row.input_manifest)
        out["executions"] = [{"detector_id": e.detector_id, "detector_version": e.detector_version,
            "status": e.status, "input_count": e.input_count, "match_count": e.match_count,
            "elapsed_ms": e.elapsed_ms, "effective_config": e.effective_config, "detail": e.detail}
            for e in s.scalars(select(DetectorExecution).where(DetectorExecution.run_id == row.id)
                                .order_by(DetectorExecution.detector_id))]
        out["findings"] = []
        for snapshot in s.scalars(select(FindingSnapshot).where(FindingSnapshot.run_id == row.id)):
            if digest(snapshot.payload) != snapshot.payload_sha256:
                raise ValueError("finding_snapshot_corrupt")
            out["findings"].append({"id": snapshot.id, "sha256": snapshot.payload_sha256,
                                    "finding": deepcopy(snapshot.payload)})
    return out
