"""Leased bounded calculation with source validation immediately before publishing."""
from __future__ import annotations
import hashlib
import time
from copy import deepcopy
from sqlalchemy import func, select
from saw import container
from saw.behavior.calculator import calculate
from saw.behavior.models import BehaviorResult
from saw.behavior.service import MAX_RESULT_BYTES, ensure_source_idle, source_manifest
from saw.core.application import audit
from saw.core.application.data_deletion import lock_investigation
from saw.core.application.provenance import canonical, digest
from saw.core.schemas.query import Filter, TimeRange
from saw.core.security.masking import mask_text
from saw.knowledge.golden import EVENT_KEYS, masked
from saw.storage.db import session_scope, utcnow
from saw.storage.models import EvidenceFile, Job
from saw.workers.pipeline import Cancelled, StaleLease
from saw.workers.runner import task

MAX_EVENTS = 100000
MAX_SECONDS = 120

def _scope_events(inv_id, request, check):
    es = container.get().events
    base = [Filter.model_validate(f) for f in request["filters"]]
    time = TimeRange.model_validate(request["time"]) if request.get("time") else None
    ips = request.get("ips") or []
    role = request.get("role", "src")
    branches = [base]
    if ips:
        branches = [base + [Filter(field="src_ip" if role == "src" else "dst_ip", op="in", value=ips)]]
        if role == "either":
            branches = [base + [Filter(field="src_ip", op="in", value=ips)],
                        base + [Filter(field="dst_ip", op="in", value=ips)]]
    seen = set()
    for filters in branches:
        for index, event in enumerate(es.iterate(inv_id, filters, time, batch=500)):
            if index % 100 == 0:
                check()
            event_id = event["event_id"]
            if event_id not in seen:
                seen.add(event_id)
                yield event

def _snapshots(events, known_at, manifest):
    file_ids = {f["id"] for e in manifest["evidence"] for f in e["files"]}
    with session_scope() as s:
        files = {("saw-evidence-original/" if f.parent_file_id is None else "saw-evidence-extracted/") + f.object_key:
                 {"id": f.id, "sha256": f.sha256, "evidence_id": f.evidence_id,
                  "parser_id": f.parser_id, "parser_version": f.parser_version}
                 for f in s.scalars(select(EvidenceFile).where(EvidenceFile.id.in_(file_ids)))}
    snapshots = []
    for event in events[:200]:
        projection = {k: deepcopy(v) for k, v in event.items() if k in EVENT_KEYS and k not in {"params", "raw_event"}}
        source = {k: event.get(k) for k in ("evidence_id", "source_file", "data_source") if event.get(k) is not None}
        ref = event.get("raw_ref") or {}
        file = files.get(ref.get("object_key"))
        raw, raw_hash, basis, raw_bytes = event.get("raw_event"), None, "unavailable", None
        if file and file["evidence_id"] == event.get("evidence_id"):
            source.update(file_id=file["id"], source_sha256=file["sha256"],
                          parser_id=file["parser_id"], parser_version=file["parser_version"],
                          raw_ref={k: v for k, v in ref.items() if k in {"object_key", "offset", "length", "line_no", "enc"}})
            try:
                bucket, _, key = ref["object_key"].partition("/")
                length = int(ref["length"])
                payload = container.get().objects.read_range(bucket, key, int(ref["offset"]), min(length, 32768))
                raw = payload.decode(ref.get("enc") or "utf-8", errors="replace").rstrip("\r\n").lstrip("\ufeff")
                raw_hash, raw_bytes = hashlib.sha256(payload).hexdigest(), len(payload)
                basis = "source_line_bytes" if length <= 32768 and len(payload) == length else "source_prefix_bytes"
            except (OSError, ValueError, KeyError, LookupError):
                pass
        if raw is not None:
            projection["raw_event"] = mask_text(str(raw)).text[:4096]
            if raw_hash is None:
                raw_hash = event.get("raw_sha256") or hashlib.sha256(str(raw).encode()).hexdigest()
                basis = "indexed_text_utf8"
            source["raw_preview_truncated"] = len(str(raw)) > 4096 or bool(event.get("raw_truncated"))
        source.update(raw_hash_basis=basis, raw_bytes_hashed=raw_bytes)
        projection = masked(projection)
        observation = ((event.get("ext") or {}).get("saw_observation") or {})
        if observation:
            source["observation"] = {k: v for k, v in observation.items()
                if k in {"user_agent", "timestamp_precision", "version", "producer"}}
        safe_source = masked(source)
        if file and file["evidence_id"] == event.get("evidence_id"):
            # This reference was matched to a server-owned object; retain its exact UUID path.
            safe_source["raw_ref"] = deepcopy(source["raw_ref"])
        snapshots.append({"event_id": event.get("event_id"), "event": projection,
            "sha256": digest(projection), "raw_sha256": raw_hash,
            "known_at": known_at, "source": safe_source})
    return snapshots

@task("behavior.run")
def behavior_run(job_id: str):
    epoch = None
    try:
        with session_scope() as s:
            job = s.get(Job, job_id)
            if job is None:
                return
            inv_id = job.investigation_id
            lock_investigation(s, inv_id)
            s.refresh(job)
            if job.kind != "behavior" or job.state not in ("QUEUED", "PARSING", "ANALYZING"):
                return
            if job.cancel_requested:
                job.state, job.finished_at = "CANCELLED", utcnow()
                return
            epoch = job.attempt or 0
            ensure_source_idle(s, inv_id)
            epoch = job.attempt = (job.attempt or 0) + 1
            job.state, job.started_at = "ANALYZING", job.started_at or utcnow()
            request = deepcopy(job.stages["behavior_request"])
            before = container.get().events.pin_manifest(s, inv_id, source_manifest(s, inv_id))
            author = job.requested_by
            actor_name = (job.stages.get("requested") or {}).get("name", "")
        last_poll = 0.0
        def check(force=False):
            nonlocal last_poll
            now = time.monotonic()
            if not force and now - last_poll < 0.2:
                return False
            last_poll = now
            with session_scope() as s:
                current = s.get(Job, job_id)
                if current is None or current.attempt != epoch:
                    raise StaleLease("behavior_lease_superseded")
                if current.cancel_requested or current.state == "CANCELLED":
                    raise Cancelled("behavior_cancelled")
                if current.state not in ("ANALYZING", "PARSING"):
                    raise StaleLease("behavior_job_not_running")
            return False
        calculated = calculate(_scope_events(inv_id, request, check), request.get("profile"),
                               max_events=MAX_EVENTS, max_seconds=MAX_SECONDS, check_cancel=check)
        check(force=True)
        captured_at = utcnow().isoformat()
        evidence = _snapshots(calculated.pop("evidence_events", []), captured_at, before)
        observations = {k: deepcopy(calculated[k]) for k in
            ("summary", "quality", "metrics", "timeline", "indicators", "followups", "limits", "execution") if k in calculated}
        data = {"schema": "saw.behavior.result.v1", "captured_at": captured_at,
            "scope": masked({k: deepcopy(request[k]) for k in ("filters", "time", "ips", "role")}),
            "methodology": masked(calculated["methodology"]), "profile": masked(calculated["profile"]),
            "source_manifest": before, "observations": masked(observations), "selected_evidence": evidence}
        if len(canonical(data).encode()) > MAX_RESULT_BYTES:
            raise ValueError("behavior_result_too_large")
        with session_scope() as s:
            lock_investigation(s, inv_id)
            job = s.get(Job, job_id)
            if job is None or job.attempt != epoch:
                raise StaleLease("behavior_lease_superseded")
            if job.cancel_requested:
                raise Cancelled("behavior_cancelled")
            if job.state not in ("ANALYZING", "PARSING"):
                raise StaleLease("behavior_job_not_running")
            ensure_source_idle(s, inv_id)
            if container.get().events.pin_manifest(s, inv_id, source_manifest(s, inv_id)) != before:
                raise ValueError("behavior_source_changed")
            number = (s.scalar(select(func.max(BehaviorResult.version)).where(
                BehaviorResult.investigation_id == inv_id)) or 0) + 1
            row = BehaviorResult(investigation_id=inv_id, job_id=job_id, version=number, created_by=author,
                                 result=data, result_sha256=digest(data))
            s.add(row)
            s.flush()
            job.state, job.finished_at = "COMPLETED", utcnow()
            job.events_done = int(observations.get("execution", {}).get("processed", 0))
            job.stages = {**job.stages, "behavior_result": {"id": row.id, "result_sha256": row.result_sha256}}
            audit.record(s, "behavior.completed", actor_id=author, actor_name=actor_name,
                target_type="behavior_result", target_id=row.id, investigation_id=inv_id,
                detail={"result_sha256": row.result_sha256, "version": row.version, "job_id": job_id})
    except StaleLease:
        return
    except Exception as exc:
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
            job.error = {"message": masked(str(getattr(exc, "detail", exc)))[:512], "type": type(exc).__name__}
            requested = (job.stages or {}).get("requested") or {}
            audit.record(s, "behavior." + job.state.lower(), actor_id=job.requested_by,
                actor_name=requested.get("name", ""), target_type="job", target_id=job.id,
                investigation_id=job.investigation_id, detail={"error_type": type(exc).__name__})
