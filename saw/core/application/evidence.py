"""Evidence + resumable upload use cases (docs/09, ADR-0013)."""
from __future__ import annotations

import hashlib

from sqlalchemy import select
from sqlalchemy.orm import Session

from saw import container
from saw.core.application import audit
from saw.core.application.investigations import require
from saw.core.security.authz import Principal, can
from saw.core.security.sanitize import sanitize_filename
from saw.storage.db import new_id, utcnow
from saw.storage.models import CustodyLog, Evidence, EvidenceFile, Job, UploadSession

EVIDENCE_KINDS = {"pcap", "web_log", "waf_log", "fw_log", "sec_log", "db_audit", "ioc_list", "http", "paste", "file",
                  "document", "screenshot", "auto"}
ORIGINAL = "saw-evidence-original"


class UploadError(ValueError):
    pass


def create_evidence(s: Session, p: Principal, inv_id: str, kind: str, title: str = "", tz: str | None = None,
                    classification: str = "internal") -> Evidence:
    require(s, p, "investigation.write", inv_id)
    if not can(p, "evidence.upload"):
        from saw.core.application.investigations import Forbidden

        raise Forbidden("evidence.upload")
    if kind not in EVIDENCE_KINDS:
        raise ValueError(f"unknown evidence kind {kind}")
    e = Evidence(investigation_id=inv_id, kind=kind, title=title[:256], uploaded_by=p.user_id,
                 tz_assumed=tz or container.get().settings.default_timezone, classification=classification)
    s.add(e)
    s.flush()
    audit.record(s, "evidence.create", actor_id=p.user_id, actor_name=p.username, target_type="evidence",
                 target_id=e.id, investigation_id=inv_id, detail={"kind": kind})
    return e


def _evidence_for_write(s: Session, p: Principal, evidence_id: str) -> Evidence:
    e = s.get(Evidence, evidence_id)
    if e is None:
        from saw.core.application.investigations import NotFound

        raise NotFound("evidence not found")
    require(s, p, "investigation.write", e.investigation_id)
    return e


def start_upload(s: Session, p: Principal, evidence_id: str, filename: str, size: int,
                 sha256: str | None = None) -> UploadSession:
    _evidence_for_write(s, p, evidence_id)
    cfg = container.get().settings
    if size <= 0 or size > cfg.upload_file_max_bytes:
        raise UploadError(f"file size must be 1..{cfg.upload_file_max_bytes} bytes")
    if sha256 and (len(sha256) != 64 or any(c not in "0123456789abcdef" for c in sha256.lower())):
        raise UploadError("sha256 must be 64 hex chars")
    u = UploadSession(user_id=p.user_id, evidence_id=evidence_id, filename=sanitize_filename(filename),
                      declared_size=size, declared_sha256=(sha256 or "").lower() or None)
    s.add(u)
    s.flush()
    return u


def _session_for(s: Session, p: Principal, sid: str) -> UploadSession:
    u = s.get(UploadSession, sid)
    if u is None or u.user_id != p.user_id:
        from saw.core.application.investigations import NotFound

        raise NotFound("upload session not found")
    _evidence_for_write(s, p, u.evidence_id)
    if u.status != "open":
        raise UploadError(f"upload session is {u.status}")
    return u


def put_part(s: Session, p: Principal, sid: str, part_no: int, data: bytes) -> UploadSession:
    u = _session_for(s, p, sid)
    cfg = container.get().settings
    if not 1 <= part_no <= 10000:
        raise UploadError("part number must be 1..10000")
    if len(data) > cfg.upload_part_max_bytes:
        raise UploadError("part too large")
    parts = dict(u.parts or {})
    prev = parts.get(str(part_no), {}).get("size", 0)
    if u.received_bytes - prev + len(data) > u.declared_size:
        raise UploadError("received bytes exceed declared size")
    container.get().objects.append_part(ORIGINAL, f"_uploads/{u.id}", part_no, data)
    parts[str(part_no)] = {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    u.parts = parts
    u.received_bytes = sum(x["size"] for x in parts.values())
    return u


def complete_upload(s: Session, p: Principal, sid: str) -> tuple[EvidenceFile, Job]:
    u = _session_for(s, p, sid)
    if u.received_bytes != u.declared_size:
        raise UploadError(f"incomplete upload: {u.received_bytes}/{u.declared_size} bytes")
    e = s.get(Evidence, u.evidence_id)
    assert e is not None
    file_id = new_id()
    key = f"{e.investigation_id}/{e.id}/{file_id}"
    objs = container.get().objects
    tmp_key = f"_uploads/{u.id}"
    n, sha = objs.complete_parts(ORIGINAL, tmp_key, [int(k) for k in u.parts])
    if u.declared_sha256 and sha != u.declared_sha256:
        objs.delete(ORIGINAL, tmp_key)
        u.status = "rejected"
        audit.record(s, "evidence.upload", actor_id=p.user_id, actor_name=p.username, target_type="evidence",
                     target_id=e.id, investigation_id=e.investigation_id, outcome="failure",
                     detail={"reason": "sha256 mismatch"})
        raise UploadError("sha256 mismatch")
    # move temp object into final key (local FS: rename; S3: copy semantics handled by adapter)
    src = objs.local_path(ORIGINAL, tmp_key)
    dst = objs.local_path(ORIGINAL, key)
    dst.parent.mkdir(parents=True, exist_ok=True)
    src.replace(dst)
    f = EvidenceFile(id=file_id, evidence_id=e.id, display_name=u.filename, object_key=key, sha256=sha, size=n)
    s.add(f)
    u.status = "completed"
    e.total_size += n
    e.file_count += 1
    e.status = "uploaded"
    s.add(CustodyLog(evidence_id=e.id, file_id=file_id, action="upload", actor=p.username,
                     detail={"sha256": sha, "size": n, "filename": u.filename}))
    audit.record(s, "evidence.upload", actor_id=p.user_id, actor_name=p.username, target_type="evidence_file",
                 target_id=file_id, investigation_id=e.investigation_id, detail={"sha256": sha, "size": n})
    job = s.execute(select(Job).where(Job.evidence_id == e.id, Job.state == "UPLOADING")).scalar_one_or_none()
    if job is None:
        job = Job(investigation_id=e.investigation_id, evidence_id=e.id, kind="ingest", state="UPLOADING",
                  requested_by=p.user_id, stages={"upload": {"pct": 100, "done": True}})
        s.add(job)
    s.flush()
    return f, job


ACTIVE_STATES = ("QUEUED", "PARSING", "INDEXING", "ANALYZING")


class IdempotencyConflict(ValueError):
    pass


def start_processing(s: Session, p: Principal, evidence_id: str, idempotency_key: str | None = None) -> tuple[Job, bool]:
    """Called after the last file of an evidence upload is completed (client signals 'finish').

    Returns (job, created). A repeated Idempotency-Key, or a job already running for this evidence, returns the
    existing job (created=False) so double clicks and client retries never start a second ingest.
    """
    e = _evidence_for_write(s, p, evidence_id)
    if idempotency_key:
        prev = s.execute(select(Job).where(Job.requested_by == p.user_id, Job.idempotency_key == idempotency_key)).scalars().first()
        if prev is not None:
            if prev.evidence_id != e.id:
                raise IdempotencyConflict("Idempotency-Key already used for a different request")
            return prev, False
    job = s.execute(select(Job).where(Job.evidence_id == e.id).order_by(Job.created_at.desc())).scalars().first()
    if job is not None and job.state in ACTIVE_STATES:
        return job, False
    if job is None or job.state not in ("UPLOADING",):
        job = Job(investigation_id=e.investigation_id, evidence_id=e.id, kind="ingest", requested_by=p.user_id,
                  stages={"upload": {"pct": 100, "done": True}})
        s.add(job)
    job.state = "QUEUED"
    job.idempotency_key = idempotency_key
    s.flush()
    audit.record(s, "job.start", actor_id=p.user_id, actor_name=p.username, target_type="job", target_id=job.id,
                 investigation_id=e.investigation_id)
    return job, True


def add_paste_evidence(s: Session, p: Principal, inv_id: str, text: str, kind: str = "paste") -> Evidence:
    e = create_evidence(s, p, inv_id, kind, title="Pasted input")
    file_id = new_id()
    key = f"{inv_id}/{e.id}/{file_id}"
    n, sha = container.get().objects.put_bytes(ORIGINAL, key, text.encode("utf-8"))  # type: ignore[attr-defined]
    s.add(EvidenceFile(id=file_id, evidence_id=e.id, display_name="paste.txt", object_key=key, sha256=sha, size=n))
    e.total_size, e.file_count, e.status = n, 1, "uploaded"
    s.add(CustodyLog(evidence_id=e.id, file_id=file_id, action="upload", actor=p.username, detail={"sha256": sha}))
    s.flush()
    return e


def custody(s: Session, p: Principal, evidence_id: str) -> list[dict]:
    e = s.get(Evidence, evidence_id)
    if e is None:
        from saw.core.application.investigations import NotFound

        raise NotFound("evidence not found")
    require(s, p, "investigation.read", e.investigation_id)
    return [{"action": c.action, "actor": c.actor, "at": c.at, "file_id": c.file_id, "detail": c.detail}
            for c in s.execute(select(CustodyLog).where(CustodyLog.evidence_id == evidence_id)
                               .order_by(CustodyLog.at)).scalars()]


def touch_custody(s: Session, evidence_id: str, file_id: str | None, action: str, actor: str, detail: dict) -> None:
    s.add(CustodyLog(evidence_id=evidence_id, file_id=file_id, action=action, actor=actor, detail=detail,
                     at=utcnow()))
