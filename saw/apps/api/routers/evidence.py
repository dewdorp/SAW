from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from saw import container
from saw.apps.api.deps import AuthContext, auth, db
from saw.core.application import audit
from saw.core.application import evidence as svc
from saw.core.application.investigations import NotFound, list_for, require
from saw.core.security.masking import mask_text
from saw.storage.db import session_scope
from saw.storage.models import Evidence, EvidenceFile, Job

router = APIRouter(tags=["evidence"])


class EvidenceIn(BaseModel):
    kind: str = "auto"
    title: str = ""
    tz: str | None = None
    classification: str = "internal"


class UploadIn(BaseModel):
    evidence_id: str
    filename: str = Field(min_length=1, max_length=1024)
    size: int = Field(gt=0)
    sha256: str | None = None


class ParserIn(BaseModel):
    parser_id: str


def job_out(j: Job) -> dict:
    return {"id": j.id, "investigation_id": j.investigation_id, "evidence_id": j.evidence_id, "kind": j.kind,
            "state": j.state, "stages": j.stages, "events_total_est": j.events_total_est,
            "events_done": j.events_done, "current_item": j.current_item, "error": j.error,
            "created_at": j.created_at, "started_at": j.started_at, "finished_at": j.finished_at,
            "cancel_requested": j.cancel_requested}


def file_out(f: EvidenceFile) -> dict:
    return {"id": f.id, "parent_file_id": f.parent_file_id, "name": f.display_name, "size": f.size,
            "sha256": f.sha256, "type": f.type_detected, "parser_id": f.parser_id,
            "parser_confidence": f.parser_confidence, "status": f.parse_status, "events_parsed": f.events_parsed,
            "events_failed": f.events_failed, "error_samples": f.error_samples, "message": f.message,
            "first_ts": f.first_ts, "last_ts": f.last_ts,
            "coverage": next((x["coverage"] for x in (f.error_samples or []) if isinstance(x, dict) and "coverage" in x),
                             None)}


@router.post("/investigations/{inv_id}/evidence", status_code=201)
def create_evidence(inv_id: str, body: EvidenceIn, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    e = svc.create_evidence(s, ctx.principal, inv_id, body.kind, body.title, body.tz, body.classification)
    return {"id": e.id, "kind": e.kind}


@router.post("/uploads", status_code=201)
def start_upload(body: UploadIn, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    u = svc.start_upload(s, ctx.principal, body.evidence_id, body.filename, body.size, body.sha256)
    return {"id": u.id, "part_size": container.get().settings.upload_part_max_bytes}


@router.put("/uploads/{sid}/parts/{n}")
async def put_part(sid: str, n: int, request: Request, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    data = await request.body()
    u = svc.put_part(s, ctx.principal, sid, n, data)
    return {"received": u.received_bytes, "declared": u.declared_size}


@router.get("/uploads/{sid}")
def upload_state(sid: str, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    u = svc._session_for(s, ctx.principal, sid)  # noqa: SLF001
    return {"id": u.id, "received": u.received_bytes, "declared": u.declared_size, "parts": sorted(int(k) for k in u.parts)}


@router.post("/uploads/{sid}/complete")
def complete_upload(sid: str, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    f, job = svc.complete_upload(s, ctx.principal, sid)
    return {"file_id": f.id, "sha256": f.sha256, "job_id": job.id}


@router.post("/evidence/{ev_id}/process")
def process(ev_id: str, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function"),
            idempotency_key: str | None = Header(default=None, alias="Idempotency-Key", max_length=128)):
    try:
        job, created = svc.start_processing(s, ctx.principal, ev_id, idempotency_key)
    except svc.IdempotencyConflict as e:
        raise HTTPException(409, str(e)) from None
    s.commit()
    if created:
        container.get().runner.submit("ingest.run", job_id=job.id)
    return job_out(job)


@router.get("/evidence/{ev_id}")
def get_evidence(ev_id: str, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    e = s.get(Evidence, ev_id)
    if e is None:
        raise NotFound("evidence not found")
    require(s, ctx.principal, "investigation.read", e.investigation_id)
    files = s.execute(select(EvidenceFile).where(EvidenceFile.evidence_id == ev_id)).scalars().all()
    return {"id": e.id, "investigation_id": e.investigation_id, "kind": e.kind, "title": e.title, "status": e.status,
            "size": e.total_size, "tz": e.tz_assumed, "files": [file_out(f) for f in files]}


@router.get("/evidence/{ev_id}/custody")
def custody(ev_id: str, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    return svc.custody(s, ctx.principal, ev_id)


@router.post("/evidence/{ev_id}/files/{fid}/parser")
def set_parser(ev_id: str, fid: str, body: ParserIn, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    from saw.parsers.registry import get_parser

    e = s.get(Evidence, ev_id)
    f = s.get(EvidenceFile, fid)
    if e is None or f is None or f.evidence_id != ev_id:
        raise NotFound("file not found")
    require(s, ctx.principal, "investigation.write", e.investigation_id)
    from saw.parsers.library import check_use

    check_use(s, ctx.principal, body.parser_id)  # drafts: author only
    get_parser(body.parser_id)  # validates
    if f.parse_status in ("done", "degraded"):
        # events are removed per evidence, so every parsed text file of it is parsed again (not only this one)
        container.get().events.delete_by_evidence(e.investigation_id, ev_id)
        for other in s.execute(select(EvidenceFile).where(EvidenceFile.evidence_id == ev_id, EvidenceFile.id != fid,
                                                          EvidenceFile.parse_status.in_(["done", "degraded"]))).scalars():
            if other.parser_id and other.parser_id != "pcap":
                other.parse_status = "pending"
    f.parser_id, f.parse_status, f.message = body.parser_id, "pending", ""
    audit.record(s, "evidence.parser_override", actor_id=ctx.principal.user_id, actor_name=ctx.principal.username,
                 target_type="evidence_file", target_id=fid, investigation_id=e.investigation_id,
                 detail={"parser_id": body.parser_id})
    job = s.execute(select(Job).where(Job.evidence_id == ev_id).order_by(Job.created_at.desc())).scalars().first()
    if job:  # the processing record names who re-processed, not who uploaded
        job.stages = {**(job.stages or {}), "requested": {"by": ctx.principal.user_id, "name": ctx.principal.username,
                                                          "action": "parser_override", "parser_id": body.parser_id}}
    waiting = s.execute(select(EvidenceFile).where(EvidenceFile.evidence_id == ev_id,
                                                   EvidenceFile.parse_status == "waiting_input")).scalars().all()
    s.commit()
    if job and not waiting:
        job.state = "PARSING"
        s.commit()
        container.get().runner.submit("ingest.resume", job_id=job.id)
    return {"ok": True, "remaining_waiting": len(waiting)}


@router.get("/jobs")
def list_jobs(active: bool = False, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    inv_ids = [i.id for i in list_for(s, ctx.principal, 200)]
    q = select(Job).where(Job.investigation_id.in_(inv_ids)).order_by(Job.created_at.desc()).limit(50)
    if active:
        q = q.where(Job.state.notin_(["COMPLETED", "FAILED", "CANCELLED"]))
    return [job_out(j) for j in s.execute(q).scalars()]


def _job_for(s: Session, ctx: AuthContext, job_id: str) -> Job:
    j = s.get(Job, job_id)
    if j is None:
        raise NotFound("job not found")
    require(s, ctx.principal, "investigation.read", j.investigation_id)
    return j


@router.get("/jobs/{job_id}")
def get_job(job_id: str, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    j = _job_for(s, ctx, job_id)
    out = job_out(j)
    if j.evidence_id:
        out["files"] = [file_out(f) for f in s.execute(select(EvidenceFile).where(
            EvidenceFile.evidence_id == j.evidence_id)).scalars()]
    return out


@router.post("/jobs/{job_id}/cancel")
def cancel_job(job_id: str, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    j = _job_for(s, ctx, job_id)
    require(s, ctx.principal, "investigation.write", j.investigation_id)
    j.cancel_requested = True
    if j.state in ("QUEUED", "WAITING_INPUT", "UPLOADING"):
        j.state = "CANCELLED"
    audit.record(s, "job.cancel", actor_id=ctx.principal.user_id, actor_name=ctx.principal.username,
                 target_type="job", target_id=job_id, investigation_id=j.investigation_id)
    return job_out(j)


@router.post("/jobs/{job_id}/retry")
def retry_job(job_id: str, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    j = _job_for(s, ctx, job_id)
    require(s, ctx.principal, "investigation.write", j.investigation_id)
    for f in s.execute(select(EvidenceFile).where(EvidenceFile.evidence_id == j.evidence_id,
                                                  EvidenceFile.parse_status == "failed")).scalars():
        f.parse_status = "pending"
    j.state, j.cancel_requested, j.error = "PARSING", False, {}
    j.stages = {**(j.stages or {}), "requested": {"by": ctx.principal.user_id, "name": ctx.principal.username,
                                                  "action": "retry"}}
    s.commit()
    container.get().runner.submit("ingest.resume", job_id=j.id)
    return job_out(j)


@router.get("/jobs/{job_id}/events")
async def job_events(job_id: str, request: Request, ctx: AuthContext = Depends(auth)):
    """SSE progress stream (docs/10 §6)."""
    with session_scope() as s:
        _job_for(s, ctx, job_id)

    async def gen():
        last = None
        for _ in range(3600):
            if await request.is_disconnected():
                return
            with session_scope() as s:
                j = s.get(Job, job_id)
                payload = json.dumps(job_out(j), default=str)
                state = j.state
            if payload != last:
                yield f"event: progress\ndata: {payload}\n\n"
                last = payload
            if state in ("COMPLETED", "FAILED", "CANCELLED"):
                yield "event: end\ndata: {}\n\n"
                return
            await asyncio.sleep(1)

    return StreamingResponse(gen(), media_type="text/event-stream", headers={"Cache-Control": "no-store"})


@router.post("/investigations/{inv_id}/reanalyze")
def reanalyze(inv_id: str, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    require(s, ctx.principal, "investigation.write", inv_id)
    j = Job(investigation_id=inv_id, kind="reanalyze", requested_by=ctx.principal.user_id, state="QUEUED")
    s.add(j)
    s.commit()
    container.get().runner.submit("analyze.run", job_id=j.id)
    return job_out(j)


class PasteIn(BaseModel):
    text: str = Field(min_length=1)


@router.post("/investigations/{inv_id}/paste")
def add_paste(inv_id: str, body: PasteIn, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    """'Add to Investigation' from the Universal Analyzer: keep the paste as evidence (custody), index log lines
    through the normal pipeline, and record detected observables as investigation entities."""
    from saw.analyzers.universal.detect import detect_all
    from saw.storage.models import Entity

    if len(body.text.encode()) > container.get().settings.sync_input_max_bytes:
        raise HTTPException(413, "Input exceeds sync limit (5 MB). Use upload.")
    det = detect_all(body.text)
    types = {d["type"] for d in det["detections"]}
    ev = svc.add_paste_evidence(s, ctx.principal, inv_id, body.text,
                                kind="paste" if "log_lines" not in types else "sec_log")
    added = 0
    for d in det["detections"]:
        if d["type"] in ("ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256", "sha512") and d.get("value"):
            et = "ip" if d["type"].startswith("ipv") else d["type"]
            exists = s.execute(select(Entity).where(Entity.investigation_id == inv_id, Entity.type == et,
                                                    Entity.value == d["value"])).scalar_one_or_none()
            if not exists:
                s.add(Entity(investigation_id=inv_id, type=et, value=d["value"], attrs={"source": "paste"}))
                added += 1
    job_id = None
    if "log_lines" in types:
        job, _ = svc.start_processing(s, ctx.principal, ev.id)
        s.commit()
        container.get().runner.submit("ingest.run", job_id=job.id)
        job_id = job.id
    return {"evidence_id": ev.id, "entities_added": added, "job_id": job_id}


@router.get("/findings/recent")
def recent_findings(ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    from saw.storage.models import Finding

    ids = [i.id for i in list_for(s, ctx.principal, 100)]
    rows = s.execute(select(Finding).where(Finding.investigation_id.in_(ids))
                     .order_by(Finding.created_at.desc(), Finding.risk_score.desc()).limit(10)).scalars()
    return [{"id": f.id, "display_id": f.display_id, "title": f.title, "risk_level": f.risk_level,
             "investigation_id": f.investigation_id, "time_start": f.time_start} for f in rows]


@router.get("/parsers")
def parsers(ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    """Parsers this analyst can pick: built-ins, approved analyst parsers and their own drafts."""
    from saw.parsers.library import picker
    from saw.parsers.registry import builtin_parsers

    return picker(s, ctx.principal) + [{"id": p.id, "version": p.version, "data_source": p.data_source,
                                        "product": p.product} for p in builtin_parsers()]


@router.get("/evidence/{ev_id}/files/{fid}/sample")
def file_sample(ev_id: str, fid: str, lines: int = 50, ctx: AuthContext = Depends(auth),
                s: Session = Depends(db, scope="function")):
    """First lines of an uploaded text file (masked) to start a parser definition from real data."""
    from saw.parsers.registry import sniff_encoding
    from saw.workers.pipeline import EXTRACTED, ORIGINAL

    e = s.get(Evidence, ev_id)
    f = s.get(EvidenceFile, fid)
    if e is None or f is None or f.evidence_id != ev_id:
        raise NotFound("file not found")
    require(s, ctx.principal, "investigation.read", e.investigation_id)
    head = container.get().objects.read_range(ORIGINAL if f.parent_file_id is None else EXTRACTED, f.object_key, 0,
                                              256 * 1024)
    enc = sniff_encoding(head)
    text = head[: head.rfind(b"\n") + 1 or len(head)].decode(enc, errors="replace").lstrip("\ufeff")
    out = [mask_text(x.rstrip("\r")).text for x in text.split("\n")[: max(1, min(lines, 200))]]
    return {"file": f.display_name, "encoding": enc, "lines": out}


_ = HTTPException
