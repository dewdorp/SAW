from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from saw import container
from saw.apps.api.deps import AuthContext, auth, db, require_perm
from saw.connectors import registry as creg
from saw.connectors.base import ConnectorNotImplemented
from saw.core.application import audit
from saw.core.application import evidence as ev_svc
from saw.core.application.investigations import require
from saw.core.schemas.query import Filter, TimeRange
from saw.storage.db import utcnow
from saw.storage.models import Job

router = APIRouter(tags=["connectors"])


class ConnIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    kind: str
    settings: dict = Field(default_factory=dict)
    secret: str | None = None  # write-only
    enabled: bool = True


class ImportIn(BaseModel):
    connector_id: str
    filters: list[Filter] = Field(min_length=1)
    time: TimeRange | None = None
    limit: int = Field(5000, le=50000)


@router.get("/admin/connectors")
def list_connectors(ctx: AuthContext = Depends(require_perm("admin.connectors")), s: Session = Depends(db, scope="function")):
    from sqlalchemy import select

    return [creg.to_dict(c) for c in s.execute(select(creg.ConnectorConfig)).scalars()]


@router.post("/admin/connectors", status_code=201)
def upsert_connector(body: ConnIn, ctx: AuthContext = Depends(require_perm("admin.connectors")), s: Session = Depends(db, scope="function")):
    c = creg.upsert(s, body.name, body.kind, body.settings, body.secret, body.enabled)
    audit.record(s, "connector.upsert", actor_id=ctx.principal.user_id, actor_name=ctx.principal.username,
                 target_type="connector", target_id=c.id, detail={"kind": body.kind, "secret_set": bool(body.secret)})
    return creg.to_dict(c)


@router.post("/admin/connectors/{cid}/health")
def health(cid: str, ctx: AuthContext = Depends(require_perm("admin.connectors")), s: Session = Depends(db, scope="function")):
    h = creg.get(s, cid).health_check()
    c = s.get(creg.ConnectorConfig, cid)
    c.last_health = {"ok": h.ok, "detail": h.detail, "latency_ms": h.latency_ms, "at": utcnow().isoformat()}
    return c.last_health


@router.get("/connectors")
def usable_connectors(ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    """Analysts see enabled connectors (name/kind only) to pull data into an investigation."""
    return [{"id": c.id, "name": c.name, "kind": c.kind} for c in creg.enabled(s)]


@router.post("/investigations/{inv_id}/connector-import")
def connector_import(inv_id: str, body: ImportIn, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    """Read-only pull from a SIEM connector into the investigation (custody-tracked Evidence of kind 'connector')."""
    require(s, ctx.principal, "investigation.write", inv_id)
    try:
        conn = creg.get(s, body.connector_id)
    except ValueError as e:
        raise HTTPException(404, str(e)) from None
    events, cursor = [], None
    try:
        while len(events) < body.limit:
            page = conn.search(body.filters, body.time, min(500, body.limit - len(events)), cursor)
            events += page["events"]
            cursor = page.get("next_cursor")
            if not cursor:
                break
    except ConnectorNotImplemented as e:
        raise HTTPException(501, str(e)) from None
    ev = ev_svc.create_evidence(s, ctx.principal, inv_id, "auto", f"connector:{conn.kind} ({len(events)} events)")
    ev.kind = "connector"
    docs = []
    for e in events:
        d = dict(e)
        src_id = d.get("event_id")
        d["event_id"] = str(uuid.uuid5(uuid.NAMESPACE_URL, f"{conn.id}:{src_id}"))  # deterministic, idempotent re-import
        d["investigation_id"], d["evidence_id"] = inv_id, ev.id
        d["source_file"] = f"connector:{conn.kind}"
        d.setdefault("ext", {})["connector"] = {"id": conn.id, "source_event_id": src_id}
        docs.append(d)
    container.get().events.index(docs)
    ev.status, ev.file_count = "processed", 0
    ev_svc.touch_custody(s, ev.id, None, "import", ctx.principal.username,
                         {"connector": conn.id, "filters": [f.model_dump() for f in body.filters], "events": len(docs)})
    audit.record(s, "connector.import", actor_id=ctx.principal.user_id, actor_name=ctx.principal.username,
                 target_type="connector", target_id=conn.id, investigation_id=inv_id, detail={"events": len(docs)})
    job = Job(investigation_id=inv_id, evidence_id=ev.id, kind="reanalyze", requested_by=ctx.principal.user_id, state="QUEUED")
    s.add(job)
    s.commit()
    container.get().runner.submit("analyze.run", job_id=job.id)
    return {"evidence_id": ev.id, "imported": len(docs), "job_id": job.id}
