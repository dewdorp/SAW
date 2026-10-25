from __future__ import annotations

import hashlib
import io

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from saw import container
from saw.apps.api.deps import AuthContext, auth, db, require_perm
from saw.connectors import registry as creg
from saw.connectors.base import ConnectorNotImplemented
from saw.core.application import audit
from saw.core.application import evidence as ev_svc
from saw.core.application.data_deletion import lock_investigation
from saw.core.application.investigations import require
from saw.core.schemas.query import Filter, TimeRange
from saw.storage.db import new_id, utcnow
from saw.storage.generations import canonical_event_bytes
from saw.storage.models import EvidenceFile, Job

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


def _existing_import(s, inv_id, reservation):
    sources = set(reservation['sources'])
    for job in s.scalars(select(Job).where(Job.investigation_id == inv_id).execution_options(populate_existing=True)):
        previous = (job.stages or {}).get('_connector_import') or {}
        if previous.get('connector_id') != reservation['connector_id']:
            continue
        if previous.get('payload_sha256') == reservation['payload_sha256']:
            return {'evidence_id': job.evidence_id, 'imported': previous['count'], 'job_id': job.id}
        if sources.intersection(previous.get('sources', [])):
            raise HTTPException(409, 'Connector source events already belong to another immutable import; reuse its job or select disjoint events.')
    return None


@router.post("/investigations/{inv_id}/connector-import")
def connector_import(inv_id: str, body: ImportIn, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    """Reserve immutable connector facts once per investigation before queued ingestion."""
    from saw.parsers.connector import connector_facts
    require(s, ctx.principal, "investigation.write", inv_id)
    try:
        conn = creg.get(s, body.connector_id)
    except ValueError as e:
        raise HTTPException(404, str(e)) from None
    # Remote reads, serialization and object writes do not hold the investigation lock.
    s.commit()
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
    documents = {}
    for upstream in events[:body.limit]:
        facts = connector_facts(upstream)
        fact_hash = hashlib.sha256(canonical_event_bytes(facts)).hexdigest()
        source_id = upstream.get('event_id')
        if not isinstance(source_id, (str, int)) or isinstance(source_id, bool) or source_id == '':
            source_id = 'content:' + fact_hash
        source_key = hashlib.sha256(canonical_event_bytes({'connector': conn.id, 'source': source_id})).hexdigest()
        doc = {'format': 'saw-connector-ces/1', 'event': facts, 'connector_id': conn.id,
               'connector_source_event_id': source_id}
        encoded = canonical_event_bytes(doc)
        if source_key in documents and documents[source_key] != encoded:
            raise HTTPException(409, 'Connector supplied conflicting facts for one source event.')
        documents[source_key] = encoded
    content = b''.join(documents[key] + b'\n' for key in sorted(documents))
    reservation = {'connector_id': conn.id, 'sources': sorted(documents), 'count': len(documents),
                   'payload_sha256': hashlib.sha256(canonical_event_bytes({
                       'investigation_id': inv_id, 'connector_id': conn.id,
                       'content_sha256': hashlib.sha256(content).hexdigest()})).hexdigest()}
    existing = _existing_import(s, inv_id, reservation)
    s.commit()
    if existing:
        return existing
    key = f"{inv_id}/connector-input/{new_id()}/connector.jsonl"
    objects = container.get().objects
    size, sha256 = objects.put_stream('saw-evidence-original', key, io.BytesIO(content))
    referenced = False
    try:
        lock_investigation(s, inv_id)
        require(s, ctx.principal, 'investigation.write', inv_id)
        existing = _existing_import(s, inv_id, reservation)
        if existing:
            s.commit()
            return existing
        ev = ev_svc.create_evidence(s, ctx.principal, inv_id, 'auto', f'connector:{conn.kind} ({len(documents)} events)')
        ev.kind = 'connector'
        f = EvidenceFile(evidence_id=ev.id, display_name=f'connector-{conn.kind}.jsonl', object_key=key,
                         size=size, sha256=sha256, type_detected='text', parser_id='json_lines', parse_status='pending')
        s.add(f)
        ev.total_size, ev.file_count = size, 1
        ev_svc.touch_custody(s, ev.id, None, 'import', ctx.principal.username,
                             {'connector': conn.id, 'filters': [f.model_dump() for f in body.filters], 'events': len(documents)})
        audit.record(s, 'connector.import', actor_id=ctx.principal.user_id, actor_name=ctx.principal.username,
                     target_type='connector', target_id=conn.id, investigation_id=inv_id, detail={'events': len(documents)})
        job = Job(investigation_id=inv_id, evidence_id=ev.id, kind='ingest', requested_by=ctx.principal.user_id,
                  state='QUEUED', stages={'_queue_task': 'ingest.resume', '_connector_import': reservation})
        s.add(job)
        s.commit()
        referenced = True
    finally:
        if not referenced:
            s.rollback()
            objects.delete('saw-evidence-original', key)  # only this request's newly created, unreferenced object
    container.get().runner.submit('ingest.resume', job_id=job.id)
    return {'evidence_id': ev.id, 'imported': len(documents), 'job_id': job.id}
