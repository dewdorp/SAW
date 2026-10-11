"""Processing records (provenance): who processed which input with which parser / settings and what came out.

- analysts: runs of the investigations they can read ("내 처리 기록")
- SOC manager / auditor (audit.read): every run plus a consolidated view with consistency warnings; an auditor
  without investigation access sees no file names (content-free summary, separation of duties)
"""
from __future__ import annotations

import os
from collections import defaultdict
from datetime import timedelta

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from saw.apps.api.deps import AuthContext, auth, db
from saw.core.application import provenance
from saw.core.application.investigations import Forbidden, NotFound, list_for
from saw.core.security.authz import can
from saw.storage.db import utcnow
from saw.storage.models import AuditEvent, Investigation, ProcessingRun

router = APIRouter(tags=["provenance"])


def _content(ctx: AuthContext) -> bool:
    return can(ctx.principal, "investigation.read")


def _row(r: ProcessingRun, inv: dict[str, Investigation], content: bool) -> dict:
    i = inv.get(r.investigation_id)
    out = {"id": r.id, "finished_at": r.finished_at, "actor": r.actor_name, "actor_id": r.actor_id,
           "investigation": i.display_id if i else None, "input_sha256": r.input_sha256, "input_size": r.input_size,
           "parser_id": r.parser_id, "parser_version": r.parser_version, "parser_digest": r.parser_digest,
           "settings_digest": r.settings_digest, "run_digest": r.run_digest, "events": r.events, "failed": r.failed,
           "status": r.status, "draft_parser": "@" in (r.parser_id or "")}
    if content:
        out.update(file_name=r.file_name, investigation_id=r.investigation_id,
                   investigation_title=i.title if i else None, settings=r.settings, coverage=r.coverage)
    else:  # auditors: the file type only, never the name (it can reveal the case)
        out["file_name"] = f"(비공개){os.path.splitext(r.file_name)[1][:10]}"
    return out


def _scope(s: Session, ctx: AuthContext, scope: str):
    if scope == "all":
        if not can(ctx.principal, "audit.read"):
            raise Forbidden("audit.read required for the consolidated view")
        return select(ProcessingRun)
    ids = [i.id for i in list_for(s, ctx.principal, 1000)]
    return select(ProcessingRun).where(ProcessingRun.investigation_id.in_(ids))


@router.get("/processing-runs")
def runs(scope: str = Query("mine", pattern="^(mine|all)$"), investigation_id: str | None = None,
         actor_id: str | None = None, days: int = Query(90, ge=1, le=3650), limit: int = Query(300, le=2000),
         ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    q = _scope(s, ctx, scope).where(ProcessingRun.finished_at >= utcnow() - timedelta(days=days))
    if investigation_id:
        q = q.where(ProcessingRun.investigation_id == investigation_id)
    if actor_id:
        q = q.where(ProcessingRun.actor_id == actor_id)
    rows = s.execute(q.order_by(ProcessingRun.finished_at.desc()).limit(limit)).scalars().all()
    inv = {i.id: i for i in s.execute(select(Investigation).where(
        Investigation.id.in_({r.investigation_id for r in rows}))).scalars()}
    content = _content(ctx)
    return [_row(r, inv, content) for r in rows]


@router.get("/processing-runs/summary")
def summary(days: int = Query(90, ge=1, le=3650), ctx: AuthContext = Depends(auth),
            s: Session = Depends(db, scope="function")):
    """Consolidated view: per analyst, per parser, and the inconsistencies a reviewer should look at."""
    rows = s.execute(_scope(s, ctx, "all").where(ProcessingRun.finished_at >= utcnow() - timedelta(days=days))
                     .order_by(ProcessingRun.finished_at.desc())).scalars().all()
    inv = {i.id: i for i in s.execute(select(Investigation).where(
        Investigation.id.in_({r.investigation_id for r in rows}))).scalars()}
    content = _content(ctx)
    by_user: dict[str, dict] = {}
    by_parser: dict[tuple[str, str], dict] = {}
    by_input: dict[str, list[ProcessingRun]] = defaultdict(list)
    digests: dict[str, set[str]] = defaultdict(set)
    for r in rows:
        u = by_user.setdefault(r.actor_id, {"actor": r.actor_name, "actor_id": r.actor_id, "runs": 0, "files": set(),
                                            "events": 0, "draft_runs": 0, "failed_lines": 0})
        u["runs"] += 1
        u["files"].add(r.input_sha256)
        u["events"] += r.events
        u["failed_lines"] += r.failed
        u["draft_runs"] += "@" in (r.parser_id or "")
        pk = (r.parser_id, r.parser_version)
        p = by_parser.setdefault(pk, {"parser_id": r.parser_id, "parser_version": r.parser_version, "runs": 0,
                                      "settings_variants": set(), "analysts": set()})
        p["runs"] += 1
        p["settings_variants"].add(r.settings_digest)
        p["analysts"].add(r.actor_name)
        if r.input_sha256:
            by_input[r.input_sha256].append(r)
        digests[r.parser_id].add(r.parser_digest)
    same_input = []
    for sha, rs in by_input.items():
        if len({r.settings_digest for r in rs}) > 1:
            same_input.append({"input_sha256": sha, "runs": [_row(r, inv, content) for r in rs[:10]],
                               "settings_variants": len({r.settings_digest for r in rs})})
    changed_code = [{"parser_id": pid, "variants": len(d)} for pid, d in digests.items() if len(d) > 1]
    drafts = [_row(r, inv, content) for r in rows if "@" in (r.parser_id or "")][:50]
    return {
        "days": days, "runs": len(rows), "inputs": len(by_input),
        "by_user": sorted(({**u, "files": len(u["files"])} for u in by_user.values()), key=lambda x: -x["runs"]),
        "by_parser": sorted(({**p, "settings_variants": len(p["settings_variants"]), "analysts": sorted(p["analysts"])}
                             for p in by_parser.values()), key=lambda x: -x["runs"]),
        "warnings": {"same_input_different_settings": same_input[:50], "parser_definition_changed": changed_code,
                     "draft_parser_runs": drafts},
    }


@router.get("/processing-runs/{run_id}/verify")
def verify(run_id: str, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    """Re-compute the record's fingerprints and compare them with the copy in the hash-chained audit log."""
    r = s.get(ProcessingRun, run_id)
    if r is None:
        raise NotFound("run not found")
    if not can(ctx.principal, "audit.read") and r.investigation_id not in {i.id for i in list_for(s, ctx.principal, 1000)}:
        raise NotFound("run not found")
    sdig = provenance.digest(r.settings)
    rdig = provenance.digest({"input_sha256": r.input_sha256, "settings_digest": sdig, "events": r.events,
                              "failed": r.failed, "coverage": r.coverage})
    ev = next((a for a in s.execute(select(AuditEvent).where(AuditEvent.action == "evidence.processed",
                                                             AuditEvent.target_id == r.file_id)).scalars()
               if (a.detail or {}).get("run_id") == r.id), None)
    audit_ok = bool(ev) and ev.detail.get("run_digest") == r.run_digest and ev.detail.get("settings_digest") == r.settings_digest
    return {"run_id": r.id, "recomputed_settings_digest_ok": sdig == r.settings_digest,
            "recomputed_run_digest_ok": rdig == r.run_digest, "audit_record_found": ev is not None,
            "audit_matches": audit_ok, "audit_event_id": ev.id if ev else None,
            "ok": sdig == r.settings_digest and rdig == r.run_digest and audit_ok}
