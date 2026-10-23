"""Exact report downloads; generated names and source-checked artifact streams."""
from __future__ import annotations

import tempfile
import time
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

from fastapi import Depends
from fastapi.responses import HTMLResponse, StreamingResponse
from sqlalchemy.orm import Session
from starlette.background import BackgroundTask

from saw import container
from saw.apps.api.deps import AuthContext, auth, db
from saw.apps.api.routers.evidence import job_out
from saw.reports import export_jobs, service
from saw.reports.schemas import ExportRequest

MEDIA = {"html": "text/html; charset=utf-8",
         "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"}


def stream_response(stream, artifact, fmt):
    def chunks():
        while block := stream.read(1024 * 1024):
            yield block
    from saw.reports.html import csp
    return StreamingResponse(chunks(), media_type=MEDIA[fmt],
        headers={"Content-Disposition": 'attachment; filename="' + artifact["filename"] + '"',
                 "Content-Length": str(artifact["bytes"]), "Cache-Control": "no-store",
                 "Content-Security-Policy": csp()},
        background=BackgroundTask(stream.close))


def submit_export(body: ExportRequest, ctx: AuthContext = Depends(auth),
                  s: Session = Depends(db, scope="function")):
    job, created = export_jobs.submit(s, ctx.principal, body.model_dump())
    s.commit()
    if created:
        container.get().runner.submit("report_export.run", job_id=job.id)
    s.refresh(job)
    return job_out(job)


def download_export(job_id: str, ctx: AuthContext = Depends(auth),
                    s: Session = Depends(db, scope="function")):
    stream, artifact, fmt = export_jobs.open_download(s, ctx.principal, job_id,
                                                     session_id=ctx.session.id)
    return stream_response(stream, artifact, fmt)


def _saved_snapshot(s, p, inv_id, report_id, session_id):
    actor = export_jobs.download_actor(s, p, session_id=session_id)
    row = service.get(s, actor, inv_id, report_id)
    frozen = SimpleNamespace(content=deepcopy(row.content), version=row.version,
                             content_sha256=row.content_sha256)
    s.commit()
    return frozen, actor


def _recheck_snapshot(s, actor, inv_id, report_id, session_id, sha):
    actor = export_jobs.download_actor(s, actor, session_id=session_id)
    current = service.get(s, actor, inv_id, report_id)
    if current.content_sha256 != sha:
        raise ValueError("report_snapshot_changed")


def _render_deadline():
    deadline = time.monotonic() + export_jobs.MAX_SECONDS
    def check():
        if time.monotonic() > deadline:
            raise ValueError("report_export_time_limit_split_selection")
        return False
    return check


def view_html(inv_id, report_id, ctx, s):
    from saw.reports.html import csp, render
    session_id = ctx.session.id
    frozen, actor = _saved_snapshot(s, ctx.principal, inv_id, report_id, session_id)
    check = _render_deadline()
    check()
    if frozen.content.get("schema_version") == "saw.report.v2":
        from saw.reports.projection_html import render as render_v2
        output = render_v2(frozen.content, cancelled=check)
    else:
        # The legacy renderer keeps its exact v1 interpretation and bounded snapshot.
        output = render(frozen)
    check()
    if len(output.encode("utf-8")) > export_jobs.MAX_ARTIFACT_BYTES:
        raise ValueError("report_artifact_limit_split_selection")
    _recheck_snapshot(s, actor, inv_id, report_id, session_id, frozen.content_sha256)
    return HTMLResponse(output, headers={"Content-Security-Policy": csp(),
                                         "Cache-Control": "no-store"})


def download_xlsx(inv_id: str, report_id: str, ctx: AuthContext = Depends(auth),
                  s: Session = Depends(db, scope="function")):
    session_id = ctx.session.id
    frozen, actor = _saved_snapshot(s, ctx.principal, inv_id, report_id, session_id)
    content, version, sha = frozen.content, frozen.version, frozen.content_sha256
    deadline_check = _render_deadline()
    stream = tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024, mode="w+b")  # noqa: SIM115 - response owns the stream; failures close it below.
    try:
        scratch = Path(container.get().settings.data_dir) / "scratch" / "report-export"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="download-", dir=scratch) as work:
            path = Path(work) / "report.xlsx"
            manifest = export_jobs.render_artifact(content, path, "xlsx", cancelled=deadline_check)
            if manifest["content_sha256"] != sha:
                raise ValueError("report_writer_snapshot_mismatch")
            size, output_sha = export_jobs._file_digest(path)
            with path.open("rb") as source:
                while block := source.read(1024 * 1024):
                    stream.write(block)
        _recheck_snapshot(s, actor, inv_id, report_id, session_id, sha)
        stream.seek(0)
        return stream_response(stream, {"filename": f"SAW-report-v{version}-{report_id[:8]}.xlsx",
                                       "bytes": size, "sha256": output_sha}, "xlsx")
    except Exception:
        stream.close()
        raise
